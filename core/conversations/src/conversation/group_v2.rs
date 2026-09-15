// This Implementation is a Quick and Dirty Integration of DeMLS into libchat.
// DeMLS and Libchat have different execution models, trait definitions and ownership/lifetimes of objects.
// The easies path is to do a Spike to see what it would take, gather the friction points and then iterate.

use crate::conversation::mls_extensions::{
    ConvoMetaInfo, GROUP_METADATA_EXTENSION_TYPE, capabilities_with_group_metadata,
};
use crate::types::{AddressedEncryptedPayload, ConvoMetadata};
use crate::{Content, WakeupService};
use alloy::signers::local::PrivateKeySigner;
use blake2::{Blake2b, Digest, digest::consts::U6};
use chat_proto::logoschat::encryption::{EncryptedPayload, Plaintext, encrypted_payload};
use chat_proto::logoschat::reliability::ReliablePayload;
use de_mls::protos::de_mls::messages::v1::{
    AppMessage as AppMessageProto, MemberWelcome, app_message,
};
use de_mls::{
    Conversation, ConversationError, ConversationEvent, Member, MemberId, MockClock,
    PeerScoringService, ScoringConfig, WallClock, default_score_deltas,
    defaults::{DefaultConsensusPlugin, DefaultPeerScoring, InMemoryPeerScoreStorage},
};
use hashgraph_like_consensus::signing::EthereumConsensusSigner;
use openmls::extensions::{Extension, Extensions, UnknownExtension};
use openmls::group::MlsGroupCreateConfig;
use openmls::prelude::tls_codec::Deserialize as _;
use openmls::prelude::{KeyPackageIn, OpenMlsProvider as _, ProtocolVersion};
use prost::Message;
use shared_traits::{IdentId, IdentIdRef};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{info, instrument};

use crate::IdentityProvider;
use crate::conversation::{ConversationIdRef, ExternalServices, MessageId, ServiceContext};
use crate::{
    ConvoOutcome, DeliveryService, RegistrationService,
    conversation::{ChatError, Convo, GroupConvo, Identified},
};

/// The de-mls time source: every conversation deadline (freeze windows,
/// consensus timeouts, auto-votes) and consensus wire timestamp is measured
/// against this clock. Production runs on system time; tests share one
/// `MockClock` with the harness scheduler so virtual time moves the
/// protocol's timers.
#[derive(Debug, Clone, Default)]
pub enum GroupV2Clock {
    #[default]
    System,
    Mock(MockClock),
}

impl WallClock for GroupV2Clock {
    fn now(&self) -> Duration {
        match self {
            GroupV2Clock::System => SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default(),
            GroupV2Clock::Mock(clock) => clock.now(),
        }
    }
}

/// `app_id` for outbound packets / echo-dedup — random per conversation.
fn rand_app_id() -> Arc<[u8]> {
    Arc::from(rand_string(5).as_bytes())
}

/// The signer id we name a member by — hex of its MLS signature key, the same
/// id `add_member` takes and the registry is keyed on.
fn signer_of(member: &Member) -> IdentId {
    IdentId::new(hex::encode(&member.signature_key))
}

/// Peer-scoring plug-in: the library default over in-memory storage.
fn make_scoring() -> DefaultPeerScoring {
    PeerScoringService::new(
        InMemoryPeerScoreStorage::default(),
        default_score_deltas(),
        ScoringConfig::default(),
    )
}

/// Consensus service: the library default over a fresh in-memory store and a
/// random Ethereum consensus signer.
fn make_consensus() -> DefaultConsensusPlugin {
    DefaultConsensusPlugin::new(EthereumConsensusSigner::new(PrivateKeySigner::random()))
}

pub struct GroupV2Convo {
    convo_id: String,
    conversation: Conversation<DefaultConsensusPlugin, InMemoryPeerScoreStorage, GroupV2Clock>,
    /// Map of invited members: signature key to credential.
    pending_invites: HashMap<Vec<u8>, Vec<u8>>,
    /// Keeps track of current group members: maps de-mls `MemberId` handles to signer ids.
    /// We update this list when members are added or removed.
    member_directory: HashMap<MemberId, IdentId>,
}

impl std::fmt::Debug for GroupV2Convo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroupV2Convo")
            .field("convo_id", &self.convo_id)
            .finish_non_exhaustive()
    }
}

fn rand_string(n: usize) -> String {
    let bytes: Vec<u8> = (0..n).map(|_| rand::random::<u8>()).collect();
    hex::encode(bytes)
}

fn group_config(name: &str, desc: &str) -> MlsGroupCreateConfig {
    let meta = ConvoMetaInfo::new(name, desc);

    let extensions = Extensions::from_vec(vec![Extension::Unknown(
        GROUP_METADATA_EXTENSION_TYPE,
        UnknownExtension(meta.to_extension_bytes()),
    )])
    .expect("failed to create extensions");

    MlsGroupCreateConfig::builder()
        .ciphersuite(crate::inbox_v2::CIPHER_SUITE)
        .capabilities(capabilities_with_group_metadata())
        .use_ratchet_tree_extension(true) // Embed the ratchet tree in the Welcome so joiners can build the group
        .with_group_context_extensions(extensions)
        .build()
}

/// Info about a member to add:
/// `signature_key` points to their welcome message,
/// and `credential` will show in the group member.
struct FetchedMember {
    signature_key: Vec<u8>,
    credential: Vec<u8>,
    key_package: Vec<u8>,
}

/// Fetch each signer's key package, deduped, reading the two ids off the leaf.
/// Fails if anyone lacks one, before any member is admitted.
fn fetch_key_packages<S: ExternalServices>(
    service_ctx: &ServiceContext<S>,
    participants: &[IdentIdRef],
) -> Result<Vec<FetchedMember>, ChatError> {
    let mut seen = HashSet::new();
    participants
        .iter()
        .copied()
        .filter(|m| seen.insert(m.as_str()))
        .map(|member| {
            let key_package = service_ctx
                .registry
                .retrieve(member.as_str())
                .map_err(ChatError::generic)?
                .ok_or_else(|| ChatError::generic("No key package"))?;
            let validated = KeyPackageIn::tls_deserialize(&mut key_package.as_slice())?
                .validate(service_ctx.mls_provider.crypto(), ProtocolVersion::Mls10)?;
            // SECURITY: a valid KeyPackage proves only that it is well-formed and
            // self-signed, not that it belongs to the signer we requested — a
            // compromised registry could hand back an attacker's package under a
            // victim's id. The signer id is hex(the leaf's Ed25519 verifying key),
            // so bind the leaf's signature_key to it; the credential is
            // self-asserted and can't be trusted for this.
            let signature_key = validated.leaf_node().signature_key().as_slice().to_vec();
            let leaf_key = hex::encode(&signature_key);
            if leaf_key != member.as_str() {
                return Err(ChatError::generic(format!(
                    "key package for {member} is bound to a different signing key ({leaf_key})"
                )));
            }
            let credential = validated
                .leaf_node()
                .credential()
                .serialized_content()
                .to_vec();
            Ok(FetchedMember {
                signature_key,
                credential,
                key_package,
            })
        })
        .collect()
}

impl GroupV2Convo {
    pub fn new<S: ExternalServices>(
        service_ctx: &mut ServiceContext<S>,
        name: &str,
        desc: &str,
        participants: &[IdentIdRef],
    ) -> Result<Self, ChatError> {
        let convo_id = rand_string(5);
        let group_config = group_config(name, desc);
        let invites = fetch_key_packages(service_ctx, participants)?;
        let initial_members: Vec<&[u8]> =
            invites.iter().map(|m| m.key_package.as_slice()).collect();
        let conversation = Conversation::create(
            &convo_id,
            &service_ctx.mls_provider,
            service_ctx.mls_identity.get_credential(),
            &group_config,
            &service_ctx.mls_identity,
            &make_consensus(),
            make_scoring(),
            service_ctx.demls_clock.clone(),
            rand_app_id(),
            service_ctx.demls_config.clone(),
            &initial_members,
        )?;
        let pending_invites = invites
            .into_iter()
            .map(|m| (m.signature_key, m.credential))
            .collect();

        let mut convo = GroupV2Convo {
            convo_id,
            conversation,
            pending_invites,
            member_directory: HashMap::new(),
        };
        // Genesis members are seeded inside `create` and never surface as a
        // `MembersChanged`, so read the initial set straight from the group.
        convo.rebuild_member_directory();

        convo.init(service_ctx)?;
        convo.after_op(service_ctx)?;
        Ok(convo)
    }

    /// Joiner side: ingest a de-mls welcome handed over the InboxV2 1-1
    /// channel. `from_welcome` attaches MLS and applies the bundled
    /// `ConversationSync` in one call; we then subscribe to the
    /// conversation address and flush the join broadcast.
    #[instrument(name = "groupv2.new_from_welcome", skip_all, fields(user_id = %service_ctx.mls_identity.display_name()))]
    pub fn new_from_welcome<S: ExternalServices>(
        service_ctx: &mut ServiceContext<S>,
        welcome: &MemberWelcome,
    ) -> Result<Self, ChatError> {
        let Some(conv) = Conversation::join(
            &service_ctx.mls_provider,
            &service_ctx.mls_identity,
            &welcome.welcome_bytes,
            &welcome.conversation_sync_bytes,
            &make_consensus(),
            make_scoring(),
            service_ctx.demls_clock.clone(),
            rand_app_id(),
            service_ctx.demls_config.clone(),
        )?
        else {
            return Err(ChatError::generic("welcome not addressed to this member"));
        };

        let mut convo = GroupV2Convo {
            convo_id: conv.id().to_string(),
            conversation: conv,
            pending_invites: HashMap::new(),
            member_directory: HashMap::new(),
        };
        // The welcome already carries the full member set; the members present
        // before we joined never arrive as a `MembersChanged`, so seed from the
        // group we just built.
        convo.rebuild_member_directory();

        convo.init(service_ctx)?; // subscribe
        convo.after_op(service_ctx)?; // flush join broadcast + schedule wakeup

        Ok(convo)
    }

    fn delivery_address_from_id(convo_id: &str) -> String {
        let hash = Blake2b::<U6>::new()
            .chain_update("delivery_addr|")
            .chain_update(convo_id)
            .finalize();
        hex::encode(hash)
    }

    fn init<S: ExternalServices>(
        &self,
        service_ctx: &mut ServiceContext<S>,
    ) -> Result<(), ChatError> {
        // Configure the delivery service to listen for the required delivery addresses.
        service_ctx
            .ds
            .subscribe(&Self::delivery_address_from_id(&self.convo_id))
            .map_err(ChatError::generic)?;
        Ok(())
    }

    pub fn id(&self) -> ConversationIdRef<'_> {
        &self.convo_id
    }

    /// Rebuild the member directory from the group's current members. Used to
    /// seed the set at construction, where no `MembersChanged` is emitted.
    fn rebuild_member_directory(&mut self) {
        self.member_directory = self
            .conversation
            .members_view()
            .iter()
            .map(|m| (MemberId::from(m), signer_of(m)))
            .collect();
    }
}

impl Identified for GroupV2Convo {
    fn id(&self) -> ConversationIdRef<'_> {
        &self.convo_id
    }
}

impl<S> Convo<S> for GroupV2Convo
where
    S: ExternalServices,
{
    #[instrument(name = "groupv2.send_content", skip_all, fields(user_id = %service_ctx.mls_identity.display_name(), content))]
    fn send_content(
        &mut self,
        service_ctx: &mut super::ServiceContext<S>,
        content: &[u8],
    ) -> Result<MessageId, ChatError> {
        let reliable = service_ctx.causal.on_send(
            &self.convo_id,
            service_ctx.mls_identity.id().as_str(),
            content,
        );

        self.conversation.send_message(
            &service_ctx.mls_provider,
            &service_ctx.mls_identity,
            reliable.encode_to_vec(),
        )?;
        self.after_op(service_ctx)?;
        Ok(reliable.message_id)
    }

    #[instrument(name = "groupv2.handle_frame", skip_all, fields(user_id = %service_ctx.mls_identity.display_name()))]
    fn handle_frame(
        &mut self,
        service_ctx: &mut super::ServiceContext<S>,
        encoded_payload: EncryptedPayload,
    ) -> Result<ConvoOutcome, ChatError> {
        let bytes = match encoded_payload.encryption {
            Some(encrypted_payload::Encryption::Plaintext(pt)) => pt.payload,
            _ => {
                return Err(ChatError::generic("Expected plaintext"));
            }
        };
        let frame = GroupV2Frame::decode(bytes.as_ref()).map_err(ChatError::generic)?;
        let inner = match frame.payload {
            Some(GroupV2Payload::DeMlsWrapper(b)) => b.to_vec(),
            _ => return Ok(ConvoOutcome::empty(self.convo_id.clone())),
        };

        self.conversation.process_inbound(
            &service_ctx.mls_provider,
            &service_ctx.mls_identity,
            &frame.sender_app_id,
            &inner,
        )?;
        self.conversation
            .poll(&service_ctx.mls_provider, &service_ctx.mls_identity);
        let events = self.after_op(service_ctx)?; // route + publish + re-arm, returns events
        self.outcome_from_events(service_ctx, &events)
    }

    #[instrument(name = "groupv2.wakeup", skip_all, fields(user_id = %ctx.mls_identity.display_name()))]
    fn wakeup(&mut self, ctx: &mut ServiceContext<S>) -> Result<ConvoOutcome, ChatError> {
        info!(convo = %self.convo_id, "Wakeup");

        let poll_outcome = self.conversation.poll(&ctx.mls_provider, &ctx.mls_identity);
        if poll_outcome.leave_requested {
            // Commit ejected us (or join expired). Real handling - drops
            // this convo from its map;
            tracing::warn!(convo = %self.convo_id, "conversation requested teardown");
        }
        let events = self.after_op(ctx)?; // publish what poll produced + re-arm alarm
        self.outcome_from_events(ctx, &events)
    }

    fn members(&self) -> Result<Vec<Vec<u8>>, ChatError> {
        Ok(self
            .conversation
            .members_view()
            .into_iter()
            .map(|m| m.credential.serialized_content().to_vec())
            .collect())
    }

    fn can_send(&self) -> bool {
        // A de-mls member id is the big-endian u32 of the member's ratchet-tree
        // leaf index; `member_id_bytes` is our own. We can send while a member
        // still occupies that leaf — i.e. we have not been removed.
        let me = self.conversation.member_id_bytes();
        self.conversation
            .members_view()
            .iter()
            .any(|m| m.index.u32().to_be_bytes().as_slice() == me)
    }
}

impl<S> GroupConvo<S> for GroupV2Convo
where
    S: ExternalServices,
{
    #[instrument(name = "groupv2.add_member", skip_all, fields(user_id = %service_ctx.mls_identity.display_name()))]
    fn add_member(
        &mut self,
        service_ctx: &mut ServiceContext<S>,
        members: &[IdentIdRef],
    ) -> Result<(), ChatError> {
        // Fetch every signer's key package + joiner credential up front (deduped),
        // failing before any proposal opens if one has no key package.
        let members_to_add = fetch_key_packages(service_ctx, members)?;
        // Skip devices already seated. The signature key names one device.
        let existing: HashSet<Vec<u8>> = self
            .conversation
            .members_view()
            .iter()
            .map(|m| m.signature_key.clone())
            .collect();

        let mut result = Ok(());
        for FetchedMember {
            signature_key,
            credential,
            key_package,
        } in members_to_add
        {
            if existing.contains(&signature_key) {
                continue;
            }
            self.pending_invites
                .insert(signature_key.clone(), credential);
            match self.conversation.add_member(
                &service_ctx.mls_provider,
                &service_ctx.mls_identity,
                &key_package,
            ) {
                Ok(()) => {}
                // Already seated — it raced the check above. Nothing to invite,
                // and no reason to drop the rest of the batch.
                Err(ConversationError::AlreadyMember) => {
                    self.pending_invites.remove(&signature_key);
                }
                Err(e) => {
                    self.pending_invites.remove(&signature_key);
                    result = Err(e.into());
                    break;
                }
            }
        }
        // Flush even on a mid-loop failure: proposals already opened must be
        // published and the wakeup re-armed, or they sit dormant until an
        // unrelated frame drives the conversation.
        let flushed = self.after_op(service_ctx).map(drop);
        result.and(flushed)
    }

    fn pending_members(&self) -> Result<Vec<Vec<u8>>, ChatError> {
        Ok(self.pending_invites.values().cloned().collect())
    }

    fn metadata(&self) -> Option<ConvoMetadata> {
        let res = self.conversation.extensions().iter().find_map(|ext| {
            if let Extension::Unknown(ext_type, UnknownExtension(bytes)) = ext
                && *ext_type == GROUP_METADATA_EXTENSION_TYPE
            {
                return ConvoMetaInfo::from_extension_bytes(bytes).ok();
            };
            None
        });

        res.map(Into::into)
    }

    // fn conversation_state(&self) -> Result<ConversationState, ChatError> {
    //     Ok(self
    //         .conversation
    //         .as_ref()
    //         .map(|c| c.state())
    //         .unwrap_or(ConversationState::PendingJoin))
    // }
}

impl GroupV2Convo {
    fn after_op<S: ExternalServices>(
        &mut self,
        service_ctx: &mut ServiceContext<S>,
    ) -> Result<Vec<ConversationEvent>, ChatError> {
        // Pull everything first (these are &self, take-all):
        let events = self.conversation.drain_events();
        let outbound = self.conversation.drain_outbound(); // Vec<de_mls::session::Outbound>
        let wakeup = self.conversation.next_wakeup_in();

        // 1. Route welcomes for joiners WE invited: every member sees the
        //    WelcomeReady, and the welcome travels to the joiner's signer id —
        //    its InboxV2 transport address. In the same pass, keep the member
        //    directory current from the membership deltas de-mls reports.
        for evt in &events {
            match evt {
                ConversationEvent::WelcomeReady { welcome, .. } => {
                    for joiner in &welcome.joiner_identities {
                        if self.pending_invites.remove(joiner).is_some() {
                            let signer = IdentId::new(hex::encode(joiner));
                            crate::inbox_v2::invite_user_v2(&mut service_ctx.ds, &signer, welcome)?;
                        }
                    }
                }
                ConversationEvent::MembersChanged { added, removed } => {
                    for m in added {
                        self.member_directory
                            .insert(MemberId::from(m), signer_of(m));
                    }
                    for mid in removed {
                        self.member_directory.remove(mid);
                    }
                }
                _ => {}
            }
        }

        // 2. Publish
        for out in outbound {
            let frame = GroupV2Frame {
                payload: Some(GroupV2Payload::DeMlsWrapper(out.payload.into())),
                sender_app_id: out.sender, // was pkt.app_id
            };
            let payload = AddressedEncryptedPayload {
                delivery_address: Self::delivery_address_from_id(&out.conversation_id),
                data: EncryptedPayload {
                    encryption: Some(encrypted_payload::Encryption::Plaintext(Plaintext {
                        payload: frame.encode_to_vec().into(),
                    })),
                },
            };
            service_ctx
                .ds
                .publish(payload.into_envelope(out.conversation_id))
                .map_err(ChatError::generic)?;
        }

        // 3. Re-arm the alarm with the conversation's earliest deadline.
        if let Some(d) = wakeup {
            service_ctx
                .wakeup_service
                .wakeup_in(d, self.convo_id.clone());
        }
        Ok(events)
    }

    /// Turn drained de-mls events into a [`ConvoOutcome`], unwrapping the
    /// message from its causal-history envelope.
    ///
    /// An outcome holds one message and de-mls emits at most one per frame, so
    /// the first wins. A second would be dropped without being recorded as
    /// seen, leaving a later reference to report it missing.
    fn outcome_from_events<S: ExternalServices>(
        &self,
        service_ctx: &ServiceContext<S>,
        events: &[ConversationEvent],
    ) -> Result<ConvoOutcome, ChatError> {
        let content = events
            .iter()
            .find_map(|evt| match evt {
                ConversationEvent::ConversationMessage {
                    message:
                        AppMessageProto {
                            payload: Some(app_message::Payload::ConversationMessage(cm)),
                        },
                    sender,
                } => Some((cm, sender)),
                _ => None,
            })
            .map(|(cm, sender)| -> Result<Content, ChatError> {
                let reliable =
                    ReliablePayload::decode(cm.message.as_slice()).map_err(ChatError::generic)?;
                service_ctx.causal.on_receive(&self.convo_id, &reliable);
                Ok(Content {
                    bytes: reliable.content.to_vec(),
                    // `sender` is the MLS-authenticated signer of the frame; its
                    // credential content is the account identity to attribute to.
                    encoded_credential: sender.credential.serialized_content().to_vec(),
                    message_id: reliable.message_id.clone(),
                })
            })
            .transpose()?;

        let members_changed = events.iter().any(|evt| {
            matches!(
                evt,
                ConversationEvent::CommitApplied(_) | ConversationEvent::WelcomeReady { .. }
            )
        });
        Ok(ConvoOutcome {
            convo_id: self.convo_id.clone(),
            content,
            members_changed,
        })
    }
}

use prost::{Oneof, bytes::Bytes};

#[derive(Clone, PartialEq, Message)]
pub struct GroupV2Frame {
    #[prost(oneof = "GroupV2Payload", tags = "2, 3")]
    pub payload: Option<GroupV2Payload>,
    #[prost(bytes = "vec", tag = "4")]
    pub sender_app_id: Vec<u8>,
}

#[derive(Clone, PartialEq, Oneof)]
pub enum GroupV2Payload {
    #[prost(message, tag = "2")]
    DeMlsWrapper(Bytes),
    #[prost(message, tag = "3")]
    MlsCommitMessage(Bytes),
}
