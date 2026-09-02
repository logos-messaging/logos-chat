use crate::kv::ScopedKvStore;
/// GroupV1 is a conversationType which provides effecient handling of multiple participants
/// Properties:
///     - Harvest Now Decrypt Later (HNDL) protection provided by XWING
///     - Multiple
use blake2::{Blake2b, Digest, digest::consts::U6};
use chat_proto::logoschat::encryption::{EncryptedPayload, Plaintext, encrypted_payload};
use chat_proto::logoschat::reliability::ReliablePayload;
use openmls::prelude::tls_codec::Deserialize;
use openmls::prelude::*;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::random::OpenMlsRand;
use prost::Message as _;
use shared_traits::IdentIdRef;
use std::collections::VecDeque;
use tracing::debug;

use crate::conversation::{ConversationId, ConversationIdRef, MessageId};
use crate::inbox_v2::invite_user;
use crate::mls::{KeyPackages, MlsAdapter, MlsProvider};
use crate::service_context::{ExternalServices, ServiceContext};

use crate::types::ConvoMetadata;
use crate::utils::{blake2b_hex, hash_size};
use crate::{
    DeliveryService, IdentityProvider,
    conversation::{ChatError, Convo, GroupConvo, Identified},
    outcomes::{Content, ConvoOutcome},
    service_traits::KeyPackageProvider,
    types::AddressedEncryptedPayload,
};

const OUTBOUND_HASH_CACHE_SIZE: usize = 25;

pub struct GroupV1Convo {
    mls_group: MlsGroup,
    convo_id: String,
    // Cache outbound message Id's to filter out re-entrant messages
    outbound_msgs: VecDeque<String>,
}

impl std::fmt::Debug for GroupV1Convo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroupV1Convo")
            .field("convo_id", &self.convo_id)
            .field("mls_epoch", &self.mls_group.epoch())
            .finish_non_exhaustive()
    }
}

impl GroupV1Convo {
    /// A fresh conversation id, the hex of a random MLS group id, minted before the group so the
    /// scope holding it can be bound first.
    pub fn mint_id(rand: &impl OpenMlsRand) -> ConversationId {
        Self::convo_id_for(&GroupId::random(rand))
    }

    /// The conversation id an MLS group id spells.
    pub fn convo_id_for(group_id: &GroupId) -> ConversationId {
        hex::encode(group_id.as_slice())
    }

    /// The MLS group id a conversation id carries.
    fn group_id_for(convo_id: &str) -> Result<GroupId, ChatError> {
        let bytes = hex::decode(convo_id).map_err(ChatError::generic)?;
        Ok(GroupId::from_slice(&bytes))
    }

    // Create a new conversation with the creator as the only participant.
    pub fn new<S: ExternalServices>(
        cx: &mut ServiceContext<S>,
        kv: ScopedKvStore<'_>,
        convo_id: ConversationId,
    ) -> Result<Self, ChatError> {
        let config = Self::mls_create_config();
        let group_id = Self::group_id_for(&convo_id)?;
        let mls_group = MlsGroup::new_with_group_id(
            &MlsProvider::new(&cx.crypto, MlsAdapter::for_convo(kv)),
            &cx.mls_identity,
            &config,
            group_id,
            cx.mls_identity.get_credential(),
        )
        .map_err(ChatError::generic)?;
        Self::subscribe(&mut cx.ds, &convo_id)?;

        Ok(Self {
            mls_group,
            convo_id,
            outbound_msgs: VecDeque::new(),
        })
    }

    /// Decrypts a welcome far enough to name the group it admits us to. Only key packages are
    /// read, so the group's own scope is not needed yet and can be bound from the id this returns.
    pub fn process_welcome<S: ExternalServices>(
        cx: &ServiceContext<S>,
        key_packages: KeyPackages<'_>,
        welcome: Welcome,
    ) -> Result<ProcessedWelcome, ChatError> {
        ProcessedWelcome::new_from_welcome(
            &MlsProvider::new(&cx.crypto, MlsAdapter::for_key_packages(key_packages)),
            &Self::mls_join_config(),
            welcome,
        )
        .map_err(ChatError::generic)
    }

    // Constructs a new conversation upon receiving a MlsWelcome message.
    pub fn new_from_welcome<S: ExternalServices>(
        cx: &mut ServiceContext<S>,
        kv: ScopedKvStore<'_>,
        processed: ProcessedWelcome,
    ) -> Result<Self, ChatError> {
        let provider = MlsProvider::new(&cx.crypto, MlsAdapter::for_convo(kv));
        let mls_group = processed
            .into_staged_welcome(&provider, None)
            .map_err(ChatError::generic)?
            .into_group(&provider)
            .map_err(ChatError::generic)?;

        let convo_id = Self::convo_id_for(mls_group.group_id());
        Self::subscribe(&mut cx.ds, &convo_id)?;

        Ok(Self {
            mls_group,
            convo_id,
            outbound_msgs: VecDeque::new(),
        })
    }

    pub fn load<S: ExternalServices>(
        cx: &mut ServiceContext<S>,
        kv: ScopedKvStore<'_>,
        convo_id: ConversationId,
    ) -> Result<Self, ChatError> {
        let group_id = Self::group_id_for(&convo_id)?;
        let mls_group = MlsGroup::load(&MlsAdapter::for_convo(kv), &group_id)
            .map_err(ChatError::generic)?
            .ok_or_else(|| ChatError::NoConvo("mls group not found".into()))?;

        Self::subscribe(&mut cx.ds, &convo_id)?;

        Ok(GroupV1Convo {
            mls_group,
            convo_id,
            outbound_msgs: VecDeque::new(),
        })
    }

    // Configure the delivery service to listen for the required delivery addresses.
    fn subscribe(ds: &mut impl DeliveryService, convo_id: &str) -> Result<(), ChatError> {
        ds.subscribe(&Self::delivery_address_from_id(convo_id))
            .map_err(ChatError::generic)?;

        Ok(())
    }

    fn mls_create_config() -> MlsGroupCreateConfig {
        MlsGroupCreateConfig::builder()
            .ciphersuite(crate::inbox_v2::CIPHER_SUITE)
            .use_ratchet_tree_extension(true) // This is handy for now, until there is central store for this data
            .build()
    }

    fn mls_join_config() -> MlsGroupJoinConfig {
        MlsGroupJoinConfig::builder().build()
    }

    fn delivery_address_from_id(convo_id: &str) -> String {
        let hash = Blake2b::<U6>::new()
            .chain_update("delivery_addr|")
            .chain_update(convo_id)
            .finalize();
        hex::encode(hash)
    }

    fn delivery_address(&self) -> String {
        Self::delivery_address_from_id(&self.convo_id)
    }

    /// Fetch a signer's KeyPackage from the registry. Members are signer
    /// (installation) ids; resolving an account to its signers is the caller's
    /// concern, above the core.
    fn key_package_for_signer(
        &self,
        signer: IdentIdRef,
        crypto: &impl OpenMlsCrypto,
        registry: &impl KeyPackageProvider,
    ) -> Result<KeyPackage, ChatError> {
        let retrieved = registry
            .retrieve(signer.as_str())
            .map_err(|e| ChatError::Generic(e.to_string()))?;
        let Some(keypkg_bytes) = retrieved else {
            return Err(ChatError::Protocol(format!(
                "no keypackage for signer {signer}"
            )));
        };

        let key_package_in = KeyPackageIn::tls_deserialize(&mut keypkg_bytes.as_slice())?;
        let keypkg = key_package_in.validate(crypto, ProtocolVersion::Mls10)?; //TODO: P3 - Hardcoded Protocol Version
        // SECURITY: validate() only proves the package is well-formed and self-signed
        // — NOT that it belongs to the signer we asked the registry for. Bind the
        // fetched leaf's signature_key to the requested id (a signer id is
        // hex(Ed25519 verifying key)); reject a mismatch so a malicious/compromised
        // registry cannot insert an attacker's leaf under a victim's identity
        // (confidentiality break + sender-attribution spoof). Bind to the key, not the
        // spoofable credential bytes.
        let leaf_key = hex::encode(keypkg.leaf_node().signature_key().as_slice());
        if leaf_key != signer.as_str() {
            return Err(ChatError::Protocol(format!(
                "keypackage for signer {signer} is bound to a different signing key ({leaf_key})"
            )));
        }
        Ok(keypkg)
    }

    fn send_message<S: ExternalServices>(
        &mut self,
        content: &[u8],
        cx: &mut ServiceContext<S>,
        kv: ScopedKvStore<'_>,
    ) -> Result<MessageId, ChatError> {
        let sender_id = cx.mls_identity.id().as_str();
        let reliable = cx.causal.on_send(&self.convo_id, sender_id, content);
        let wire = reliable.encode_to_vec();

        let mls_message_out = self
            .mls_group
            .create_message(
                &MlsProvider::new(&cx.crypto, MlsAdapter::for_convo(kv)),
                &cx.mls_identity,
                &wire,
            )
            .map_err(ChatError::generic)?;

        let msg_bytes = mls_message_out.to_bytes().unwrap();
        self.send_payload(cx, msg_bytes)?;
        Ok(reliable.message_id)
    }

    // Publish outbound payloads to the DeliveryService
    fn send_payload<S: ExternalServices>(
        &mut self,
        cx: &mut ServiceContext<S>,
        msg_bytes: Vec<u8>,
    ) -> Result<(), ChatError> {
        // Hash and Cache to detect inbound messages
        let msg_hash = blake2b_hex::<hash_size::MessageId>(&[&msg_bytes]);
        self.outbound_msgs.push_back(msg_hash);
        if self.outbound_msgs.len() > OUTBOUND_HASH_CACHE_SIZE {
            let _ = self.outbound_msgs.remove(0);
        }

        // Wrap in Payload frames
        let aep = AddressedEncryptedPayload {
            delivery_address: self.delivery_address(),
            data: EncryptedPayload {
                encryption: Some(encrypted_payload::Encryption::Plaintext(Plaintext {
                    payload: msg_bytes.into(),
                })),
            },
        };
        let env = aep.into_envelope(self.convo_id.clone());

        // Send via DS
        cx.ds
            .publish(env)
            .map_err(|e| ChatError::Delivery(e.to_string()))
    }
}

impl Identified for GroupV1Convo {
    fn id(&self) -> ConversationIdRef<'_> {
        &self.convo_id
    }
}

impl<S: ExternalServices> Convo<S> for GroupV1Convo {
    fn send_content(
        &mut self,
        cx: &mut ServiceContext<S>,
        kv: ScopedKvStore<'_>,
        content: &[u8],
    ) -> Result<MessageId, ChatError> {
        self.send_message(content, cx, kv)
    }

    fn handle_frame(
        &mut self,
        cx: &mut ServiceContext<S>,
        kv: ScopedKvStore<'_>,
        encoded_payload: EncryptedPayload,
    ) -> Result<ConvoOutcome, ChatError> {
        let bytes = match encoded_payload.encryption {
            Some(encrypted_payload::Encryption::Plaintext(pt)) => pt.payload,
            _ => {
                return Err(ChatError::ProtocolExpectation(
                    "None",
                    "Some(Encryption::Plaintext)".into(),
                ));
            }
        };

        // Bail early if we sent this message
        let msg_hash = blake2b_hex::<hash_size::MessageId>(&[bytes.as_ref()]);
        if self.outbound_msgs.contains(&msg_hash) {
            debug!("Dropping message, sent from self");
            return Ok(ConvoOutcome::empty(self.convo_id.to_string()));
        }

        let mls_message: MlsMessageIn =
            MlsMessageIn::tls_deserialize_exact_bytes(&bytes).map_err(ChatError::generic)?;

        let protocol_message: ProtocolMessage = mls_message
            .try_into_protocol_message()
            .map_err(ChatError::generic)?;

        if protocol_message.epoch() < self.mls_group.epoch() {
            // TODO: (P1) Add logging for messages arriving from past epoch.
            return Ok(ConvoOutcome::empty(self.id().to_string()));
        }

        let provider = MlsProvider::new(&cx.crypto, MlsAdapter::for_convo(kv));
        let processed = self
            .mls_group
            .process_message(&provider, protocol_message)
            .map_err(ChatError::generic)?;

        let cred_bytes = processed.credential().serialized_content().to_vec();

        let content = match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(msg) => {
                let reliable = ReliablePayload::decode(msg.into_bytes().as_slice())?;
                cx.causal.on_receive(&self.convo_id, &reliable);
                Some(Content {
                    bytes: reliable.content.to_vec(),
                    encoded_credential: cred_bytes,
                })
            }
            ProcessedMessageContent::StagedCommitMessage(commit) => {
                self.mls_group
                    .merge_staged_commit(&provider, *commit)
                    .map_err(ChatError::generic)?;
                None
            }
            _ => {
                // TODO: (P2) Log unknown message type
                None
            }
        };
        Ok(ConvoOutcome {
            convo_id: self.id().to_string(),
            content,
            members_changed: false,
        })
    }

    fn wakeup(
        &mut self,
        _: &mut ServiceContext<S>,
        _: ScopedKvStore<'_>,
    ) -> Result<ConvoOutcome, ChatError> {
        Ok(ConvoOutcome::empty(self.id().to_string()))
    }

    fn members(&self) -> Result<Vec<Vec<u8>>, ChatError> {
        Ok(self
            .mls_group
            .members()
            .map(|m| m.credential.serialized_content().to_vec())
            .collect())
    }
}

impl<S: ExternalServices> GroupConvo<S> for GroupV1Convo {
    // add_members returns:
    //   commit      — the Commit message Alice broadcasts to all members
    //   welcome     — the Welcome message sent privately to each new joiner
    //   _group_info — used for external joins; ignore for now
    fn add_member(
        &mut self,
        cx: &mut ServiceContext<S>,
        kv: ScopedKvStore<'_>,
        members: &[IdentIdRef],
    ) -> Result<(), ChatError> {
        if members.len() > 50 {
            // This is a temporary limit that originates from the De-MLS epoch time.
            return Err(ChatError::Protocol(
                "Cannot add more than 50 Members at a time".into(),
            ));
        }

        // Members are signer (installation) ids: one KeyPackage each, one MLS
        // leaf each. A caller inviting an account passes every signer id the
        // account's directory bundle lists.
        let mut keypkgs = Vec::with_capacity(members.len());
        for ident in members {
            keypkgs.push(self.key_package_for_signer(ident, &cx.crypto, &cx.registry)?);
        }

        let provider = MlsProvider::new(&cx.crypto, MlsAdapter::for_convo(kv));
        let (commit, welcome, _group_info) = self
            .mls_group
            .add_members(&provider, &cx.mls_identity, keypkgs.iter().as_slice())
            .map_err(ChatError::generic)?;

        self.mls_group
            .merge_pending_commit(&provider)
            .map_err(ChatError::generic)?;

        // TODO: (P3) Evaluate privacy/performance implications of an aggregated Welcome for multiple users
        for signer_id in members {
            invite_user(&mut cx.ds, signer_id, &welcome)?;
        }

        self.send_payload(cx, commit.to_bytes()?)
    }

    /// Always empty: `add_member` merges its own commit, so an added member is
    /// on the roster by the time the call returns.
    fn pending_members(&self) -> Result<Vec<Vec<u8>>, ChatError> {
        Ok(Vec::new())
    }

    fn metadata(&self) -> Option<ConvoMetadata> {
        None
    }
}
