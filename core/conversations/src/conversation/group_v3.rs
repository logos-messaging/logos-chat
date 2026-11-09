// TESTING ONLY
// A Group Conversation that uses SDS for message ordering
//
// Invariants:
//  - Signers are not allowed change their SigningKey.
//  - Everyone is an "Admin"
//

mod beacons;
pub(crate) mod external;
mod handlers;
#[cfg(any(test, feature = "test-support"))]
pub mod inspect;
mod payloads;
mod readd;
mod sealed;

use std::collections::VecDeque;

use openmls::ciphersuite::hash_ref::ProposalRef;
use openmls::framing::MlsMessageOut;
use openmls::group::{MlsGroup, StagedWelcome};
use openmls::key_packages::KeyPackage;
use openmls::messages::Welcome;
use openmls::prelude::tls_codec::DeserializeBytes as _;
use openmls::prelude::{GroupId, LeafNodeIndex, MlsMessageIn};
use openmls_traits::OpenMlsProvider;
use openmls_traits::storage::StorageProvider as _;
use prost::Message;
use tracing::{debug, info, instrument, warn};

use crate::conversation::mls_groups::{HasMlsConvo, create_group, mls_join_config};
use crate::conversation::{ConversationIdRef, Convo, ConvoBase, GroupConvo, Identified};
use crate::errors::SendError;
use crate::service_context::ServiceContext;
use crate::utils::{blake2b_hex, hash_size};
use crate::{
    AddressedEnvelope, ChatError, ConvoOutcome, DeliveryService, ExternalServices,
    IdentityProvider, SignerKey,
};

use super::mls_utils::{fetch_key_packages, member_diff, unique};

use self::beacons::Beacons;
use self::payloads::{GroupV3Payload, frame_id, to_envelope};

// Type Aliases
type Frame = payloads::GroupV3Frame;
type FrameId = String;

fn delivery_address_from_id(convo_id: &str) -> String {
    blake2b_hex::<hash_size::DeliveryAddr>(&["delivery_addr|", convo_id])
}

#[derive(Debug)]
pub struct GroupV3Convo {
    convo_id: String,
    mls_group: MlsGroup,
    beacons: Beacons,
    served_readds: VecDeque<sealed::ReAddRequest>,
    /// Who committed the current epoch, if we know.
    committer: Option<LeafNodeIndex>,
    /// Our last re-add request's attempt; it picks the answerer.
    readd_attempt: u32,
}

impl GroupV3Convo {
    pub fn new<S: ExternalServices>(
        cx: &mut ServiceContext<S>,
        name: &str,
        desc: &str,
        signers: &[SignerKey],
    ) -> Result<Self, ChatError> {
        // Create MlsGroup
        let mls_group = create_group(cx, name, desc)?;

        let mut convo = Self {
            convo_id: hex::encode(mls_group.group_id().as_slice()),
            committer: Some(mls_group.own_leaf_index()),
            mls_group,
            beacons: Beacons::default(),
            served_readds: VecDeque::new(),
            readd_attempt: 0,
        };

        convo.init(cx)?;
        convo.add_signer(cx, signers)?;
        convo.enter_epoch(cx);
        Ok(convo)
    }

    /// Join from a Welcome. Also returns whether it replaced a group we held,
    /// which only a re-add we asked for may do.
    pub fn new_from_welcome<S: ExternalServices>(
        cx: &mut ServiceContext<S>,
        welcome: Welcome,
    ) -> Result<(Self, bool), ChatError> {
        let staged =
            StagedWelcome::build_from_welcome(&cx.mls_provider, &mls_join_config(), welcome)
                .map_err(ChatError::generic)?
                .replace_old_group()
                .build()
                .map_err(ChatError::generic)?;
        let held = held_group_to_replace(cx, &staged)?;
        let committer = staged.welcome_sender_index();
        let mls_group = staged
            .into_group(&cx.mls_provider)
            .map_err(ChatError::generic)?;

        let mut convo = Self {
            convo_id: hex::encode(mls_group.group_id().as_slice()),
            mls_group,
            beacons: Beacons::default(),
            served_readds: VecDeque::new(),
            committer: Some(committer),
            readd_attempt: 0,
        };

        convo.init(cx)?;
        if let Some(held) = &held {
            forget_held_group(cx, held, &convo.mls_group)?;
            cx.readd_pending.remove(&convo.convo_id);
            info!(convo = %convo.convo_id, "a Welcome replaced a group we held");
        }
        convo.enter_epoch(cx);
        Ok((convo, held.is_some()))
    }
}

/// A re-add sends a Welcome for a group we hold. Accept it only while we asked,
/// and only from a member of that group. Not proof of descent: a member we
/// still list could build a lookalike group. Read-only, so a Welcome that fails
/// to install leaves the held group and the pending re-add as they were.
fn held_group_to_replace<S: ExternalServices>(
    cx: &ServiceContext<S>,
    staged: &StagedWelcome,
) -> Result<Option<MlsGroup>, ChatError> {
    let group_id = staged.group_context().group_id();
    let Some(held) =
        MlsGroup::load(cx.mls_provider.storage(), group_id).map_err(ChatError::generic)?
    else {
        return Ok(None);
    };
    if !cx.readd_pending.contains(&hex::encode(group_id.as_slice())) {
        return Err(ChatError::generic(
            "a Welcome for a group we hold, and we did not ask to be re-added",
        ));
    }
    let sender = staged.welcome_sender().map_err(ChatError::generic)?;
    if !held
        .members()
        .any(|m| m.signature_key == sender.signature_key().as_slice())
    {
        return Err(ChatError::generic(
            "a Welcome for a group we hold, from outside it",
        ));
    }
    Ok(Some(held))
}

/// Drop what the new group, stored under the same id, did not overwrite.
fn forget_held_group<S: ExternalServices>(
    cx: &ServiceContext<S>,
    held: &MlsGroup,
    new: &MlsGroup,
) -> Result<(), ChatError> {
    let storage = cx.mls_provider.storage();
    let group_id = held.group_id();
    let (epoch, leaf) = (held.epoch(), held.own_leaf_index());
    if (epoch, leaf) != (new.epoch(), new.own_leaf_index()) {
        storage
            .delete_encryption_epoch_key_pairs(group_id, &epoch, leaf.u32())
            .map_err(ChatError::generic)?;
    }
    storage
        .delete_own_leaf_nodes(group_id)
        .map_err(ChatError::generic)?;
    storage
        .clear_proposal_queue::<GroupId, ProposalRef>(group_id)
        .map_err(ChatError::generic)
}

impl GroupV3Convo {
    fn init<S: ExternalServices>(&self, cx: &mut ServiceContext<S>) -> Result<(), ChatError> {
        // Configure the delivery service to listen for the required delivery addresses.
        cx.ds
            .subscribe(&delivery_address_from_id(&self.convo_id))
            .map_err(ChatError::generic)?;
        Ok(())
    }

    /// Primary entry point to putting a Frame into the conversation.
    ///
    /// EncodeFrame -> MlsEncrypt -> Wrap in Envelope
    fn send_frame<S: ExternalServices>(
        &mut self,
        cx: &mut ServiceContext<S>,
        frame: Frame,
    ) -> Result<super::MessageId, SendError> {
        let frame = frame.encode();
        let frame_id = frame_id(frame.as_slice());

        // OpenMLS clears the AAD after every message it creates.
        self.mls_group.set_aad(self.beacons.aad().to_vec());
        let mls_msg =
            self.mls_group
                .create_message(&cx.mls_provider, &cx.mls_identity, frame.as_slice())?;

        self.publish_mls_msg(cx, mls_msg)?;

        Ok(frame_id)
    }

    fn send_pending_commit<S: ExternalServices>(
        &mut self,
        cx: &mut ServiceContext<S>,
        commit_msg: MlsMessageOut,
        dependent_msgs: Vec<AddressedEnvelope>,
    ) -> Result<(), ChatError> {
        // Send Commit
        if let Err(e) = self.publish_mls_msg(cx, commit_msg) {
            // Discard the staged commit so the group isn't left wedged
            if let Err(clear_err) = self
                .mls_group
                .clear_pending_commit(cx.mls_provider.storage())
            {
                warn!(convo = %self.convo_id, error = %clear_err, "failed to clear pending commit");
            }
            return Err(e.into());
        }

        // Update State
        self.mls_group.merge_pending_commit(&cx.mls_provider)?;
        self.committer = Some(self.mls_group.own_leaf_index());
        self.enter_epoch(cx);

        // Send Welcomes
        for env in dependent_msgs {
            Self::publish_envelope(cx, env)?;
        }
        Ok(())
    }

    fn publish_mls_msg<S: ExternalServices>(
        &mut self,
        cx: &mut ServiceContext<S>,
        msg: MlsMessageOut,
    ) -> Result<(), SendError> {
        let env = to_envelope(self.convo_id.to_string(), msg)?;
        Self::publish_envelope(cx, env)
    }

    fn publish_envelope<S: ExternalServices>(
        cx: &mut ServiceContext<S>,
        env: AddressedEnvelope,
    ) -> Result<(), SendError> {
        cx.ds
            .publish(env)
            .map_err(|e| SendError::Delivery(e.to_string()))?;

        Ok(())
    }

    fn default_outcome(&self) -> ConvoOutcome {
        ConvoOutcome::empty(self.convo_id.clone())
    }
}

impl GroupV3Convo {
    /// Call after merging any commit, ours or a peer's.
    fn enter_epoch<S: ExternalServices>(&mut self, cx: &mut ServiceContext<S>) {
        self.beacons
            .enter_epoch(&self.mls_group, &self.convo_id, cx);
    }
}

impl<S> GroupConvo<S> for GroupV3Convo
where
    S: ExternalServices,
{
    fn add_signer(
        &mut self,
        cx: &mut ServiceContext<S>,
        signers: &[SignerKey],
    ) -> Result<(), ChatError> {
        // filter for duplicates and existing signers
        let existing = self.signers()?.into_iter();
        let signers = unique(member_diff(signers, existing));

        let key_packages: Vec<KeyPackage> = fetch_key_packages(cx, signers)?;
        if key_packages.is_empty() {
            warn!("no members to add to mls::group, ignoring");
            return Ok(());
        }

        let (commit_msg, welcome, _) = self
            .mls_group
            .add_members(&cx.mls_provider, &cx.mls_identity, key_packages.as_slice())
            .map_err(ChatError::generic)?;

        let invites: Result<Vec<AddressedEnvelope>, SendError> = key_packages
            .iter()
            .map(|s| crate::inbox_v2::create_invite_v3(&SignerKey::from(s.leaf_node()), &welcome))
            .collect();

        self.send_pending_commit(cx, commit_msg, invites?)?;

        Ok(())
    }

    fn remove_signer(
        &mut self,
        _cx: &mut ServiceContext<S>,
        _signer: &[crate::SignerRef],
    ) -> Result<(), ChatError> {
        todo!()
    }

    fn request_readd(
        &mut self,
        cx: &mut ServiceContext<S>,
        next_answerer: bool,
    ) -> Result<usize, ChatError> {
        GroupV3Convo::request_readd(self, cx, next_answerer)
    }
}

impl<S> Convo<S> for GroupV3Convo
where
    S: ExternalServices,
{
    fn send_content(
        &mut self,
        cx: &mut ServiceContext<S>,
        content: &[u8],
    ) -> Result<super::MessageId, ChatError> {
        let frame = Frame::from_content(content);
        self.send_frame(cx, frame).map_err(Into::into)
    }

    #[instrument(name = "groupv3.handle_frame", skip_all, fields(user_id = %cx.mls_identity.display_name()))]
    fn handle_payload(
        &mut self,
        cx: &mut ServiceContext<S>,
        payload: &[u8],
    ) -> Result<ConvoOutcome, ChatError> {
        let payload = GroupV3Payload::decode(payload)?;

        if !payload.external.is_empty() {
            let ours = self.mls_group.ciphersuite();
            return match external::admit_frame(&payload.external, ours) {
                Some(external::Inbound::Beacon(beacon)) => {
                    let crypto = cx.mls_provider.crypto();
                    self.beacons
                        .receive_frame(crypto, &self.convo_id, beacon, &payload.external);
                    Ok(self.default_outcome())
                }
                Some(external::Inbound::Sealed(msg)) => self.receive_sealed(cx, msg),
                None => {
                    debug!(convo = %self.convo_id, "refused a malformed external frame");
                    Ok(self.default_outcome())
                }
            };
        }

        let protocol_message =
            MlsMessageIn::tls_deserialize_exact_bytes(payload.encrypted_frame.as_ref())
                .map_err(ChatError::generic)?
                .try_into_protocol_message()
                .map_err(ChatError::generic)?;

        self.handle_mls_protocol_msg(cx, protocol_message)
    }

    fn wakeup(&mut self, cx: &mut ServiceContext<S>) -> Result<crate::ConvoOutcome, ChatError> {
        self.beacons.wakeup(&self.convo_id, cx);
        Ok(self.default_outcome())
    }
}

impl Identified for GroupV3Convo {
    fn id(&self) -> ConversationIdRef<'_> {
        &self.convo_id
    }
}

impl HasMlsConvo for GroupV3Convo {
    fn mls_group(&self) -> &MlsGroup {
        &self.mls_group
    }
}
