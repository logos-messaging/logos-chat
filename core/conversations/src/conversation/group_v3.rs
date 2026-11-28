// TESTING ONLY
// A Group Conversation that uses SDS for message ordering
//
// Invariants:
//  - Signers are not allowed change their SigningKey.
//  - Everyone is an "Admin"
//

mod beacons;
mod commits;
mod debug_data;
mod debug_events;
mod external;
mod finality;
mod handlers;
#[cfg(any(test, feature = "test-support"))]
pub mod inspect;
mod payloads;
mod readd;
mod sds_channel;
mod sealed;
mod send;
mod sync_state;
mod trace;

use std::collections::HashMap;
use std::collections::VecDeque;
use std::fmt;
use std::time::Duration;

use openmls::ciphersuite::hash_ref::ProposalRef;
use openmls::framing::ProtocolMessage;
use openmls::group::{MlsGroup, StagedWelcome};
use openmls::key_packages::KeyPackage;
use openmls::messages::Welcome;
use openmls::prelude::GroupId;
use openmls_traits::OpenMlsProvider;
use openmls_traits::storage::StorageProvider as _;
use prost::Message;
use sds::{Channel, StartPoint};
use tracing::field::{Empty, display};
use tracing::{Span, debug, info, instrument, warn};

use crate::conversation::mls_groups::{HasMlsConvo, create_group, group_join_config};
use crate::conversation::mls_trace::record::{ConvoId, Short};
use crate::conversation::mls_utils::EpochFingerprint;
use crate::conversation::{
    ConversationId, ConversationIdRef, Convo, ConvoBase, Debuggable, GroupConvo, Identified,
    PayloadTag, Typed,
};
use crate::service_context::ServiceContext;
use crate::utils::{blake2b_hex, hash_size};
use crate::{
    ChatError, ConvoOutcome, DebugData, DeliveryInfo, DeliveryService, ExternalServices,
    IdentityProvider, Observation, SignerKey, WakeupService,
};

use super::mls_utils::{fetch_key_packages, member_diff, unique};

use self::beacons::Beacons;
use self::commits::DeferredCommit;
use self::debug_data::DebugState;
use self::payloads::{EncryptedSdsMessage, EpochData, GroupV3Packet};
use self::sds_channel::{SDS_TICK_INTERVAL, create_sds_channel, now_ms};
pub use self::sync_state::SyncState;
use self::sync_state::SyncTracker;

// Type Aliases
type Frame = payloads::GroupV3Frame;

// How long this member waits, from the first commit it defers, sent or received, before it
// finalizes one. The `test-fast-commits` feature puts it under one SDS tick, so a commit lands
// on the next tick.
#[cfg(not(feature = "test-fast-commits"))]
const COMMIT_FINALIZE_TIMEOUT: Duration = Duration::from_secs(120);
#[cfg(feature = "test-fast-commits")]
const COMMIT_FINALIZE_TIMEOUT: Duration = Duration::from_millis(100);
// Max messages deferred for a later epoch. Copy value from SDS's incoming buffer.
// TODO: Derive the value from SDS library or based on storage size.
const MAX_LATER_EPOCH_MSGS: usize = 500;

fn delivery_address_from_id(convo_id: &str) -> String {
    blake2b_hex::<hash_size::DeliveryAddr>(&["delivery_addr|", convo_id])
}

/// Payloads sent under the recovery convo id.
const RECOVERY: PayloadTag = PayloadTag(1);

/// Derived from the convo id alone: a forked member holds no epoch secrets.
fn recovery_convo_id(convo_id: &str) -> String {
    blake2b_hex::<hash_size::ConvoId>(&["recovery_convo_id|", convo_id])
}

pub struct GroupV3Convo {
    convo_id: String,
    mls_group: MlsGroup,
    channel: Channel,
    deferred_commits: HashMap<EpochFingerprint, DeferredCommit>,
    finality: finality::Timeout,
    beacons: Beacons,
    /// Signers re-added in a commit we merged, with the epoch it started. Kept
    /// by every member, so a later request can't remove the fresh leaf.
    readds: VecDeque<(Vec<u8>, u64)>,
    /// Our last re-add request's attempt; it picks the answerer.
    readd_attempt: u32,
    sync: SyncTracker,
    /// The sync state last reported to the app.
    reported_sync: SyncState,
    epoch_data: EpochData,
    later_epoch_msgs: Vec<(super::MessageId, ProtocolMessage)>,
    debug_data: DebugState,
}

// `sds::Channel` implements no `Debug`.
impl fmt::Debug for GroupV3Convo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GroupV3Convo")
            .field("convo_id", &self.convo_id)
            .field("mls_group", &self.mls_group)
            .finish_non_exhaustive()
    }
}

impl GroupV3Convo {
    // `convo` is recorded on the span once the group exists.
    #[instrument(name = "groupv3.new", skip_all, fields(user_id = %cx.mls_identity.display_name(), signer = %Short(cx.mls_identity.signer_key().as_bytes()), convo = Empty))]
    pub fn new<S: ExternalServices>(
        cx: &mut ServiceContext<S>,
        name: &str,
        desc: &str,
        signers: &[SignerKey],
    ) -> Result<Self, ChatError> {
        // Create MlsGroup
        let mls_group = create_group(cx, name, desc)?;
        let mut convo = Self::from_group(cx, mls_group, None)?;
        Span::current().record("convo", display(ConvoId(&convo.convo_id)));
        trace::epoch(&convo);

        convo.init(cx)?;
        convo.add_signer(cx, signers)?;
        Ok(convo)
    }

    /// Joins from a Welcome, starting our SDS channel at `start`, the commit that added us. Also
    /// returns whether it replaced a group we held: one we were removed from, or one a re-add we
    /// asked for answers.
    #[instrument(name = "groupv3.new_from_welcome", skip_all, fields(user_id = %cx.mls_identity.display_name(), signer = %Short(cx.mls_identity.signer_key().as_bytes()), convo = Empty))]
    pub fn new_from_welcome<S: ExternalServices>(
        cx: &mut ServiceContext<S>,
        welcome: Welcome,
        start: StartPoint,
    ) -> Result<(Self, bool), ChatError> {
        let staged =
            StagedWelcome::build_from_welcome(&cx.mls_provider, &group_join_config(), welcome)
                .map_err(ChatError::generic)?
                .replace_old_group()
                .build()
                .map_err(ChatError::generic)?;
        let held = held_group_to_replace(cx, &staged)?;
        let mls_group = staged
            .into_group(&cx.mls_provider)
            .map_err(ChatError::generic)?;

        let mut convo = Self::from_group(cx, mls_group, Some(start))?;
        Span::current().record("convo", display(ConvoId(&convo.convo_id)));
        trace::epoch(&convo);

        // A replaced group's subscription and tick carry over.
        if held.is_none() {
            convo.init(cx)?;
        }
        if let Some(held) = &held {
            forget_held_group(cx, held, &convo.mls_group)?;
            cx.readd_pending.remove(&convo.convo_id);
            info!(convo = %convo.convo_id, "a Welcome replaced a group we held");
        }
        convo.enter_epoch(cx);
        Ok((convo, held.is_some()))
    }

    fn from_group<S: ExternalServices>(
        cx: &ServiceContext<S>,
        mls_group: MlsGroup,
        start: Option<StartPoint>,
    ) -> Result<Self, ChatError> {
        let convo_id = hex::encode(mls_group.group_id().as_slice());
        let channel = create_sds_channel(cx, &convo_id, start)?;
        Ok(Self {
            epoch_data: EpochData::from_group(&mls_group),
            convo_id,
            mls_group,
            channel,
            deferred_commits: HashMap::default(),
            finality: finality::Timeout::new(COMMIT_FINALIZE_TIMEOUT),
            beacons: Beacons::default(),
            readds: VecDeque::new(),
            readd_attempt: 0,
            sync: SyncTracker::default(),
            reported_sync: SyncState::Unknown,
            later_epoch_msgs: Vec::with_capacity(MAX_LATER_EPOCH_MSGS),
            debug_data: DebugState::default(),
        })
    }
}

/// How long an asker waits for the Welcome that answers it: the repair is
/// finalized a commit timeout after it is sent, with room for a retry. Fixed,
/// so fast test commits don't shrink it under an SDS tick.
const READD_WELCOME_WAIT: Duration = Duration::from_secs(360);

/// A Welcome for a group we hold. Once we were removed from it, any later
/// Welcome adds us again: a Welcome for a group we don't hold is accepted from
/// anyone too. Otherwise it is a re-add: accept it only while we wait for one,
/// only from a member of that group who vouched for the branch we asked, and
/// only past that branch's epoch.
/// Not proof of descent: a member we still list could build a lookalike group.
/// Read-only, so a Welcome that fails to install leaves the held group and the
/// pending re-add as they were.
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
    let epoch = staged.group_context().epoch();
    if !held.is_active() {
        if epoch <= held.epoch() {
            return Err(ChatError::generic(
                "a Welcome no later than our removal from the group",
            ));
        }
        return Ok(Some(held));
    }
    let Some(target) = cx.readd_pending.get(&hex::encode(group_id.as_slice())) else {
        return Err(ChatError::generic(
            "a Welcome for a group we hold, and we did not ask to be re-added",
        ));
    };
    if cx.clock.now() > target.until {
        return Err(ChatError::generic(
            "a Welcome for a re-add we stopped waiting for",
        ));
    }
    // Any old member could build a group under this id. Only one who vouched
    // for the branch we asked could be answering us, and its repair lands on
    // a later epoch.
    let sender = staged.welcome_sender().map_err(ChatError::generic)?;
    let sender = sender.signature_key().as_slice();
    if !held.members().any(|m| m.signature_key == sender) {
        return Err(ChatError::generic(
            "a Welcome for a group we hold, from outside it",
        ));
    }
    if !target.vouchers.iter().any(|v| v == sender) {
        return Err(ChatError::generic(
            "a Welcome from a member who did not vouch for the branch we asked",
        ));
    }
    if epoch.as_u64() <= target.epoch {
        return Err(ChatError::generic(
            "a Welcome no later than the branch we asked",
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
    // The leaf's own HPKE key pair is stored by public key, not by group.
    if let (Some(old), Some(fresh)) = (held.own_leaf_node(), new.own_leaf_node())
        && old.encryption_key() != fresh.encryption_key()
    {
        storage
            .delete_encryption_key_pair(old.encryption_key())
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
        cx.wakeup_service
            .wakeup_in(SDS_TICK_INTERVAL, self.convo_id.clone());
        Ok(())
    }

    fn default_outcome(&self) -> ConvoOutcome {
        ConvoOutcome::empty(self.convo_id.clone())
    }

    /// Reports the sync state once it differs from what the app last heard.
    fn report_sync(&mut self, outcome: &mut ConvoOutcome) {
        if self.sync.state() != &self.reported_sync {
            self.reported_sync = self.sync.state().clone();
            outcome
                .observations
                .push(Observation::SyncChanged(self.reported_sync.clone()));
        }
    }
}

impl GroupV3Convo {
    /// Call after merging any commit, ours or a peer's.
    fn enter_epoch<S: ExternalServices>(&mut self, cx: &mut ServiceContext<S>) {
        self.sync.enter_epoch();
        self.beacons
            .enter_epoch(cx, &self.mls_group, &self.convo_id);
        let roster: Vec<_> = self.mls_group.members().map(|m| m.signature_key).collect();
        self.sync.forget_departed(&self.beacons, &roster);
        // Peers who got here first signed this epoch while it was ahead of us.
        let epoch = self.mls_group.epoch().as_u64();
        for peer in self.beacons.peers_at(epoch) {
            self.observe_beacon(peer);
        }
        self.send_beacon(cx);
    }

    fn receive_external<S: ExternalServices>(
        &mut self,
        cx: &mut ServiceContext<S>,
        frame: &[u8],
    ) -> Result<ConvoOutcome, ChatError> {
        match external::admit_frame(frame) {
            Some(external::Inbound::Beacon(beacon)) => {
                let crypto = cx.mls_provider.crypto();
                let keys = self.mls_group.members().map(|m| m.signature_key);
                if let Some(peer) =
                    self.beacons
                        .receive_frame(crypto, &self.convo_id, keys, beacon, frame)
                {
                    self.observe_beacon(peer);
                }
                Ok(self.default_outcome())
            }
            Some(external::Inbound::Sealed(msg)) => self.receive_sealed(cx, msg),
            None => {
                debug!(convo = %self.convo_id, "refused a malformed external frame");
                Ok(self.default_outcome())
            }
        }
    }

    /// A verified peer beacon: the only evidence that concludes or clears a
    /// fork. Detection only: nothing here asks for a re-add.
    fn observe_beacon(&mut self, peer: external::Branch) {
        let before = self.sync.state().clone();
        let epoch = self.mls_group.epoch().as_u64();
        self.sync.observe(&self.beacons, epoch, peer);
        let now = self.sync.state();
        if now != &before && matches!(now, SyncState::Forked { .. }) {
            warn!(convo = %self.convo_id, state = ?now, "fork detected");
        }
    }
}

impl<S> GroupConvo<S> for GroupV3Convo
where
    S: ExternalServices,
{
    #[instrument(name = "groupv3.add_member", skip_all, fields(user_id = %cx.mls_identity.display_name(), signer = %Short(cx.mls_identity.signer_key().as_bytes()), convo = %ConvoId(&self.convo_id), epoch = self.mls_group.epoch().as_u64()))]
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

        // Commit sent prior to deferring, as the `StartPoint` must be known prior to creating invites
        let commit = self.send_pending_commit(cx, commit_msg)?;

        // Welcomes are sent once the commit is finalized.
        let invites = key_packages
            .iter()
            .map(|key_package| {
                crate::inbox_v2::create_invite_v3(
                    &SignerKey::from(key_package.leaf_node()),
                    &welcome,
                    &commit,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;

        self.defer_pending_commit(cx, invites)
    }

    /// Removes a list of signers from the group.
    ///
    /// Caveats:
    ///   - a signer cannot remove themselves from the conversation.
    ///     Attempting to do so results in the entire call failing,
    ///     and no state being changed.
    #[instrument(name = "groupv3.remove_member", skip_all, fields(user_id = %cx.mls_identity.display_name(), signer = %Short(cx.mls_identity.signer_key().as_bytes()), convo = %ConvoId(&self.convo_id), epoch = self.mls_group.epoch().as_u64()))]
    fn remove_signer(
        &mut self,
        cx: &mut ServiceContext<S>,
        signers: &[crate::SignerRef],
    ) -> Result<(), ChatError> {
        let leaves: Vec<_> = self
            .mls_group
            .members()
            .filter(|m| signers.iter().any(|s| m.signature_key == s.as_bytes()))
            .map(|m| m.index)
            .collect();
        if leaves.is_empty() {
            return Err(ChatError::NotAGroupMember);
        }

        let (commit_msg, _welcome, _) = self
            .mls_group
            .remove_members(&cx.mls_provider, &cx.mls_identity, &leaves)
            .map_err(ChatError::generic)?;

        self.send_pending_commit(cx, commit_msg)?;
        self.defer_pending_commit(cx, vec![])
    }

    fn request_readd(
        &mut self,
        cx: &mut ServiceContext<S>,
        next_answerer: bool,
    ) -> Result<usize, ChatError> {
        GroupV3Convo::request_readd(self, cx, next_answerer)
    }

    #[cfg(feature = "test-support")]
    fn force_readd(
        &mut self,
        cx: &mut ServiceContext<S>,
        signer: crate::SignerRef,
    ) -> Result<(), ChatError> {
        GroupV3Convo::force_readd(self, cx, signer)
    }

    fn sync_state(&self) -> SyncState {
        self.sync.state().clone()
    }
}

impl<S> Convo<S> for GroupV3Convo
where
    S: ExternalServices,
{
    #[instrument(name = "groupv3.send_content", skip_all, fields(user_id = %cx.mls_identity.display_name(), signer = %Short(cx.mls_identity.signer_key().as_bytes()), convo = %ConvoId(&self.convo_id), epoch = self.mls_group.epoch().as_u64()))]
    fn send_content(
        &mut self,
        cx: &mut ServiceContext<S>,
        content: &[u8],
    ) -> Result<super::MessageId, ChatError> {
        let frame = Frame::from_content(content);
        self.send_frame(cx, frame).map_err(Into::into)
    }

    /// Unwrap Envelope -> SDS -> MlsDecrypt -> DecodeFrame
    #[instrument(name = "groupv3.handle_frame", skip_all, fields(user_id = %cx.mls_identity.display_name(), signer = %Short(cx.mls_identity.signer_key().as_bytes()), convo = %ConvoId(&self.convo_id), epoch = self.mls_group.epoch().as_u64()))]
    fn handle_payload(
        &mut self,
        cx: &mut ServiceContext<S>,
        payload: &[u8],
        delivery_info: Option<&DeliveryInfo>,
    ) -> Result<ConvoOutcome, ChatError> {
        let mut observations = vec![];

        let record = EncryptedSdsMessage::decode(payload)?.try_into_record()?;
        // A sync carries no message, so it has no steps to report.
        let message_id = record
            .content
            .is_some()
            .then(|| record.header.message_id.clone());
        observations.extend(debug_events::sds_received(&record, delivery_info));
        if let Some(packet) = record
            .content
            .as_deref()
            .and_then(|content| GroupV3Packet::decode(content).ok())
        {
            self.debug_data.record_epoch_data(&packet, &self.mls_group);
        }
        let retrieval_hint = delivery_info.map(|info| info.delivery_msg_id.as_bytes().to_vec());
        match self.channel.receive(record, retrieval_hint, now_ms(cx)) {
            Ok(events) => observations.extend(self.handle_sds_events(cx, events)),
            // A peer's record SDS refuses is dropped, like a released message that fails.
            Err(e) => {
                warn!(convo = %self.convo_id, error = %e, "sds refused a record");
                observations
                    .extend(message_id.and_then(|id| debug_events::sds_ignored_for_error(id, &e)));
            }
        }
        let mut outcome = ConvoOutcome {
            observations,
            ..self.default_outcome()
        };
        self.report_sync(&mut outcome);
        Ok(outcome)
    }

    #[instrument(name = "groupv3.wakeup", skip_all, fields(user_id = %cx.mls_identity.display_name(), signer = %Short(cx.mls_identity.signer_key().as_bytes()), convo = %ConvoId(&self.convo_id), epoch = self.mls_group.epoch().as_u64()))]
    fn wakeup(&mut self, cx: &mut ServiceContext<S>) -> Result<ConvoOutcome, ChatError> {
        cx.wakeup_service
            .wakeup_in(SDS_TICK_INTERVAL, self.convo_id.clone());
        let events = self.channel.tick(now_ms(cx), &mut rand_0_10::rng());
        let mut observations = self.handle_sds_events(cx, events);

        let epoch = self.mls_group.epoch().as_u64();
        if let Some(fingerprint) = self
            .finality
            .finalized(cx.clock.now(), epoch, &self.debug_data)
        {
            match self.finalize_deferred_commit(cx, &fingerprint) {
                Ok(outcome) => {
                    observations.extend(outcome.observations);
                    observations.extend(self.handle_later_epoch_msgs(cx));
                }
                Err(e) => {
                    warn!(convo = %self.convo_id, error = %e, "failed to finalize deferred commit")
                }
            }
        }

        self.send_beacon(cx);
        let mut outcome = ConvoOutcome {
            observations,
            ..self.default_outcome()
        };
        self.report_sync(&mut outcome);
        Ok(outcome)
    }

    fn handle_delivery_report(
        &mut self,
        message_id: &str,
        info: &DeliveryInfo,
    ) -> Result<(), ChatError> {
        self.channel
            .set_retrieval_hint(message_id, info.delivery_msg_id.as_bytes().to_vec())
            .map_err(ChatError::generic)
    }

    fn additional_convo_ids(&self) -> Vec<(ConversationId, PayloadTag)> {
        vec![(recovery_convo_id(&self.convo_id), RECOVERY)]
    }

    /// Unwrap Envelope -> GroupV3External
    fn handle_additional_payload(
        &mut self,
        cx: &mut ServiceContext<S>,
        tag: PayloadTag,
        payload: &[u8],
    ) -> Result<ConvoOutcome, ChatError> {
        match tag {
            RECOVERY => {
                let mut outcome = self.receive_external(cx, payload)?;
                self.report_sync(&mut outcome);
                Ok(outcome)
            }
            _ => Err(ChatError::generic("unknown payload tag")),
        }
    }
}

impl Identified for GroupV3Convo {
    fn id(&self) -> ConversationIdRef<'_> {
        &self.convo_id
    }
}

impl Typed for GroupV3Convo {
    fn type_name(&self) -> &'static str {
        "GroupV3"
    }
}

impl Debuggable for GroupV3Convo {
    fn debug_data(&self) -> DebugData {
        let group = self.mls_group();
        DebugData::from_iter([
            ("epoch".to_owned(), group.epoch().as_u64().into()),
            (
                "epoch_fingerprint".to_owned(),
                EpochFingerprint::from_group(group).to_string().into(),
            ),
            (
                "members".to_owned(),
                self.debug_data.members(group, &self.beacons).into(),
            ),
        ])
    }
}

impl HasMlsConvo for GroupV3Convo {
    fn mls_group(&self) -> &MlsGroup {
        &self.mls_group
    }
}
