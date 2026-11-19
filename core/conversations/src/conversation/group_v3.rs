// TESTING ONLY
// A Group Conversation that uses SDS for message ordering
//
// Invariants:
//  - Signers are not allowed change their SigningKey.
//  - Everyone is an "Admin"
//

mod beacons;
mod external;
mod finality;
mod handlers;
#[cfg(any(test, feature = "test-support"))]
pub mod inspect;
mod payloads;
mod readd;
mod sealed;
mod sync_state;
mod trace;

use std::collections::HashMap;
use std::collections::VecDeque;
use std::fmt;
use std::time::Duration;

use openmls::ciphersuite::hash_ref::ProposalRef;
use openmls::framing::{MlsMessageOut, ProtocolMessage};
use openmls::group::{MlsGroup, StagedCommit, StagedWelcome};
use openmls::key_packages::KeyPackage;
use openmls::messages::Welcome;
use openmls::prelude::GroupId;
use openmls_traits::OpenMlsProvider;
use openmls_traits::storage::StorageProvider as _;
use prost::Message;
use sds::{Channel, Config, SDSRecord, StartPoint};
use tracing::field::{Empty, display};
use tracing::{Span, debug, info, instrument, warn};

use crate::conversation::group_v3::payloads::GroupV3Header;
use crate::conversation::mls_groups::{HasMlsConvo, create_group, group_join_config};
use crate::conversation::mls_trace::record::{ConvoId, Short};
use crate::conversation::mls_utils::EpochFingerprint;
use crate::conversation::{
    ConversationIdRef, Convo, ConvoBase, Debuggable, GroupConvo, Identified, Typed,
};
use crate::errors::SendError;
use crate::service_context::ServiceContext;
use crate::utils::{blake2b_hex, hash_size};
use crate::{
    AddressedEnvelope, ChatError, ConvoOutcome, DebugData, DeliveryInfo, DeliveryService,
    ExternalServices, IdentityProvider, Observation, SignerKey, WakeupService,
};

use super::mls_utils::{fetch_key_packages, member_diff, unique};

use self::beacons::Beacons;
use self::payloads::{
    EncryptedSdsMessage, EpochData, GroupV3External, GroupV3FrameType, GroupV3Packet,
};
pub use self::sync_state::SyncState;
use self::sync_state::SyncTracker;

// Type Aliases
type Frame = payloads::GroupV3Frame;

// Fires SDS's resend and sync deadlines within a second. `wakeup_in` adds a timer rather than
// replacing one, so only `init` and `wakeup` arm it.
const SDS_TICK_INTERVAL: Duration = Duration::from_secs(1);
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

fn create_sds_channel<S: ExternalServices>(
    cx: &ServiceContext<S>,
    convo_id: &str,
    start: Option<StartPoint>,
) -> Result<Channel, ChatError> {
    // The signer, not the account: two installations of one account would drop each other's
    // messages as their own.
    let mut config = Config::new(cx.mls_identity.signer_key().to_string(), convo_id);
    config.repair = None;
    config.start = start;
    Channel::new(config).map_err(ChatError::generic)
}

fn now_ms<S: ExternalServices>(cx: &ServiceContext<S>) -> u64 {
    cx.clock.now().as_millis() as u64
}

/// A commit that has been generated, but not applied. Commits are either `Pending` created by this member, or `Staged`.
/// PendingCommits are grouped with the outbound payloads, so that welcomes are not sent until the commit is finalized.
/// openmls holds a `Pending` commit itself, as the group's pending commit.
enum DeferredCommit {
    Pending(Vec<AddressedEnvelope>),
    Staged(StagedCommit),
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
    epoch_data: EpochData,
    later_epoch_msgs: Vec<(super::MessageId, ProtocolMessage)>,
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
    /// returns whether it replaced a group we held, which only a re-add we asked for may do.
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
            epoch_data: EpochData::starting_at(mls_group.epoch().as_u64()),
            convo_id,
            mls_group,
            channel,
            deferred_commits: HashMap::default(),
            finality: finality::Timeout::new(COMMIT_FINALIZE_TIMEOUT),
            beacons: Beacons::default(),
            readds: VecDeque::new(),
            readd_attempt: 0,
            sync: SyncTracker::default(),
            later_epoch_msgs: Vec::with_capacity(MAX_LATER_EPOCH_MSGS),
        })
    }
}

/// How long an asker waits for the Welcome that answers it: the repair is
/// finalized a commit timeout after it is sent, with room for a retry. Fixed,
/// so fast test commits don't shrink it under an SDS tick.
const READD_WELCOME_WAIT: Duration = Duration::from_secs(360);

/// A re-add sends a Welcome for a group we hold. Accept it only while we wait
/// for one, only from a member of that group who vouched for the branch we
/// asked, and only past that branch's epoch.
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
    if staged.group_context().epoch().as_u64() <= target.epoch {
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

    /// Primary entry point to putting a Frame into the conversation.
    ///
    /// EncodeFrame -> MlsEncrypt -> SDS -> Wrap in Envelope
    fn send_frame<S: ExternalServices>(
        &mut self,
        cx: &mut ServiceContext<S>,
        frame: Frame,
    ) -> Result<super::MessageId, SendError> {
        let is_post = matches!(frame.payload, Some(GroupV3FrameType::Content(_)));
        let mls_message = self.mls_group.create_message(
            &cx.mls_provider,
            &cx.mls_identity,
            frame.encode().as_slice(),
        )?;

        let header = GroupV3Header::with_epoch_data(&self.epoch_data);
        let message = GroupV3Packet::from_mls_message(header, mls_message)?.into_outgoing_message();
        let message_id = message.message_id.clone();

        let record = self.channel.send(message, now_ms(cx))?;
        // SDS resends a logged message, so it counts as sent even if the publish fails.
        if is_post {
            trace::sent(self, &message_id);
        }
        self.publish_record(cx, record)?;

        Ok(message_id)
    }

    /// Sends the pending commit through SDS. Returns the commit's place in the SDS channel, where a
    /// member it adds starts. The commit stays pending until `defer_pending_commit`.
    fn send_pending_commit<S: ExternalServices>(
        &mut self,
        cx: &mut ServiceContext<S>,
        commit_msg: MlsMessageOut,
    ) -> Result<StartPoint, ChatError> {
        let header = GroupV3Header::with_epoch_data(&self.epoch_data);
        // Send Commit
        let sent = GroupV3Packet::from_mls_message(header, commit_msg).and_then(|envelope| {
            Ok(self
                .channel
                .send(envelope.into_outgoing_message(), now_ms(cx))?)
        });
        let record = match sent {
            Ok(record) => record,
            Err(e) => {
                // Discard the staged commit so the group isn't left wedged
                if let Err(clear_err) = self
                    .mls_group
                    .clear_pending_commit(cx.mls_provider.storage())
                {
                    warn!(convo = %self.convo_id, error = %clear_err, "failed to clear pending commit");
                }
                return Err(e.into());
            }
        };

        let start = StartPoint {
            message_id: record.header.message_id.clone(),
            lamport_timestamp: record
                .header
                .lamport_timestamp
                .ok_or_else(|| ChatError::generic("sds sent the commit without a timestamp"))?,
        };
        // SDS keeps the commit and resends it, so a failed publish heals as a lost one does.
        if let Err(e) = self.publish_record(cx, record) {
            warn!(convo = %self.convo_id, error = %e, "failed to publish commit");
        }
        Ok(start)
    }

    /// Holds the pending commit, and `dependent_msgs` with it, until the commit is finalized.
    fn defer_pending_commit<S: ExternalServices>(
        &mut self,
        cx: &ServiceContext<S>,
        dependent_msgs: Vec<AddressedEnvelope>,
    ) -> Result<(), ChatError> {
        let fingerprint = self
            .mls_group
            .pending_commit()
            .and_then(EpochFingerprint::from_staged_commit)
            .ok_or_else(|| ChatError::generic("no pending commit"))?;

        // openmls keeps the commit pending until it is finalized.
        self.defer_commit(cx, fingerprint, DeferredCommit::Pending(dependent_msgs));
        Ok(())
    }

    fn defer_commit<S: ExternalServices>(
        &mut self,
        cx: &ServiceContext<S>,
        fingerprint: EpochFingerprint,
        commit: DeferredCommit,
    ) {
        self.finality.defer(fingerprint.clone(), cx.clock.now());
        self.deferred_commits.insert(fingerprint, commit);
    }

    /// Incorporate the commit into the group state, and send out any payloads if necessary.
    ///
    /// Call after there is confidence that all group members will apply the same commit.
    fn finalize_deferred_commit<S: ExternalServices>(
        &mut self,
        cx: &mut ServiceContext<S>,
        fingerprint: &EpochFingerprint,
    ) -> Result<ConvoOutcome, ChatError> {
        let deferred = self
            .deferred_commits
            .remove(fingerprint)
            .ok_or_else(|| ChatError::generic("cannot finalize commit that does not exist"))?;
        let starting_epoch = self.mls_group.epoch().as_u64();

        let payloads = match deferred {
            DeferredCommit::Pending(payloads) => {
                // `merge_pending_commit` silently does nothing once the pending commit is gone.
                let pending = self
                    .mls_group
                    .pending_commit()
                    .and_then(EpochFingerprint::from_staged_commit);
                if pending.as_ref() != Some(fingerprint) {
                    return Err(ChatError::generic("pending commit no longer exists"));
                }
                let readded = self
                    .mls_group
                    .pending_commit()
                    .map(|commit| readd::readded_signers(&self.mls_group, commit))
                    .unwrap_or_default();
                self.mls_group.merge_pending_commit(&cx.mls_provider)?;
                self.note_readds(readded);
                payloads
            }
            DeferredCommit::Staged(commit) => {
                if commit.epoch().as_u64() != starting_epoch + 1 {
                    return Err(ChatError::generic("commit is not for the next epoch"));
                }
                let readded = readd::readded_signers(&self.mls_group, &commit);
                self.mls_group
                    .merge_staged_commit(&cx.mls_provider, commit)
                    .map_err(ChatError::generic)?;
                self.note_readds(readded);
                vec![]
            }
        };
        // Recorded before the sends below, so a failed send cannot skip it.
        trace::epoch(self);

        // Notify Epoch history that we've updated the group state.
        // Record the fingerprint of the final state, to catch any state bugs
        self.epoch_data.advance_to(
            self.mls_group.epoch().as_u64(),
            EpochFingerprint::from_group(self.mls_group()),
        );

        self.drop_expired_deferred_commits();
        self.enter_epoch(cx);
        info!(
            convo = %self.convo_id,
            epoch = starting_epoch,
            new_epoch = self.mls_group.epoch().as_u64(),
            epochfingerprint = %fingerprint,
            "commit merged"
        );

        for env in payloads {
            Self::publish_envelope(cx, env)?;
        }

        Ok(ConvoOutcome {
            observations: vec![Observation::SignersChanged],
            ..self.default_outcome()
        })
    }

    fn drop_expired_deferred_commits(&mut self) {
        let epoch = self.mls_group.epoch();
        self.deferred_commits.retain(|_, v| match v {
            DeferredCommit::Staged(commit) => commit.epoch() > epoch,
            DeferredCommit::Pending(_) => false,
        })
    }

    /// Publishes a record SDS logged, and gives its message the id the delivery service returned
    /// as its retrieval hint, which later histories name it by. An id the service reports later
    /// comes through `handle_delivery_report`.
    fn publish_record<S: ExternalServices>(
        &mut self,
        cx: &mut ServiceContext<S>,
        record: SDSRecord,
    ) -> Result<(), SendError> {
        let message_id = record.header.message_id.clone();
        let env = EncryptedSdsMessage::from_record(record).into_envelope(self.id().to_owned());
        if let Some(delivery_msg_id) = cx
            .ds
            .publish_tracked(env, &self.convo_id, &message_id)
            .map_err(|e| SendError::Delivery(e.to_string()))?
            && let Err(e) = self
                .channel
                .set_retrieval_hint(&message_id, delivery_msg_id.as_bytes().to_vec())
        {
            warn!(convo = %self.convo_id, error = %e, "failed to keep the retrieval hint");
        }
        Ok(())
    }

    fn publish_payload<S: ExternalServices>(
        &self,
        cx: &mut ServiceContext<S>,
        message: EncryptedSdsMessage,
    ) -> Result<(), SendError> {
        Self::publish_envelope(cx, message.into_envelope(self.convo_id.to_string()))
    }

    fn publish_envelope<S: ExternalServices>(
        cx: &mut ServiceContext<S>,
        env: AddressedEnvelope,
    ) -> Result<(), SendError> {
        cx.ds
            .publish(env)
            .map_err(|e| SendError::Delivery(e.to_string()))
            .map(drop)
    }

    fn default_outcome(&self) -> ConvoOutcome {
        ConvoOutcome::empty(self.convo_id.clone())
    }
}

impl GroupV3Convo {
    /// Call after merging any commit, ours or a peer's.
    fn enter_epoch<S: ExternalServices>(&mut self, cx: &mut ServiceContext<S>) {
        self.sync.enter_epoch();
        self.beacons
            .enter_epoch(cx, &self.mls_group, &self.convo_id);
        self.send_beacon(cx);
    }

    /// Send our beacon once it is due. A failure is retried on a later tick
    /// rather than failing the operation that changed the epoch.
    fn send_beacon<S: ExternalServices>(&mut self, cx: &mut ServiceContext<S>) {
        let now = cx.clock.now();
        let Some(beacon) = self.beacons.due(now) else {
            return;
        };
        match self.publish_external(cx, GroupV3External::beacon(beacon.clone())) {
            Ok(()) => self.beacons.sent(),
            Err(e) => {
                warn!(convo = %self.convo_id, error = %e, "beacon not sent");
                self.beacons.failed(now);
            }
        }
    }

    /// Sends a frame outside SDS: nothing orders or resends it, and a forked
    /// member must still be able to read it.
    fn publish_external<S: ExternalServices>(
        &self,
        cx: &mut ServiceContext<S>,
        frame: GroupV3External,
    ) -> Result<(), SendError> {
        let packet = GroupV3Packet::external(frame);
        self.publish_payload(cx, EncryptedSdsMessage::outside_sds(&packet))
            .map(|_| ())
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

    fn remove_signer(
        &mut self,
        _cx: &mut ServiceContext<S>,
        _signer: &[crate::SignerRef],
    ) -> Result<(), ChatError> {
        Err(ChatError::UnsupportedFunction(
            self.convo_id.clone(),
            "Remove Member".into(),
        ))
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
        let message = EncryptedSdsMessage::decode(payload)?;
        if let Some(packet) = message.packet_outside_sds() {
            return self.receive_external(cx, &packet?.into_external()?);
        }
        let record = message.try_into_record()?;
        let retrieval_hint = delivery_info.map(|info| info.delivery_msg_id.as_bytes().to_vec());
        let events = self
            .channel
            .receive(record, retrieval_hint, now_ms(cx))
            .map_err(ChatError::generic)?;
        Ok(ConvoOutcome {
            observations: self.handle_sds_events(cx, events),
            ..self.default_outcome()
        })
    }

    #[instrument(name = "groupv3.wakeup", skip_all, fields(user_id = %cx.mls_identity.display_name(), signer = %Short(cx.mls_identity.signer_key().as_bytes()), convo = %ConvoId(&self.convo_id), epoch = self.mls_group.epoch().as_u64()))]
    fn wakeup(&mut self, cx: &mut ServiceContext<S>) -> Result<ConvoOutcome, ChatError> {
        cx.wakeup_service
            .wakeup_in(SDS_TICK_INTERVAL, self.convo_id.clone());
        let events = self.channel.tick(now_ms(cx), &mut rand_0_10::rng());
        let mut observations = self.handle_sds_events(cx, events);

        let epoch = self.mls_group.epoch().as_u64();
        if let Some(fingerprint) = self.finality.finalized(cx.clock.now(), epoch) {
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
        Ok(ConvoOutcome {
            observations,
            ..self.default_outcome()
        })
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
        ])
    }
}

impl HasMlsConvo for GroupV3Convo {
    fn mls_group(&self) -> &MlsGroup {
        &self.mls_group
    }
}
