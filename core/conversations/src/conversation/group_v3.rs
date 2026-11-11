// TESTING ONLY
// A Group Conversation that uses SDS for message ordering
//
// Invariants:
//  - Signers are not allowed change their SigningKey.
//  - Everyone is an "Admin"
//

mod handlers;
mod payloads;

use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

use openmls::framing::MlsMessageOut;
use openmls::group::{MlsGroup, StagedCommit, StagedWelcome};
use openmls::key_packages::KeyPackage;
use openmls::messages::Welcome;
use openmls_traits::OpenMlsProvider;
use sds::{Channel, Config, OutgoingMessage, SDSRecord};
use tracing::{info, instrument, warn};

use crate::conversation::group_v3::payloads::EpochData;
use crate::conversation::mls_groups::{HasMlsConvo, create_group, group_join_config};
use crate::conversation::mls_utils::EpochFingerprint;
use crate::conversation::{ConversationIdRef, Convo, ConvoBase, GroupConvo, Identified};
use crate::errors::SendError;
use crate::service_context::ServiceContext;
use crate::utils::{blake2b_hex, hash_size};
use crate::{
    AddressedEnvelope, ChatError, ConvoOutcome, DeliveryService, ExternalServices,
    IdentityProvider, Observation, SignerKey, WakeupService,
};

use super::mls_utils::{fetch_key_packages, member_diff, unique};

use self::payloads::{GroupV3Payload, commit_record, message_id, protocol_message, to_envelope};

// Type Aliases
type Frame = payloads::GroupV3Frame;

// Fires SDS's resend and sync deadlines within a second. `wakeup_in` adds a timer rather than
// replacing one, so only `init` and `wakeup` arm it.
const SDS_TICK_INTERVAL: Duration = Duration::from_secs(1);
const COMMIT_FINALIZE_DELAY: Duration = Duration::from_secs(30);

fn delivery_address_from_id(convo_id: &str) -> String {
    blake2b_hex::<hash_size::DeliveryAddr>(&["delivery_addr|", convo_id])
}

fn create_sds_channel<S: ExternalServices>(
    cx: &ServiceContext<S>,
    convo_id: &str,
) -> Result<Channel, ChatError> {
    // The signer, not the account: two installations of one account would drop each other's
    // messages as their own.
    let mut config = Config::new(cx.mls_identity.signer_key().to_string(), convo_id);
    config.repair = None;
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
    next_commit: Option<(Duration, EpochFingerprint)>, //Temporary
    epoch_data: EpochData,
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
    pub fn new<S: ExternalServices>(
        cx: &mut ServiceContext<S>,
        name: &str,
        desc: &str,
        signers: &[SignerKey],
    ) -> Result<Self, ChatError> {
        // Create MlsGroup
        let mls_group = create_group(cx, name, desc)?;

        let mut convo = Self::from_group(cx, mls_group)?;

        convo.init(cx)?;
        convo.add_signer(cx, signers)?;
        Ok(convo)
    }

    pub fn new_from_welcome<S: ExternalServices>(
        cx: &mut ServiceContext<S>,
        welcome: Welcome,
    ) -> Result<Self, ChatError> {
        let mls_group =
            StagedWelcome::build_from_welcome(&cx.mls_provider, &group_join_config(), welcome)
                .map_err(ChatError::generic)?
                .build()
                .map_err(ChatError::generic)?
                .into_group(&cx.mls_provider)
                .map_err(ChatError::generic)?;

        let convo = Self::from_group(cx, mls_group)?;

        convo.init(cx)?;
        Ok(convo)
    }

    fn from_group<S: ExternalServices>(
        cx: &ServiceContext<S>,
        mls_group: MlsGroup,
    ) -> Result<Self, ChatError> {
        let convo_id = hex::encode(mls_group.group_id().as_slice());
        let channel = create_sds_channel(cx, &convo_id)?;
        let epoch = mls_group.epoch().as_u64();
        Ok(Self {
            convo_id,
            mls_group,
            channel,
            deferred_commits: HashMap::default(),
            next_commit: None,
            epoch_data: EpochData::starting_at(epoch),
        })
    }
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
        let frame = frame.encode();

        let mls_msg =
            self.mls_group
                .create_message(&cx.mls_provider, &cx.mls_identity, frame.as_slice())?;
        let mls_bytes = mls_msg.to_bytes()?;
        let message_id = message_id(&mls_bytes);

        let message = OutgoingMessage {
            message_id: message_id.clone(),
            content: mls_bytes,
            retrieval_hint: None,
        };
        let record = self.channel.send(message, now_ms(cx))?;
        self.publish_payload(cx, record)?;

        Ok(message_id)
    }

    fn send_pending_commit<S: ExternalServices>(
        &mut self,
        cx: &mut ServiceContext<S>,
        commit_msg: MlsMessageOut,
        dependent_msgs: Vec<AddressedEnvelope>,
    ) -> Result<(), ChatError> {
        let fingerprint = self
            .mls_group
            .pending_commit()
            .map(EpochFingerprint::from)
            .ok_or_else(|| ChatError::generic("no pending commit"))?;

        // Send Commit
        if let Err(e) =
            commit_record(commit_msg).and_then(|record| self.publish_payload(cx, record))
        {
            // Discard the pending commit so the group isn't left wedged
            if let Err(clear_err) = self
                .mls_group
                .clear_pending_commit(cx.mls_provider.storage())
            {
                warn!(convo = %self.convo_id, error = %clear_err, "failed to clear pending commit");
            }
            return Err(e.into());
        }

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
        // Simulate some finalization mechanism
        if self.next_commit.is_none() {
            self.next_commit = Some((cx.clock.now() + COMMIT_FINALIZE_DELAY, fingerprint.clone()));
        }
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
                let pending = self.mls_group.pending_commit().map(EpochFingerprint::from);
                if pending.as_ref() != Some(fingerprint) {
                    return Err(ChatError::generic("pending commit no longer exists"));
                }
                self.mls_group.merge_pending_commit(&cx.mls_provider)?;
                payloads
            }
            DeferredCommit::Staged(commit) => {
                if commit.epoch().as_u64() != starting_epoch + 1 {
                    return Err(ChatError::generic("commit is not for the next epoch"));
                }
                self.mls_group
                    .merge_staged_commit(&cx.mls_provider, commit)
                    .map_err(ChatError::generic)?;
                vec![]
            }
        };

        self.epoch_data
            .advance_to(self.mls_group.epoch().as_u64(), fingerprint.clone());
        self.drop_expired_deferred_commits();
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

    /// Every outbound payload goes through here, so every one carries the epoch data.
    fn publish_payload<S: ExternalServices>(
        &self,
        cx: &mut ServiceContext<S>,
        record: SDSRecord,
    ) -> Result<(), SendError> {
        let payload = GroupV3Payload::new(record, self.epoch_data.clone())?;
        let env = to_envelope(self.convo_id.to_string(), payload);
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
        let (record, _epoch_data) = GroupV3Payload::parse(payload)?;

        // TODO: remove once commits travel through SDS.
        if record.header.is_empty() {
            let commit = record.content.unwrap_or_default();
            return self.handle_mls_protocol_msg(cx, None, protocol_message(&commit)?);
        }

        let events = self
            .channel
            .receive(record, None, now_ms(cx))
            .map_err(ChatError::generic)?;
        Ok(ConvoOutcome {
            observations: self.handle_sds_events(cx, events),
            ..self.default_outcome()
        })
    }

    fn wakeup(&mut self, cx: &mut ServiceContext<S>) -> Result<ConvoOutcome, ChatError> {
        cx.wakeup_service
            .wakeup_in(SDS_TICK_INTERVAL, self.convo_id.clone());
        let events = self.channel.tick(now_ms(cx), &mut rand_0_10::rng());
        let mut observations = self.handle_sds_events(cx, events);

        let now = cx.clock.now();
        if let Some((_, fingerprint)) = self.next_commit.take_if(|(due, _)| *due <= now) {
            match self.finalize_deferred_commit(cx, &fingerprint) {
                Ok(outcome) => observations.extend(outcome.observations),
                Err(e) => {
                    warn!(convo = %self.convo_id, error = %e, "failed to finalize deferred commit")
                }
            }
        }

        Ok(ConvoOutcome {
            observations,
            ..self.default_outcome()
        })
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
