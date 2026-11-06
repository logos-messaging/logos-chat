// TESTING ONLY
// A Group Conversation that uses SDS for message ordering
//
// Invariants:
//  - Signers are not allowed change their SigningKey.
//  - Everyone is an "Admin"
//

mod handlers;
mod payloads;
mod storage;

use std::collections::VecDeque;
use std::fmt;
use std::time::Duration;

use openmls::framing::MlsMessageOut;
use openmls::group::{GroupEpoch, MlsGroup, StagedWelcome};
use openmls::key_packages::KeyPackage;
use openmls::messages::Welcome;
use openmls_traits::OpenMlsProvider;
use prost::Message;
use sds::{Channel, Config, OutgoingMessage, Packet};
use tracing::{instrument, warn};

use crate::conversation::mls_groups::{HasMlsConvo, create_group, mls_join_config};
use crate::conversation::{ConversationIdRef, Convo, ConvoBase, GroupConvo, Identified};
use crate::errors::SendError;
use crate::service_context::ServiceContext;
use crate::utils::{blake2b_hex, hash_size};
use crate::{
    AddressedEnvelope, ChatError, ConvoOutcome, DeliveryService, ExternalServices,
    IdentityProvider, MessageId, SignerKey, WakeupService,
};

use super::mls_utils::{fetch_key_packages, member_diff, unique};

use self::handlers::HeldMessage;
use self::payloads::{GroupV3Payload, commit_payload, message_id, protocol_message, to_envelope};
use self::storage::SeededStorage;

// Type Aliases
type Frame = payloads::GroupV3Frame;

// Fires SDS's resend and sync deadlines within a second. `wakeup_in` adds a timer rather than
// replacing one, so only `init` and `wakeup` arm it.
const SDS_TICK_INTERVAL: Duration = Duration::from_secs(1);

// A message names this many of its sender's newest SDS log entries, so an invite carries as many
// ids for the joiner to count as delivered.
const MAX_CAUSAL_HISTORY: usize = 10;

// Messages wait in SDS for a missing dependency, or here for a later epoch; each wait holds at
// most this many, dropping the oldest, though the wait for an epoch keeps its commits.
const MAX_WAITING_MESSAGES: usize = 500;

fn delivery_address_from_id(convo_id: &str) -> String {
    blake2b_hex::<hash_size::DeliveryAddr>(&["delivery_addr|", convo_id])
}

fn create_sds_channel<S: ExternalServices>(
    cx: &ServiceContext<S>,
    convo_id: &str,
    seeded_ids: &[MessageId],
) -> Result<Channel<SeededStorage>, ChatError> {
    // The signer, not the account: two installations of one account would drop each other's
    // messages as their own.
    let mut config = Config::new(cx.mls_identity.signer_key().to_string(), convo_id);
    config.max_causal_history = MAX_CAUSAL_HISTORY;
    config.max_incoming_buffer = MAX_WAITING_MESSAGES;
    config.repair = None;
    Channel::with_storage(config, SeededStorage::new(seeded_ids)).map_err(ChatError::generic)
}

fn now_ms<S: ExternalServices>(cx: &ServiceContext<S>) -> u64 {
    cx.clock.now().as_millis() as u64
}

pub struct GroupV3Convo {
    convo_id: String,
    mls_group: MlsGroup,
    /// The epoch we created or joined the group at.
    joined_epoch: GroupEpoch,
    channel: Channel<SeededStorage>,
    /// The ids our invite carried, which our channel counts as delivered, oldest first; none for
    /// the creator.
    seeded_ids: Vec<MessageId>,
    /// Held for a later epoch, oldest first.
    held_messages: VecDeque<HeldMessage>,
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

        let mut convo = Self::from_group(cx, mls_group, Vec::new())?;

        convo.init(cx)?;
        convo.add_signer(cx, signers)?;
        Ok(convo)
    }

    /// Joins from a Welcome. `seeded_ids` are the newest ids the inviter counts as delivered, and
    /// our channel counts them as delivered too.
    pub fn new_from_welcome<S: ExternalServices>(
        cx: &mut ServiceContext<S>,
        welcome: Welcome,
        seeded_ids: Vec<MessageId>,
    ) -> Result<Self, ChatError> {
        let mls_group =
            StagedWelcome::build_from_welcome(&cx.mls_provider, &mls_join_config(), welcome)
                .map_err(ChatError::generic)?
                .build()
                .map_err(ChatError::generic)?
                .into_group(&cx.mls_provider)
                .map_err(ChatError::generic)?;

        let convo = Self::from_group(cx, mls_group, seeded_ids)?;

        convo.init(cx)?;
        Ok(convo)
    }

    fn from_group<S: ExternalServices>(
        cx: &ServiceContext<S>,
        mls_group: MlsGroup,
        seeded_ids: Vec<MessageId>,
    ) -> Result<Self, ChatError> {
        let convo_id = hex::encode(mls_group.group_id().as_slice());
        let joined_epoch = mls_group.epoch();
        let channel = create_sds_channel(cx, &convo_id, &seeded_ids)?;
        Ok(Self {
            convo_id,
            mls_group,
            joined_epoch,
            channel,
            seeded_ids,
            held_messages: VecDeque::new(),
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
        let packet = self.channel.send(message, now_ms(cx))?;
        self.publish_payload(cx, packet.into())?;

        Ok(message_id)
    }

    fn send_pending_commit<S: ExternalServices>(
        &mut self,
        cx: &mut ServiceContext<S>,
        commit_msg: MlsMessageOut,
        dependent_msgs: Vec<AddressedEnvelope>,
    ) -> Result<(), ChatError> {
        // Send Commit
        if let Err(e) =
            commit_payload(commit_msg).and_then(|payload| self.publish_payload(cx, payload))
        {
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

        // Send Welcomes
        for env in dependent_msgs {
            Self::publish_envelope(cx, env)?;
        }
        Ok(())
    }

    fn publish_payload<S: ExternalServices>(
        &self,
        cx: &mut ServiceContext<S>,
        payload: GroupV3Payload,
    ) -> Result<(), SendError> {
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

    /// The newest ids we count as delivered, oldest first, taking every logged id as newer than
    /// every seeded one, since the invite carries no timestamps to interleave them.
    fn recent_message_ids(&self) -> Vec<MessageId> {
        let mut ids = self.seeded_ids.clone();
        ids.extend(self.channel.history());
        ids.split_off(ids.len().saturating_sub(MAX_CAUSAL_HISTORY))
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

        let recent_message_ids = self.recent_message_ids();
        let invites: Result<Vec<AddressedEnvelope>, SendError> = key_packages
            .iter()
            .map(|s| {
                crate::inbox_v2::create_invite_v3(
                    &SignerKey::from(s.leaf_node()),
                    &welcome,
                    &recent_message_ids,
                )
            })
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
        let payload = GroupV3Payload::decode(payload)?;
        if payload.encrypted_header.is_empty() {
            let mut outcome = self.handle_mls_protocol_msg(
                cx,
                None,
                protocol_message(&payload.encrypted_frame)?,
            )?;
            // A merged commit can bring the epoch held messages wait for.
            outcome.observations.extend(self.retry_held_messages(cx));
            return Ok(outcome);
        }

        let events = self
            .channel
            .receive(Packet::from(payload), None, now_ms(cx))
            .map_err(ChatError::generic)?;
        Ok(ConvoOutcome {
            observations: self.handle_sds_events(cx, events),
            ..self.default_outcome()
        })
    }

    fn wakeup(&mut self, cx: &mut ServiceContext<S>) -> Result<crate::ConvoOutcome, ChatError> {
        cx.wakeup_service
            .wakeup_in(SDS_TICK_INTERVAL, self.convo_id.clone());
        let events = self.channel.tick(now_ms(cx), &mut rand_0_10::rng());
        Ok(ConvoOutcome {
            observations: self.handle_sds_events(cx, events),
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
