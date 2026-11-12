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

use std::fmt;
use std::time::Duration;

use openmls::framing::MlsMessageOut;
use openmls::group::{MlsGroup, StagedWelcome};
use openmls::key_packages::KeyPackage;
use openmls::messages::Welcome;
use openmls_traits::OpenMlsProvider;
use prost::Message;
use sds::{Channel, Config, OutgoingMessage, SDSRecord, StartPoint};
use tracing::{instrument, warn};

use crate::conversation::mls_groups::{HasMlsConvo, create_group, group_join_config};
use crate::conversation::{ConversationIdRef, Convo, ConvoBase, GroupConvo, Identified};
use crate::errors::SendError;
use crate::service_context::ServiceContext;
use crate::utils::{blake2b_hex, hash_size};
use crate::{
    AddressedEnvelope, ChatError, ConvoOutcome, DeliveryService, ExternalServices,
    IdentityProvider, SignerKey, WakeupService,
};

use super::mls_utils::{fetch_key_packages, member_diff, unique};

use self::beacons::Beacons;
use self::payloads::{GroupV3Body, GroupV3External, GroupV3Payload, message_id, to_envelope};

// Type Aliases
type Frame = payloads::GroupV3Frame;

// Fires SDS's resend and sync deadlines within a second. `wakeup_in` adds a timer rather than
// replacing one, so only `init` and `wakeup` arm it.
const SDS_TICK_INTERVAL: Duration = Duration::from_secs(1);

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

pub struct GroupV3Convo {
    convo_id: String,
    mls_group: MlsGroup,
    channel: Channel,
    beacons: Beacons,
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

        let mut convo = Self::from_group(cx, mls_group, None)?;

        convo.init(cx)?;
        convo.add_signer(cx, signers)?;
        convo.enter_epoch(cx);
        Ok(convo)
    }

    /// Joins from a Welcome, starting our SDS channel at `start`, the commit that added us.
    pub fn new_from_welcome<S: ExternalServices>(
        cx: &mut ServiceContext<S>,
        welcome: Welcome,
        start: StartPoint,
    ) -> Result<Self, ChatError> {
        let mls_group =
            StagedWelcome::build_from_welcome(&cx.mls_provider, &group_join_config(), welcome)
                .map_err(ChatError::generic)?
                .build()
                .map_err(ChatError::generic)?
                .into_group(&cx.mls_provider)
                .map_err(ChatError::generic)?;

        let mut convo = Self::from_group(cx, mls_group, Some(start))?;

        convo.init(cx)?;
        convo.enter_epoch(cx);
        Ok(convo)
    }

    fn from_group<S: ExternalServices>(
        cx: &ServiceContext<S>,
        mls_group: MlsGroup,
        start: Option<StartPoint>,
    ) -> Result<Self, ChatError> {
        let convo_id = hex::encode(mls_group.group_id().as_slice());
        let channel = create_sds_channel(cx, &convo_id, start)?;
        Ok(Self {
            convo_id,
            mls_group,
            channel,
            beacons: Beacons::default(),
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
        self.publish_payload(cx, record.into())?;

        Ok(message_id)
    }

    /// Sends the pending commit through SDS and merges it. Returns the commit's place in the SDS
    /// channel, where a member it adds starts.
    fn send_pending_commit<S: ExternalServices>(
        &mut self,
        cx: &mut ServiceContext<S>,
        commit_msg: MlsMessageOut,
    ) -> Result<StartPoint, ChatError> {
        // Send Commit
        let sent = commit_msg
            .to_bytes()
            .map_err(SendError::from)
            .and_then(|commit| {
                let message = OutgoingMessage {
                    message_id: message_id(&commit),
                    content: commit,
                    retrieval_hint: None,
                };
                Ok(self.channel.send(message, now_ms(cx))?)
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

        // Update State
        self.mls_group.merge_pending_commit(&cx.mls_provider)?;
        self.enter_epoch(cx);

        let start = StartPoint {
            message_id: record.header.message_id.clone(),
            lamport_timestamp: record
                .header
                .lamport_timestamp
                .ok_or_else(|| ChatError::generic("sds sent the commit without a timestamp"))?,
        };
        // SDS keeps the commit and resends it, so a failed publish heals as a lost one does.
        if let Err(e) = self.publish_payload(cx, record.into()) {
            warn!(convo = %self.convo_id, error = %e, "failed to publish commit");
        }
        Ok(start)
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

    fn default_outcome(&self) -> ConvoOutcome {
        ConvoOutcome::empty(self.convo_id.clone())
    }
}

impl GroupV3Convo {
    /// Call after merging any commit, ours or a peer's.
    fn enter_epoch<S: ExternalServices>(&mut self, cx: &mut ServiceContext<S>) {
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
        let payload = GroupV3Payload::external(GroupV3External::beacon(beacon.clone()));
        match self.publish_payload(cx, payload) {
            Ok(()) => self.beacons.sent(),
            Err(e) => {
                warn!(convo = %self.convo_id, error = %e, "beacon not sent");
                self.beacons.failed(now);
            }
        }
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

        let commit = self.send_pending_commit(cx, commit_msg)?;

        // Send Welcomes
        for key_package in &key_packages {
            let invite = crate::inbox_v2::create_invite_v3(
                &SignerKey::from(key_package.leaf_node()),
                &welcome,
                &commit,
            )?;
            Self::publish_envelope(cx, invite)?;
        }

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
        if let Some(GroupV3Body::External(frame)) = &payload.body {
            let crypto = cx.mls_provider.crypto();
            let keys = self.mls_group.members().map(|m| m.signature_key);
            self.beacons
                .receive_frame(crypto, &self.convo_id, keys, frame);
            return Ok(self.default_outcome());
        }

        let events = self
            .channel
            .receive(SDSRecord::try_from(payload)?, None, now_ms(cx))
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
        self.send_beacon(cx);
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
