use std::time::Duration;

use sds::{Channel, Config, Event, SDSRecord, StartPoint};
use tracing::warn;

use crate::conversation::ConversationId;
use crate::errors::SendError;
use crate::service_context::ServiceContext;
use crate::{
    ChatError, DeliveryInfo, DeliveryMsgId, DeliveryService as _, ExternalServices,
    IdentityProvider as _, Observation,
};

use super::payloads::{EncryptedSdsMessage, GroupV3Packet, ReceivedGroupV3Packet};
use super::{GroupV3Convo, debug_events, delivery_address_from_id};

pub(super) const SDS_TICK_INTERVAL: Duration = Duration::from_secs(1);

/// GroupV3's packets over SDS: orders, resends and fetches them, and publishes what SDS sends.
pub(super) struct SdsChannel {
    channel: Channel,
    convo_id: ConversationId,
}

/// What a receive or a tick changed, for GroupV3 to act on.
#[derive(Default)]
pub(super) struct SdsOutput {
    /// Messages SDS newly buffered, waiting on their history.
    pub(super) buffered: Vec<ReceivedGroupV3Packet>,
    /// Messages SDS released, in order.
    pub(super) released: Vec<ReceivedGroupV3Packet>,
    pub(super) observations: Vec<Observation>,
}

impl SdsChannel {
    pub(super) fn new<S: ExternalServices>(
        cx: &ServiceContext<S>,
        convo_id: &str,
        start: Option<StartPoint>,
    ) -> Result<Self, ChatError> {
        // The signer, not the account: two installations of one account would drop each other's
        // messages as their own.
        let mut config = Config::new(cx.mls_identity.signer_key().to_string(), convo_id);
        config.repair = None;
        config.start = start;
        Ok(Self {
            channel: Channel::new(config).map_err(ChatError::generic)?,
            convo_id: convo_id.to_owned(),
        })
    }

    /// Logs `packet` and publishes it, and returns its place in the channel. An error means SDS
    /// did not log it.
    pub(super) fn send<S: ExternalServices>(
        &mut self,
        cx: &mut ServiceContext<S>,
        packet: GroupV3Packet,
    ) -> Result<StartPoint, SendError> {
        let record = self
            .channel
            .send(packet.into_outgoing_message(), now_ms(cx))?;
        let start = StartPoint {
            message_id: record.header.message_id.clone(),
            // `Channel::send` always stamps the header.
            lamport_timestamp: record.header.lamport_timestamp.unwrap_or_default(),
        };
        // SDS resends a logged message, so a failed publish heals as a lost one does.
        if let Err(e) = self.publish_record(cx, record) {
            warn!(convo = %self.convo_id, error = %e, "failed to publish sds record");
        }
        Ok(start)
    }

    /// Processes an inbout message with SDS.
    /// A message refused based on SDS criterial logs a warning rather tha emitting an error.
    pub(super) fn receive<S: ExternalServices>(
        &mut self,
        cx: &mut ServiceContext<S>,
        message: EncryptedSdsMessage,
        delivery_info: Option<&DeliveryInfo>,
    ) -> Result<SdsOutput, ChatError> {
        let record = message.try_into_record()?;
        let mut output = SdsOutput::default();
        // A sync carries no message, so it has no steps to report.
        let message_id = record
            .content
            .is_some()
            .then(|| record.header.message_id.clone());
        output
            .observations
            .extend(debug_events::sds_received(&record, delivery_info));

        let arriving = record
            .content
            .as_ref()
            .and_then(|c| GroupV3Packet::from_sds_content(&record.header.message_id, &c).ok());

        let retrieval_hint = delivery_info.map(|info| info.delivery_msg_id.as_bytes().to_vec());
        match self.channel.receive(record, retrieval_hint, now_ms(cx)) {
            Ok(events) => self.handle_events(cx, events, arriving, &mut output),
            // A peer's record SDS refuses is dropped, like a released message that fails.
            Err(e) => {
                warn!(convo = %self.convo_id, error = %e, "sds refused a record");
                output
                    .observations
                    .extend(message_id.and_then(|id| debug_events::sds_ignored_for_error(id, &e)));
            }
        }
        Ok(output)
    }

    pub(super) fn tick<S: ExternalServices>(&mut self, cx: &mut ServiceContext<S>) -> SdsOutput {
        let events = self.channel.tick(now_ms(cx), &mut rand_0_10::rng());
        let mut output = SdsOutput::default();
        self.handle_events(cx, events, None, &mut output);
        output
    }

    /// Keeps the id the delivery service learned for `message_id` as its retrieval hint.
    pub(super) fn handle_delivery_report(
        &mut self,
        message_id: &str,
        info: &DeliveryInfo,
    ) -> Result<(), ChatError> {
        self.channel
            .set_retrieval_hint(message_id, info.delivery_msg_id.as_bytes().to_vec())
            .map_err(ChatError::generic)
    }

    /// Act on SDS events in order: a released or buffered message is handed back, a record is
    /// published. A failure warns and moves on to the next event.
    /// What SDS reports missing is fetched in one ask, once every event is handled.
    fn handle_events<S: ExternalServices>(
        &mut self,
        cx: &mut ServiceContext<S>,
        events: Vec<Event>,
        mut arriving: Option<ReceivedGroupV3Packet>,
        output: &mut SdsOutput,
    ) {
        let observations = &mut output.observations;
        let mut to_fetch = Vec::new();
        for event in events {
            match event {
                Event::MessageReady {
                    message_id,
                    content,
                    ..
                } => match GroupV3Packet::from_sds_content(&message_id, &content) {
                    Ok(received) => output.released.push(received),
                    Err(e) => {
                        warn!(convo = %self.convo_id, error = %e, "dropping released message");
                        observations.push(debug_events::sds_released(&message_id, &Err(e)));
                    }
                },
                Event::Resend(record) => {
                    observations.push(debug_events::sds_resent(&record));
                    if let Err(e) = self.publish_record(cx, record) {
                        warn!(convo = %self.convo_id, error = %e, "failed to publish sds record");
                    }
                }
                Event::Repair(record) => {
                    if let Err(e) = self.publish_record(cx, record) {
                        warn!(convo = %self.convo_id, error = %e, "failed to publish sds record");
                    }
                }
                // SDS logs no sync message, so it has no hint to keep.
                Event::Sync(record) => {
                    let msg = EncryptedSdsMessage::from_record(record);
                    let env = msg.into_envelope(self.convo_id.clone());

                    if let Err(e) = GroupV3Convo::publish_envelope(cx, env) {
                        warn!(convo = %self.convo_id, error = %e, "failed to publish sds record");
                    }
                }
                Event::MessageAcknowledged { message_id } => {
                    observations.push(Observation::Delivered(message_id))
                }
                Event::MessageBuffered {
                    message_id,
                    missing_dependencies,
                    buffered_dependencies,
                } => {
                    // SDS buffers only the message that just arrived.
                    if let Some(packet) = arriving.take() {
                        output.buffered.push(packet);
                    }
                    observations.push(debug_events::sds_buffered(
                        message_id,
                        &missing_dependencies,
                        &buffered_dependencies,
                    ));
                    to_fetch.extend(
                        missing_dependencies
                            .into_iter()
                            .filter_map(|entry| entry.retrieval_hint)
                            .map(DeliveryMsgId::from),
                    );
                }
                Event::MessageIgnored { message_id, reason } => {
                    observations.push(debug_events::sds_ignored(message_id, reason))
                }
                Event::Lost { message_id, reason } => {
                    observations.push(debug_events::sds_lost(message_id, reason))
                }
                Event::SendFailed { message_id } => {
                    observations.push(debug_events::sds_send_failed(message_id))
                }
            }
        }
        observations.extend(self.fetch_missing(cx, to_fetch));
    }

    /// Asks the delivery service for the payloads `delivery_msg_ids` name. A failure only warns, as
    /// the next report naming them asks again.
    fn fetch_missing<S: ExternalServices>(
        &self,
        cx: &mut ServiceContext<S>,
        delivery_msg_ids: Vec<DeliveryMsgId>,
    ) -> Option<Observation> {
        if delivery_msg_ids.is_empty() {
            return None;
        }
        if let Err(e) = cx
            .ds
            .fetch_messages(&delivery_address_from_id(&self.convo_id), &delivery_msg_ids)
        {
            warn!(convo = %self.convo_id, error = %e, "failed to fetch missing messages");
            return Some(debug_events::sds_fetch_failed(delivery_msg_ids));
        }
        None
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
        let env = EncryptedSdsMessage::from_record(record).into_envelope(self.convo_id.clone());
        let published = cx
            .ds
            .publish_tracked(env, &self.convo_id, &message_id)
            .map_err(|e| SendError::Delivery(e.to_string()))?;

        let Some(delivery_msg_id) = published else {
            return Ok(());
        };

        let hint = delivery_msg_id.as_bytes().to_vec();
        if let Err(e) = self.channel.set_retrieval_hint(&message_id, hint) {
            warn!(convo = %self.convo_id, error = %e, "failed to keep the retrieval hint");
        }
        Ok(())
    }
}

fn now_ms<S: ExternalServices>(cx: &ServiceContext<S>) -> u64 {
    cx.clock.now().as_millis() as u64
}
