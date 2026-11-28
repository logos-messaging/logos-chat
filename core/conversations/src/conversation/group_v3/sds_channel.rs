use std::time::Duration;

use sds::{Channel, Config, Event, SDSRecord, StartPoint};
use tracing::warn;

use crate::conversation::Identified as _;
use crate::errors::SendError;
use crate::service_context::ServiceContext;
use crate::{
    ChatError, DeliveryMsgId, DeliveryService as _, ExternalServices, IdentityProvider as _,
    Observation,
};

use super::payloads::{EncryptedSdsMessage, GroupV3Packet};
use super::{GroupV3Convo, debug_events, delivery_address_from_id};

// Fires SDS's resend and sync deadlines within a second. `wakeup_in` adds a timer rather than
// replacing one, so only `init` and `wakeup` arm it.
pub(super) const SDS_TICK_INTERVAL: Duration = Duration::from_secs(1);

pub(super) fn create_sds_channel<S: ExternalServices>(
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

pub(super) fn now_ms<S: ExternalServices>(cx: &ServiceContext<S>) -> u64 {
    cx.clock.now().as_millis() as u64
}

impl GroupV3Convo {
    /// Act on SDS events in order: a released message goes through MLS, a record is published.
    /// A failure warns and moves on to the next event.
    /// What SDS reports missing is fetched in one ask, once every event is handled.
    pub(super) fn handle_sds_events<S: ExternalServices>(
        &mut self,
        cx: &mut ServiceContext<S>,
        events: Vec<Event>,
    ) -> Vec<Observation> {
        let mut observations = Vec::new();
        let mut to_fetch = Vec::new();
        for event in events {
            match event {
                Event::MessageReady {
                    message_id,
                    content,
                    ..
                } => {
                    let message = GroupV3Packet::from_sds_content(&message_id, &content)
                        .and_then(|envelope| envelope.protocol_message());

                    // Record event after mls_decode
                    observations.push(debug_events::sds_released(&message_id, &message));

                    match message
                        .and_then(|message| self.handle_sds_message_ready(cx, message_id, message))
                    {
                        Ok(outcome) => observations.extend(outcome.observations),
                        Err(e) => {
                            warn!(convo = %self.convo_id, error = %e, "dropping released message")
                        }
                    }
                }
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
                    if let Err(e) =
                        self.publish_payload(cx, EncryptedSdsMessage::from_record(record))
                    {
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
        observations
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
    pub(super) fn publish_record<S: ExternalServices>(
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

    pub(super) fn publish_payload<S: ExternalServices>(
        &self,
        cx: &mut ServiceContext<S>,
        message: EncryptedSdsMessage,
    ) -> Result<(), SendError> {
        Self::publish_envelope(cx, message.into_envelope(self.convo_id.to_string()))
    }
}
