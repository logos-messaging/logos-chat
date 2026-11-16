use openmls::framing::{ApplicationMessage, ProtocolMessage};
use openmls::prelude::{
    ContentType, Member, ProcessMessageError, ProcessedMessage, ProcessedMessageContent, Sender,
    StagedCommit, ValidationError,
};
use prost::Message as _;
use sds::Event;
use tracing::{debug, warn};

use crate::conversation::mls_utils::EpochFingerprint;
use crate::service_context::ServiceContext;
use crate::{
    ChatError, Content, ConvoOutcome, DeliveryMsgId, DeliveryService, ExternalServices, MessageId,
    Observation, Signer,
};

use super::payloads::{EncryptedSdsMessage, GroupV3FrameType, GroupV3Packet};
use super::{
    DeferredCommit, Frame, GroupV3Convo, MAX_LATER_EPOCH_MSGS, delivery_address_from_id, trace,
};

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
                } => match GroupV3Packet::from_sds_content(&message_id, &content)
                    .and_then(|envelope| self.handle_group_v3_envelope(cx, message_id, envelope))
                {
                    Ok(outcome) => observations.extend(outcome.observations),
                    Err(e) => {
                        warn!(convo = %self.convo_id, error = %e, "dropping released message")
                    }
                },
                Event::Resend(record) | Event::Repair(record) => {
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
                Event::MissingDependencies { missing, .. } => to_fetch.extend(
                    missing
                        .into_iter()
                        .filter_map(|entry| entry.retrieval_hint)
                        .map(DeliveryMsgId::from),
                ),
                other => debug!(convo = %self.convo_id, ?other, "sds event"),
            }
        }
        self.fetch_missing(cx, to_fetch);
        observations
    }

    /// Asks the delivery service for the payloads `delivery_msg_ids` name. A failure only warns, as
    /// the next report naming them asks again.
    fn fetch_missing<S: ExternalServices>(
        &self,
        cx: &mut ServiceContext<S>,
        delivery_msg_ids: Vec<DeliveryMsgId>,
    ) {
        if delivery_msg_ids.is_empty() {
            return;
        }
        if let Err(e) = cx
            .ds
            .fetch_messages(&delivery_address_from_id(&self.convo_id), &delivery_msg_ids)
        {
            warn!(convo = %self.convo_id, error = %e, "failed to fetch missing messages");
        }
    }

    /// Handle an envelope SDS released: pass its MLS message on.
    fn handle_group_v3_envelope<S: ExternalServices>(
        &mut self,
        cx: &mut ServiceContext<S>,
        message_id: MessageId,
        envelope: GroupV3Packet,
    ) -> Result<ConvoOutcome, ChatError> {
        let Some(message) = envelope.protocol_message()? else {
            debug!(convo = %self.convo_id, "ignoring non-mls frame");
            return Ok(self.default_outcome());
        };
        self.handle_mls_protocol_msg(cx, message_id, message)
    }

    /// Handle inbound mls encrypted messages. Accepts a successfully decoded ProtocolMessage
    /// and the id SDS released it under.
    fn handle_mls_protocol_msg<S: ExternalServices>(
        &mut self,
        cx: &mut ServiceContext<S>,
        message_id: MessageId,
        protocol_message: ProtocolMessage,
    ) -> Result<ConvoOutcome, ChatError> {
        let heard = trace::heard(self, &message_id, &protocol_message);
        if protocol_message.epoch() < self.mls_group.epoch() {
            debug!(convo = %self.convo_id, epoch = protocol_message.epoch().as_u64(), "dropping message from past epoch");
            trace::dropped(heard);
            return Ok(self.default_outcome());
        }
        if protocol_message.epoch() > self.mls_group.epoch() {
            // TODO: The epoch is not verified here. Limit how far ahead it can be.
            self.finality
                .later_epoch_seen(protocol_message.epoch().as_u64());
            if self.later_epoch_msgs.len() < MAX_LATER_EPOCH_MSGS {
                self.later_epoch_msgs.push((message_id, protocol_message));
            } else {
                // TODO: Keep commits when full. Content can fill the queue and a dropped commit
                // leaves this member behind.
                warn!(convo = %self.convo_id, "dropping message from later epoch");
                trace::dropped(heard);
            }
            return Ok(self.default_outcome());
        }

        let is_commit = protocol_message.content_type() == ContentType::Commit;
        let processed = match self
            .mls_group
            .process_message(&cx.mls_provider, protocol_message)
        {
            Ok(processed) => processed,
            Err(ProcessMessageError::ValidationError(ValidationError::CannotDecryptOwnMessage)) => {
                debug!(convo = %self.convo_id, "dropping own message");
                return Ok(self.default_outcome());
            }
            Err(e) => {
                // A commit for our epoch applies on the branch that made it.
                if is_commit {
                    self.sync.suspect(self.mls_group.epoch().as_u64());
                }
                trace::refused(heard, &e);
                return Err(ChatError::generic(e));
            }
        };

        self.handle_mls_msg(cx, message_id, processed)
    }

    /// Handle the deferred messages again. Call after the epoch changes.
    pub(super) fn handle_later_epoch_msgs<S: ExternalServices>(
        &mut self,
        cx: &mut ServiceContext<S>,
    ) -> Vec<Observation> {
        let mut observations = Vec::new();
        for (message_id, message) in std::mem::take(&mut self.later_epoch_msgs) {
            match self.handle_mls_protocol_msg(cx, message_id, message) {
                Ok(outcome) => observations.extend(outcome.observations),
                Err(e) => warn!(convo = %self.convo_id, error = %e, "dropping deferred message"),
            }
        }
        observations
    }

    /// Handle MLS ProcessedMessage. Send Commits and Application messages down to different parsers
    fn handle_mls_msg<S: ExternalServices>(
        &mut self,
        cx: &mut ServiceContext<S>,
        message_id: MessageId,
        processed: ProcessedMessage,
    ) -> Result<ConvoOutcome, ChatError> {
        // Resolved before `into_content` consumes the message.
        let sender = match processed.sender() {
            Sender::Member(index) => self.mls_group.member_at(*index),
            _ => None,
        };
        let epoch = processed.epoch().as_u64();

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(msg) => {
                self.handle_mls_application_message(cx, sender, msg, message_id, epoch)
            }
            ProcessedMessageContent::StagedCommitMessage(commit) => {
                self.handle_mls_commit(cx, *commit)
            }
            other => {
                debug!(convo = %self.convo_id, ?other, "ignoring mls message");
                Ok(self.default_outcome())
            }
        }
    }

    /// Handle MLS Application messages
    fn handle_mls_application_message<S: ExternalServices>(
        &mut self,
        cx: &mut ServiceContext<S>,
        sender: Option<Member>,
        app_msg: ApplicationMessage,
        message_id: MessageId,
        epoch: u64,
    ) -> Result<ConvoOutcome, ChatError> {
        let bytes = app_msg.into_bytes();

        let content = match Frame::decode(&*bytes)?.payload {
            Some(GroupV3FrameType::Content(content)) => content,
            other => {
                debug!(convo = %self.convo_id, ?other, "ignoring non-content frame");
                return Ok(self.default_outcome());
            }
        };

        // Validate sender and create `Content`
        let content = sender
            .map(|leaf| {
                Signer::from_leaf(&leaf.signature_key, leaf.credential.serialized_content())
            })
            .and_then(|member| member.require_valid(&cx.auth))
            .map(|sender| Content {
                bytes: content.to_vec(),
                sender,
                message_id: message_id.clone(),
            });
        trace::read(&message_id, epoch, content.as_ref());

        Ok(ConvoOutcome {
            observations: content.into_iter().map(Observation::Content).collect(),
            ..self.default_outcome()
        })
    }

    pub(super) fn handle_mls_commit<S: ExternalServices>(
        &mut self,
        cx: &mut ServiceContext<S>,
        commit: StagedCommit,
    ) -> Result<ConvoOutcome, ChatError> {
        let curr_epoch = self.mls_group.epoch().as_u64();
        let commit_epoch = commit.epoch();
        let fingerprint = EpochFingerprint::from_staged_commit(&commit)
            .unwrap_or_else(EpochFingerprint::removing_us);

        // Save the commit and apply only after its been finalized.
        let deferred = DeferredCommit::Staged(commit);
        self.defer_commit(cx, fingerprint.clone(), deferred);
        debug!(convo = %self.convo_id, epoch=%curr_epoch, %commit_epoch, ?fingerprint, "incoming commit deferred");
        Ok(self.default_outcome())
    }
}
