use std::collections::VecDeque;

use openmls::framing::{ApplicationMessage, ProtocolMessage};
use openmls::prelude::{
    Member, ProcessMessageError, ProcessedMessage, ProcessedMessageContent, Sender, StagedCommit,
    ValidationError,
};
use prost::Message as _;
use sds::Event;
use tracing::{debug, info, warn};

use crate::conversation::mls_groups::MAX_PAST_EPOCHS;
use crate::conversation::mls_utils::EpochFingerprint;
use crate::service_context::ServiceContext;
use crate::{ChatError, Content, ConvoOutcome, ExternalServices, MessageId, Observation, Signer};

use super::payloads::{GroupV3FrameType, protocol_message};
use super::{Frame, GroupV3Convo, MAX_WAITING_MESSAGES};

/// An MLS message held for an epoch we have not reached, with its SDS id if SDS released it.
pub(super) struct HeldMessage {
    message_id: Option<MessageId>,
    message: ProtocolMessage,
}

impl GroupV3Convo {
    /// Act on SDS events in order: a released message goes through MLS, a packet is published.
    /// A failure warns and moves on to the next event.
    pub(super) fn handle_sds_events<S: ExternalServices>(
        &mut self,
        cx: &mut ServiceContext<S>,
        events: Vec<Event>,
    ) -> Vec<Observation> {
        let mut observations = Vec::new();
        for event in events {
            match event {
                Event::MessageReady {
                    message_id,
                    content,
                    ..
                } => match protocol_message(&content)
                    .and_then(|message| self.handle_mls_protocol_msg(cx, Some(message_id), message))
                {
                    Ok(outcome) => observations.extend(outcome.observations),
                    Err(e) => {
                        warn!(convo = %self.convo_id, error = %e, "dropping released message")
                    }
                },
                Event::Resend(packet) | Event::Sync(packet) | Event::Repair(packet) => {
                    if let Err(e) = self.publish_payload(cx, packet.into()) {
                        warn!(convo = %self.convo_id, error = %e, "failed to publish sds packet");
                    }
                }
                other => debug!(convo = %self.convo_id, ?other, "sds event"),
            }
        }
        observations
    }

    /// Retry the held messages whose epoch we have reached, oldest first. A retried commit moves
    /// the epoch on, which can ready more.
    pub(super) fn retry_held_messages<S: ExternalServices>(
        &mut self,
        cx: &mut ServiceContext<S>,
    ) -> Vec<Observation> {
        let mut observations = Vec::new();
        loop {
            let epoch = self.mls_group.epoch();
            let (ready, still_held): (VecDeque<_>, VecDeque<_>) =
                std::mem::take(&mut self.held_messages)
                    .into_iter()
                    .partition(|held| held.message.epoch() <= epoch);
            self.held_messages = still_held;
            if ready.is_empty() {
                return observations;
            }
            for HeldMessage {
                message_id,
                message,
            } in ready
            {
                match self.handle_mls_protocol_msg(cx, message_id, message) {
                    Ok(outcome) => observations.extend(outcome.observations),
                    Err(e) => {
                        warn!(convo = %self.convo_id, error = %e, "dropping message held for its epoch")
                    }
                }
            }
        }
    }

    /// Handle inbound mls encrypted messages. Accepts a successfully decoded ProtocolMessage
    /// and its SDS id when SDS released it.
    pub(super) fn handle_mls_protocol_msg<S: ExternalServices>(
        &mut self,
        cx: &mut ServiceContext<S>,
        message_id: Option<MessageId>,
        protocol_message: ProtocolMessage,
    ) -> Result<ConvoOutcome, ChatError> {
        let epoch = protocol_message.epoch();
        let current = self.mls_group.epoch();
        if epoch > current {
            self.hold_for_epoch(message_id, protocol_message);
            return Ok(self.default_outcome());
        }
        // OpenMLS opens only application messages from a past epoch, and keeps MAX_PAST_EPOCHS of
        // them, none from before we joined. Our own commits return here once merged.
        if epoch < current
            && (protocol_message.is_handshake_message()
                || epoch < self.joined_epoch
                || current.as_u64() - epoch.as_u64() > MAX_PAST_EPOCHS as u64)
        {
            debug!(convo = %self.convo_id, epoch = epoch.as_u64(), "dropping message from past epoch");
            return Ok(self.default_outcome());
        }

        let processed = match self
            .mls_group
            .process_message(&cx.mls_provider, protocol_message)
        {
            Ok(processed) => processed,
            Err(ProcessMessageError::ValidationError(ValidationError::CannotDecryptOwnMessage)) => {
                debug!(convo = %self.convo_id, "dropping own message");
                return Ok(self.default_outcome());
            }
            Err(e) => return Err(ChatError::generic(e)),
        };

        self.handle_mls_msg(cx, message_id, processed)
    }

    /// Keep a message for a later epoch. When full, the oldest held application message makes
    /// room, since nothing resends a commit.
    fn hold_for_epoch(&mut self, message_id: Option<MessageId>, message: ProtocolMessage) {
        debug!(convo = %self.convo_id, epoch = message.epoch().as_u64(), "holding message for a later epoch");
        if self.held_messages.len() >= MAX_WAITING_MESSAGES {
            let Some(oldest) = self
                .held_messages
                .iter()
                .position(|held| !held.message.is_handshake_message())
            else {
                warn!(convo = %self.convo_id, "dropping message for a later epoch, as only commits are held");
                return;
            };
            self.held_messages.remove(oldest);
            warn!(convo = %self.convo_id, "dropping the oldest application message held for a later epoch");
        }
        self.held_messages.push_back(HeldMessage {
            message_id,
            message,
        });
    }

    /// Handle MLS ProcessedMessage. Send Commits and Application messages down to different parsers
    fn handle_mls_msg<S: ExternalServices>(
        &mut self,
        cx: &mut ServiceContext<S>,
        message_id: Option<MessageId>,
        processed: ProcessedMessage,
    ) -> Result<ConvoOutcome, ChatError> {
        // Resolved before `into_content` consumes the message. Members are only added, so the
        // sender of a message from a past epoch still holds its leaf.
        let sender = match processed.sender() {
            Sender::Member(index) => self.mls_group.member_at(*index),
            _ => None,
        };

        // Commits travel outside SDS and application messages through it; either one arriving the
        // other way is ignored.
        match (processed.into_content(), message_id) {
            (ProcessedMessageContent::ApplicationMessage(msg), Some(message_id)) => {
                self.handle_mls_application_message(cx, sender, msg, message_id)
            }
            (ProcessedMessageContent::StagedCommitMessage(commit), None) => {
                self.handle_mls_commit(cx, *commit)
            }
            (other, _) => {
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
                message_id,
            });

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
        let epoch = self.mls_group.epoch().as_u64();
        let fingerprint = EpochFingerprint::from(&commit);

        self.mls_group
            .merge_staged_commit(&cx.mls_provider, commit)
            .map_err(ChatError::generic)?;

        info!(
            convo = %self.convo_id,
            epoch,
            new_epoch = self.mls_group.epoch().as_u64(),
            epochfingerprint = fingerprint.as_str(),
            "incoming commit merged"
        );
        Ok(ConvoOutcome {
            observations: vec![Observation::SignersChanged],
            ..self.default_outcome()
        })
    }
}
