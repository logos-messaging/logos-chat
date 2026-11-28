use openmls::framing::{ApplicationMessage, ProtocolMessage};
use openmls::prelude::{
    ContentType, Member, ProcessMessageError, ProcessedMessage, ProcessedMessageContent, Sender,
    StagedCommit, ValidationError,
};
use prost::Message as _;
use tracing::{debug, warn};

use crate::conversation::mls_utils::EpochFingerprint;
use crate::service_context::ServiceContext;
use crate::{ChatError, Content, ConvoOutcome, ExternalServices, MessageId, Observation, Signer};

use super::payloads::GroupV3FrameType;
use super::{DeferredCommit, Frame, GroupV3Convo, MAX_LATER_EPOCH_MSGS, trace};

impl GroupV3Convo {
    /// Handle a message SDS released.
    pub(super) fn handle_sds_message_ready<S: ExternalServices>(
        &mut self,
        cx: &mut ServiceContext<S>,
        message_id: MessageId,
        message: Option<ProtocolMessage>,
    ) -> Result<ConvoOutcome, ChatError> {
        let Some(message) = message else {
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
