use openmls::framing::{ApplicationMessage, ProtocolMessage};
use openmls::prelude::{
    Member, ProcessMessageError, ProcessedMessage, ProcessedMessageContent, Sender, StagedCommit,
    ValidationError,
};
use prost::Message as _;
use tracing::{debug, info};

use crate::conversation::mls_utils::EpochFingerprint;
use crate::service_context::ServiceContext;
use crate::{ChatError, Content, ConvoOutcome, ExternalServices, Signer};

use super::payloads::{GroupV3FrameType, frame_id};
use super::{Frame, GroupV3Convo};

impl GroupV3Convo {
    /// Handle inbound mls encrypted messages. Accepts a successfully decoded ProtocolMessage
    pub(super) fn handle_mls_protocol_msg<S: ExternalServices>(
        &mut self,
        cx: &mut ServiceContext<S>,
        protocol_message: ProtocolMessage,
    ) -> Result<ConvoOutcome, ChatError> {
        // Includes our own commits, which return here after we merged them.
        if protocol_message.epoch() < self.mls_group.epoch() {
            debug!(convo = %self.convo_id, epoch = protocol_message.epoch().as_u64(), "dropping message from past epoch");
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

        self.handle_mls_msg(cx, processed)
    }

    /// Handle MLS ProcessedMessage. Send Commits and Application messages down to different parsers
    fn handle_mls_msg<S: ExternalServices>(
        &mut self,
        cx: &mut ServiceContext<S>,
        processed: ProcessedMessage,
    ) -> Result<ConvoOutcome, ChatError> {
        // Resolved before `into_content` consumes the message.
        let sender = match processed.sender() {
            Sender::Member(index) => self.mls_group.member_at(*index),
            _ => None,
        };

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(msg) => {
                self.handle_mls_application_message(cx, sender, msg)
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
    ) -> Result<ConvoOutcome, ChatError> {
        let bytes = app_msg.into_bytes();
        let message_id = frame_id(&bytes);

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
            content,
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

        // TODO: Validate Commit

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
            members_changed: true,
            ..self.default_outcome()
        })
    }
}
