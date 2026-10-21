use openmls::group::StagedCommit;
use openmls::prelude::Member;
use prost::Message as _;
use tracing::{debug, info, warn};

use super::consensus::CommitValidator;
use super::payloads::{GroupV3Payload, frame_id};
use super::{Frame, GroupV3Convo};
use crate::service_context::ServiceContext;
use crate::{ChatError, Content, ConvoOutcome, ExternalServices, Signer};

impl<V> GroupV3Convo<V>
where
    V: CommitValidator,
{
    pub(super) fn handle_content<S: ExternalServices>(
        &self,
        cx: &mut ServiceContext<S>,
        sender: Option<Member>,
        bytes: &[u8],
    ) -> Result<ConvoOutcome, ChatError> {
        let message_id = frame_id(bytes);

        let content = match Frame::decode(bytes)?.payload {
            Some(GroupV3Payload::Content(content)) => content,
            other => {
                debug!(convo = %self.convo_id, ?other, "ignoring non-content frame");
                return Ok(ConvoOutcome::empty(self.convo_id.to_string()));
            }
        };

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
            ..ConvoOutcome::empty(self.convo_id.to_string())
        })
    }

    pub(super) fn handle_mls_commit<S: ExternalServices>(
        &mut self,
        cx: &mut ServiceContext<S>,
        commit: StagedCommit,
    ) -> Result<ConvoOutcome, ChatError> {
        let epoch = self.mls_group.epoch().as_u64();
        if !self.commit_validator.can_merge_commit() {
            warn!(convo = %self.convo_id, epoch, "incoming commit rejected by validator");
            return Ok(ConvoOutcome::empty(self.convo_id.to_string()));
        }

        self.mls_group
            .merge_staged_commit(&cx.mls_provider, commit)
            .map_err(ChatError::generic)?;

        info!(
            convo = %self.convo_id,
            epoch,
            new_epoch = self.mls_group.epoch().as_u64(),
            "incoming commit merged"
        );
        Ok(ConvoOutcome {
            members_changed: true,
            ..ConvoOutcome::empty(self.convo_id.to_string())
        })
    }
}
