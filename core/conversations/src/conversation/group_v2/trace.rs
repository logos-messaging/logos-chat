//! The trace a GroupV2 conversation writes ([`MlsTrace`]), read off what
//! de-mls hands over.

use de_mls::defaults::{DefaultConsensusPlugin, InMemoryPeerScoreStorage};
use de_mls::{Conversation, ConversationEvent};

use super::{GroupV2Clock, roster};
use crate::conversation::mls_trace::MlsTrace;
use crate::identity::SignerKey;

type DeMlsConversation =
    Conversation<DefaultConsensusPlugin, InMemoryPeerScoreStorage, GroupV2Clock>;

/// What an installation records of one conversation, from what each op
/// hands over.
pub(super) struct ConvoTrace {
    trace: MlsTrace,
}

impl ConvoTrace {
    pub(super) fn new(installation: &SignerKey, convo_id: &str) -> Self {
        Self {
            trace: MlsTrace::new(installation, convo_id),
        }
    }

    /// Writes the trace record the op called for: the first `epoch`, an
    /// `epoch` when the epoch moved, `left` when a commit removed us.
    pub(super) fn after_op(
        &mut self,
        conversation: &DeMlsConversation,
        events: &[ConversationEvent],
    ) {
        // `Leaving`, not `is_member`: a commit that removes us and adds
        // another can seat the newcomer in our leaf.
        let leaving = events
            .iter()
            .any(|evt| matches!(evt, ConversationEvent::Leaving));
        let Some(epoch) = epoch(conversation) else {
            return;
        };
        if leaving {
            self.trace.left(epoch);
        } else {
            self.trace.epoch(epoch, || {
                (
                    conversation.epoch_authenticator(),
                    roster(&conversation.members_view()),
                )
            });
        }
    }
}

/// The group's epoch number, or `None`, logged, when it cannot be read.
fn epoch(conversation: &DeMlsConversation) -> Option<u64> {
    match conversation.epoch_and_retry() {
        Ok((epoch, _)) => Some(epoch),
        Err(error) => {
            tracing::warn!(convo = %conversation.id(), %error, "epoch unreadable");
            None
        }
    }
}
