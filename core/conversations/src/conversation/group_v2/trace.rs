//! The trace a GroupV2 conversation writes ([`MlsTrace`]), read off what
//! de-mls hands over.

use de_mls::defaults::{DefaultConsensusPlugin, InMemoryPeerScoreStorage};
use de_mls::mls_crypto::MlsError;
use de_mls::{Conversation, ConversationError, ConversationEvent, DispatchOutcome};
use openmls::group::ProcessMessageError;
use prost::bytes::Bytes;

use super::{GroupV2Clock, roster};
use crate::Content;
use crate::conversation::mls_trace::record::Why;
use crate::conversation::mls_trace::{Heard, MlsTrace, unable_to_decrypt};
use crate::identity::SignerKey;
use crate::inbox_v2::MlsEphemeralPqProvider;

type DeMlsConversation =
    Conversation<DefaultConsensusPlugin, InMemoryPeerScoreStorage, GroupV2Clock>;

/// What an installation records of one conversation, from what each op
/// hands over.
pub(super) struct ConvoTrace {
    trace: MlsTrace,
    /// The last frame the op in hand has published.
    last_out: Option<Bytes>,
}

impl ConvoTrace {
    pub(super) fn new(installation: &SignerKey, convo_id: &str) -> Self {
        Self {
            // A de-mls group's id is its conversation id's bytes.
            trace: MlsTrace::new(installation, convo_id, convo_id.as_bytes()),
            last_out: None,
        }
    }

    /// Writes the trace record the op called for: the first `epoch`, an
    /// `epoch` when the epoch moved, `left` when a commit removed us.
    pub(super) fn after_op(
        &mut self,
        conversation: &DeMlsConversation,
        events: &[ConversationEvent],
    ) {
        self.last_out = None;
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

    pub(super) fn published(&mut self, frame: Bytes) {
        self.last_out = Some(frame);
    }

    /// Writes `sent` for the post the op queued: de-mls queues a post last, so
    /// it is the last frame out.
    pub(super) fn sent(&mut self) {
        if let Some(frame) = self.last_out.take() {
            self.trace.sent(&frame);
        }
    }

    /// `frame`, an encoded [`GroupV2Frame`](super::GroupV2Frame), as the
    /// records name it, when `inner` is an MLS message of this group. Writes
    /// `unreadable` when de-mls ignored it as of another epoch or could not
    /// decrypt it.
    pub(super) fn inbound<'a>(
        &self,
        frame: &'a [u8],
        inner: &[u8],
        processed: &Result<DispatchOutcome, ConversationError>,
    ) -> Option<Heard<'a>> {
        // Nothing is recorded of our own frame coming back.
        if matches!(processed, Ok(DispatchOutcome::Dropped)) {
            return None;
        }
        let heard = self.trace.heard(frame, inner)?;
        match processed {
            // de-mls reads the MLS header as `heard` does and drops a frame
            // of another epoch without a word.
            Ok(_) if !heard.at_held_epoch() => self.trace.unreadable(heard, Why::Epoch),
            Err(error) if failed_to_decrypt(error) => self.trace.unreadable(heard, Why::Decrypt),
            _ => {}
        }
        Some(heard)
    }

    /// Writes what became of the post `heard` carried.
    pub(super) fn read(&self, heard: Option<Heard<'_>>, content: Option<&Content>) {
        self.trace.read(heard, content);
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

/// What OpenMLS fails to process a message with, over our provider's storage.
type ProcessError = ProcessMessageError<
    <MlsEphemeralPqProvider as openmls::storage::OpenMlsProvider>::StorageError,
>;

/// Whether de-mls failed to decrypt a frame of the epoch number we hold. It
/// hands on the OpenMLS error boxed.
fn failed_to_decrypt(error: &ConversationError) -> bool {
    let ConversationError::Mls(MlsError::ProcessMessage(error)) = error else {
        return false;
    };
    error
        .downcast_ref::<ProcessError>()
        .is_some_and(unable_to_decrypt)
}
