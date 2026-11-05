//! The trace records a GroupV2 conversation writes ([`record`]), read off
//! the conversation and what de-mls hands over.

use de_mls::mls_crypto::MlsError;
use de_mls::protos::de_mls::messages::v1::{AppMessage as AppMessageProto, app_message};
use de_mls::{ConversationError, ConversationEvent, DispatchOutcome};
use openmls::group::ProcessMessageError;

use super::GroupV2Convo;
use crate::Observation;
use crate::conversation::ConvoBase;
use crate::conversation::mls_trace::record::{self, Why};
use crate::conversation::mls_trace::{Heard, unable_to_decrypt};
use crate::identity::SignerKey;
use crate::inbox_v2::MlsEphemeralPqProvider;

/// The epoch of `convo` that `signer` is in, read ahead of an op for the
/// records it writes: `None` when they are not written or `signer` is no
/// longer seated in it.
pub(super) fn own_epoch(convo: &GroupV2Convo, signer: &SignerKey) -> Option<u64> {
    if !record::enabled() || !is_seated(convo, signer) {
        return None;
    }
    epoch(convo)
}

/// Writes the record an op called for: `left` when a commit removed us, or
/// `epoch` when the epoch moved from `before`, which is `None` for a
/// conversation just created or joined.
pub(super) fn after_op(
    convo: &GroupV2Convo,
    signer: &SignerKey,
    before: Option<u64>,
    events: &[ConversationEvent],
) {
    if !record::enabled() {
        return;
    }
    // `Leaving`, not `is_member`: a commit that removes us and adds
    // another can seat the newcomer in our leaf.
    let leaving = events
        .iter()
        .any(|evt| matches!(evt, ConversationEvent::Leaving));
    let Some(epoch) = epoch(convo) else {
        return;
    };
    if leaving {
        record::left(epoch);
    } else if before != Some(epoch) && is_seated(convo, signer) {
        match convo.signers() {
            Ok(signers) => {
                record::epoch(epoch, &convo.conversation.epoch_authenticator(), &signers)
            }
            Err(error) => tracing::warn!(convo = %convo.convo_id, %error, "signers unreadable"),
        }
    }
}

/// Writes `sent` for `post`, the frame of the post an op queued, sent at
/// `own_epoch`.
pub(super) fn sent(own_epoch: Option<u64>, post: Option<&[u8]>) {
    if let (Some(epoch), Some(frame)) = (own_epoch, post) {
        record::sent(frame, epoch);
    }
}

/// `frame`, an encoded [`GroupV2Frame`](super::GroupV2Frame), as the records
/// name it, when `inner` is an MLS message of this group; `own_epoch` is the
/// epoch the signer was in when it arrived. Writes `unreadable` when de-mls
/// ignored it as of another epoch or could not decrypt it.
pub(super) fn inbound<'a>(
    convo: &GroupV2Convo,
    own_epoch: Option<u64>,
    frame: &'a [u8],
    inner: &[u8],
    processed: &Result<DispatchOutcome, ConversationError>,
) -> Option<Heard<'a>> {
    // Nothing is recorded of our own frame coming back.
    if matches!(processed, Ok(DispatchOutcome::Dropped)) {
        return None;
    }
    // A de-mls group's id is its conversation id's bytes.
    let heard = Heard::of(convo.convo_id.as_bytes(), frame, inner, own_epoch?)?;
    match processed {
        // de-mls drops a frame of another epoch without a word, so the epoch
        // its MLS header names is what tells.
        Ok(_) if !heard.at_own_epoch() => unreadable(heard, Why::Epoch),
        Err(error) if failed_to_decrypt(error) => unreadable(heard, Why::Decrypt),
        _ => {}
    }
    Some(heard)
}

/// Writes what became of the post `heard` carried, once `events` say it
/// carried one: `received`, or `unreadable` when its sender failed auth
/// and `observations` hold no content.
pub(super) fn read(
    heard: Option<Heard<'_>>,
    events: &[ConversationEvent],
    observations: &[Observation],
) {
    let Some(heard) = heard else {
        return;
    };
    if !events.iter().any(is_post) {
        return;
    }
    let content = observations
        .iter()
        .find_map(|observation| match observation {
            Observation::Content(content) => Some(content),
            _ => None,
        });
    match content {
        Some(content) => record::received(heard.frame, content.sender.signer(), heard.epoch),
        None => unreadable(heard, Why::Sender),
    }
}

/// Whether `event` hands over a post: the app message `outcome_from_events`
/// turns into content.
fn is_post(event: &ConversationEvent) -> bool {
    matches!(
        event,
        ConversationEvent::ConversationMessage {
            message: AppMessageProto {
                payload: Some(app_message::Payload::ConversationMessage(_)),
            },
            ..
        }
    )
}

/// Writes `unreadable` for the frame `heard` names.
fn unreadable(heard: Heard<'_>, why: Why) {
    record::unreadable(heard.frame, heard.epoch, why);
}

/// Whether `signer` is still seated in `convo`. A commit that removes it
/// leaves its leaf empty or seats another there, and its group goes on to
/// read later epoch numbers over the old epoch's secrets: an `epoch` record
/// would name a state nobody else holds.
fn is_seated(convo: &GroupV2Convo, signer: &SignerKey) -> bool {
    convo.own_signer().as_ref() == Some(signer)
}

/// The group's epoch number, or `None`, logged, when it cannot be read.
pub(super) fn epoch(convo: &GroupV2Convo) -> Option<u64> {
    match convo.conversation.epoch_and_retry() {
        Ok((epoch, _)) => Some(epoch),
        Err(error) => {
            tracing::warn!(convo = %convo.convo_id, %error, "epoch unreadable");
            None
        }
    }
}

/// What OpenMLS fails to process a message with, over our provider's storage.
type ProcessError = ProcessMessageError<
    <MlsEphemeralPqProvider as openmls::storage::OpenMlsProvider>::StorageError,
>;

/// Whether de-mls failed to decrypt a frame of our own epoch number. It
/// hands on the OpenMLS error boxed.
fn failed_to_decrypt(error: &ConversationError) -> bool {
    let ConversationError::Mls(MlsError::ProcessMessage(error)) = error else {
        return false;
    };
    error
        .downcast_ref::<ProcessError>()
        .is_some_and(unable_to_decrypt)
}
