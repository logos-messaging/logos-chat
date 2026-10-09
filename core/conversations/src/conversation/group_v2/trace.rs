//! The trace records a GroupV2 conversation writes ([`record`]), read off
//! the conversation and what de-mls hands over.

use de_mls::ConversationEvent;

use super::GroupV2Convo;
use crate::conversation::ConvoBase;
use crate::conversation::mls_trace::record;
use crate::identity::SignerKey;

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
