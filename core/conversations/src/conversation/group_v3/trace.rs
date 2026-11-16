//! The trace records of a GroupV3 conversation ([`record`]). A frame's id
//! is its SDS message id.

use openmls::framing::ProtocolMessage;
use openmls::group::ProcessMessageError;

use super::GroupV3Convo;
use crate::Content;
use crate::conversation::ConvoBase;
use crate::conversation::mls_trace::record::{self, Why};
use crate::conversation::mls_trace::{Heard, unable_to_decrypt};

/// Records the epoch `convo` is in.
pub(super) fn epoch(convo: &GroupV3Convo) {
    if !record::enabled() {
        return;
    }
    match convo.signers() {
        Ok(signers) => record::epoch(
            convo.mls_group.epoch().as_u64(),
            convo.mls_group.epoch_authenticator().as_slice(),
            &signers,
        ),
        Err(error) => tracing::warn!(convo = %convo.convo_id, %error, "signers unreadable"),
    }
}

/// Records that `convo` sent message `message_id` in its current epoch.
pub(super) fn sent(convo: &GroupV3Convo, message_id: &str) {
    record::sent(message_id, convo.mls_group.epoch().as_u64());
}

/// The incoming message `message_id`, as the records need it. `None` when
/// tracing is off or the message is for another group.
pub(super) fn heard(
    convo: &GroupV3Convo,
    message_id: &str,
    message: &ProtocolMessage,
) -> Option<Heard> {
    if !record::enabled() {
        return None;
    }
    Heard::of_message(
        convo.mls_group.group_id().as_slice(),
        message_id.to_owned(),
        message,
        convo.mls_group.epoch().as_u64(),
    )
}

/// Records a message that was dropped because of its epoch.
pub(super) fn dropped(heard: Option<Heard>) {
    if let Some(heard) = heard {
        unreadable(&heard, Why::Epoch);
    }
}

/// Records a message OpenMLS refused with `error`, when it is from another
/// epoch or did not decrypt.
pub(super) fn refused<E>(heard: Option<Heard>, error: &ProcessMessageError<E>) {
    let Some(heard) = heard else {
        return;
    };
    if !heard.at_own_epoch() {
        unreadable(&heard, Why::Epoch);
    } else if unable_to_decrypt(error) {
        unreadable(&heard, Why::Decrypt);
    }
}

/// Records whether message `message_id`, sent at `epoch`, was read. There
/// is no `content` when its sender failed auth.
pub(super) fn read(message_id: &str, epoch: u64, content: Option<&Content>) {
    match content {
        Some(content) => record::received(message_id, content.sender.signer(), epoch),
        None => record::unreadable(message_id, epoch, Why::Sender),
    }
}

fn unreadable(heard: &Heard, why: Why) {
    record::unreadable(&heard.frame, heard.epoch, why);
}
