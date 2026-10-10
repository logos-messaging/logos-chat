//! Trace records of an MLS group: their format ([`record`]), and what they
//! read off its messages.

pub(crate) mod record;

use openmls::group::{ProcessMessageError, ValidationError};
use openmls::prelude::tls_codec::DeserializeBytes as _;
use openmls::prelude::{GroupId, MlsMessageIn};

/// A frame of the group, as the trace records name it.
#[derive(Clone, Copy)]
pub(super) struct Heard<'a> {
    /// The frame's bytes, as they arrived.
    pub(super) frame: &'a [u8],
    /// The epoch its MLS header names.
    pub(super) epoch: u64,
    /// The epoch the signer was in when it arrived.
    own_epoch: u64,
}

impl<'a> Heard<'a> {
    /// `frame` as the records name it, when `message` is an MLS message of
    /// the group `group_id` names. `own_epoch` is the epoch the signer was in
    /// when it arrived.
    pub(super) fn of(
        group_id: &[u8],
        frame: &'a [u8],
        message: &[u8],
        own_epoch: u64,
    ) -> Option<Self> {
        let (header_group, epoch) = mls_header(message)?;
        (header_group.as_slice() == group_id).then_some(Self {
            frame,
            epoch,
            own_epoch,
        })
    }

    /// Whether the frame is of the epoch the signer was in when it
    /// arrived.
    pub(super) fn at_own_epoch(&self) -> bool {
        self.epoch == self.own_epoch
    }
}

/// The group id and epoch in the clear at the head of an MLS public or
/// private message. `None` for any other bytes.
fn mls_header(message: &[u8]) -> Option<(GroupId, u64)> {
    let (message, _) = MlsMessageIn::tls_deserialize_bytes(message).ok()?;
    let message = message.try_into_protocol_message().ok()?;
    Some((message.group_id().clone(), message.epoch().as_u64()))
}

/// Whether OpenMLS failed to decrypt a message, its refusal of one of our
/// own (`CannotDecryptOwnMessage`) aside.
pub(super) fn unable_to_decrypt<E>(error: &ProcessMessageError<E>) -> bool {
    matches!(
        error,
        ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(_))
    )
}
