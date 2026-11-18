//! Trace records of an MLS group: their format ([`record`]), and what they
//! read off its messages.

pub(crate) mod record;

use openmls::framing::ProtocolMessage;
use openmls::group::{ProcessMessageError, ValidationError};
use openmls::prelude::MlsMessageIn;
use openmls::prelude::tls_codec::DeserializeBytes as _;

use crate::conversation::frame_id;

/// A frame of the group, as the trace records name it.
pub(super) struct Heard {
    /// The frame's id.
    pub(super) frame: String,
    /// The epoch its MLS header names.
    pub(super) epoch: u64,
    /// The epoch the signer was in when it arrived.
    own_epoch: u64,
}

impl Heard {
    /// `frame` as the records name it, when `message` is an MLS message of
    /// the group `group_id` names. `own_epoch` is the epoch the signer was in
    /// when it arrived.
    pub(super) fn of(
        group_id: &[u8],
        frame: &[u8],
        message: &[u8],
        own_epoch: u64,
    ) -> Option<Self> {
        let (message, _) = MlsMessageIn::tls_deserialize_bytes(message).ok()?;
        let message = message.try_into_protocol_message().ok()?;
        Self::of_message(group_id, frame_id(frame), &message, own_epoch)
    }

    /// Like [`Self::of`], for a decoded `message` with the id `frame_id`.
    pub(super) fn of_message(
        group_id: &[u8],
        frame_id: String,
        message: &ProtocolMessage,
        own_epoch: u64,
    ) -> Option<Self> {
        (message.group_id().as_slice() == group_id).then_some(Self {
            frame: frame_id,
            epoch: message.epoch().as_u64(),
            own_epoch,
        })
    }

    /// Whether the frame is of the epoch the signer was in when it
    /// arrived.
    pub(super) fn at_own_epoch(&self) -> bool {
        self.epoch == self.own_epoch
    }
}

/// Whether OpenMLS failed to decrypt a message, its refusal of one of our
/// own (`CannotDecryptOwnMessage`) aside.
pub(super) fn unable_to_decrypt<E>(error: &ProcessMessageError<E>) -> bool {
    matches!(
        error,
        ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(_))
    )
}
