//! Trace records: their format ([`record`]) and when those of an MLS group
//! are due ([`MlsTrace`]).

pub(crate) mod record;

use openmls::group::{ProcessMessageError, ValidationError};
use openmls::prelude::tls_codec::DeserializeBytes as _;
use openmls::prelude::{GroupId, MlsMessageIn};

use crate::Content;
use crate::identity::{Signer, SignerKey};
use record::Why;

/// What an installation records of one MLS group.
#[derive(Debug)]
pub(super) struct MlsTrace {
    installation: SignerKey,
    convo_id: String,
    /// The group id its MLS messages carry.
    group_id: Vec<u8>,
    held: Held,
}

/// The epoch the records say the installation holds.
#[derive(Debug, PartialEq)]
enum Held {
    Unrecorded,
    /// The epoch the last `epoch` record named.
    Epoch(u64),
    /// `left` was recorded.
    Left,
}

/// A frame of the group, as the trace records name it.
#[derive(Clone, Copy)]
pub(super) struct Heard<'a> {
    /// The frame's bytes, as they arrived.
    frame: &'a [u8],
    /// The epoch its MLS header names.
    epoch: u64,
    /// The epoch the installation held when it arrived.
    held: u64,
}

impl MlsTrace {
    pub(super) fn new(installation: &SignerKey, convo_id: &str, group_id: &[u8]) -> Self {
        Self {
            installation: installation.clone(),
            convo_id: convo_id.to_owned(),
            group_id: group_id.to_vec(),
            held: Held::Unrecorded,
        }
    }

    /// Writes `epoch` when the group holds another epoch than the one last
    /// written. `state` gives its authenticator and roster, and is called
    /// only for a record that goes out.
    pub(super) fn epoch(&mut self, epoch: u64, state: impl FnOnce() -> (Vec<u8>, Vec<Signer>)) {
        if self.held == Held::Left || self.held == Held::Epoch(epoch) {
            return;
        }
        if record::enabled() {
            let (authenticator, roster) = state();
            record::epoch(
                &self.installation,
                &self.convo_id,
                epoch,
                &authenticator,
                &roster,
            );
        }
        self.held = Held::Epoch(epoch);
    }

    /// Writes `left`, after which no epoch is recorded: a removed member's
    /// group reads the new epoch number over the old epoch's secrets, so an
    /// `epoch` record would name a state nobody else holds.
    pub(super) fn left(&mut self, epoch: u64) {
        if self.held != Held::Left {
            self.held = Held::Left;
            record::left(&self.installation, &self.convo_id, epoch);
        }
    }

    /// Writes `sent` for a post of ours, published as `frame`.
    pub(super) fn sent(&self, frame: &[u8]) {
        if let Held::Epoch(epoch) = self.held {
            record::sent(&self.installation, &self.convo_id, frame, epoch);
        }
    }

    /// `frame` as the records name it, when `message` is an MLS message of
    /// this group.
    pub(super) fn heard<'a>(&self, frame: &'a [u8], message: &[u8]) -> Option<Heard<'a>> {
        let Held::Epoch(held) = self.held else {
            return None;
        };
        if !record::enabled() {
            return None;
        }
        let (group_id, epoch) = mls_header(message)?;
        if group_id.as_slice() != self.group_id {
            return None;
        }
        Some(Heard { frame, epoch, held })
    }

    /// Writes `unreadable` for the frame `heard` names.
    pub(super) fn unreadable(&self, heard: Heard<'_>, why: Why) {
        record::unreadable(
            &self.installation,
            &self.convo_id,
            heard.frame,
            heard.epoch,
            why,
        );
    }

    /// Writes what became of the post `heard` carried: `received`, or
    /// `unreadable` when its sender's account did not check and there is no
    /// `content`.
    pub(super) fn read(&self, heard: Option<Heard<'_>>, content: Option<&Content>) {
        let Some(heard) = heard else {
            return;
        };
        match content {
            Some(content) => record::received(
                &self.installation,
                &self.convo_id,
                heard.frame,
                content.sender.signer(),
                heard.epoch,
            ),
            None => self.unreadable(heard, Why::Sender),
        }
    }
}

impl Heard<'_> {
    /// Whether the frame is of the epoch the installation held when it
    /// arrived.
    pub(super) fn at_held_epoch(&self) -> bool {
        self.epoch == self.held
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
