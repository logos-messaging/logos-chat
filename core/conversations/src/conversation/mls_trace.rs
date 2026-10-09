//! Trace records: their format ([`record`]) and when those of an MLS group
//! are due ([`MlsTrace`]).

pub(crate) mod record;

use crate::identity::{Signer, SignerKey};

/// What an installation records of one MLS group.
#[derive(Debug)]
pub(super) struct MlsTrace {
    installation: SignerKey,
    convo_id: String,
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

impl MlsTrace {
    pub(super) fn new(installation: &SignerKey, convo_id: &str) -> Self {
        Self {
            installation: installation.clone(),
            convo_id: convo_id.to_owned(),
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
}
