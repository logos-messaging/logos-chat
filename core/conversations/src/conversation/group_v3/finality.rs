//! Tells GroupV3 which deferred commit to finalize, and when.
//!
//! Members that defer the same commits before the timeout finalize the same commit.
//! A member that is behind does not wait for the timeout.

use std::collections::BTreeSet;
use std::time::Duration;

use super::debug_data::DebugState;
use crate::conversation::mls_utils::EpochFingerprint;

/// Finalizes the commit with the lowest fingerprint, `timeout` after the first commit was deferred,
/// or at once the commit a peer reported as its state at the next epoch.
/// Members receive commits in different orders, but the same commits have the same lowest
/// fingerprint for every member.
pub(super) struct Timeout {
    timeout: Duration,
    /// When the lowest deferred commit is due.
    due: Option<Duration>,
    /// Commits deferred for the current epoch.
    deferred: BTreeSet<EpochFingerprint>,
}

impl Timeout {
    pub(super) fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            due: None,
            deferred: BTreeSet::new(),
        }
    }

    /// Call for every commit deferred for the current epoch.
    pub(super) fn defer(&mut self, fingerprint: EpochFingerprint, now: Duration) {
        self.due.get_or_insert(now + self.timeout);
        self.deferred.insert(fingerprint);
    }

    /// The commit to finalize, returned once, when it is due.
    /// Due at once if a peer reported it as its state after `epoch`.
    pub(super) fn finalized(
        &mut self,
        now: Duration,
        epoch: u64,
        peers: &DebugState,
    ) -> Option<EpochFingerprint> {
        let reported = self
            .deferred
            .iter()
            .find(|commit| peers.reported(epoch + 1, commit));
        let timed_out = || {
            self.due
                .filter(|due| *due <= now)
                .and_then(|_| self.deferred.first())
        };
        let fingerprint = reported.or_else(timed_out)?.clone();

        self.due = None;
        self.deferred.clear();
        Some(fingerprint)
    }
}
