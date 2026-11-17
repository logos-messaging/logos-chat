//! Tells GroupV3 which deferred commit to finalize, and when.
//!
//! Members that defer the same commits before the timeout finalize the same commit.
//! A member that is behind does not wait for the timeout.

use std::time::Duration;

use crate::conversation::mls_utils::EpochFingerprint;

/// Finalizes the commit with the lowest fingerprint, `timeout` after the first commit was deferred,
/// or at once if a message was seen from a later epoch.
/// Members receive commits in different orders, but the same commits have the same lowest
/// fingerprint for every member.
pub(super) struct Timeout {
    timeout: Duration,
    /// When the next commit is due, and its fingerprint.
    next: Option<(Duration, EpochFingerprint)>,
    /// Latest epoch seen in a message.
    // TODO: Use the fingerprint from the fork detection header instead of the epoch.
    latest_epoch: u64,
}

impl Timeout {
    pub(super) fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            next: None,
            latest_epoch: 0,
        }
    }

    /// Call for every commit deferred for the current epoch.
    pub(super) fn defer(&mut self, fingerprint: EpochFingerprint, now: Duration) {
        self.next = Some(match self.next.take() {
            None => (now + self.timeout, fingerprint),
            Some((due, lowest)) => (due, lowest.min(fingerprint)),
        });
    }

    /// Call for every message from a later epoch.
    pub(super) fn later_epoch_seen(&mut self, epoch: u64) {
        self.latest_epoch = self.latest_epoch.max(epoch);
    }

    /// The commit to finalize, returned once, when it is due.
    /// Due at once if an epoch later than `epoch` was seen.
    pub(super) fn finalized(&mut self, now: Duration, epoch: u64) -> Option<EpochFingerprint> {
        self.next
            .take_if(|(due, _)| epoch < self.latest_epoch || *due <= now)
            .map(|(_, fingerprint)| fingerprint)
    }
}
