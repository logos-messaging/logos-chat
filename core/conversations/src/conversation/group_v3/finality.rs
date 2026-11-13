//! Tells GroupV3 which deferred commit to finalize, and when.
//!
//! Members that defer the same commits before the timeout finalize the same commit.

use std::time::Duration;

use crate::conversation::mls_utils::EpochFingerprint;

/// Finalizes the commit with the lowest fingerprint, `timeout` after the first commit was deferred.
/// Members receive commits in different orders, but the same commits have the same lowest
/// fingerprint for every member.
pub(super) struct Timeout {
    timeout: Duration,
    /// When the next commit is due, and its fingerprint.
    next: Option<(Duration, EpochFingerprint)>,
}

impl Timeout {
    pub(super) fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            next: None,
        }
    }

    /// Call for every commit deferred for the current epoch.
    pub(super) fn defer(&mut self, fingerprint: EpochFingerprint, now: Duration) {
        self.next = Some(match self.next.take() {
            None => (now + self.timeout, fingerprint),
            Some((due, lowest)) => (due, lowest.min(fingerprint)),
        });
    }

    /// The commit to finalize, returned once, when it is due.
    pub(super) fn finalized(&mut self, now: Duration) -> Option<EpochFingerprint> {
        self.next
            .take_if(|(due, _)| *due <= now)
            .map(|(_, fingerprint)| fingerprint)
    }
}
