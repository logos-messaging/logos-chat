//! Forked, or just behind? Compares a peer's epoch id against the ones we held.

use std::collections::VecDeque;

use super::beacons::Beacons;
use super::external::Branch;

/// Epochs of our own fingerprints kept; bounds how far back a peer can be compared.
const FINGERPRINTS_RETAINED: usize = 64;

/// Rival branches tracked at once; the oldest seen is dropped first.
const RIVALS_RETAINED: usize = 8;

/// The state we held at each recent epoch.
#[derive(Debug, Default)]
pub(crate) struct FingerprintLog {
    entries: VecDeque<(u64, String)>,
}

impl FingerprintLog {
    /// Epochs only move forward within one conversation, so this appends.
    pub(crate) fn record(&mut self, epoch: u64, epoch_id: String) {
        if self.entries.len() == FINGERPRINTS_RETAINED {
            self.entries.pop_front();
        }
        self.entries.push_back((epoch, epoch_id));
    }

    pub(crate) fn at(&self, epoch: u64) -> Option<&str> {
        self.entries
            .iter()
            .find(|(e, _)| *e == epoch)
            .map(|(_, id)| id.as_str())
    }
}

/// Where this member stands relative to the group, as far as the evidence goes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum SyncState {
    #[default]
    Unknown,
    /// A peer holds the same state at our epoch.
    Synced,
    /// A peer is ahead. We may be behind on its branch or on another one.
    Lagging { peer_epoch: u64 },
    /// A commit for our epoch would not apply. Only a hint: its framing is
    /// cleartext, so anyone can forge one.
    Suspect { epoch: u64 },
    /// Verified beacons name other states at epochs we held, and their signers
    /// have not come back to our branch. `we_move` when any of them outranks
    /// ours.
    Forked { at_or_before: u64, we_move: bool },
}

/// Our own history, the branches that left it, and what that makes us.
#[derive(Debug, Default)]
pub(crate) struct SyncTracker {
    pub(crate) log: FingerprintLog,
    rivals: VecDeque<Branch>,
    state: SyncState,
}

impl SyncTracker {
    pub(crate) fn state(&self) -> &SyncState {
        &self.state
    }

    pub(crate) fn enter_epoch(&mut self, epoch: u64, epoch_id: String) {
        self.log.record(epoch, epoch_id);
        // What a peer said about the last epoch says nothing about this one.
        if !matches!(self.state, SyncState::Forked { .. }) {
            self.state = SyncState::Unknown;
        }
    }

    /// A commit for our epoch would not apply.
    pub(crate) fn suspect(&mut self, epoch: u64) {
        if !matches!(self.state, SyncState::Forked { .. }) {
            self.state = SyncState::Suspect { epoch };
        }
    }

    /// Take in one verified peer beacon. True when we became `Forked` or our
    /// side of the fork changed.
    pub(crate) fn observe(&mut self, beacons: &Beacons, own_epoch: u64, peer: Branch) -> bool {
        // An epoch past ours is not in the log: a peer ahead can't prove a fork.
        let differs = self
            .log
            .at(peer.epoch)
            .is_some_and(|ours| ours != peer.epoch_id);
        if differs && !self.rivals.contains(&peer) {
            if self.rivals.len() == RIVALS_RETAINED {
                self.rivals.pop_front();
            }
            self.rivals.push_back(peer.clone());
        }
        let log = &self.log;
        self.rivals.retain(|rival| !beacons.rejoined(rival, log));

        let outranks = |rival: &Branch| {
            log.at(rival.epoch).is_some_and(|ours| {
                let ours = Branch {
                    epoch: rival.epoch,
                    epoch_id: ours.to_string(),
                };
                beacons.outranks(&ours, rival)
            })
        };
        let next = match self.rivals.iter().map(|r| r.epoch).min() {
            Some(at_or_before) => SyncState::Forked {
                at_or_before,
                we_move: self.rivals.iter().any(outranks),
            },
            None => match classify(log, own_epoch, &peer) {
                SyncState::Unknown if !matches!(self.state, SyncState::Forked { .. }) => {
                    self.state.clone()
                }
                seen => seen,
            },
        };
        let report = match (&self.state, &next) {
            (SyncState::Forked { we_move: was, .. }, SyncState::Forked { we_move, .. }) => {
                was != we_move
            }
            (_, SyncState::Forked { .. }) => true,
            _ => false,
        };
        self.state = next;
        report
    }
}

/// What a beacon that names no unresolved rival says about us.
fn classify(log: &FingerprintLog, own_epoch: u64, peer: &Branch) -> SyncState {
    // We never held the epochs past ours, so a peer ahead can't prove a fork.
    if peer.epoch > own_epoch {
        return SyncState::Lagging {
            peer_epoch: peer.epoch,
        };
    }
    match log.at(peer.epoch) {
        Some(ours) if ours == peer.epoch_id && peer.epoch == own_epoch => SyncState::Synced,
        // Agreeing in the past: they are behind, or we parted after that epoch.
        _ => SyncState::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conversation::group_v3::external::tests::id;

    fn peer(epoch: u64, n: u64) -> Branch {
        Branch {
            epoch,
            epoch_id: id(n),
        }
    }

    /// Held our own state, `id(epoch)`, at every epoch through `last`.
    fn tracker_through(last: u64) -> SyncTracker {
        let mut tracker = SyncTracker::default();
        for epoch in 0..=last {
            tracker.enter_epoch(epoch, id(epoch));
        }
        tracker
    }

    fn observe(tracker: &mut SyncTracker, beacons: &Beacons, own_epoch: u64, p: Branch) -> bool {
        tracker.observe(beacons, own_epoch, p)
    }

    fn see(beacons: &Beacons, own_epoch: u64, p: Branch) -> SyncState {
        let mut tracker = tracker_through(own_epoch);
        observe(&mut tracker, beacons, own_epoch, p);
        tracker.state().clone()
    }

    fn forked(at_or_before: u64, we_move: bool) -> SyncState {
        SyncState::Forked {
            at_or_before,
            we_move,
        }
    }

    /// Each branch at `epoch` signed by its own `signers`.
    fn vouched(epoch: u64, branches: &[(u64, &[u8])]) -> Beacons {
        let mut beacons = Beacons::default();
        for (n, signers) in branches {
            for s in *signers {
                beacons.vouch(peer(epoch, *n), &[*s]);
            }
        }
        beacons
    }

    #[test]
    fn the_log_keeps_only_the_newest_epochs() {
        let last = FINGERPRINTS_RETAINED as u64 + 9;
        let log = tracker_through(last).log;

        assert_eq!(log.at(9), None);
        assert_eq!(log.at(10), Some(id(10).as_str()));
        assert_eq!(log.at(last), Some(id(last).as_str()));
    }

    #[test]
    fn same_epoch_same_id_is_synced() {
        assert_eq!(
            see(&Beacons::default(), 41, peer(41, 41)),
            SyncState::Synced
        );
    }

    #[test]
    fn same_epoch_different_id_is_forked() {
        let beacons = vouched(41, &[(99, &[1])]);
        assert_eq!(see(&beacons, 41, peer(41, 99)), forked(41, true));
    }

    #[test]
    fn a_peer_ahead_is_lagging_never_forked() {
        for peer_epoch in [41, 47, 5_000] {
            assert_eq!(
                see(&Beacons::default(), 40, peer(peer_epoch, 99)),
                SyncState::Lagging { peer_epoch }
            );
        }
    }

    #[test]
    fn a_peer_behind_that_differs_is_forked() {
        let beacons = vouched(38, &[(99, &[1])]);
        assert_eq!(see(&beacons, 41, peer(38, 99)), forked(38, true));
    }

    #[test]
    fn a_peer_behind_that_agrees_is_unknown() {
        assert_eq!(
            see(&Beacons::default(), 41, peer(38, 38)),
            SyncState::Unknown
        );
    }

    #[test]
    fn a_peer_behind_our_window_is_unknown() {
        let last = FINGERPRINTS_RETAINED as u64 + 9;
        let beacons = vouched(2, &[(99, &[1])]);
        assert_eq!(see(&beacons, last, peer(2, 99)), SyncState::Unknown);
    }

    #[test]
    fn only_the_outranked_side_moves() {
        let beacons = vouched(41, &[(99, &[1, 2]), (41, &[3])]);
        assert_eq!(see(&beacons, 41, peer(41, 99)), forked(41, true));

        let beacons = vouched(41, &[(99, &[1, 2]), (41, &[3, 4, 5])]);
        assert_eq!(see(&beacons, 41, peer(41, 99)), forked(41, false));
    }

    /// Signers choose the id, so a smaller one must not make us move: we would
    /// have no branch to ask.
    #[test]
    fn on_a_tie_neither_side_moves() {
        let beacons = vouched(41, &[(1, &[1]), (41, &[2])]);
        assert_eq!(see(&beacons, 41, peer(41, 1)), forked(41, false));
    }

    /// A outranks us, C does not. Whatever order they arrive in, and with our
    /// own branch's beacons in between, we move.
    #[test]
    fn a_weaker_third_branch_does_not_hide_a_stronger_one() {
        let (a, b, c) = (peer(41, 1), peer(41, 41), peer(41, 2));
        let beacons = vouched(41, &[(1, &[1, 2, 3]), (41, &[4, 5]), (2, &[6])]);
        let orders = [
            [&a, &b, &c],
            [&a, &c, &b],
            [&b, &a, &c],
            [&b, &c, &a],
            [&c, &a, &b],
            [&c, &b, &a],
        ];
        for order in orders {
            let mut tracker = tracker_through(41);
            for p in order {
                observe(&mut tracker, &beacons, 41, p.clone());
            }
            assert_eq!(tracker.state(), &forked(41, true), "{order:?}");
        }
    }

    #[test]
    fn the_fork_is_dated_by_the_oldest_rival() {
        let mut beacons = vouched(38, &[(99, &[1])]);
        beacons.vouch(peer(40, 98), &[2]);
        let mut tracker = tracker_through(41);
        observe(&mut tracker, &beacons, 41, peer(40, 98));
        observe(&mut tracker, &beacons, 41, peer(38, 99));
        observe(&mut tracker, &beacons, 41, peer(40, 98));

        assert_eq!(tracker.state(), &forked(38, true));
    }

    #[test]
    fn only_the_newest_rivals_are_kept() {
        let mut beacons = Beacons::default();
        let mut tracker = tracker_through(41);
        let first = 41 - RIVALS_RETAINED as u64;
        for epoch in first..=41 {
            beacons.vouch(peer(epoch, 99), &[1]);
            observe(&mut tracker, &beacons, 41, peer(epoch, 99));
        }

        assert_eq!(tracker.state(), &forked(first + 1, true));
    }

    /// The side that stays keeps `Forked` through its branch-mates' beacons,
    /// and reports it once.
    #[test]
    fn a_branch_mate_does_not_clear_a_fork() {
        let beacons = vouched(41, &[(99, &[1]), (41, &[2, 3])]);
        let mut tracker = tracker_through(41);

        assert!(observe(&mut tracker, &beacons, 41, peer(41, 99)));
        for p in [peer(41, 41), peer(41, 99), peer(41, 41)] {
            assert!(!observe(&mut tracker, &beacons, 41, p));
            assert_eq!(tracker.state(), &forked(41, false));
        }
    }

    #[test]
    fn a_fork_clears_once_the_rivals_signers_are_back_on_our_branch() {
        let mut beacons = vouched(41, &[(99, &[1]), (41, &[2, 3])]);
        let mut tracker = tracker_through(42);
        observe(&mut tracker, &beacons, 42, peer(41, 99));

        beacons.vouch(peer(42, 42), &[1]);
        observe(&mut tracker, &beacons, 42, peer(42, 42));

        assert_eq!(tracker.state(), &SyncState::Synced);
    }

    #[test]
    fn a_fork_cleared_by_an_older_beacon_is_unknown() {
        let mut beacons = vouched(41, &[(99, &[1]), (41, &[2, 3])]);
        let mut tracker = tracker_through(43);
        observe(&mut tracker, &beacons, 43, peer(41, 99));

        beacons.vouch(peer(42, 42), &[1]);
        observe(&mut tracker, &beacons, 43, peer(42, 42));

        assert_eq!(tracker.state(), &SyncState::Unknown);
    }

    #[test]
    fn a_rival_still_signed_elsewhere_keeps_the_fork() {
        let mut beacons = vouched(41, &[(99, &[1, 4]), (41, &[2, 3])]);
        let mut tracker = tracker_through(42);
        observe(&mut tracker, &beacons, 42, peer(41, 99));

        beacons.vouch(peer(42, 42), &[1]);
        beacons.vouch(peer(42, 97), &[4]);
        observe(&mut tracker, &beacons, 42, peer(42, 42));

        assert!(matches!(tracker.state(), SyncState::Forked { .. }));
    }

    #[test]
    fn a_peer_ahead_never_clears_a_fork() {
        let beacons = vouched(41, &[(99, &[1])]);
        let mut tracker = tracker_through(41);
        observe(&mut tracker, &beacons, 41, peer(41, 99));
        observe(&mut tracker, &beacons, 41, peer(50, 50));

        assert_eq!(tracker.state(), &forked(41, true));
    }

    #[test]
    fn a_new_signer_reranks_and_is_reported() {
        let mut beacons = vouched(41, &[(99, &[1, 4]), (41, &[2])]);
        let mut tracker = tracker_through(41);
        observe(&mut tracker, &beacons, 41, peer(41, 99));
        assert_eq!(tracker.state(), &forked(41, true));

        beacons.vouch(peer(41, 41), &[3]);
        beacons.vouch(peer(41, 41), &[5]);
        assert!(observe(&mut tracker, &beacons, 41, peer(41, 41)));
        assert_eq!(tracker.state(), &forked(41, false));
    }

    #[test]
    fn an_inconclusive_beacon_changes_nothing() {
        let mut tracker = tracker_through(41);
        observe(&mut tracker, &Beacons::default(), 41, peer(41, 41));
        observe(&mut tracker, &Beacons::default(), 41, peer(38, 38));

        assert_eq!(tracker.state(), &SyncState::Synced);
    }
}
