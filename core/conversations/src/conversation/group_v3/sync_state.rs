//! Forked, or just behind? Compares a peer's beacon against the states we held.

use std::collections::VecDeque;

use super::beacons::Beacons;
use super::external::Branch;

/// Rival branches tracked at once; the oldest seen is dropped first.
const RIVALS_RETAINED: usize = 8;

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
    /// have not come back to our branch. Which side is repaired is for the
    /// re-add to decide.
    Forked { at_or_before: u64 },
}

/// The branches that left ours, and what that makes us.
#[derive(Debug, Default)]
pub(crate) struct SyncTracker {
    rivals: VecDeque<Branch>,
    state: SyncState,
}

impl SyncTracker {
    pub(crate) fn state(&self) -> &SyncState {
        &self.state
    }

    pub(crate) fn enter_epoch(&mut self) {
        // What a peer said about the last epoch says nothing about this one.
        if !matches!(self.state, SyncState::Forked { .. }) {
            self.state = SyncState::Unknown;
        }
    }

    /// Drop rivals none of whose signers is still a member, as after they were
    /// removed rather than re-added. Call once the roster changes.
    pub(crate) fn forget_departed<K: AsRef<[u8]>>(&mut self, beacons: &Beacons, roster: &[K]) {
        self.rivals.retain(|rival| !beacons.departed(rival, roster));
        if self.rivals.is_empty() && matches!(self.state, SyncState::Forked { .. }) {
            self.state = SyncState::Unknown;
        }
    }

    /// A commit for our epoch would not apply.
    pub(crate) fn suspect(&mut self, epoch: u64) {
        if !matches!(self.state, SyncState::Forked { .. }) {
            self.state = SyncState::Suspect { epoch };
        }
    }

    /// Take in one verified peer beacon.
    pub(crate) fn observe(&mut self, beacons: &Beacons, own_epoch: u64, peer: Branch) {
        // An epoch past ours is not one we held: a peer ahead can't prove a fork.
        let differs = beacons
            .our_epoch_id(peer.epoch)
            .is_some_and(|ours| ours != peer.epoch_id);
        if differs && !self.rivals.contains(&peer) {
            if self.rivals.len() == RIVALS_RETAINED {
                self.rivals.pop_front();
            }
            self.rivals.push_back(peer.clone());
        }
        self.rivals.retain(|rival| !beacons.rejoined(rival));

        self.state = match self.rivals.iter().map(|r| r.epoch).min() {
            Some(at_or_before) => SyncState::Forked { at_or_before },
            None => match classify(beacons, own_epoch, &peer) {
                SyncState::Unknown if !matches!(self.state, SyncState::Forked { .. }) => return,
                seen => seen,
            },
        };
    }
}

/// What a beacon that names no unresolved rival says about us.
fn classify(beacons: &Beacons, own_epoch: u64, peer: &Branch) -> SyncState {
    if peer.epoch > own_epoch {
        return SyncState::Lagging {
            peer_epoch: peer.epoch,
        };
    }
    match beacons.our_epoch_id(peer.epoch) {
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
    fn held_through(last: u64) -> Beacons {
        let mut beacons = Beacons::default();
        for epoch in 0..=last {
            beacons.held(epoch, &id(epoch));
        }
        beacons
    }

    /// Each branch at `epoch` signed by its own `signers`.
    fn vouched(mut beacons: Beacons, epoch: u64, branches: &[(u64, &[u8])]) -> Beacons {
        for (n, signers) in branches {
            for s in *signers {
                beacons.vouch(peer(epoch, *n), &[*s]);
            }
        }
        beacons
    }

    fn see(beacons: &Beacons, own_epoch: u64, p: Branch) -> SyncState {
        let mut tracker = SyncTracker::default();
        tracker.observe(beacons, own_epoch, p);
        tracker.state().clone()
    }

    fn forked(at_or_before: u64) -> SyncState {
        SyncState::Forked { at_or_before }
    }

    /// Raya forked at 2 and was removed instead of re-added: nobody is left on
    /// her branch, so the fork is over.
    #[test]
    fn a_fork_clears_once_the_rivals_signers_are_removed() {
        let beacons = vouched(held_through(3), 2, &[(7, &[5])]);
        let mut tracker = SyncTracker::default();
        tracker.observe(&beacons, 3, peer(2, 7));
        assert_eq!(tracker.state(), &forked(2));

        tracker.forget_departed(&beacons, &[[5u8]]);
        assert_eq!(tracker.state(), &forked(2), "Raya is still a member");

        tracker.forget_departed(&beacons, &[[1u8], [2u8]]);
        assert_eq!(tracker.state(), &SyncState::Unknown);
    }

    #[test]
    fn same_epoch_same_id_is_synced() {
        assert_eq!(see(&held_through(41), 41, peer(41, 41)), SyncState::Synced);
    }

    #[test]
    fn same_epoch_different_id_is_forked() {
        let beacons = vouched(held_through(41), 41, &[(99, &[1])]);
        assert_eq!(see(&beacons, 41, peer(41, 99)), forked(41));
    }

    #[test]
    fn a_peer_ahead_is_lagging_never_forked() {
        for peer_epoch in [41, 47, 5_000] {
            assert_eq!(
                see(&held_through(40), 40, peer(peer_epoch, 99)),
                SyncState::Lagging { peer_epoch }
            );
        }
    }

    #[test]
    fn a_peer_behind_that_differs_is_forked() {
        let beacons = vouched(held_through(41), 38, &[(99, &[1])]);
        assert_eq!(see(&beacons, 41, peer(38, 99)), forked(38));
    }

    #[test]
    fn a_peer_behind_that_agrees_is_unknown() {
        assert_eq!(see(&held_through(41), 41, peer(38, 38)), SyncState::Unknown);
    }

    #[test]
    fn a_peer_behind_what_we_remember_is_unknown() {
        let beacons = vouched(held_through(200), 2, &[(99, &[1])]);
        assert_eq!(see(&beacons, 200, peer(2, 99)), SyncState::Unknown);
    }

    /// Whatever order the branches arrive in, and with our own branch's
    /// beacons in between, a rival keeps us forked.
    #[test]
    fn our_own_branch_does_not_hide_a_rival() {
        let (a, b, c) = (peer(41, 1), peer(41, 41), peer(41, 2));
        let beacons = vouched(held_through(41), 41, &[(1, &[1]), (41, &[4]), (2, &[6])]);
        let orders = [
            [&a, &b, &c],
            [&a, &c, &b],
            [&b, &a, &c],
            [&b, &c, &a],
            [&c, &a, &b],
            [&c, &b, &a],
        ];
        for order in orders {
            let mut tracker = SyncTracker::default();
            for p in order {
                tracker.observe(&beacons, 41, p.clone());
            }
            assert_eq!(tracker.state(), &forked(41), "{order:?}");
        }
    }

    #[test]
    fn the_fork_is_dated_by_the_oldest_rival() {
        let mut beacons = vouched(held_through(41), 38, &[(99, &[1])]);
        beacons.vouch(peer(40, 98), &[2]);
        let mut tracker = SyncTracker::default();
        for p in [peer(40, 98), peer(38, 99), peer(40, 98)] {
            tracker.observe(&beacons, 41, p);
        }

        assert_eq!(tracker.state(), &forked(38));
    }

    #[test]
    fn only_the_newest_rivals_are_kept() {
        let mut beacons = held_through(41);
        let mut tracker = SyncTracker::default();
        let first = 41 - RIVALS_RETAINED as u64;
        for epoch in first..=41 {
            beacons.vouch(peer(epoch, 99), &[1]);
            tracker.observe(&beacons, 41, peer(epoch, 99));
        }

        assert_eq!(tracker.state(), &forked(first + 1));
    }

    #[test]
    fn a_fork_clears_once_the_rivals_signers_are_back_on_our_branch() {
        let mut beacons = vouched(held_through(42), 41, &[(99, &[1]), (41, &[2, 3])]);
        let mut tracker = SyncTracker::default();
        tracker.observe(&beacons, 42, peer(41, 99));

        beacons.vouch(peer(42, 42), &[1]);
        tracker.observe(&beacons, 42, peer(42, 42));

        assert_eq!(tracker.state(), &SyncState::Synced);
    }

    #[test]
    fn a_fork_cleared_by_an_older_beacon_is_unknown() {
        let mut beacons = vouched(held_through(43), 41, &[(99, &[1]), (41, &[2, 3])]);
        let mut tracker = SyncTracker::default();
        tracker.observe(&beacons, 43, peer(41, 99));

        beacons.vouch(peer(42, 42), &[1]);
        tracker.observe(&beacons, 43, peer(42, 42));

        assert_eq!(tracker.state(), &SyncState::Unknown);
    }

    #[test]
    fn a_rival_still_signed_elsewhere_keeps_the_fork() {
        let mut beacons = vouched(held_through(42), 41, &[(99, &[1, 4]), (41, &[2, 3])]);
        let mut tracker = SyncTracker::default();
        tracker.observe(&beacons, 42, peer(41, 99));

        beacons.vouch(peer(42, 42), &[1]);
        beacons.vouch(peer(42, 97), &[4]);
        tracker.observe(&beacons, 42, peer(42, 42));

        assert_eq!(tracker.state(), &forked(41));
    }

    #[test]
    fn a_peer_ahead_never_clears_a_fork() {
        let beacons = vouched(held_through(41), 41, &[(99, &[1])]);
        let mut tracker = SyncTracker::default();
        tracker.observe(&beacons, 41, peer(41, 99));
        tracker.observe(&beacons, 41, peer(50, 50));

        assert_eq!(tracker.state(), &forked(41));
    }

    #[test]
    fn an_inconclusive_beacon_changes_nothing() {
        let beacons = held_through(41);
        let mut tracker = SyncTracker::default();
        tracker.observe(&beacons, 41, peer(41, 41));
        tracker.observe(&beacons, 41, peer(38, 38));

        assert_eq!(tracker.state(), &SyncState::Synced);
    }

    #[test]
    fn a_new_epoch_forgets_all_but_a_fork() {
        let mut tracker = SyncTracker::default();
        tracker.suspect(41);
        tracker.enter_epoch();
        assert_eq!(tracker.state(), &SyncState::Unknown);

        let beacons = vouched(held_through(41), 41, &[(99, &[1])]);
        tracker.observe(&beacons, 41, peer(41, 99));
        tracker.suspect(41);
        tracker.enter_epoch();
        assert_eq!(tracker.state(), &forked(41));
    }
}
