//! What GroupV3 keeps for its debug data: each member's group state compared with ours, read
//! from the epoch data in their packet headers.

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};

use openmls::group::MlsGroup;
use tracing::warn;

use crate::conversation::group_v3::beacons::Beacons;
use crate::conversation::group_v3::payloads::{EpochData, GroupV3Packet};
use crate::conversation::mls_utils::EpochFingerprint;
use crate::{DebugData, SignerKey};

/// Epochs kept from each member's packet headers.
const EPOCHS_RETAINED: usize = 8;

/// How a member's group state compares with ours.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MemberSync {
    /// No epoch data we can check against our own history.
    Unconfirmed,
    /// They are in our state at our epoch.
    Synced,
    /// They are in a state we were in at an earlier epoch.
    Behind,
    /// They are past our epoch, and were in our state at it.
    Ahead,
    /// At the newest epoch we both know, their state is not ours.
    Forked,
}

impl MemberSync {
    fn name(self) -> &'static str {
        match self {
            Self::Unconfirmed => "unconfirmed",
            Self::Synced => "synced",
            Self::Behind => "behind",
            Self::Ahead => "ahead",
            Self::Forked => "forked",
        }
    }
}

/// A member's fingerprint at each epoch.
type EpochHistory<'a> = BTreeMap<u64, &'a str>;

/// The fingerprints each member's packet headers carry. Headers are not signed.
#[derive(Debug, Default)]
pub(crate) struct DebugState {
    epoch_histories: HashMap<SignerKey, BTreeMap<u64, String>>,
}

impl DebugState {
    /// Reads the sender's epoch data from a packet header. Read on arrival, because SDS never
    /// releases a forked member's packets.
    pub(crate) fn record_epoch_data(&mut self, packet: &GroupV3Packet, group: &MlsGroup) {
        let data = match packet.epoch_data() {
            Ok(data) => data,
            Err(e) => {
                warn!(error = %e, "unreadable epoch data in a packet header");
                return;
            }
        };
        let Ok(signer) = packet.sender() else {
            return;
        };
        let is_member = group
            .members()
            .any(|member| member.signature_key == signer.as_bytes());
        if is_member && own_signer(group) != Some(signer.as_bytes()) {
            self.add_epochs(&signer, &data);
        }
    }

    /// Each member's state compared with ours. Ours is synced; any other comes from unsigned
    /// headers, so a forged packet can change it.
    pub(crate) fn members(&self, group: &MlsGroup, beacons: &Beacons) -> Vec<serde_json::Value> {
        let our_epoch = group.epoch().as_u64();
        let fingerprint = EpochFingerprint::from_group(group).to_string();
        let ours = |epoch| {
            if epoch == our_epoch {
                Some(fingerprint.as_str())
            } else {
                beacons.our_epoch_id(epoch)
            }
        };
        let own = own_signer(group);
        group
            .members()
            .map(|member| {
                let signer = SignerKey::from(member.signature_key.as_slice());
                let mut state =
                    DebugData::from_iter([("signer".to_owned(), signer.to_string().into())]);
                if own == Some(member.signature_key.as_slice()) {
                    state.insert("sync".to_owned(), MemberSync::Synced.name().into());
                    state.insert("epoch".to_owned(), our_epoch.into());
                    state.insert("epoch_fingerprint".to_owned(), fingerprint.clone().into());
                } else {
                    let history = self.epoch_history(&signer);
                    state.insert(
                        "sync".to_owned(),
                        sync(&history, our_epoch, ours).name().into(),
                    );
                    if let Some((&epoch, theirs)) = history.last_key_value() {
                        state.insert("epoch".to_owned(), epoch.into());
                        state.insert("epoch_fingerprint".to_owned(), (*theirs).into());
                    }
                }
                state.into()
            })
            .collect()
    }

    fn add_epochs(&mut self, signer: &SignerKey, data: &EpochData) {
        let epochs = self.epoch_histories.entry(signer.clone()).or_default();
        for (epoch, fingerprint) in data.iter() {
            epochs.insert(epoch, fingerprint.to_string());
        }
        while epochs.len() > EPOCHS_RETAINED {
            epochs.pop_first();
        }
    }

    /// Whether another member reported `state` as its own at `epoch`.
    pub(crate) fn reported(&self, epoch: u64, state: &EpochFingerprint) -> bool {
        let state = state.to_string();
        self.epoch_histories
            .values()
            .any(|epochs| epochs.get(&epoch) == Some(&state))
    }

    fn epoch_history(&self, signer: &SignerKey) -> EpochHistory<'_> {
        let headers = self.epoch_histories.get(signer).into_iter().flatten();
        headers
            .map(|(epoch, fingerprint)| (*epoch, fingerprint.as_str()))
            .collect()
    }
}

/// Our signature key in `group`.
fn own_signer(group: &MlsGroup) -> Option<&[u8]> {
    group
        .own_leaf_node()
        .map(|leaf| leaf.signature_key().as_slice())
}

/// How a member with `history` compares with us at `our_epoch`. `ours` gives our fingerprint at an
/// epoch.
fn sync<'a>(
    history: &EpochHistory<'_>,
    our_epoch: u64,
    ours: impl Fn(u64) -> Option<&'a str>,
) -> MemberSync {
    let Some((&newest, _)) = history.last_key_value() else {
        return MemberSync::Unconfirmed;
    };
    let shared = history
        .range(..=our_epoch)
        .rev()
        .find_map(|(&epoch, theirs)| ours(epoch).map(|ours| (epoch, ours == *theirs)));
    match shared {
        None => MemberSync::Unconfirmed,
        Some((_, false)) => MemberSync::Forked,
        Some((epoch, true)) => match newest.cmp(&our_epoch) {
            Ordering::Equal => MemberSync::Synced,
            Ordering::Less if epoch == newest => MemberSync::Behind,
            Ordering::Greater if epoch == our_epoch => MemberSync::Ahead,
            // We agreed at an earlier epoch, but cannot check theirs against ours.
            _ => MemberSync::Unconfirmed,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raya() -> SignerKey {
        SignerKey::from(b"raya".as_slice())
    }

    /// Our fingerprint at each epoch is `s<epoch>`.
    fn sync_at(history: &[(u64, &str)], our_epoch: u64) -> MemberSync {
        let ours: Vec<String> = (0..=our_epoch).map(|epoch| format!("s{epoch}")).collect();
        let history = history.iter().copied().collect();
        sync(&history, our_epoch, |epoch| {
            ours.get(epoch as usize).map(String::as_str)
        })
    }

    fn header(epoch: u64, byte: u8) -> EpochData {
        let mut data = EpochData::starting_at(epoch);
        data.advance_to(
            epoch,
            EpochFingerprint::try_from([byte; 7].as_slice()).unwrap(),
        );
        data
    }

    #[test]
    fn no_epoch_data_is_unconfirmed() {
        assert_eq!(sync_at(&[], 4), MemberSync::Unconfirmed);
    }

    #[test]
    fn our_state_at_our_epoch_is_synced() {
        assert_eq!(sync_at(&[(4, "s4")], 4), MemberSync::Synced);
    }

    #[test]
    fn another_state_at_our_epoch_is_forked() {
        assert_eq!(sync_at(&[(3, "s3"), (4, "r4")], 4), MemberSync::Forked);
    }

    #[test]
    fn our_earlier_state_is_behind() {
        assert_eq!(sync_at(&[(3, "s3")], 4), MemberSync::Behind);
    }

    #[test]
    fn another_earlier_state_is_forked() {
        assert_eq!(sync_at(&[(3, "r3")], 4), MemberSync::Forked);
    }

    #[test]
    fn past_our_epoch_through_our_state_is_ahead() {
        assert_eq!(sync_at(&[(4, "s4"), (5, "x5")], 4), MemberSync::Ahead);
    }

    #[test]
    fn past_our_epoch_through_another_state_is_forked() {
        assert_eq!(sync_at(&[(4, "r4"), (5, "r5")], 4), MemberSync::Forked);
    }

    /// Their epochs 3 and 4 are unknown, so they may have left our state after 2.
    #[test]
    fn past_our_epoch_without_our_epoch_is_unconfirmed() {
        assert_eq!(sync_at(&[(2, "s2"), (5, "x5")], 4), MemberSync::Unconfirmed);
    }

    /// A member re-added after a fork is in our state again.
    #[test]
    fn the_newest_shared_epoch_decides() {
        assert_eq!(sync_at(&[(2, "r2"), (3, "s3")], 3), MemberSync::Synced);
    }

    #[test]
    fn only_the_newest_epochs_are_kept() {
        let mut state = DebugState::default();
        for epoch in 0..=EPOCHS_RETAINED as u64 {
            state.add_epochs(&raya(), &header(epoch, epoch as u8));
        }
        let epochs: Vec<u64> = state.epoch_history(&raya()).keys().copied().collect();
        assert_eq!(epochs, (1..=EPOCHS_RETAINED as u64).collect::<Vec<_>>());
    }
}
