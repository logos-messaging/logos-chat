//! Each member's group state against ours, from the fingerprints their packets' headers carry
//! and their signed beacons.

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};

use super::beacons::EPOCHS_AHEAD;
use super::payloads::EpochData;
use crate::SignerKey;
use crate::conversation::GroupEpoch;

/// Epochs of each member's history kept.
const EPOCHS_RETAINED: usize = 8;

/// How a member's group state compares with this member's.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum MemberSync {
    /// Nothing heard from them yet, or nothing we can check against our own history.
    Unconfirmed,
    /// They hold our state at our epoch.
    Synced,
    /// They hold the state we held at an earlier epoch: a commit has not reached them yet.
    Behind,
    /// They are past our epoch, and held our state at it.
    Ahead,
    /// At the newest epoch both of us held, their state is not ours.
    Forked,
}

/// A member's group state, and the epoch it was told at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberState {
    pub signer: SignerKey,
    pub sync: MemberSync,
    /// The newest epoch they were heard at, with their fingerprint of it.
    pub heard: Option<GroupEpoch>,
}

/// A fingerprint a member claimed for one epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Claim {
    fingerprint: String,
    /// From a signed beacon. An unsigned header does not replace it.
    signed: bool,
}

/// What each member claimed, per epoch.
#[derive(Debug, Default)]
pub(crate) struct MemberEpochs {
    claims: HashMap<SignerKey, BTreeMap<u64, Claim>>,
    changed: bool,
}

impl MemberEpochs {
    /// The fingerprints a packet's header carries. Unsigned, and filed under the sender SDS names.
    pub(crate) fn hear_header(&mut self, signer: &SignerKey, our_epoch: u64, data: &EpochData) {
        let last = our_epoch.saturating_add(EPOCHS_AHEAD);
        for (epoch, fingerprint) in data.epochs().filter(|(epoch, _)| *epoch <= last) {
            let claim = Claim {
                fingerprint: fingerprint.to_string(),
                signed: false,
            };
            self.claim(signer, epoch, claim);
        }
    }

    /// The fingerprint of a beacon `signer` signed.
    pub(crate) fn hear_beacon(&mut self, signer: &SignerKey, epoch: u64, fingerprint: &str) {
        let claim = Claim {
            fingerprint: fingerprint.to_string(),
            signed: true,
        };
        self.claim(signer, epoch, claim);
    }

    fn claim(&mut self, signer: &SignerKey, epoch: u64, claim: Claim) {
        let epochs = self.claims.entry(signer.clone()).or_default();
        let too_old = epochs.len() == EPOCHS_RETAINED
            && epochs
                .first_key_value()
                .is_some_and(|(first, _)| epoch < *first);
        let kept = epochs
            .get(&epoch)
            .is_some_and(|held| *held == claim || (held.signed && !claim.signed));
        if too_old || kept {
            return;
        }
        epochs.insert(epoch, claim);
        if epochs.len() > EPOCHS_RETAINED {
            epochs.pop_first();
        }
        self.changed = true;
    }

    /// Our epoch moved, and every comparison with it. Forgets who is no longer a member.
    pub(crate) fn enter_epoch(&mut self, is_member: impl Fn(&SignerKey) -> bool) {
        self.claims.retain(|signer, _| is_member(signer));
        self.changed = true;
    }

    /// Whether a member's claims or our epoch changed since the last call.
    pub(crate) fn take_changed(&mut self) -> bool {
        std::mem::take(&mut self.changed)
    }

    /// `signer`'s state against ours: `current`, and `past` for the fingerprints we held before.
    pub(crate) fn state<'a>(
        &self,
        signer: &SignerKey,
        current: &'a GroupEpoch,
        past: impl Fn(u64) -> Option<&'a str>,
    ) -> MemberState {
        let claims = self.claims.get(signer);
        let Some((claims, (&newest, claim))) =
            claims.and_then(|claims| Some((claims, claims.last_key_value()?)))
        else {
            return MemberState {
                signer: signer.clone(),
                sync: MemberSync::Unconfirmed,
                heard: None,
            };
        };
        let ours = |epoch: u64| {
            if epoch == current.epoch {
                Some(current.fingerprint.as_str())
            } else {
                past(epoch)
            }
        };
        let shared = claims
            .range(..=current.epoch)
            .rev()
            .find_map(|(&epoch, claim)| ours(epoch).map(|ours| (epoch, ours == claim.fingerprint)));
        let sync = match shared {
            None => MemberSync::Unconfirmed,
            Some((_, false)) => MemberSync::Forked,
            Some((epoch, true)) => match newest.cmp(&current.epoch) {
                Ordering::Equal => MemberSync::Synced,
                Ordering::Less if epoch == newest => MemberSync::Behind,
                Ordering::Greater if epoch == current.epoch => MemberSync::Ahead,
                // We agreed at an earlier epoch, but cannot check theirs against ours.
                _ => MemberSync::Unconfirmed,
            },
        };
        MemberState {
            signer: signer.clone(),
            sync,
            heard: Some(GroupEpoch {
                epoch: newest,
                fingerprint: claim.fingerprint.clone(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conversation::mls_utils::EpochFingerprint;

    fn raya() -> SignerKey {
        SignerKey::from(b"raya".as_slice())
    }

    /// Our fingerprint at each epoch is `s<epoch>`.
    fn ours(epoch: u64) -> String {
        format!("s{epoch}")
    }

    fn sync_at(heard: &MemberEpochs, our_epoch: u64) -> MemberSync {
        let current = GroupEpoch {
            epoch: our_epoch,
            fingerprint: ours(our_epoch),
        };
        let history: Vec<String> = (0..our_epoch).map(ours).collect();
        heard
            .state(&raya(), &current, |epoch| {
                history.get(epoch as usize).map(String::as_str)
            })
            .sync
    }

    fn fingerprint(byte: u8) -> EpochFingerprint {
        EpochFingerprint::try_from([byte; 7].as_slice()).unwrap()
    }

    fn heard(claims: &[(u64, &str)]) -> MemberEpochs {
        let mut heard = MemberEpochs::default();
        for (epoch, fingerprint) in claims {
            heard.hear_beacon(&raya(), *epoch, fingerprint);
        }
        heard
    }

    #[test]
    fn nothing_heard_is_unconfirmed() {
        assert_eq!(sync_at(&heard(&[]), 4), MemberSync::Unconfirmed);
    }

    #[test]
    fn our_state_at_our_epoch_is_synced() {
        assert_eq!(sync_at(&heard(&[(4, "s4")]), 4), MemberSync::Synced);
    }

    #[test]
    fn another_state_at_our_epoch_is_forked() {
        assert_eq!(
            sync_at(&heard(&[(3, "s3"), (4, "r4")]), 4),
            MemberSync::Forked
        );
    }

    #[test]
    fn our_earlier_state_is_behind() {
        assert_eq!(sync_at(&heard(&[(3, "s3")]), 4), MemberSync::Behind);
    }

    #[test]
    fn another_earlier_state_is_forked() {
        assert_eq!(sync_at(&heard(&[(3, "r3")]), 4), MemberSync::Forked);
    }

    #[test]
    fn past_our_epoch_through_our_state_is_ahead() {
        assert_eq!(
            sync_at(&heard(&[(4, "s4"), (5, "x5")]), 4),
            MemberSync::Ahead
        );
    }

    #[test]
    fn past_our_epoch_through_another_state_is_forked() {
        assert_eq!(
            sync_at(&heard(&[(4, "r4"), (5, "r5")]), 4),
            MemberSync::Forked
        );
    }

    /// Their epochs 3 and 4 are unknown, so they may have left our state after 2.
    #[test]
    fn past_our_epoch_with_our_epoch_unheard_is_unconfirmed() {
        assert_eq!(
            sync_at(&heard(&[(2, "s2"), (5, "x5")]), 4),
            MemberSync::Unconfirmed
        );
    }

    /// A member re-added after a fork holds our state again.
    #[test]
    fn the_newest_shared_epoch_decides() {
        assert_eq!(
            sync_at(&heard(&[(2, "r2"), (3, "s3")]), 3),
            MemberSync::Synced
        );
    }

    #[test]
    fn an_unsigned_claim_does_not_replace_a_signed_one() {
        let mut heard = heard(&[(4, "s4")]);
        let forged = EpochData::from_history(4, vec![fingerprint(0xf4)]);
        heard.hear_header(&raya(), 4, &forged);
        assert_eq!(sync_at(&heard, 4), MemberSync::Synced);
    }

    #[test]
    fn only_the_newest_epochs_are_kept() {
        let claims: Vec<(u64, String)> = (0..=EPOCHS_RETAINED as u64)
            .map(|epoch| (epoch, ours(epoch)))
            .collect();
        let claims: Vec<(u64, &str)> = claims.iter().map(|(e, f)| (*e, f.as_str())).collect();
        let mut heard = heard(&claims);
        assert!(heard.take_changed());

        heard.hear_beacon(&raya(), 0, "s0");
        assert!(
            !heard.take_changed(),
            "an epoch below the window is dropped"
        );
        heard.hear_beacon(&raya(), EPOCHS_RETAINED as u64, "s8");
        assert!(!heard.take_changed(), "a repeated claim changes nothing");
    }

    #[test]
    fn a_header_past_the_bound_is_ignored() {
        let mut heard = MemberEpochs::default();
        let far = EpochData::from_history(4 + EPOCHS_AHEAD + 1, vec![fingerprint(0xff)]);
        heard.hear_header(&raya(), 4, &far);
        assert!(!heard.take_changed());
    }

    #[test]
    fn a_former_member_is_forgotten_on_the_next_epoch() {
        let mut heard = heard(&[(4, "s4")]);
        heard.enter_epoch(|_| false);
        assert_eq!(sync_at(&heard, 5), MemberSync::Unconfirmed);
    }
}
