//! What a member does with beacons: make its own once per epoch, and keep the
//! verified ones it hears. Sending is left to the conversation.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ops::Bound;
use std::time::Duration;

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use openmls::group::MlsGroup;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::HpkePrivateKey;
use prost::bytes::Bytes;
use tracing::{debug, warn};

use super::external::{self, Admitted, Branch, EpochBeacon};
use super::sealed::{EVIDENCE_BRANCHES, EVIDENCE_SIGNATURES, Vouch, Vouches};
use crate::ExternalServices;
use crate::service_context::ServiceContext;

/// Digests of verified frames remembered, so a repeat skips verification.
const VERIFIED_RETAINED: usize = 64;

/// Epochs whose state id we remember: never to seal to a state we were in,
/// and to tell an asker that is merely behind.
const STATES_RETAINED: usize = 16;

/// Epochs each signer's vouches are kept for, and branches kept per epoch.
const SIGNED_EPOCHS_RETAINED: usize = 64;
const BRANCHES_PER_EPOCH: usize = 8;

const FIRST_RETRY: Duration = Duration::from_secs(1);
const LAST_RETRY: Duration = Duration::from_secs(60);

#[derive(Debug, Default)]
pub struct Beacons {
    store: BeaconStore,
    /// Our external private key, for the current state only: a request sealed
    /// to an earlier state may be a replay of one already answered.
    key: Option<HeldKey>,
    /// The states we were in, newest last.
    states: VecDeque<(u64, String)>,
    /// Epoch our beacon was made for.
    epoch: Option<u64>,
    /// Frames already verified this epoch, with the key that signed each.
    verified: VecDeque<([u8; 32], Vec<u8>)>,
    /// Our own signed beacon, until it is sent.
    outgoing: Option<EpochBeacon>,
    retry_in: Duration,
    /// When `outgoing` is next due.
    due_at: Duration,
}

impl Beacons {
    /// Make our beacon, once per epoch. It is due at once.
    pub fn enter_epoch<S: ExternalServices>(
        &mut self,
        cx: &ServiceContext<S>,
        group: &MlsGroup,
        convo_id: &str,
    ) {
        let epoch = group.epoch().as_u64();
        if self.epoch == Some(epoch) {
            return;
        }
        self.epoch = Some(epoch);
        self.verified.clear();
        self.outgoing = None;
        self.key = None;
        self.retry_in = FIRST_RETRY;
        self.due_at = Duration::ZERO;

        if let Err(e) = self.prepare(cx, group, convo_id) {
            warn!(convo = convo_id, error = %e, "no beacon this epoch");
        }
    }

    fn prepare<S: ExternalServices>(
        &mut self,
        cx: &ServiceContext<S>,
        group: &MlsGroup,
        convo_id: &str,
    ) -> Result<(), external::ExternalError> {
        let keys = external::derive_external_keys(group, &cx.mls_provider)?;
        let mut beacon = external::beacon_for_epoch(group, keys.public.into());
        self.hold(beacon.epoch, &beacon.epoch_id, keys.private);
        beacon.signature = external::sign_beacon(&beacon, convo_id, &cx.mls_identity)?;

        // We count among our own branch's signers.
        if let Some(own) = group.own_leaf_node() {
            let own_key = own.signature_key().as_slice().to_vec();
            self.store.vouch(&beacon, own_key);
        }
        self.outgoing = Some(beacon);
        Ok(())
    }

    /// Our beacon, if it is waiting and due at `now`.
    pub fn due(&self, now: Duration) -> Option<&EpochBeacon> {
        self.outgoing.as_ref().filter(|_| now >= self.due_at)
    }

    pub fn sent(&mut self) {
        self.outgoing = None;
    }

    /// Sending failed at `now`: back off before the next try.
    pub fn failed(&mut self, now: Duration) {
        self.due_at = now + self.retry_in;
        self.retry_in = (self.retry_in * 2).min(LAST_RETRY);
    }

    fn hold(&mut self, epoch: u64, epoch_id: &str, private: HpkePrivateKey) {
        self.states.retain(|(e, _)| *e != epoch);
        if self.states.len() == STATES_RETAINED {
            self.states.pop_front();
        }
        self.states.push_back((epoch, epoch_id.to_string()));
        self.key = Some(HeldKey {
            epoch,
            epoch_id: epoch_id.to_string(),
            private,
        });
    }

    /// Our external key, if `epoch` and `epoch_id` name the state we are in.
    pub fn key_for(&self, epoch: u64, epoch_id: &str) -> Option<&HpkePrivateKey> {
        self.key
            .as_ref()
            .filter(|k| k.epoch == epoch && k.epoch_id == epoch_id)
            .map(|k| &k.private)
    }

    /// The state we were in at `epoch`, if we remember it.
    pub fn our_epoch_id(&self, epoch: u64) -> Option<&str> {
        self.states
            .iter()
            .find(|(e, _)| *e == epoch)
            .map(|(_, id)| id.as_str())
    }

    /// The most-signed head of a branch we were never in, with the key its
    /// signers vouched for, and those signers. A state stops being a head once
    /// one of its signers vouches at a later epoch. Signers choose the id, so
    /// a tie is no target.
    pub fn seal_target(&self) -> Option<(EpochBeacon, Vec<Vec<u8>>)> {
        let mut best: Option<Candidate> = None;
        let mut tied = false;
        for &epoch in self.store.signers.keys() {
            let tally = Tally::of(self.heard(epoch));
            for &id in tally.0.keys() {
                if self.our_epoch_id(epoch) == Some(id) || self.superseded(epoch, id) {
                    continue;
                }
                let Some((key, by)) = tally.key(id) else {
                    continue;
                };
                let top = best.as_ref().map_or(0, |(.., v)| v.len());
                if by.len() > top {
                    let vouchers = by.iter().map(|s| s.to_vec()).collect();
                    best = Some((epoch, id, key, vouchers));
                    tied = false;
                } else if by.len() == top {
                    tied = true;
                }
            }
        }
        let (epoch, id, key, vouchers) = best.filter(|_| !tied)?;
        let beacon = EpochBeacon {
            epoch,
            epoch_id: id.to_string(),
            external_hpke_pub: Bytes::copy_from_slice(key),
            ..Default::default()
        };
        Some((beacon, vouchers))
    }

    fn superseded(&self, epoch: u64, id: &str) -> bool {
        let signers: Vec<_> = self
            .heard(epoch)
            .filter(|(i, ..)| *i == id)
            .map(|(.., signer)| signer)
            .collect();
        self.store
            .signers
            .range((Bound::Excluded(epoch), Bound::Unbounded))
            .any(|(&later, _)| self.heard(later).any(|(.., s)| signers.contains(&s)))
    }

    /// A beacon heard on the wire, `bytes` being its whole frame. Kept only if
    /// one of `keys`, our state's leaf keys, signed it. `keys` is read only for
    /// a new frame.
    pub fn receive_frame<I, K>(
        &mut self,
        crypto: &impl OpenMlsCrypto,
        convo_id: &str,
        keys: I,
        beacon: Admitted,
        bytes: &[u8],
    ) where
        I: IntoIterator<Item = K>,
        K: AsRef<[u8]>,
    {
        let digest: [u8; 32] = Blake2b::<U32>::digest(bytes).into();
        let cached = self.verified.iter().find(|(d, _)| *d == digest);
        let signer = match cached {
            Some((_, signer)) => signer.clone(),
            None => {
                let Some(key) = external::verify_beacon(crypto, convo_id, beacon.beacon(), keys)
                else {
                    debug!(convo = convo_id, "refused a beacon no member signed");
                    return;
                };
                let signer = key.as_ref().to_vec();
                if self.verified.len() == VERIFIED_RETAINED {
                    self.verified.pop_front();
                }
                self.verified.push_back((digest, signer.clone()));
                signer
            }
        };
        self.store.vouch(beacon.beacon(), signer);
    }

    /// Every `(branch id, advertised key, signer)` we verified at `epoch`.
    fn heard(&self, epoch: u64) -> impl Iterator<Item = (&str, &[u8], &[u8])> {
        self.store
            .signers
            .get(&epoch)
            .into_iter()
            .flatten()
            .flat_map(|((id, key), by)| {
                by.keys()
                    .map(move |signer| (id.as_str(), key.as_ref(), signer.as_slice()))
            })
    }

    /// The vouches in `evidence` signed by the member of `keys` they name, up
    /// to the caps.
    fn shown<'a, K: AsRef<[u8]>>(
        crypto: &impl OpenMlsCrypto,
        convo_id: &str,
        keys: &'a [K],
        epoch: u64,
        evidence: &'a [Vouches],
    ) -> Vec<(&'a str, &'a [u8], &'a [u8])> {
        let mut shown = Vec::new();
        for vouches in evidence.iter().take(EVIDENCE_BRANCHES) {
            for vouch in vouches.vouches.iter().take(EVIDENCE_SIGNATURES) {
                let Some(signer) = keys.iter().find(|k| k.as_ref() == vouch.signer_key) else {
                    continue;
                };
                let beacon = EpochBeacon {
                    epoch,
                    external_hpke_pub: vouches.external_hpke_pub.clone(),
                    epoch_id: vouches.epoch_id.clone(),
                    signature: vouch.signature.clone(),
                };
                if external::verify_beacon(crypto, convo_id, &beacon, [signer]).is_some() {
                    let key = vouches.external_hpke_pub.as_ref();
                    shown.push((vouches.epoch_id.as_str(), key, signer.as_ref()));
                }
            }
        }
        shown
    }

    /// Whether we, on `ours`, should move to `theirs`: it has more signers, or
    /// as many and the smaller id, counting what we heard plus the asker's
    /// `evidence` signed by one of `keys`, our roster. Never with no verified
    /// signer for `theirs`. Counts are a lower bound: members who joined after
    /// the fork aren't in our roster.
    pub fn yields<K: AsRef<[u8]>>(
        &self,
        crypto: &impl OpenMlsCrypto,
        convo_id: &str,
        keys: &[K],
        ours: &Branch,
        theirs: &Branch,
        evidence: &[Vouches],
    ) -> bool {
        if ours.epoch != theirs.epoch {
            return false;
        }
        let shown = Self::shown(crypto, convo_id, keys, ours.epoch, evidence);
        let tally = Tally::of(self.heard(ours.epoch).chain(shown));
        let (m, n) = (tally.count(&ours.epoch_id), tally.count(&theirs.epoch_id));
        n > 0 && (n > m || (n == m && theirs.epoch_id < ours.epoch_id))
    }

    /// The signed beacons we hold at `epoch`, for a request: our own branch
    /// first, then the most signed others.
    pub fn evidence(&self, epoch: u64, own_id: &str) -> Vec<Vouches> {
        let Some(at_epoch) = self.store.signers.get(&epoch) else {
            return Vec::new();
        };
        let mut records: Vec<_> = at_epoch.iter().collect();
        records
            .sort_by_key(|((id, _), by)| (id.as_str() != own_id, Reverse(by.len()), id.as_str()));
        records
            .into_iter()
            .take(EVIDENCE_BRANCHES)
            .map(|((id, key), by)| Vouches {
                epoch_id: id.clone(),
                external_hpke_pub: key.clone(),
                vouches: by
                    .iter()
                    .take(EVIDENCE_SIGNATURES)
                    .map(|(signer, signature)| Vouch {
                        signer_key: Bytes::copy_from_slice(signer),
                        signature: signature.clone(),
                    })
                    .collect(),
            })
            .collect()
    }
}

/// A seal target: epoch, id, key and its signers.
type Candidate<'a> = (u64, &'a str, &'a [u8], Vec<Vec<u8>>);

/// Signer counts at one epoch, by branch id and advertised key. A signer on two
/// branch ids counts for neither.
struct Tally<'a>(BTreeMap<&'a str, BTreeMap<&'a [u8], Vec<&'a [u8]>>>);

impl<'a> Tally<'a> {
    fn of(vouches: impl IntoIterator<Item = (&'a str, &'a [u8], &'a [u8])>) -> Self {
        let vouches: BTreeSet<_> = vouches.into_iter().collect();
        let mut branch_of: BTreeMap<&[u8], Option<&str>> = BTreeMap::new();
        for &(id, _, signer) in &vouches {
            let branch = branch_of.entry(signer).or_insert(Some(id));
            if *branch != Some(id) {
                *branch = None;
            }
        }
        let mut signers: BTreeMap<_, BTreeMap<_, Vec<_>>> = BTreeMap::new();
        for (id, key, signer) in vouches {
            if branch_of[signer] == Some(id) {
                signers
                    .entry(id)
                    .or_default()
                    .entry(key)
                    .or_default()
                    .push(signer);
            }
        }
        Self(signers)
    }

    /// An id counts as many signers as its most-signed key.
    fn count(&self, id: &str) -> usize {
        self.0
            .get(id)
            .and_then(|by_key| by_key.values().map(Vec::len).max())
            .unwrap_or(0)
    }

    /// The most-signed key for `id` and its signers, or `None` if two keys
    /// tie for it.
    fn key(&self, id: &str) -> Option<(&'a [u8], &[&'a [u8]])> {
        let by_key = self.0.get(id)?;
        let top = by_key.values().map(Vec::len).max()?;
        let mut keys = by_key.iter().filter(|(_, by)| by.len() == top);
        let (key, by) = keys.next()?;
        keys.next().is_none().then_some((*key, by.as_slice()))
    }
}

/// The beacons members of our roster signed.
#[derive(Debug, Default)]
struct BeaconStore {
    /// Per epoch and (branch id, advertised key), each signer's signature.
    signers: BTreeMap<u64, BTreeMap<(String, Bytes), Signatures>>,
}

/// Verified signatures on one beacon, by signer key.
type Signatures = BTreeMap<Vec<u8>, Bytes>;

impl BeaconStore {
    /// Keep `signer`'s signature on `beacon`. A second record per epoch is
    /// kept, to show it equivocated, but not a third.
    fn vouch(&mut self, beacon: &EpochBeacon, signer: Vec<u8>) {
        let at_epoch = self.signers.entry(beacon.epoch).or_default();
        let record = (beacon.epoch_id.clone(), beacon.external_hpke_pub.clone());
        let records_signed = at_epoch
            .values()
            .filter(|by| by.contains_key(&signer))
            .count();
        let room = at_epoch.contains_key(&record) || at_epoch.len() < BRANCHES_PER_EPOCH;
        if records_signed < 2 && room {
            at_epoch
                .entry(record)
                .or_default()
                .entry(signer.clone())
                .or_insert_with(|| beacon.signature.clone());
            self.forget_oldest_of(&signer);
        }
    }

    /// Keep each signer's vouches for [`SIGNED_EPOCHS_RETAINED`] epochs, so a
    /// member crowds out only itself.
    fn forget_oldest_of(&mut self, signer: &[u8]) {
        let mut epochs = self
            .signers
            .iter()
            .filter(|(_, at)| at.values().any(|by| by.contains_key(signer)))
            .map(|(epoch, _)| *epoch);
        let Some(lowest) = epochs.next() else {
            return;
        };
        if epochs.count() < SIGNED_EPOCHS_RETAINED {
            return;
        }
        if let Some(at) = self.signers.get_mut(&lowest) {
            at.values_mut().for_each(|by| {
                by.remove(signer);
            });
            at.retain(|_, by| !by.is_empty());
            if at.is_empty() {
                self.signers.remove(&lowest);
            }
        }
    }
}

#[cfg(test)]
impl Beacons {
    /// As if `signer` had signed a verified beacon for `branch`.
    pub(super) fn vouch(&mut self, branch: Branch, signer: &[u8]) {
        let beacon = EpochBeacon {
            epoch: branch.epoch,
            epoch_id: branch.epoch_id,
            ..Default::default()
        };
        self.store.vouch(&beacon, signer.to_vec());
    }
}

#[derive(Debug)]
struct HeldKey {
    epoch: u64,
    epoch_id: String,
    private: HpkePrivateKey,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conversation::group_v3::external::tests::{
        beacon, frame, id, leaf_key, provider, signed,
    };
    use crate::inbox_v2::MlsEphemeralPqProvider;
    use openmls_traits::OpenMlsProvider as _;

    const NO_KEYS: [&[u8]; 0] = [];

    fn admitted(epoch: u64, n: u64) -> Admitted {
        external::admit(beacon(epoch, &id(n))).expect("well formed")
    }

    fn receive<K: AsRef<[u8]>>(
        beacons: &mut Beacons,
        p: &impl OpenMlsCrypto,
        keys: &[K],
        bytes: &[u8],
    ) {
        let Some(external::Inbound::Beacon(beacon)) = external::admit_frame(bytes) else {
            panic!("not a beacon frame");
        };
        beacons.receive_frame(p, "convo-a", keys, beacon, bytes);
    }

    fn branch(epoch: u64, n: u64) -> Branch {
        Branch {
            epoch,
            epoch_id: id(n),
        }
    }

    fn signer_count(beacons: &Beacons, epoch: u64, n: u64) -> usize {
        Tally::of(beacons.heard(epoch)).count(&id(n))
    }

    /// The ranking on what `beacons` heard, with no evidence from an asker.
    fn yields(beacons: &Beacons, ours: &Branch, theirs: &Branch) -> bool {
        beacons.yields(provider().crypto(), "convo-a", &NO_KEYS, ours, theirs, &[])
    }

    /// `(branch id, signer)` pairs at epoch 41, each verified.
    fn vouched(pairs: &[(u64, u8)]) -> Beacons {
        let mut beacons = Beacons::default();
        for &(n, key) in pairs {
            beacons.store.vouch(admitted(41, n).beacon(), vec![key]);
        }
        beacons
    }

    #[test]
    fn each_signer_counts_once_per_branch() {
        let p = provider();
        let (a, a_pub) = leaf_key(&p);
        let (b, b_pub) = leaf_key(&p);
        let (c, c_pub) = leaf_key(&p);
        let roster = [a_pub, b_pub, c_pub];
        let mut beacons = Beacons::default();
        let mut again = beacon(41, &id(1));
        again.external_hpke_pub = vec![2; crate::inbox_v2::HPKE_PUBLIC_KEY_LEN].into();

        for (b, key) in [
            (beacon(41, &id(1)), &a),
            (beacon(41, &id(1)), &b),
            (again, &a),
            (beacon(41, &id(2)), &c),
        ] {
            let bytes = frame(&signed(&p, b, key));
            receive(&mut beacons, p.crypto(), &roster, &bytes);
        }

        assert_eq!(signer_count(&beacons, 41, 1), 2);
        assert_eq!(signer_count(&beacons, 41, 2), 1);
    }

    /// Verify once, then forget the counts and offer no keys: a repeat of the
    /// same frame must still credit its signer, so it was answered from the
    /// cache.
    #[test]
    fn a_repeated_frame_is_not_verified_again() {
        let p = provider();
        let (private, public) = leaf_key(&p);
        let bytes = frame(&signed(&p, beacon(41, &id(1)), &private));
        let mut beacons = Beacons::default();

        receive(&mut beacons, p.crypto(), &[&public], &bytes);
        beacons.store.signers.clear();
        receive(&mut beacons, p.crypto(), &NO_KEYS, &bytes);

        assert_eq!(signer_count(&beacons, 41, 1), 1);
    }

    #[test]
    fn a_beacon_no_member_signed_is_dropped() {
        let p = provider();
        let (outsider, _) = leaf_key(&p);
        let (_, member) = leaf_key(&p);
        let bytes = frame(&signed(&p, beacon(41, &id(1)), &outsider));
        let mut beacons = Beacons::default();

        receive(&mut beacons, p.crypto(), &[&member], &bytes);

        assert!(beacons.store.signers.is_empty());
        assert!(beacons.verified.is_empty());
    }

    /// Members 0 to 3, each with a leaf key.
    struct Members {
        p: MlsEphemeralPqProvider,
        keys: Vec<(Vec<u8>, Vec<u8>)>,
    }

    /// What one member heard, and the roster it verifies against.
    struct View {
        beacons: Beacons,
        roster: Vec<Vec<u8>>,
    }

    impl View {
        fn evidence(&self, epoch: u64, own_id: &str) -> Vec<Vouches> {
            self.beacons.evidence(epoch, own_id)
        }
    }

    impl Members {
        fn new() -> Self {
            let p = provider();
            let keys = (0..4).map(|_| leaf_key(&p)).collect();
            Self { p, keys }
        }

        /// On a roster of the first `roster` members, having heard each
        /// `(branch id, signer)` beacon at epoch 41.
        fn hearing(&self, roster: usize, pairs: &[(u64, usize)]) -> View {
            let roster: Vec<_> = self.keys[..roster].iter().map(|(_, k)| k.clone()).collect();
            let mut beacons = Beacons::default();
            for &(n, k) in pairs {
                let bytes = frame(&signed(&self.p, beacon(41, &id(n)), &self.keys[k].0));
                receive(&mut beacons, self.p.crypto(), &roster, &bytes);
            }
            View { beacons, roster }
        }

        fn yields(&self, v: &View, ours: u64, theirs: u64, evidence: &[Vouches]) -> bool {
            v.beacons.yields(
                self.p.crypto(),
                "convo-a",
                &v.roster,
                &branch(41, ours),
                &branch(41, theirs),
                evidence,
            )
        }
    }

    /// Branch 1 is signed by members 0 and 1, branch 2 by 2 and 3, and each
    /// side missed one of the other's beacons. Alone each thinks it is the
    /// stronger; on each other's evidence both see the tie, which branch 1 wins.
    #[test]
    fn both_sides_rank_alike_on_each_others_evidence() {
        let m = Members::new();
        let asker = m.hearing(4, &[(1, 0), (1, 1), (2, 2)]);
        let answerer = m.hearing(4, &[(1, 0), (2, 2), (2, 3)]);
        assert!(!m.yields(&asker, 1, 2, &[]) && !m.yields(&answerer, 2, 1, &[]));

        assert!(m.yields(&answerer, 2, 1, &asker.evidence(41, &id(1))));
        assert!(!m.yields(&asker, 1, 2, &answerer.evidence(41, &id(2))));
    }

    /// Member 3 joined the asker's branch after the fork, so the answerer's
    /// roster lacks its key.
    #[test]
    fn evidence_from_outside_our_roster_counts_for_nothing() {
        let m = Members::new();
        let asker = m.hearing(4, &[(1, 0), (1, 3)]);
        let answerer = m.hearing(3, &[(2, 1), (2, 2)]);

        assert!(!m.yields(&answerer, 2, 1, &asker.evidence(41, &id(1))));
    }

    /// We saw member 0 sign branch 2, the asker shows it signing branch 1.
    #[test]
    fn a_key_shown_on_another_branch_counts_for_neither() {
        let m = Members::new();
        let asker = m.hearing(4, &[(1, 0)]);
        let answerer = m.hearing(4, &[(2, 0)]);

        assert!(!m.yields(&answerer, 2, 1, &asker.evidence(41, &id(1))));
    }

    /// Member 0's vouch arrives both ways, and counts once.
    #[test]
    fn a_vouch_we_also_heard_counts_once() {
        let m = Members::new();
        let asker = m.hearing(4, &[(1, 0)]);
        let answerer = m.hearing(4, &[(1, 0), (2, 2), (2, 3)]);

        assert!(!m.yields(&answerer, 2, 1, &asker.evidence(41, &id(1))));
    }

    /// The asker's evidence with member 1's vouch relabelled as member 0's.
    #[test]
    fn a_vouch_must_be_signed_by_the_key_it_names() {
        let m = Members::new();
        let asker = m.hearing(4, &[(1, 1)]);
        let answerer = m.hearing(4, &[(2, 2)]);
        let mut evidence = asker.evidence(41, &id(1));
        evidence[0].vouches[0].signer_key = m.keys[0].1.clone().into();

        assert!(!m.yields(&answerer, 2, 1, &evidence));
    }

    /// We were on branch 9 at epoch 41.
    fn on_branch_9(pairs: &[(u64, u64, u8)]) -> Beacons {
        let mut beacons = Beacons::default();
        beacons.states.push_back((41, id(9)));
        for &(epoch, n, key) in pairs {
            beacons.store.vouch(admitted(epoch, n).beacon(), vec![key]);
        }
        beacons
    }

    fn target(beacons: &Beacons) -> Option<(u64, String)> {
        let (to, _) = beacons.seal_target()?;
        Some((to.epoch, to.epoch_id.clone()))
    }

    #[test]
    fn the_target_is_the_most_signed_other_branch() {
        let beacons = on_branch_9(&[
            (41, 9, 0),
            (41, 9, 7),
            (41, 9, 8),
            (41, 1, 1),
            (41, 3, 2),
            (41, 3, 3),
            (41, 2, 4),
            (41, 2, 5),
            (41, 2, 6),
        ]);

        assert_eq!(target(&beacons), Some((41, id(2))));
    }

    #[test]
    fn the_target_comes_with_its_signers() {
        let beacons = on_branch_9(&[(41, 2, 4), (41, 2, 5), (41, 1, 1)]);

        let (_, vouchers) = beacons.seal_target().expect("a target");
        assert_eq!(vouchers, [vec![4], vec![5]]);
    }

    /// The signers choose the id, so a smaller one must not break the tie.
    #[test]
    fn two_branches_that_tie_are_no_target() {
        let beacons = on_branch_9(&[(41, 9, 0), (41, 3, 2), (41, 3, 3), (41, 0, 4), (41, 0, 5)]);

        assert_eq!(target(&beacons), None);
    }

    /// Member 1 signed branch 1 at 41 and then a state at 43, so 41's state is
    /// behind its own branch and no longer opens.
    #[test]
    fn a_state_whose_signers_moved_on_is_not_a_target() {
        let beacons = on_branch_9(&[(41, 1, 1), (41, 1, 2), (43, 5, 1)]);

        assert_eq!(target(&beacons), Some((43, id(5))));
    }

    /// A verified beacon for `(epoch, n)` advertising key `[k; ..]`.
    fn keyed(epoch: u64, n: u64, k: u8) -> Admitted {
        let mut b = beacon(epoch, &id(n));
        b.external_hpke_pub = vec![k; crate::inbox_v2::HPKE_PUBLIC_KEY_LEN].into();
        external::admit(b).expect("well formed")
    }

    fn sealed_key(beacons: &Beacons) -> Option<u8> {
        Some(beacons.seal_target()?.0.external_hpke_pub[0])
    }

    /// A member signs branch 1 with key 7. An outsider copies its epoch and id
    /// under key 6, and branch 2 arrives unsigned: neither counts or is sealed to.
    #[test]
    fn a_forged_or_unsigned_beacon_never_counts_or_becomes_a_target() {
        let p = provider();
        let (member, public) = leaf_key(&p);
        let (outsider, _) = leaf_key(&p);
        let mut beacons = on_branch_9(&[]);

        let real = signed(&p, keyed(41, 1, 7).beacon().clone(), &member);
        let copy = signed(&p, keyed(41, 1, 6).beacon().clone(), &outsider);
        for b in [real, copy, beacon(41, &id(2))] {
            receive(&mut beacons, p.crypto(), &[&public], &frame(&b));
        }

        assert_eq!(sealed_key(&beacons), Some(7));
        assert_eq!(signer_count(&beacons, 41, 1), 1);
        assert_eq!(signer_count(&beacons, 41, 2), 0);
    }

    /// One signer on key 6 arrives first, two on key 7 after.
    #[test]
    fn a_branch_is_sealed_to_its_most_signed_key() {
        let mut beacons = on_branch_9(&[]);
        beacons.store.vouch(keyed(41, 1, 6).beacon(), vec![1]);
        beacons.store.vouch(keyed(41, 1, 7).beacon(), vec![2]);
        beacons.store.vouch(keyed(41, 1, 7).beacon(), vec![3]);

        assert_eq!(sealed_key(&beacons), Some(7));
        assert_eq!(signer_count(&beacons, 41, 1), 2);
    }

    #[test]
    fn a_branch_whose_keys_tie_is_not_a_target() {
        let mut beacons = on_branch_9(&[]);
        beacons.store.vouch(keyed(41, 1, 6).beacon(), vec![1]);
        beacons.store.vouch(keyed(41, 1, 7).beacon(), vec![2]);

        assert!(beacons.seal_target().is_none());
    }

    /// Member 9 vouches for many far-future epochs; member 1's count at 41
    /// must survive, and member 9 loses only its own oldest.
    #[test]
    fn a_member_signing_far_ahead_evicts_only_itself() {
        let mut store = BeaconStore::default();
        store.vouch(admitted(41, 1).beacon(), vec![1]);
        for epoch in 1000..1000 + SIGNED_EPOCHS_RETAINED as u64 + 1 {
            store.vouch(admitted(epoch, epoch).beacon(), vec![9]);
        }

        assert!(store.signers.contains_key(&41));
        assert!(!store.signers.contains_key(&1000), "its own oldest");
        assert_eq!(store.signers.len(), SIGNED_EPOCHS_RETAINED + 1);
    }

    #[test]
    fn a_key_that_signs_two_branches_counts_for_neither() {
        let beacons = vouched(&[(1, 1), (2, 1), (1, 2), (1, 1)]);

        assert_eq!(signer_count(&beacons, 41, 1), 1);
        assert_eq!(signer_count(&beacons, 41, 2), 0);
    }

    #[test]
    fn the_lowest_epoch_signers_are_forgotten_first() {
        let mut store = BeaconStore::default();
        for epoch in (0..=SIGNED_EPOCHS_RETAINED as u64).rev() {
            store.vouch(admitted(epoch, epoch).beacon(), vec![1]);
        }

        assert_eq!(store.signers.len(), SIGNED_EPOCHS_RETAINED);
        assert!(!store.signers.contains_key(&0));
        assert!(store.signers.contains_key(&64));
    }

    #[test]
    fn the_branch_with_more_signers_wins() {
        let beacons = vouched(&[(1, 1), (2, 2), (2, 3)]);

        assert!(yields(&beacons, &branch(41, 1), &branch(41, 2)));
        assert!(!yields(&beacons, &branch(41, 2), &branch(41, 1)));
    }

    #[test]
    fn a_tie_goes_to_the_smaller_verified_id() {
        let beacons = vouched(&[(1, 1), (2, 2)]);

        assert!(yields(&beacons, &branch(41, 2), &branch(41, 1)));
        assert!(!yields(&beacons, &branch(41, 1), &branch(41, 2)));
    }

    /// An asker can claim any id; with nobody vouching for it, a smaller one
    /// must not win the tie at zero.
    #[test]
    fn an_unvouched_branch_never_wins() {
        let beacons = Beacons::default();

        assert!(!yields(&beacons, &branch(41, 2), &branch(41, 1)));
    }

    /// Id 2 is strong at epoch 41, but the asker names it at epoch 40.
    #[test]
    fn branches_at_different_epochs_are_not_compared() {
        let beacons = vouched(&[(1, 1), (2, 2), (2, 3)]);

        assert!(!yields(&beacons, &branch(41, 1), &branch(40, 2)));
    }

    #[test]
    fn only_the_current_state_has_a_key() {
        let mut beacons = Beacons::default();
        for epoch in 0..STATES_RETAINED as u64 + 1 {
            beacons.hold(epoch, &id(epoch), vec![epoch as u8; 32].into());
        }
        let last = STATES_RETAINED as u64;

        assert!(beacons.key_for(last, &id(last)).is_some());
        assert!(
            beacons.key_for(last - 1, &id(last - 1)).is_none(),
            "an earlier state"
        );
        assert!(beacons.key_for(last, &id(99)).is_none(), "another branch");
        assert_eq!(beacons.our_epoch_id(5), Some(id(5).as_str()));
        assert_eq!(beacons.our_epoch_id(0), None, "oldest state forgotten");
    }

    #[test]
    fn the_verified_cache_is_bounded() {
        let p = provider();
        let (private, public) = leaf_key(&p);
        let mut beacons = Beacons::default();

        for epoch in 0..VERIFIED_RETAINED as u64 + 5 {
            let bytes = frame(&signed(&p, beacon(epoch, &id(epoch)), &private));
            receive(&mut beacons, p.crypto(), &[&public], &bytes);
        }

        assert_eq!(beacons.verified.len(), VERIFIED_RETAINED);
    }

    #[test]
    fn both_branches_at_one_epoch_are_kept() {
        let mut store = BeaconStore::default();
        store.vouch(admitted(41, 5).beacon(), vec![1]);
        store.vouch(admitted(41, 6).beacon(), vec![2]);

        assert_eq!(store.signers[&41].len(), 2);
    }
}
