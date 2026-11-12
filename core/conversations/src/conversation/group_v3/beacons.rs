//! What a member does with beacons: make its own once per epoch, and keep the
//! verified ones it hears. Sending is left to the conversation.

use std::collections::VecDeque;
use std::time::Duration;

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use openmls::group::MlsGroup;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::HpkePrivateKey;
use tracing::{debug, warn};

use super::external::{self, Admitted, EpochBeacon};
use crate::ExternalServices;
use crate::service_context::ServiceContext;

/// Beacons kept in [`BeaconStore`].
const BEACONS_RETAINED: usize = 8;

/// Digests of verified frames remembered, so a repeat skips verification.
const VERIFIED_RETAINED: usize = 64;

/// Epochs whose state id we remember: never to seal to a state we were in,
/// and to tell an asker that is merely behind.
const STATES_RETAINED: usize = 16;

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

        // Kept so a request can later be sealed to every branch *but* ours.
        if let (Some(own), Some(leaf)) = (external::admit(beacon.clone()), group.own_leaf_node()) {
            self.store
                .remember(own, leaf.signature_key().as_slice().to_vec());
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

    /// The newest states we were never in. An older state is likely
    /// superseded, and a member still in it would answer from behind.
    pub fn seal_targets(&self) -> impl Iterator<Item = &HeardState> {
        let mut others = self
            .store
            .states
            .iter()
            .filter(|s| {
                let b = s.beacon();
                self.our_epoch_id(b.epoch) != Some(b.epoch_id.as_str())
            })
            .peekable();
        let newest = others.peek().map(|s| s.beacon().epoch);
        others.take_while(move |s| Some(s.beacon().epoch) == newest)
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
        self.store.remember(beacon, signer);
    }
}

/// A state we heard, and the members whose beacons for it verified: each is
/// on our roster and in that state.
#[derive(Debug)]
pub struct HeardState {
    beacon: Admitted,
    signers: Vec<Vec<u8>>,
}

impl HeardState {
    pub fn beacon(&self) -> &EpochBeacon {
        self.beacon.beacon()
    }

    /// Leaf signature keys, in the order first heard.
    pub fn signers(&self) -> &[Vec<u8>] {
        &self.signers
    }
}

/// Recent verified states. Signers come from our roster, so they are bounded
/// by it.
#[derive(Debug, Default)]
struct BeaconStore {
    states: Vec<HeardState>,
}

impl BeaconStore {
    /// Keep the beacon, newest epoch first, one entry per state.
    fn remember(&mut self, beacon: Admitted, signer: Vec<u8>) {
        if let Some(held) = self
            .states
            .iter_mut()
            .find(|s| same_state(&s.beacon, &beacon))
        {
            held.beacon = beacon;
            if !held.signers.contains(&signer) {
                held.signers.push(signer);
            }
            return;
        }
        self.states.push(HeardState {
            beacon,
            signers: vec![signer],
        });
        self.states
            .sort_by_key(|s| std::cmp::Reverse(s.beacon().epoch));
        self.states.truncate(BEACONS_RETAINED);
    }
}

#[derive(Debug)]
struct HeldKey {
    epoch: u64,
    epoch_id: String,
    private: HpkePrivateKey,
}

/// Two branches of a fork share an epoch number, so compare the id too.
fn same_state(a: &Admitted, b: &Admitted) -> bool {
    a.beacon().epoch == b.beacon().epoch && a.beacon().epoch_id == b.beacon().epoch_id
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conversation::group_v3::external::tests::{
        beacon, frame, id, leaf_key, provider, signed,
    };
    use openmls_traits::OpenMlsProvider as _;

    fn admitted(epoch: u64, n: u64) -> Admitted {
        external::admit(beacon(epoch, &id(n))).expect("well formed")
    }

    const NO_KEYS: [&[u8]; 0] = [];

    fn key(n: u8) -> Vec<u8> {
        vec![n; 32]
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

    /// Verify once, then offer no keys: a repeat of the same frame must still
    /// be kept, so it was answered from the cache.
    #[test]
    fn a_repeated_frame_is_not_verified_again() {
        let p = provider();
        let (private, public) = leaf_key(&p);
        let bytes = frame(&signed(&p, beacon(41, &id(1)), &private));
        let mut beacons = Beacons::default();

        receive(&mut beacons, p.crypto(), &[&public], &bytes);
        beacons.store.states.clear();
        receive(&mut beacons, p.crypto(), &NO_KEYS, &bytes);

        assert_eq!(beacons.store.states.len(), 1);
        assert_eq!(beacons.store.states[0].signers(), [public]);
    }

    #[test]
    fn a_beacon_no_member_signed_is_dropped() {
        let p = provider();
        let (outsider, _) = leaf_key(&p);
        let (_, member) = leaf_key(&p);
        let bytes = frame(&signed(&p, beacon(41, &id(1)), &outsider));
        let mut beacons = Beacons::default();

        receive(&mut beacons, p.crypto(), &[&member], &bytes);

        assert!(beacons.store.states.is_empty());
        assert!(beacons.verified.is_empty());
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
    fn a_newer_beacon_replaces_one_for_the_same_state() {
        let mut store = BeaconStore::default();
        store.remember(admitted(41, 4), key(1));
        let mut newer = beacon(41, &id(4));
        newer.external_hpke_pub = vec![2; crate::inbox_v2::HPKE_PUBLIC_KEY_LEN].into();
        store.remember(external::admit(newer).unwrap(), key(1));

        assert_eq!(store.states.len(), 1);
        assert_eq!(store.states[0].beacon().external_hpke_pub[0], 2);
    }

    #[test]
    fn every_member_heard_in_a_state_is_kept_once() {
        let mut store = BeaconStore::default();
        for k in [1, 2, 1] {
            store.remember(admitted(41, 4), key(k));
        }

        assert_eq!(store.states[0].signers(), [key(1), key(2)]);
    }

    #[test]
    fn both_branches_at_one_epoch_are_kept() {
        let mut store = BeaconStore::default();
        store.remember(admitted(41, 5), key(1));
        store.remember(admitted(41, 6), key(1));

        assert_eq!(store.states.len(), 2);
    }

    /// A branch's older states are superseded: a member still in one would
    /// answer from behind and fork itself.
    #[test]
    fn only_the_newest_other_states_are_sealed_to() {
        let mut beacons = Beacons::default();
        beacons.hold(7, &id(7), vec![7; 32].into());
        for (epoch, n) in [(7, 7), (5, 1), (6, 2), (6, 3)] {
            beacons.store.remember(admitted(epoch, n), key(1));
        }

        let targets: Vec<_> = beacons
            .seal_targets()
            .map(|s| (s.beacon().epoch, s.beacon().epoch_id.clone()))
            .collect();
        assert_eq!(targets, [(6, id(2)), (6, id(3))]);
    }

    #[test]
    fn the_store_keeps_the_newest_epochs() {
        let mut store = BeaconStore::default();
        for epoch in 0..BEACONS_RETAINED as u64 + 3 {
            store.remember(admitted(epoch, epoch), key(1));
        }

        assert_eq!(store.states.len(), BEACONS_RETAINED);
        assert_eq!(store.states[0].beacon().epoch, BEACONS_RETAINED as u64 + 2);
    }
}
