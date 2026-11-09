//! What a member does with beacons: publish its own once per epoch, and keep
//! the ones it hears.

use std::collections::{HashSet, VecDeque};
use std::time::Duration;

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use openmls::group::MlsGroup;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::{Ciphersuite, HpkePrivateKey};
use prost::Message as _;
use tracing::warn;

use super::external::{self, Admitted, EpochBeacon, GroupV3External};
use super::payloads::to_external_envelope;
use crate::service_context::ServiceContext;
use crate::{AddressedEnvelope, DeliveryService, ExternalServices, WakeupService};

/// Beacons kept per bucket in [`BeaconStore`].
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
    /// Epoch used to prepare the cached beacon and roster.
    epoch: Option<u64>,
    /// Leaf signature keys of this epoch's roster. Taken once per epoch:
    /// `MlsGroup::members` copies every member's whole leaf.
    roster_keys: Vec<Vec<u8>>,
    /// Frames already verified against `roster_keys`.
    verified: VecDeque<[u8; 32]>,
    /// Our own unsigned beacon, encoded, for the AAD of every message.
    aad: Vec<u8>,
    /// Our own signed beacon frame, until it is delivered.
    outgoing: Option<AddressedEnvelope>,
    retry_in: Duration,
    /// A retry wakeup is queued. Only scheduling sets it and only a wakeup
    /// clears it: an epoch change or a delivery leaves the wakeup queued.
    /// Assumes beacons own every GroupV3 wakeup; once anything else schedules
    /// one, this needs tagged timers.
    timer_armed: bool,
}

impl Beacons {
    /// Prepare once per epoch; retry delivery without failing the conversation
    /// operation.
    pub fn enter_epoch<S: ExternalServices>(
        &mut self,
        group: &MlsGroup,
        convo_id: &str,
        cx: &mut ServiceContext<S>,
    ) {
        let epoch = group.epoch().as_u64();
        if self.epoch == Some(epoch) {
            return;
        }
        self.epoch = Some(epoch);
        self.roster_keys = group.members().map(|m| m.signature_key).collect();
        self.verified.clear();
        self.aad.clear();
        self.outgoing = None;
        self.key = None;
        self.retry_in = FIRST_RETRY;

        if let Err(e) = self.prepare(group, convo_id, cx) {
            warn!(convo = convo_id, error = %e, "no beacon this epoch");
            return;
        }
        self.deliver(convo_id, cx);
    }

    fn prepare<S: ExternalServices>(
        &mut self,
        group: &MlsGroup,
        convo_id: &str,
        cx: &ServiceContext<S>,
    ) -> Result<(), external::ExternalError> {
        let keys = external::derive_external_keys(group, &cx.mls_provider)?;
        let mut beacon = external::beacon_for_epoch(group, keys.public.into());
        self.aad = beacon.encode_to_vec();
        self.hold(beacon.epoch, &beacon.epoch_id, keys.private);

        beacon.signature = external::sign_beacon(&beacon, convo_id, &cx.mls_identity)?;
        let frame = GroupV3External::beacon(beacon.clone()).encode_to_vec();
        self.outgoing = Some(to_external_envelope(convo_id, frame));

        // Kept so a request can later be sealed to every branch *but* ours.
        if let Some(own) = external::admit(beacon, group.ciphersuite()) {
            self.store.remember(own, true);
        }
        Ok(())
    }

    /// Send our beacon if it hasn't gone out; on failure, try again later.
    fn deliver<S: ExternalServices>(&mut self, convo_id: &str, cx: &mut ServiceContext<S>) {
        let Some(envelope) = &self.outgoing else {
            return;
        };
        match cx.ds.publish(envelope.clone()) {
            Ok(()) => self.outgoing = None,
            Err(e) => {
                warn!(convo = convo_id, error = %e, "beacon not delivered");
                // An armed timer, even one from an earlier epoch, retries this.
                if !self.timer_armed {
                    cx.wakeup_service
                        .wakeup_in(self.retry_in, convo_id.to_string());
                    self.timer_armed = true;
                    self.retry_in = (self.retry_in * 2).min(LAST_RETRY);
                }
            }
        }
    }

    /// Our retry timer fired.
    pub fn wakeup<S: ExternalServices>(&mut self, convo_id: &str, cx: &mut ServiceContext<S>) {
        self.timer_armed = false;
        self.deliver(convo_id, cx);
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

    /// One beacon per state we were never in, verified first.
    pub fn seal_targets(&self) -> impl Iterator<Item = &EpochBeacon> {
        let mut seen = HashSet::new();
        self.store
            .verified
            .iter()
            .chain(&self.store.unverified)
            .map(Admitted::beacon)
            .filter(move |b| {
                self.our_epoch_id(b.epoch) != Some(b.epoch_id.as_str())
                    && seen.insert((b.epoch, b.epoch_id.as_str()))
            })
    }

    /// Our own beacon, for a message's AAD. Empty if there is none this epoch.
    pub fn aad(&self) -> &[u8] {
        &self.aad
    }

    /// A beacon frame heard on the wire, `bytes` being the whole frame. Kept
    /// even if it fails to verify; see [`BeaconStore`].
    pub fn receive_frame(
        &mut self,
        crypto: &impl OpenMlsCrypto,
        convo_id: &str,
        beacon: Admitted,
        bytes: &[u8],
    ) {
        let digest: [u8; 32] = Blake2b::<U32>::digest(bytes).into();
        let cached = self.verified.contains(&digest);
        let verified =
            cached || external::verify_beacon(crypto, convo_id, beacon.beacon(), &self.roster_keys);
        if verified && !cached {
            if self.verified.len() == VERIFIED_RETAINED {
                self.verified.pop_front();
            }
            self.verified.push_back(digest);
        }
        self.store.remember(beacon, verified);
    }

    /// The unsigned beacon in a message's AAD, kept as unverified.
    pub fn receive_aad(&mut self, ours: Ciphersuite, aad: &[u8], epoch: u64) {
        if let Some(beacon) = external::admit_aad(aad, epoch, ours) {
            self.store.remember(beacon, false);
        }
    }
}

/// Recent beacons, verified and unverified kept in separate budgets.
///
/// Anyone can publish to the address, so a shared list would let forgeries
/// evict the real beacons. Unverified ones are still kept: a member who joined
/// after we forked won't verify against our stale tree.
#[derive(Debug, Default)]
struct BeaconStore {
    verified: Vec<Admitted>,
    unverified: Vec<Admitted>,
}

impl BeaconStore {
    /// One per state. Unverified beacons are kept in arrival order, so
    /// forgeries at a huge epoch can't evict real ones.
    fn remember(&mut self, beacon: Admitted, verified: bool) {
        let bucket = if verified {
            &mut self.verified
        } else {
            &mut self.unverified
        };

        bucket.retain(|held| !same_state(held, &beacon));
        if verified {
            bucket.push(beacon);
            bucket.sort_by_key(|b| std::cmp::Reverse(b.beacon().epoch));
            bucket.truncate(BEACONS_RETAINED);
        } else {
            if bucket.len() == BEACONS_RETAINED {
                bucket.remove(0);
            }
            bucket.push(beacon);
        }
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
    use crate::inbox_v2::CIPHER_SUITE;
    use openmls_traits::OpenMlsProvider as _;

    fn receive(beacons: &mut Beacons, p: &impl OpenMlsCrypto, bytes: &[u8]) {
        let Some(external::Inbound::Beacon(beacon)) = external::admit_frame(bytes, CIPHER_SUITE)
        else {
            panic!("not a beacon frame");
        };
        beacons.receive_frame(p, "convo-a", beacon, bytes);
    }

    fn admitted(epoch: u64, n: u64) -> Admitted {
        external::admit(beacon(epoch, &id(n)), CIPHER_SUITE).expect("well formed")
    }

    /// Verify once, then take the roster away: a repeat of the same frame must
    /// still count as verified, so it was answered from the cache.
    #[test]
    fn a_repeated_frame_is_not_verified_again() {
        let p = provider();
        let (private, public) = leaf_key(&p);
        let bytes = frame(&signed(&p, beacon(41, &id(1)), &private));
        let mut beacons = Beacons {
            roster_keys: vec![public],
            ..Default::default()
        };

        receive(&mut beacons, p.crypto(), &bytes);
        beacons.roster_keys.clear();
        receive(&mut beacons, p.crypto(), &bytes);

        assert_eq!(beacons.store.verified.len(), 1);
        assert!(beacons.store.unverified.is_empty());
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
        let mut beacons = Beacons {
            roster_keys: vec![public],
            ..Default::default()
        };

        for epoch in 0..VERIFIED_RETAINED as u64 + 5 {
            let bytes = frame(&signed(&p, beacon(epoch, &id(epoch)), &private));
            receive(&mut beacons, p.crypto(), &bytes);
        }

        assert_eq!(beacons.verified.len(), VERIFIED_RETAINED);
    }

    #[test]
    fn a_newer_beacon_replaces_one_for_the_same_state() {
        let mut store = BeaconStore::default();
        store.remember(admitted(41, 4), true);
        let mut newer = beacon(41, &id(4));
        newer.external_hpke_pub = vec![2; crate::inbox_v2::HPKE_PUBLIC_KEY_LEN].into();
        store.remember(external::admit(newer, CIPHER_SUITE).unwrap(), true);

        assert_eq!(store.verified.len(), 1);
        assert_eq!(store.verified[0].beacon().external_hpke_pub[0], 2);
    }

    #[test]
    fn both_branches_at_one_epoch_are_kept() {
        let mut store = BeaconStore::default();
        store.remember(admitted(41, 5), true);
        store.remember(admitted(41, 6), true);

        assert_eq!(store.verified.len(), 2);
    }

    #[test]
    fn forgeries_cannot_evict_a_verified_beacon() {
        let mut store = BeaconStore::default();
        store.remember(admitted(41, 7), true);
        for epoch in 100..100 + (BEACONS_RETAINED as u64 * 4) {
            store.remember(admitted(epoch, epoch), false);
        }

        assert_eq!(store.verified.len(), 1);
        assert_eq!(store.verified[0].beacon().epoch_id, id(7));
        assert_eq!(store.unverified.len(), BEACONS_RETAINED);
    }

    /// Anyone can claim any epoch, so a forged huge epoch must not pin the
    /// unverified bucket.
    #[test]
    fn forgeries_at_a_huge_epoch_do_not_pin_the_unverified_bucket() {
        let mut store = BeaconStore::default();
        for k in 0..BEACONS_RETAINED as u64 {
            store.remember(admitted(u64::MAX - k, k), false);
        }
        store.remember(admitted(3, 99), false);

        assert!(store.unverified.iter().any(|b| b.beacon().epoch == 3));
        assert_eq!(store.unverified.len(), BEACONS_RETAINED);
    }

    #[test]
    fn an_unverified_beacon_is_kept_in_its_own_bucket() {
        let mut store = BeaconStore::default();
        store.remember(admitted(41, 8), false);

        assert!(store.verified.is_empty());
        assert_eq!(store.unverified.len(), 1);
    }
}
