//! What a member does with beacons: publish its own once per epoch, and keep
//! the ones it hears.

use std::collections::VecDeque;
use std::time::Duration;

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use openmls::group::MlsGroup;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::Ciphersuite;
use prost::Message as _;
use tracing::{debug, warn};

use super::external::{self, Admitted, GroupV3External};
use super::payloads::to_external_envelope;
use crate::service_context::ServiceContext;
use crate::{AddressedEnvelope, DeliveryService, ExternalServices};

/// Beacons kept per bucket in [`BeaconStore`].
const BEACONS_RETAINED: usize = 8;

/// Digests of verified frames remembered, so a repeat skips verification.
const VERIFIED_RETAINED: usize = 64;

const FIRST_RETRY: Duration = Duration::from_secs(1);
const LAST_RETRY: Duration = Duration::from_secs(60);

#[derive(Debug, Default)]
pub struct Beacons {
    store: BeaconStore,
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
    /// When to try `outgoing` again. Checked on the conversation's SDS tick,
    /// so beacons schedule no wakeups of their own.
    retry_at: Duration,
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
                self.retry_at = cx.clock.now() + self.retry_in;
                self.retry_in = (self.retry_in * 2).min(LAST_RETRY);
            }
        }
    }

    /// Retry delivery once it is due.
    pub fn wakeup<S: ExternalServices>(&mut self, convo_id: &str, cx: &mut ServiceContext<S>) {
        if cx.clock.now() >= self.retry_at {
            self.deliver(convo_id, cx);
        }
    }

    /// Our own beacon, for a message's AAD. Empty if there is none this epoch.
    pub fn aad(&self) -> &[u8] {
        &self.aad
    }

    /// A beacon frame heard on the wire. Kept even if it fails to verify; see
    /// [`BeaconStore`].
    pub fn receive_frame(
        &mut self,
        crypto: &impl OpenMlsCrypto,
        convo_id: &str,
        ours: Ciphersuite,
        bytes: &[u8],
    ) {
        let Some(beacon) = external::admit_frame(bytes, ours) else {
            debug!(convo = convo_id, "refused a malformed beacon frame");
            return;
        };

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
    /// Keep the beacon, newest epoch first, one per state.
    fn remember(&mut self, beacon: Admitted, verified: bool) {
        let bucket = if verified {
            &mut self.verified
        } else {
            &mut self.unverified
        };

        bucket.retain(|held| !same_state(held, &beacon));
        bucket.push(beacon);
        bucket.sort_by_key(|b| std::cmp::Reverse(b.beacon().epoch));
        bucket.truncate(BEACONS_RETAINED);
    }
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

        beacons.receive_frame(p.crypto(), "convo-a", CIPHER_SUITE, &bytes);
        beacons.roster_keys.clear();
        beacons.receive_frame(p.crypto(), "convo-a", CIPHER_SUITE, &bytes);

        assert_eq!(beacons.store.verified.len(), 1);
        assert!(beacons.store.unverified.is_empty());
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
            beacons.receive_frame(p.crypto(), "convo-a", CIPHER_SUITE, &bytes);
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

    #[test]
    fn an_unverified_beacon_is_kept_in_its_own_bucket() {
        let mut store = BeaconStore::default();
        store.remember(admitted(41, 8), false);

        assert!(store.verified.is_empty());
        assert_eq!(store.unverified.len(), 1);
    }
}
