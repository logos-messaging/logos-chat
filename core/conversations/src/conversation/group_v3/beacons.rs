//! What a member does with beacons: make its own once per epoch, and keep the
//! verified ones it hears. Sending is left to the conversation.

use std::collections::VecDeque;
use std::time::Duration;

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use openmls::group::MlsGroup;
use openmls_traits::OpenMlsProvider as _;
use openmls_traits::crypto::OpenMlsCrypto;
use tracing::{debug, warn};

use super::external::{self, Admitted, EpochBeacon};
use crate::ExternalServices;
use crate::service_context::ServiceContext;

/// Beacons kept in [`BeaconStore`].
const BEACONS_RETAINED: usize = 8;

/// Digests of verified frames remembered, so a repeat skips verification.
const VERIFIED_RETAINED: usize = 64;

/// Frames for the next epoch held until we enter it. A member who joins there
/// signs before we have merged the commit that added them.
const AHEAD_RETAINED: usize = 8;

/// How far past our epoch a beacon may claim to be. Bounds how far a member
/// can push the store with made-up epochs.
const EPOCHS_AHEAD: u64 = 64;

const FIRST_RETRY: Duration = Duration::from_secs(1);
const LAST_RETRY: Duration = Duration::from_secs(60);

#[derive(Debug, Default)]
pub struct Beacons {
    store: BeaconStore,
    /// Epoch our beacon was made for.
    epoch: Option<u64>,
    /// Frames already verified this epoch.
    verified: VecDeque<[u8; 32]>,
    /// Frames for the next epoch that no current member signed.
    ahead: VecDeque<Vec<u8>>,
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
        self.retry_in = FIRST_RETRY;
        self.due_at = Duration::ZERO;

        if let Err(e) = self.prepare(cx, group, convo_id) {
            warn!(convo = convo_id, error = %e, "no beacon this epoch");
        }

        let crypto = cx.mls_provider.crypto();
        let keys: Vec<_> = group.members().map(|m| m.signature_key).collect();
        for bytes in std::mem::take(&mut self.ahead) {
            self.receive_frame(crypto, convo_id, &keys, &bytes);
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
        beacon.signature = external::sign_beacon(&beacon, convo_id, &cx.mls_identity)?;

        // Our own state is held like any heard one.
        if let Some(own) = external::admit(beacon.clone()) {
            self.store.remember(own);
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

    /// A beacon frame heard on the wire, kept only if one of `keys`, our
    /// state's leaf keys, signed it. `keys` is read only for a new frame.
    pub fn receive_frame<I, K>(
        &mut self,
        crypto: &impl OpenMlsCrypto,
        convo_id: &str,
        keys: I,
        bytes: &[u8],
    ) where
        I: IntoIterator<Item = K>,
        K: AsRef<[u8]>,
    {
        let Some(beacon) = external::admit_frame(bytes) else {
            debug!(convo = convo_id, "refused a malformed beacon frame");
            return;
        };
        let epoch = beacon.beacon().epoch;
        let ours = self.epoch.unwrap_or_default();
        if epoch > ours + EPOCHS_AHEAD {
            debug!(convo = convo_id, epoch, "refused a beacon too far ahead");
            return;
        }

        let digest: [u8; 32] = Blake2b::<U32>::digest(bytes).into();
        if !self.verified.contains(&digest) {
            if !external::verify_beacon(crypto, convo_id, beacon.beacon(), keys) {
                if epoch == ours + 1 && !self.ahead.iter().any(|b| b == bytes) {
                    if self.ahead.len() == AHEAD_RETAINED {
                        self.ahead.pop_front();
                    }
                    self.ahead.push_back(bytes.to_vec());
                }
                debug!(convo = convo_id, "refused a beacon no member signed");
                return;
            }
            if self.verified.len() == VERIFIED_RETAINED {
                self.verified.pop_front();
            }
            self.verified.push_back(digest);
        }
        self.store.remember(beacon);
    }
}

/// Recent verified beacons.
#[derive(Debug, Default)]
struct BeaconStore {
    beacons: Vec<Admitted>,
}

impl BeaconStore {
    /// Keep the beacon, newest epoch first, one per state. Every member derives
    /// the same key for a state, so the first one heard stays.
    fn remember(&mut self, beacon: Admitted) {
        if self.beacons.iter().any(|held| same_state(held, &beacon)) {
            return;
        }
        self.beacons.push(beacon);
        self.beacons
            .sort_by_key(|b| std::cmp::Reverse(b.beacon().epoch));
        self.beacons.truncate(BEACONS_RETAINED);
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

    fn admitted(epoch: u64, n: u64) -> Admitted {
        external::admit(beacon(epoch, &id(n))).expect("well formed")
    }

    const NO_KEYS: [&[u8]; 0] = [];

    /// Verify once, then offer no keys: a repeat of the same frame must still
    /// be kept, so it was answered from the cache.
    #[test]
    fn a_repeated_frame_is_not_verified_again() {
        let p = provider();
        let (private, public) = leaf_key(&p);
        let bytes = frame(&signed(&p, beacon(41, &id(1)), &private));
        let mut beacons = Beacons::default();

        beacons.receive_frame(p.crypto(), "convo-a", [&public], &bytes);
        beacons.store.beacons.clear();
        beacons.receive_frame(p.crypto(), "convo-a", NO_KEYS, &bytes);

        assert_eq!(beacons.store.beacons.len(), 1);
    }

    #[test]
    fn a_beacon_no_member_signed_is_dropped() {
        let p = provider();
        let (outsider, _) = leaf_key(&p);
        let (_, member) = leaf_key(&p);
        let bytes = frame(&signed(&p, beacon(41, &id(1)), &outsider));
        let mut beacons = Beacons::default();

        beacons.receive_frame(p.crypto(), "convo-a", [&member], &bytes);

        assert!(beacons.store.beacons.is_empty());
        assert!(beacons.verified.is_empty());
    }

    #[test]
    fn the_verified_cache_is_bounded() {
        let p = provider();
        let (private, public) = leaf_key(&p);
        let mut beacons = Beacons::default();

        for epoch in 0..VERIFIED_RETAINED as u64 + 5 {
            let bytes = frame(&signed(&p, beacon(epoch, &id(epoch)), &private));
            beacons.receive_frame(p.crypto(), "convo-a", [&public], &bytes);
        }

        assert_eq!(beacons.verified.len(), VERIFIED_RETAINED);
    }

    #[test]
    fn the_first_key_for_a_state_stays() {
        let mut store = BeaconStore::default();
        store.remember(admitted(41, 4));
        let first = store.beacons[0].beacon().external_hpke_pub.clone();
        let mut other = beacon(41, &id(4));
        other.external_hpke_pub = vec![2; crate::inbox_v2::HPKE_PUBLIC_KEY_LEN].into();
        store.remember(external::admit(other).unwrap());

        assert_eq!(store.beacons.len(), 1);
        assert_eq!(store.beacons[0].beacon().external_hpke_pub, first);
    }

    #[test]
    fn a_beacon_too_far_ahead_is_dropped() {
        let p = provider();
        let (private, public) = leaf_key(&p);
        let bytes = frame(&signed(&p, beacon(EPOCHS_AHEAD + 1, &id(1)), &private));
        let mut beacons = Beacons::default();

        beacons.receive_frame(p.crypto(), "convo-a", [&public], &bytes);

        assert!(beacons.store.beacons.is_empty());
    }

    /// A joiner's first beacon reaches us before we merge the commit that added
    /// them. It is kept for the next epoch, not dropped.
    #[test]
    fn a_beacon_for_the_next_epoch_waits_for_its_roster() {
        let p = provider();
        let (joiner, _) = leaf_key(&p);
        let (_, member) = leaf_key(&p);
        let bytes = frame(&signed(&p, beacon(1, &id(1)), &joiner));
        let mut beacons = Beacons::default();

        beacons.receive_frame(p.crypto(), "convo-a", [&member], &bytes);
        assert!(beacons.store.beacons.is_empty());
        assert_eq!(beacons.ahead.len(), 1);

        let far = frame(&signed(&p, beacon(2, &id(2)), &joiner));
        beacons.receive_frame(p.crypto(), "convo-a", [&member], &far);
        assert_eq!(beacons.ahead.len(), 1, "only the next epoch waits");
    }

    #[test]
    fn both_branches_at_one_epoch_are_kept() {
        let mut store = BeaconStore::default();
        store.remember(admitted(41, 5));
        store.remember(admitted(41, 6));

        assert_eq!(store.beacons.len(), 2);
    }

    #[test]
    fn the_store_keeps_the_newest_epochs() {
        let mut store = BeaconStore::default();
        for epoch in 0..BEACONS_RETAINED as u64 + 3 {
            store.remember(admitted(epoch, epoch));
        }

        assert_eq!(store.beacons.len(), BEACONS_RETAINED);
        assert_eq!(store.beacons[0].beacon().epoch, BEACONS_RETAINED as u64 + 2);
    }
}
