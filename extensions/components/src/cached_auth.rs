//! An [`AuthService`] that remembers each participant's endorsed signers for a TTL.
//!
//! Only a positive answer is served from the cache: a signer missing from the
//! cached list, a miss, or an error goes to the inner service, so a fresh
//! endorsement is seen at once and the inner service alone tells `Revoked`
//! from `Invalid`. The cost is that a revocation goes unseen until the entry
//! expires.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use libchat::{AuthResult, AuthService, ParticipantId, SignerKey};

#[derive(Debug)]
pub struct CachedAuth<A> {
    inner: A,
    ttl: Duration,
    signers: Mutex<HashMap<ParticipantId, (Instant, Vec<SignerKey>)>>,
}

impl<A: AuthService> CachedAuth<A> {
    pub fn new(inner: A, ttl: Duration) -> Self {
        Self {
            inner,
            ttl,
            signers: Mutex::new(HashMap::new()),
        }
    }

    fn cached(&self, id: &ParticipantId) -> Option<Vec<SignerKey>> {
        let map = self.signers.lock().unwrap();
        map.get(id)
            .filter(|(at, _)| at.elapsed() < self.ttl)
            .map(|(_, signers)| signers.clone())
    }
}

impl<A: AuthService> AuthService for CachedAuth<A> {
    type Error = A::Error;

    fn validate_signer(
        &self,
        signer_key: SignerKey,
        participant_id: ParticipantId,
    ) -> Result<AuthResult, Self::Error> {
        if self
            .cached(&participant_id)
            .is_some_and(|signers| signers.contains(&signer_key))
        {
            return Ok(AuthResult::Valid);
        }
        self.inner.validate_signer(signer_key, participant_id)
    }

    fn signers_for_participant(
        &self,
        participant_id: &ParticipantId,
    ) -> Result<Vec<SignerKey>, Self::Error> {
        if let Some(signers) = self.cached(participant_id) {
            return Ok(signers);
        }
        let signers = self.inner.signers_for_participant(participant_id)?;
        self.signers
            .lock()
            .unwrap()
            .insert(participant_id.clone(), (Instant::now(), signers.clone()));
        Ok(signers)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    /// Endorses one signer and counts lookups.
    #[derive(Debug)]
    struct Counting {
        signer: SignerKey,
        lookups: Cell<u32>,
    }

    impl Counting {
        fn new(signer: &SignerKey) -> Self {
            Self {
                signer: signer.clone(),
                lookups: Cell::new(0),
            }
        }
    }

    impl AuthService for Counting {
        type Error = String;

        fn validate_signer(&self, key: SignerKey, _: ParticipantId) -> Result<AuthResult, String> {
            self.lookups.set(self.lookups.get() + 1);
            Ok(if key == self.signer {
                AuthResult::Valid
            } else {
                AuthResult::Invalid
            })
        }

        fn signers_for_participant(&self, _: &ParticipantId) -> Result<Vec<SignerKey>, String> {
            self.lookups.set(self.lookups.get() + 1);
            Ok(vec![self.signer.clone()])
        }
    }

    fn participant() -> ParticipantId {
        ParticipantId::from([1u8; 32].as_slice())
    }

    #[test]
    fn cached_signers_answer_without_a_lookup() {
        let signer = SignerKey::from([7u8; 32].as_slice());
        let auth = CachedAuth::new(Counting::new(&signer), Duration::from_secs(60));

        auth.signers_for_participant(&participant()).unwrap();
        auth.signers_for_participant(&participant()).unwrap();
        let result = auth.validate_signer(signer, participant()).unwrap();

        assert!(matches!(result, AuthResult::Valid), "{result:?}");
        assert_eq!(auth.inner.lookups.get(), 1);
    }

    #[test]
    fn unknown_signer_goes_to_the_inner_service() {
        let signer = SignerKey::from([7u8; 32].as_slice());
        let auth = CachedAuth::new(Counting::new(&signer), Duration::from_secs(60));

        auth.signers_for_participant(&participant()).unwrap();
        let other = SignerKey::from([8u8; 32].as_slice());
        let result = auth.validate_signer(other, participant()).unwrap();

        assert!(matches!(result, AuthResult::Invalid), "{result:?}");
        assert_eq!(auth.inner.lookups.get(), 2);
    }

    #[test]
    fn expired_entry_is_looked_up_again() {
        let signer = SignerKey::from([7u8; 32].as_slice());
        let auth = CachedAuth::new(Counting::new(&signer), Duration::ZERO);

        auth.signers_for_participant(&participant()).unwrap();
        auth.signers_for_participant(&participant()).unwrap();

        assert_eq!(auth.inner.lookups.get(), 2);
    }
}
