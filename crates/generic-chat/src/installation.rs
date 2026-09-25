use crypto::{Ed25519SigningKey, Ed25519VerifyingKey};
use libchat::{
    AuthResult, AuthService, IdentityProvider, IdentityStore, ParticipantId, SignerKey, SignerRef,
    StoredInstallation, trunc,
};
use logos_account::AccountAddr;

use crate::errors::ClientError;
use crate::members::account_id;

/// How a client comes by the installation it runs as.
///
/// There is deliberately no "replace what is stored" mode: overwriting an installation orphans
/// every conversation joined under it, silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IdentityMode {
    /// Reuse the stored installation, creating and storing one if the store holds none.
    #[default]
    LoadOrCreate,
    /// Create one and store nothing. Tests and throwaway sessions; the next open is a stranger.
    Ephemeral,
}

/// The encoding version leading a stored record, so a later shape can be told from this one.
const RECORD_V1: u8 = 1;
const SEED_LEN: usize = 32;
const ACCOUNT_LEN: usize = 32;

/// A key generated for one installation, waiting for its account to endorse
/// it. Held in memory only: nothing persists it.
/// [`complete`](Self::complete) pairs it with that account once endorsed.
pub struct PendingInstallation {
    signing_key: Ed25519SigningKey,
    verifying_key: Ed25519VerifyingKey,
}

impl PendingInstallation {
    pub fn generate() -> Self {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// The signer the account must endorse.
    pub fn endorsement_request(&self) -> Vec<u8> {
        self.verifying_key.as_ref().to_vec()
    }

    /// This key as an installation of `account`. Nothing is checked here:
    /// [`ChatClientBuilder`](crate::ChatClientBuilder) confirms the
    /// endorsement when it builds.
    pub fn complete(self, account: AccountAddr) -> Installation {
        Installation {
            signer: SignerKey::from(self.verifying_key),
            signing_key: self.signing_key,
            account,
        }
    }
}

/// An installation paired with its account: the identity a
/// [`ChatClient`](crate::ChatClient) runs as.
pub struct Installation {
    signing_key: Ed25519SigningKey,
    /// The public key, which is what this installation signs under.
    signer: SignerKey,
    account: AccountAddr,
}

impl Installation {
    pub fn account(&self) -> &AccountAddr {
        &self.account
    }

    /// The installation `store` belongs to, or `None` if it has never held one.
    ///
    /// A record this build cannot read is an error, not a `None`: treating it as absent would
    /// register a second installation over conversations belonging to the first.
    pub fn load(store: &impl IdentityStore) -> Result<Option<Self>, ClientError> {
        let Some(record) = store.load_installation()? else {
            return Ok(None);
        };
        Self::decode(record.as_bytes()).map(Some)
    }

    /// Records this installation as the one `store` belongs to.
    ///
    /// Only once its endorsement is published: a stored installation tells the next open that
    /// registration already happened, so storing one that never reached the network leaves a
    /// client nobody can invite.
    pub fn save(&self, store: &mut impl IdentityStore) -> Result<(), ClientError> {
        store.save_installation(&StoredInstallation::new(self.encode()))?;
        Ok(())
    }

    /// `version ‖ seed ‖ account`. The signer is the seed's public half, so storing it too
    /// would only add something that can disagree.
    fn encode(&self) -> Vec<u8> {
        let seed = self.signing_key.seed();
        let mut bytes = Vec::with_capacity(1 + SEED_LEN + ACCOUNT_LEN);
        bytes.push(RECORD_V1);
        bytes.extend_from_slice(seed.as_slice());
        bytes.extend_from_slice(self.account.to_bytes());
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, ClientError> {
        let malformed = |what: &str| ClientError::MalformedInstallationRecord(what.to_string());

        let [RECORD_V1, rest @ ..] = bytes else {
            return Err(malformed(
                "not a record this build writes; the store was written by another version",
            ));
        };
        if rest.len() != SEED_LEN + ACCOUNT_LEN {
            return Err(malformed("wrong length for a version 1 record"));
        }

        let (seed, account) = rest.split_at(SEED_LEN);
        let seed: &[u8; SEED_LEN] = seed.try_into().expect("split at SEED_LEN");
        let signing_key = Ed25519SigningKey::from_seed(seed);
        let account =
            AccountAddr::try_from(account).map_err(|e| malformed(&format!("account: {e}")))?;

        Ok(Self {
            signer: SignerKey::from(signing_key.verifying_key()),
            signing_key,
            account,
        })
    }

    /// `Ok` only if `auth` confirms the account endorses this installation.
    pub(crate) fn validate(&self, auth: &impl AuthService) -> Result<(), ClientError> {
        match auth.validate_signer(self.signer.clone(), self.participant_id()) {
            Ok(AuthResult::Valid) => Ok(()),
            Ok(verdict) => Err(ClientError::NotEndorsed(format!("{verdict:?}"))),
            Err(e) => Err(ClientError::NotEndorsed(format!(
                "auth service could not decide: {e}"
            ))),
        }
    }
}

impl IdentityProvider for Installation {
    fn signer_key(&self) -> SignerRef<'_> {
        &self.signer
    }

    fn participant_id(&self) -> ParticipantId {
        account_id(&self.account)
    }

    fn display_name(&self) -> String {
        trunc(&self.signer.to_string())
    }

    fn sign(&self, payload: &[u8]) -> crypto::Ed25519Signature {
        self.signing_key.sign(payload)
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use super::*;
    use integration_tests_core::AcceptAllAuth;
    use libchat::test_support::MemStore;

    #[derive(Debug)]
    struct RejectAll;

    impl AuthService for RejectAll {
        type Error = Infallible;

        fn validate_signer(
            &self,
            _signer: SignerKey,
            _participant_id: ParticipantId,
        ) -> Result<AuthResult, Self::Error> {
            Ok(AuthResult::Invalid)
        }

        fn signers_for_participant(
            &self,
            _ident: &ParticipantId,
        ) -> Result<Vec<SignerKey>, Self::Error> {
            Ok(Vec::new())
        }
    }

    fn account() -> AccountAddr {
        AccountAddr::try_from(Ed25519SigningKey::generate().verifying_key().as_ref())
            .expect("a generated key is an address")
    }

    #[test]
    fn an_installation_signs_as_its_key_for_its_account() {
        let pending = PendingInstallation::generate();
        let signer = pending.endorsement_request();
        let account = account();

        let installation = pending.complete(account.clone());
        assert_eq!(installation.signer_key().as_bytes(), signer);
        assert_eq!(installation.participant_id(), account_id(&account));
    }

    #[test]
    fn validation_follows_the_auth_service() {
        let installation = PendingInstallation::generate().complete(account());

        assert!(installation.validate(&AcceptAllAuth::default()).is_ok());
        assert!(matches!(
            installation.validate(&RejectAll),
            Err(ClientError::NotEndorsed(_))
        ));
    }

    /// The whole point: what comes back out signs as, and is addressed as, what went in.
    #[test]
    fn a_stored_installation_comes_back_as_itself() {
        let mut store = MemStore::new();
        let original = PendingInstallation::generate().complete(account());

        original.save(&mut store).unwrap();
        let loaded = Installation::load(&store).unwrap().expect("just saved");

        assert_eq!(loaded.signer_key(), original.signer_key());
        assert_eq!(loaded.account(), original.account());
        assert_eq!(loaded.participant_id(), original.participant_id());
        assert_eq!(
            loaded.sign(b"after a restart").as_ref(),
            original.sign(b"after a restart").as_ref()
        );
    }
}
