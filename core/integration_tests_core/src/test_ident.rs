use crypto::{Ed25519SigningKey, Ed25519VerifyingKey};
use libchat::IdentityProvider;
use shared_traits::{IdentId, IdentIdRef};

/// Test identity with a fixed, human-readable id ("saro"). Stands in for a
/// device signer so core tests can address peers by name.
pub struct TestIdent {
    id: IdentId,
    signing_key: Ed25519SigningKey,
    verifying_key: Ed25519VerifyingKey,
}

impl TestIdent {
    pub fn new(explicit_id: impl Into<String>) -> Self {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        Self {
            id: IdentId::new(explicit_id.into()),
            signing_key,
            verifying_key,
        }
    }

    /// Derives the signing key from `seed` instead of generating one, so two identities built
    /// from the same seed sign and are addressed alike.
    pub fn from_seed(explicit_id: impl Into<String>, seed: &[u8; 32]) -> Self {
        let signing_key = Ed25519SigningKey::from_seed(seed);
        let verifying_key = signing_key.verifying_key();
        Self {
            id: IdentId::new(explicit_id.into()),
            signing_key,
            verifying_key,
        }
    }
}

impl IdentityProvider for TestIdent {
    fn id(&self) -> IdentIdRef<'_> {
        &self.id
    }

    fn display_name(&self) -> String {
        self.id.to_string()
    }

    fn public_key(&self) -> &Ed25519VerifyingKey {
        &self.verifying_key
    }

    fn sign(&self, payload: &[u8]) -> crypto::Ed25519Signature {
        self.signing_key.sign(payload)
    }
}
