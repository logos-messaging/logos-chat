use crypto::Ed25519SigningKey;
use libchat::IdentityProvider;
use libchat::{SignerKey, SignerRef};

/// Test identity with a human-readable name ("saro"). Stands in for a device
/// signer so core tests can address peers by name.
///
/// The name is a label, not the signer: a signer is an Ed25519 key, so the
/// name travels as the credential and in [`display_name`] while the signer is
/// generated.
pub struct TestIdent {
    name: String,
    signer: SignerKey,
    signing_key: Ed25519SigningKey,
}

impl TestIdent {
    pub fn new(name: impl Into<String>) -> Self {
        let signing_key = Ed25519SigningKey::generate();
        let signer = SignerKey::from(signing_key.verifying_key());
        Self {
            name: name.into(),
            signer,
            signing_key,
        }
    }
}

impl IdentityProvider for TestIdent {
    fn signer_key(&self) -> SignerRef<'_> {
        &self.signer
    }

    fn participant_id(&self) -> libchat::ParticipantId {
        self.name.as_bytes().into()
    }

    fn display_name(&self) -> String {
        self.name.clone()
    }

    fn sign(&self, payload: &[u8]) -> crypto::Ed25519Signature {
        self.signing_key.sign(payload)
    }
}

/// Accepts every identifier without checking it.
///
/// A `TestIdent`'s external id is the name it was built from, so there is
/// nothing to resolve it against. Test-only: this asserts nothing about a
/// sender, and must never stand in for a real [`AuthService`] once the core
/// gates on the result.
#[derive(Debug, Clone, Copy, Default)]
pub struct AcceptAllAuth;

impl libchat::AuthService for AcceptAllAuth {
    type Error = std::convert::Infallible;

    fn validate_signer(
        &self,
        _signer: SignerKey,
        _participant_id: libchat::ParticipantId,
    ) -> Result<libchat::AuthResult, Self::Error> {
        Ok(libchat::AuthResult::Valid)
    }
}
