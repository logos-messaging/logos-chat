use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crypto::Ed25519SigningKey;
use libchat::IdentityProvider;
use libchat::{ExternalIdentifier, Signer, SignerRef};

/// Test identity with a human-readable name ("saro"). Stands in for a device
/// signer so core tests can address peers by name.
///
/// The name is a label, not the signer: a signer is an Ed25519 key, so the
/// name travels as the credential and in [`display_name`] while the signer is
/// generated.
pub struct TestIdent {
    name: String,
    signer: Signer,
    signing_key: Ed25519SigningKey,
}

impl TestIdent {
    pub fn new(name: impl Into<String>) -> Self {
        let signing_key = Ed25519SigningKey::generate();
        let signer = Signer::from(signing_key.verifying_key());
        Self {
            name: name.into(),
            signer,
            signing_key,
        }
    }
}

impl IdentityProvider for TestIdent {
    fn signer(&self) -> SignerRef<'_> {
        &self.signer
    }

    fn external_id(&self) -> ExternalIdentifier {
        self.name.as_bytes().into()
    }

    fn display_name(&self) -> String {
        self.name.clone()
    }

    fn sign(&self, payload: &[u8]) -> crypto::Ed25519Signature {
        self.signing_key.sign(payload)
    }
}

/// Accepts every identifier without checking it, and resolves an account to
/// the signers [registered](Self::register) under it. An account nobody
/// registered does not resolve.
///
/// Test-only: this asserts nothing about a sender, and must never stand in for
/// a real [`AuthService`](libchat::AuthService). Clones share one registry.
#[derive(Debug, Clone, Default)]
pub struct AcceptAllAuth {
    signers: Arc<Mutex<HashMap<ExternalIdentifier, Vec<Signer>>>>,
}

impl AcceptAllAuth {
    /// Makes `ident`'s signer resolvable from its external id.
    pub fn register(&self, ident: &impl IdentityProvider) {
        self.signers
            .lock()
            .unwrap()
            .entry(ident.external_id())
            .or_default()
            .push(ident.signer().clone());
    }
}

impl libchat::AuthService for AcceptAllAuth {
    type Error = String;

    fn validate_external_identifier(
        &self,
        _signer: Signer,
        _external_id: libchat::ExternalIdentifier,
    ) -> Result<libchat::AuthResult, Self::Error> {
        Ok(libchat::AuthResult::Valid)
    }

    fn signers_for_account(&self, ident: &ExternalIdentifier) -> Result<Vec<Signer>, Self::Error> {
        self.signers
            .lock()
            .unwrap()
            .get(ident)
            .cloned()
            .ok_or_else(|| format!("no signers registered for {ident}"))
    }
}
