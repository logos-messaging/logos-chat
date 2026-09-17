use crypto::{Ed25519SigningKey, Ed25519VerifyingKey};
use libchat::{ExternalIdentifier, IdentityProvider, Signer, trunc};

use crate::ClientError;
use crate::members::account_id;

/// A local signing identity that holds an Ed25519 keypair — the per-device
/// (installation) signer. It knows nothing about accounts: the client pairs it
/// with one in [`DelegateIdentity`].
pub struct DelegateSigner {
    signing_key: Ed25519SigningKey,
    verifying_key: Ed25519VerifyingKey,
}

impl DelegateSigner {
    /// Create a new signer with a randomly generated keypair.
    pub fn random() -> Self {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    pub fn public_key(&self) -> &Ed25519VerifyingKey {
        &self.verifying_key
    }

    pub fn sign(&self, payload: &[u8]) -> crypto::Ed25519Signature {
        self.signing_key.sign(payload)
    }
}

/// The identity the core sees: a [`DelegateSigner`] and the account it acts
/// for, carried as the external id. The core never interprets the account.
pub(crate) struct DelegateIdentity {
    signer: DelegateSigner,
    /// The delegate key, which is what this identity signs under.
    identity: Signer,
    account: ExternalIdentifier,
}

impl DelegateIdentity {
    pub(crate) fn new(signer: DelegateSigner, account: &str) -> Result<Self, ClientError> {
        Ok(Self {
            identity: Signer::from(signer.public_key().clone()),
            account: account_id(account)?,
            signer,
        })
    }
}

impl IdentityProvider for DelegateIdentity {
    fn signer(&self) -> libchat::SignerRef<'_> {
        &self.identity
    }

    fn external_id(&self) -> ExternalIdentifier {
        self.account.clone()
    }

    fn display_name(&self) -> String {
        trunc(&self.identity.to_string())
    }

    fn sign(&self, payload: &[u8]) -> crypto::Ed25519Signature {
        self.signer.sign(payload)
    }
}

/// Accepts every identifier without checking it.
///
/// A placeholder: the real check confirms in the account directory that the
/// external id's account endorses the signer. Until then the core's auth gate
/// asserts nothing.
#[derive(Debug, Clone, Copy, Default)]
pub struct UncheckedAuth;

impl libchat::AuthService for UncheckedAuth {
    type Error = std::convert::Infallible;

    fn validate_external_identifier(
        &self,
        _signer: Signer,
        _external_id: libchat::ExternalIdentifier,
    ) -> Result<libchat::AuthResult, Self::Error> {
        Ok(libchat::AuthResult::Valid)
    }

    fn signers_for_account(
        &self,
        ident: &libchat::ExternalIdentifier,
    ) -> Result<Vec<Signer>, Self::Error> {
        // TODO: resolving an account to its devices went with the device-bundle
        // directory and has no replacement yet.
        unimplemented!("account resolution for {ident}")
    }
}

/// Temp mock: panics so tests will not pass
#[derive(Debug, Clone, Copy, Default)]
pub struct PanicAuth;

impl libchat::AuthService for PanicAuth {
    type Error = std::convert::Infallible;

    fn validate_external_identifier(
        &self,
        _signer: Signer,
        _external_id: libchat::ExternalIdentifier,
    ) -> Result<libchat::AuthResult, Self::Error> {
        panic!("DANGER")
    }

    fn signers_for_account(
        &self,
        _ident: &libchat::ExternalIdentifier,
    ) -> Result<Vec<Signer>, Self::Error> {
        panic!("DANGER")
    }
}
