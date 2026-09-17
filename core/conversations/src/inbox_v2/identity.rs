use std::ops::Deref;

use crate::identity::{ExternalIdentifier, SignerRef};
use openmls::credentials::{BasicCredential, CredentialWithKey};
use openmls_traits::{
    signatures::{Signer, SignerError},
    types::SignatureScheme,
};

use crate::IdentityProvider;

/// A Wrapper for an IdentityProvider which provides MLS specific functionality
///
/// This type stops OpenMLS internal from leaking outside the crate.
/// Developers provider a simple IdentityProvider, and Signer and Credential generation
/// is provided
pub struct MlsIdentityProvider<T: IdentityProvider>(T);

impl<T: IdentityProvider> MlsIdentityProvider<T> {
    pub fn new(inner: T) -> Self {
        Self(inner)
    }

    pub fn get_credential(&self) -> CredentialWithKey {
        CredentialWithKey {
            credential: BasicCredential::new(self.external_id().to_bytes()).into(),
            signature_key: self.signer().as_bytes().into(),
        }
    }
}

impl<T: IdentityProvider> Deref for MlsIdentityProvider<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: IdentityProvider> IdentityProvider for MlsIdentityProvider<T> {
    fn signer(&self) -> SignerRef<'_> {
        self.0.signer()
    }

    fn external_id(&self) -> ExternalIdentifier {
        self.0.external_id()
    }

    fn display_name(&self) -> String {
        self.0.display_name()
    }

    fn sign(&self, payload: &[u8]) -> crypto::Ed25519Signature {
        self.0.sign(payload)
    }
}

// Implement Signer directly for MlsIdentityProvider, so that openmls Signer constraint
// does not leave the module.
impl<T: IdentityProvider> Signer for MlsIdentityProvider<T> {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        Ok(self.0.sign(payload).as_ref().to_vec())
    }

    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}
