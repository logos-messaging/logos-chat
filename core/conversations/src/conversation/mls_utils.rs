use openmls::{
    key_packages::{KeyPackage, KeyPackageIn},
    prelude::tls_codec::Deserialize,
    versions::ProtocolVersion,
};
use openmls_traits::OpenMlsProvider;
use std::collections::HashSet;

use crate::{
    ChatError, ExternalServices, RegistrationService,
    Signer, SignerKey, errors::KeyPackageError, service_context::ServiceContext,
};

pub fn unique<'a, T, I>(iter: I) -> impl Iterator<Item = &'a T>
where
    T: Eq + std::hash::Hash + 'a,
    I: IntoIterator<Item = &'a T>,
{
    let mut seen = HashSet::new();
    iter.into_iter().filter(move |x| seen.insert(*x))
}

pub fn member_diff(
    new: &[SignerKey],
    existing: impl Iterator<Item = Signer>,
) -> impl Iterator<Item = &SignerKey> {
    let existing: HashSet<SignerKey> = existing.map(|s| s.signer).collect();
    new.iter().filter(move |s| !existing.contains(*s))
}

/// Fetch each signer's key package, deduped, reading the two ids off the leaf.
/// Fails if anyone lacks one, before any member is admitted.
pub(super) fn fetch_key_packages<'a, S: ExternalServices>(
    service_ctx: &ServiceContext<S>,
    signers: impl Iterator<Item = &'a SignerKey>,
) -> Result<Vec<KeyPackage>, ChatError> {
    let mut seen = HashSet::new();
    signers
        .filter(|s| seen.insert(s.as_bytes()))
        .map(|signer| {
            let kp_bytes = service_ctx
                .registry
                .retrieve(&signer.to_string())
                .map_err(ChatError::generic)?
                .ok_or_else(|| ChatError::generic("No key package"))?;

            let key_package = validate_keypackage(service_ctx, signer, kp_bytes.as_slice())?;
            Ok(key_package)
        })
        .collect()
}

/// Ensure that the Keypackage meets all the requirements.
fn validate_keypackage<S: ExternalServices>(
    service_ctx: &ServiceContext<S>,
    expected_signer_key: &SignerKey,
    kp_bytes: &[u8],
) -> Result<KeyPackage, KeyPackageError> {
    // Verify that Keypackage decodes
    let unchecked = KeyPackageIn::tls_deserialize_exact(kp_bytes)?;

    // Verify that the signature on this key package is valid
    // Verify that the signature on the leaf node is valid
    // Verify that all extensions are supported by the leaf node
    // Make sure that the lifetime is valid
    // Make sure that the init key and the encryption key are different
    // Make sure that the protocol version is valid
    let key_package =
        unchecked.validate(service_ctx.mls_provider.crypto(), ProtocolVersion::Mls10)?;

    // Validate that the Keypackage matches expected Signer
    let reported_signer = Signer::from_leaf_node(key_package.leaf_node())?;
    if *expected_signer_key != reported_signer.signer {
        return Err(KeyPackageError::WrongPackage {
            expected: expected_signer_key.clone(),
            got: key_package.leaf_node().signature_key().clone(),
        });
    }

    // Validate the Signer is valid for the provided ParticipantId
    let auth_status = reported_signer.auth_status(&service_ctx.auth);
    match auth_status {
        crate::identity::AuthStatus::Valid => Ok(key_package),
        _ => Err(KeyPackageError::AuthFailed {
            signer: reported_signer,
            auth_status,
        }),
    }
}
