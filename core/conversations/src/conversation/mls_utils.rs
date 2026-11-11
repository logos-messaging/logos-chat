use openmls::{
    group::{MlsGroup, StagedCommit},
    key_packages::{KeyPackage, KeyPackageIn},
    prelude::tls_codec::Deserialize,
    schedule::EpochAuthenticator,
    versions::ProtocolVersion,
};
use openmls_traits::OpenMlsProvider;
use std::collections::HashSet;
use std::fmt;

use crate::{
    ChatError, ExternalServices, RegistrationService, Signer, SignerKey,
    errors::KeyPackageError,
    service_context::ServiceContext,
    utils::{blake2b_bytes, hash_size},
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

/// Names a group's state at one epoch: a short hash of the epoch authenticator.
/// Two branches of a fork at the same epoch get different values.
#[derive(Debug, PartialEq, Clone, Eq, Hash, PartialOrd, Ord)]
pub struct EpochFingerprint([u8; 7]);

const EPOCH_FINGERPRINT_LABEL: &[u8] = b"logos-chat|epoch-fingerprint|v1\0";

impl EpochFingerprint {
    fn calculate_from_authenticator(authenticator: &EpochAuthenticator) -> Self {
        let hash = blake2b_bytes::<hash_size::EpochFingerprint>(&[
            EPOCH_FINGERPRINT_LABEL,
            authenticator.as_slice(),
        ]);

        Self(hash.into())
    }
}

impl TryFrom<&[u8]> for EpochFingerprint {
    type Error = std::array::TryFromSliceError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        <[u8; 7]>::try_from(bytes).map(Self)
    }
}

impl fmt::Display for EpochFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl EpochFingerprint {
    /// `None` for a commit that removes us: we hold no secrets for the epoch
    /// it starts.
    pub fn of_commit(commit: &StagedCommit) -> Option<Self> {
        commit
            .epoch_authenticator()
            .map(|authenticator| Self::of(authenticator.as_slice()))
    }
}

impl EpochFingerprint {
    /// Stands in for a commit that removes us, whose epoch we can't name. Sorts
    /// after every real fingerprint, which are hex, so any other commit for the
    /// epoch is finalized first.
    pub fn removing_us() -> Self {
        Self([0; 7])
    }
}
impl From<&StagedCommit> for EpochFingerprint {
    fn from(value: &StagedCommit) -> Self {
        let authenticator = value.epoch_authenticator().expect("is member"); // To receive a Staged commit the signer must be a member of the group.
        Self::calculate_from_authenticator(authenticator)
    }
}

impl From<&MlsGroup> for EpochFingerprint {
    fn from(group: &MlsGroup) -> Self {
        Self::calculate_from_authenticator(group.epoch_authenticator())
    }
}
