use openmls::{
    group::{MlsGroup, StagedCommit},
    key_packages::{KeyPackage, KeyPackageIn},
    prelude::tls_codec::Deserialize,
    schedule::EpochAuthenticator,
    versions::ProtocolVersion,
};
use openmls_traits::OpenMlsProvider;
use openmls_traits::types::HpkeKemType;
use std::collections::HashSet;
use std::fmt;

use crate::{
    ChatError, ExternalServices, RegistrationService, Signer, SignerKey,
    errors::KeyPackageError,
    inbox_v2::CIPHER_SUITE,
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

/// HPKE public key length for [`CIPHER_SUITE`]: a 1184-byte ML-KEM-768 key
/// followed by a 32-byte X25519 key.
pub(super) const HPKE_PUBLIC_KEY_LEN: usize = 1184 + 32;

// The length above is XWing-specific; fail the build if the ciphersuite moves.
const _: () = assert!(matches!(
    CIPHER_SUITE.hpke_kem_algorithm(),
    HpkeKemType::XWingKemDraft6
));

/// Reject an HPKE public key that is not the length [`CIPHER_SUITE`] requires.
///
/// RUSTSEC-2026-0331: `KeyPackageIn::validate` checks a key package's signatures
/// but never its key lengths, and libcrux-kem 0.0.7 indexes `[0..1184]` decoding
/// an XWing key, so a shorter one panics instead of erroring.
///
/// REMOVE, once the build resolves libcrux-kem >= 0.0.10:
/// it returns `InvalidPublicKey` rather than panicking, so openmls can reject a
/// malformed key on its own. That is the same gate as the deny.toml ignore, and
/// `grep RUSTSEC-2026-0331` finds everything to delete.
pub(super) fn check_hpke_public_key(key: &[u8]) -> Result<(), ChatError> {
    if key.len() != HPKE_PUBLIC_KEY_LEN {
        return Err(ChatError::BadBundleValue(format!(
            "HPKE public key is {} bytes, expected {HPKE_PUBLIC_KEY_LEN}",
            key.len()
        )));
    }
    Ok(())
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

    // RUSTSEC-2026-0331: a short init_key panics libcrux-kem once openmls
    // encrypts the Welcome to it. Delete when libcrux-kem >= 0.0.10.
    let init_key = key_package.hpke_init_key().as_slice();
    check_hpke_public_key(init_key).map_err(|_| KeyPackageError::InitKeyLength(init_key.len()))?;

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
    pub fn from_group(group: &MlsGroup) -> Self {
        Self::calculate_from_authenticator(group.epoch_authenticator())
    }

    pub fn from_staged_commit(commit: &StagedCommit) -> Option<Self> {
        commit
            .epoch_authenticator()
            .map(Self::calculate_from_authenticator)
    }

    /// Stands in for a commit that removes us, whose epoch we can't name. Sorts
    /// after every real fingerprint, so any other commit for the epoch is
    /// finalized first.
    pub fn removing_us() -> Self {
        Self([0xff; 7])
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

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

impl From<&MlsGroup> for EpochFingerprint {
    fn from(group: &MlsGroup) -> Self {
        Self::calculate_from_authenticator(group.epoch_authenticator())
    }
}

#[cfg(test)]
mod tests {
    use super::{HPKE_PUBLIC_KEY_LEN, check_hpke_public_key};

    #[test]
    fn hpke_public_key_length_is_enforced() {
        assert!(check_hpke_public_key(&vec![0; HPKE_PUBLIC_KEY_LEN]).is_ok());
        // A key short enough to panic libcrux-kem's decode (RUSTSEC-2026-0331).
        assert!(check_hpke_public_key(&[]).is_err());
        assert!(check_hpke_public_key(&vec![0; 1183]).is_err());
        // Long enough to decode, still the wrong size.
        assert!(check_hpke_public_key(&vec![0; HPKE_PUBLIC_KEY_LEN + 1]).is_err());
    }
}
