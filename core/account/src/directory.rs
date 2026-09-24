//! Account → device directory: traits and the signed device-list bundle codec.
//!
//! An Account (AccountAddress, an Ed25519 key) endorses a set of device
//! (LocalIdentity) public keys by signing a bundle. The directory service stores
//! one such bundle per account so that an inviter can resolve an account public
//! key to every device it must invite.
//!
//! [`AccountDirectory`] is the client that publishes and fetches+verifies the
//! bundle against the directory service. Signing a bundle is account
//! functionality (e.g. [`TestLogosAccount::add_delegate_signer`](crate::TestLogosAccount));
//! the account key never leaves the account type.
//!
//! The bundle `payload` is opaque to the server. Both the signing side
//! ([`encode_bundle_payload`]) and the verifying side ([`verify_bundle`]) live
//! here so they cannot drift apart.

use std::fmt::{Debug, Display};

use crypto::{Ed25519Signature, Ed25519VerifyingKey};
use thiserror::Error;

/// A device (LocalIdentity) verifying key, hex-encoded — the same shape as the
/// keypackage registry's `device_id`, so values flow straight into a keypackage
/// retrieval.
pub type DeviceId = String;

/// The account's monotonic version counter, bumped on every membership change.
/// The directory server reads it from the signed payload and rejects a publish
/// whose lamport is not strictly higher than the stored one, so an older bundle
/// can't be replayed to downgrade the device list. Consumers also keep the
/// highest value seen per account and reject anything lower as defence in depth.
pub type Lamport = u64;

/// Current bundle payload version. Bump when the layout in
/// [`encode_bundle_payload`] changes.
pub const BUNDLE_VERSION: u8 = 1;

/// Domain-separation tag prepended to every signed payload. The account key may
/// live in an external signer (wallet/enclave) that signs other things too, so
/// binding the signature to this exact purpose stops a signature obtained
/// elsewhere from being replayed as a device-bundle signature (and vice-versa).
/// It is a fixed constant prefix — not a field separator — so it adds no parsing
/// ambiguity. The trailing NUL keeps it from being a prefix of any other domain.
pub const BUNDLE_DOMAIN: &[u8] = b"libchat:account-device-bundle\0";

/// The signed device-list bundle. The `payload` bytes are exactly
/// what the account signed, so verifiers check the signature over
/// the same bytes they received.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedDeviceBundle {
    /// The account verifying key this bundle belongs to. Used for addressing on
    /// publish; on verify the caller supplies the expected account key separately
    /// and the signature is checked under it.
    pub account_pub: Ed25519VerifyingKey,
    /// Canonical signed bytes — see [`encode_bundle_payload`].
    pub payload: Vec<u8>,
    /// Account signature over `payload`.
    pub signature: Ed25519Signature,
}

/// The verified result of a directory fetch: an account's device set at a given
/// version. Produced only after the account signature has been checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceSet {
    pub lamport: Lamport,
    /// Device verifying keys, hex-encoded, ready for keypackage retrieval.
    pub devices: Vec<DeviceId>,
}

/// Client for the account → device directory service.
///
/// Mirrors the core's `RegistrationService`: an injected trait with an HTTP
/// implementation in the extension layer.
/// The service is untrusted, so [`fetch`](AccountDirectory::fetch) verifies the
/// account signature before returning a [`DeviceSet`].
pub trait AccountDirectory: Debug {
    type Error: Display + Debug;

    /// Upsert the signed device list for an account, replacing any previous one.
    fn publish(&mut self, bundle: &SignedDeviceBundle) -> Result<(), Self::Error>;

    /// Fetch and verify the device set for `account`. `Ok(None)` means the
    /// account has never published — callers fall back to legacy 1:1 resolution.
    fn fetch(&self, account: &Ed25519VerifyingKey) -> Result<Option<DeviceSet>, Self::Error>;
}

/// Failures decoding or verifying a [`SignedDeviceBundle`].
#[derive(Debug, Error)]
pub enum BundleError {
    #[error("payload shorter than its declared layout")]
    Short,
    #[error("payload is missing the account-device-bundle domain prefix")]
    Domain,
    #[error("unsupported bundle version {0}")]
    Version(u8),
    #[error("account signature verification failed")]
    SignatureInvalid,
}

/// The decoded (but not yet signature-verified) contents of a bundle payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedBundle {
    pub lamport: Lamport,
    pub devices: Vec<[u8; 32]>,
}

/// Canonical binary payload — the bytes that are both signed and transmitted.
/// Opaque to the server; decoded only by consumers:
///
/// ```text
/// domain  : BUNDLE_DOMAIN          (constant prefix, NUL-terminated)
/// version : u8        (1 byte)
/// lamport : u64 LE    (8 bytes)
/// count   : u16 LE    (2 bytes)   — number of device keys that follow
/// devices : [u8; 32] * count      (32 * count bytes)
/// ```
///
/// Fixed-width fields with an explicit `count` make every byte string parse
/// exactly one way. The [`BUNDLE_DOMAIN`] prefix binds the signature to this
/// purpose (see its docs). The account key is *not* embedded: the account is
/// identified out-of-band by the account verifying key the caller requests, and
/// [`verify_bundle`] checks the signature under that key — so a bundle for one
/// account cannot be passed off as another's.
pub fn encode_bundle_payload(lamport: Lamport, devices: &[Ed25519VerifyingKey]) -> Vec<u8> {
    let mut out = Vec::with_capacity(BUNDLE_DOMAIN.len() + 1 + 8 + 2 + devices.len() * 32);
    out.extend_from_slice(BUNDLE_DOMAIN);
    out.push(BUNDLE_VERSION);
    out.extend_from_slice(&lamport.to_le_bytes());
    out.extend_from_slice(&(devices.len() as u16).to_le_bytes());
    for device in devices {
        out.extend_from_slice(device.as_ref());
    }
    out
}

/// Inverse of [`encode_bundle_payload`]. Strips the domain prefix, then validates
/// the version and that the declared device count matches the remaining bytes
/// exactly.
pub fn decode_bundle_payload(payload: &[u8]) -> Result<DecodedBundle, BundleError> {
    const HEADER: usize = 1 + 8 + 2;
    let payload = payload
        .strip_prefix(BUNDLE_DOMAIN)
        .ok_or(BundleError::Domain)?;
    if payload.len() < HEADER {
        return Err(BundleError::Short);
    }
    let version = payload[0];
    if version != BUNDLE_VERSION {
        return Err(BundleError::Version(version));
    }
    let lamport = u64::from_le_bytes(payload[1..9].try_into().expect("9 - 1 == 8"));
    let count = u16::from_le_bytes(payload[9..11].try_into().expect("11 - 9 == 2")) as usize;

    let body = &payload[HEADER..];
    if body.len() != count * 32 {
        return Err(BundleError::Short);
    }
    let devices = body.as_chunks::<32>().0.to_vec();

    Ok(DecodedBundle { lamport, devices })
}

/// Decode `bundle`, confirm it belongs to `expected_account`, and verify the
/// account signature over the exact payload bytes. Returns the verified
/// [`DeviceSet`] (device keys hex-encoded for keypackage retrieval).
pub fn verify_bundle(
    expected_account: &Ed25519VerifyingKey,
    bundle: &SignedDeviceBundle,
) -> Result<DeviceSet, BundleError> {
    let decoded = decode_bundle_payload(&bundle.payload)?;

    // Verifying the signature under the *requested* account key is what binds the
    // bundle to that account: another account's validly-signed bundle won't verify
    // under this key, so an untrusted server cannot substitute one.
    expected_account
        .verify(&bundle.payload, &bundle.signature)
        .map_err(|_| BundleError::SignatureInvalid)?;

    Ok(DeviceSet {
        lamport: decoded.lamport,
        devices: decoded.devices.iter().map(hex::encode).collect(),
    })
}

/// Failures resolving an account address to its device ids.
#[derive(Debug, Error)]
pub enum ResolveError {
    #[error("account has published no device bundle")]
    NoDeviceBundle,
    #[error("directory: {0}")]
    Directory(String),
}

/// Resolve an account to the device ids whose KeyPackages must be fetched.
///
/// The directory is keyed by the account verifying key — so the only failures
/// left are an unpublished account and a directory outage, which the variants
/// tell apart.
pub fn resolve_device_ids<D: AccountDirectory + ?Sized>(
    directory: &D,
    account: &Ed25519VerifyingKey,
) -> Result<Vec<DeviceId>, ResolveError> {
    let set = directory
        .fetch(account)
        .map_err(|e| ResolveError::Directory(e.to_string()))?
        .ok_or(ResolveError::NoDeviceBundle)?;
    Ok(set.devices)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::Ed25519SigningKey;

    /// encode → decode round-trips, including zero and many devices.
    #[test]
    fn payload_roundtrips() {
        let devices: Vec<_> = (0..3)
            .map(|_| Ed25519SigningKey::generate().verifying_key())
            .collect();

        let payload = encode_bundle_payload(7, &devices);
        let decoded = decode_bundle_payload(&payload).unwrap();

        assert_eq!(decoded.lamport, 7);
        let want: Vec<[u8; 32]> = devices
            .iter()
            .map(|d| d.as_ref().try_into().unwrap())
            .collect();
        assert_eq!(decoded.devices, want);

        // Empty device set is valid (an account with no devices).
        let empty = encode_bundle_payload(0, &[]);
        assert!(decode_bundle_payload(&empty).unwrap().devices.is_empty());
    }

    #[test]
    fn decode_rejects_short_and_truncated() {
        // A domain-prefixed payload too short to hold the header.
        let mut short = BUNDLE_DOMAIN.to_vec();
        short.extend_from_slice(&[0u8; 5]);
        assert!(matches!(
            decode_bundle_payload(&short),
            Err(BundleError::Short)
        ));

        let device = Ed25519SigningKey::generate().verifying_key();
        let mut payload = encode_bundle_payload(1, &[device]);
        payload.pop(); // drop a device byte: count no longer matches the body
        assert!(matches!(
            decode_bundle_payload(&payload),
            Err(BundleError::Short)
        ));
    }

    #[test]
    fn decode_rejects_missing_domain() {
        // Bytes that would be a valid body but lack the domain prefix.
        let payload = encode_bundle_payload(1, &[]);
        let without_domain = &payload[BUNDLE_DOMAIN.len()..];
        assert!(matches!(
            decode_bundle_payload(without_domain),
            Err(BundleError::Domain)
        ));
    }

    #[test]
    fn decode_rejects_bad_version() {
        let mut payload = encode_bundle_payload(1, &[]);
        payload[BUNDLE_DOMAIN.len()] = 99; // first byte after the domain prefix
        assert!(matches!(
            decode_bundle_payload(&payload),
            Err(BundleError::Version(99))
        ));
    }

    /// Full happy path: sign with the account key, verify under the account key.
    #[test]
    fn verify_accepts_well_formed_bundle() {
        let account_key = Ed25519SigningKey::generate();
        let account_pub = account_key.verifying_key();
        let devices: Vec<_> = (0..2)
            .map(|_| Ed25519SigningKey::generate().verifying_key())
            .collect();

        let payload = encode_bundle_payload(42, &devices);
        let bundle = SignedDeviceBundle {
            account_pub: account_pub.clone(),
            signature: account_key.sign(&payload),
            payload,
        };

        let set = verify_bundle(&account_pub, &bundle).unwrap();
        assert_eq!(set.lamport, 42);
        assert_eq!(set.devices.len(), 2);
        assert_eq!(set.devices[0], hex::encode(devices[0].as_ref()));
    }

    /// A bundle validly signed by account A, served as the answer to a query for
    /// account B, fails: B's key does not verify A's signature. This is the
    /// anti-substitution guarantee, now resting entirely on the signature check.
    #[test]
    fn verify_rejects_wrong_account() {
        let account_key = Ed25519SigningKey::generate();
        let account_pub = account_key.verifying_key();
        let payload = encode_bundle_payload(1, &[]);
        let bundle = SignedDeviceBundle {
            account_pub,
            signature: account_key.sign(&payload),
            payload,
        };

        let other = Ed25519SigningKey::generate().verifying_key();
        assert!(matches!(
            verify_bundle(&other, &bundle),
            Err(BundleError::SignatureInvalid)
        ));
    }

    /// Minimal in-test directory so `resolve_device_ids` can be exercised
    /// without pulling in the `components` crate.
    #[derive(Debug, Default)]
    struct FakeDir(Option<SignedDeviceBundle>);

    impl AccountDirectory for FakeDir {
        type Error = BundleError;
        fn publish(&mut self, bundle: &SignedDeviceBundle) -> Result<(), Self::Error> {
            self.0 = Some(bundle.clone());
            Ok(())
        }
        fn fetch(&self, account: &Ed25519VerifyingKey) -> Result<Option<DeviceSet>, Self::Error> {
            self.0
                .as_ref()
                .map(|b| verify_bundle(account, b))
                .transpose()
        }
    }

    /// An account that never published a bundle is unreachable.
    #[test]
    fn resolve_rejects_unpublished_account() {
        let account_pub = Ed25519SigningKey::generate().verifying_key();
        assert!(matches!(
            resolve_device_ids(&FakeDir(None), &account_pub),
            Err(ResolveError::NoDeviceBundle)
        ));
    }

    /// A published bundle → resolve to its verified device ids (hex pubkeys).
    #[test]
    fn resolve_returns_published_devices() {
        let account_key = Ed25519SigningKey::generate();
        let account_pub = account_key.verifying_key();
        let devices: Vec<_> = (0..2)
            .map(|_| Ed25519SigningKey::generate().verifying_key())
            .collect();

        let payload = encode_bundle_payload(1, &devices);
        let bundle = SignedDeviceBundle {
            account_pub: account_pub.clone(),
            signature: account_key.sign(&payload),
            payload,
        };

        // The identifier is the hex of the account key, so resolution consults the
        // directory rather than falling back.
        let resolved = resolve_device_ids(&FakeDir(Some(bundle)), &account_pub).unwrap();
        let want: Vec<String> = devices.iter().map(|d| hex::encode(d.as_ref())).collect();
        assert_eq!(resolved, want);
    }

    /// Tampering with any payload byte breaks verification.
    #[test]
    fn verify_rejects_tampered_payload() {
        let account_key = Ed25519SigningKey::generate();
        let account_pub = account_key.verifying_key();
        let device = Ed25519SigningKey::generate().verifying_key();

        let payload = encode_bundle_payload(1, std::slice::from_ref(&device));
        let signature = account_key.sign(&payload);

        // Re-encode with a different lamport, keep the old signature.
        let tampered = encode_bundle_payload(2, &[device]);
        let bundle = SignedDeviceBundle {
            account_pub: account_pub.clone(),
            payload: tampered,
            signature,
        };
        assert!(matches!(
            verify_bundle(&account_pub, &bundle),
            Err(BundleError::SignatureInvalid)
        ));
    }
}
