//! The external frames on the wire, epoch beacons and sealed messages, after
//! [draft-mahy-mls-private-external].
//!
//! Every member of an epoch derives the same HPKE keypair from the MLS
//! exporter. Each one publishes the public half in a beacon signed with its
//! leaf key, so a client that can no longer read the group can still see where
//! it is and, later, seal to it.
//!
//! - Anyone can publish to the delivery address, so a beacon counts only if its
//!   signature verifies against a leaf in the receiver's last known state.
//! - The signature covers the conversation id, so a beacon can't be replayed
//!   into another group.
//! - A beacon travels in plaintext: epoch, epoch id and public key are visible
//!   to anyone watching the address.
//!
//! [draft-mahy-mls-private-external]: https://datatracker.ietf.org/doc/html/draft-mahy-mls-private-external-01

use openmls::group::MlsGroup;
use openmls_traits::OpenMlsProvider;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::{HpkeKeyPair, SignatureScheme};
use prost::Message;
use prost::bytes::Bytes;

use super::payloads::{GroupV3External, GroupV3ExternalKind};
use super::sealed::{MAX_SEALED_LEN, SealedMessage};
use crate::conversation::mls_utils::EpochFingerprint;
use crate::inbox_v2::{CIPHER_SUITE, HPKE_PUBLIC_KEY_LEN, check_hpke_public_key};

const EXPORTER_LABEL: &str = "logos-chat private external encryption v1";
const BEACON_SIG_LABEL: &[u8] = b"logos-chat/beacon-signature/v1";

/// An [`EpochFingerprint`] in hex.
pub(super) const EPOCH_ID_LEN: usize = 14;

pub(super) const ED25519_SIGNATURE_LEN: usize = 64;

// The length above is Ed25519-specific; fail the build if the ciphersuite moves.
const _: () = assert!(matches!(
    CIPHER_SUITE.signature_algorithm(),
    SignatureScheme::ED25519
));

/// Encoded size of the largest well-formed beacon: tag, length prefix and
/// largest value of each field.
///
/// Checked before decoding. Protobuf lets a field repeat, so a frame can carry
/// a huge field followed by a valid one: the decoder allocates for both, and a
/// length check afterwards sees only the valid one.
const MAX_BEACON_LEN: usize = (1 + 10) // epoch
    + (1 + 2 + HPKE_PUBLIC_KEY_LEN) // key
    + (1 + 1 + EPOCH_ID_LEN) // epoch id
    + (1 + 1 + ED25519_SIGNATURE_LEN); // signature

/// [`GroupV3External`] adds a tag and a length prefix around its largest kind.
const MAX_FRAME_LEN: usize = 1
    + 2
    + if MAX_BEACON_LEN > MAX_SEALED_LEN {
        MAX_BEACON_LEN
    } else {
        MAX_SEALED_LEN
    };

/// Published by every member on entering an epoch. The ciphersuite is the
/// conversation's, so it isn't sent.
#[derive(Clone, PartialEq, Message)]
pub struct EpochBeacon {
    #[prost(uint64, tag = "1")]
    pub epoch: u64,
    #[prost(bytes = "bytes", tag = "3")]
    pub external_hpke_pub: Bytes,
    #[prost(string, tag = "4")]
    pub epoch_id: String,
    #[prost(bytes = "bytes", tag = "5")]
    pub signature: Bytes,
}

/// The bytes a beacon signature covers. A fixed layout, not protobuf, so signer
/// and verifier can't disagree: big-endian integers, and byte strings behind a
/// `u32` length.
fn tbs(beacon: &EpochBeacon, convo_id: &str) -> Vec<u8> {
    let mut out = Vec::new();
    put_bytes(&mut out, BEACON_SIG_LABEL);
    put_bytes(&mut out, convo_id.as_bytes());
    out.extend_from_slice(&beacon.epoch.to_be_bytes());
    put_bytes(&mut out, &beacon.external_hpke_pub);
    put_bytes(&mut out, beacon.epoch_id.as_bytes());
    out
}

pub(super) fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// The current epoch's external keypair. Every member derives the same one.
///
/// Uses the plain exporter: `safe_export_secret` ratchets per call, so members
/// would disagree.
pub fn derive_external_keys<P: OpenMlsProvider>(
    group: &MlsGroup,
    provider: &P,
) -> Result<HpkeKeyPair, ExternalError> {
    let ciphersuite = group.ciphersuite();

    let ikm = group
        .export_secret(
            provider.crypto(),
            EXPORTER_LABEL,
            &[],
            ciphersuite.hash_length(),
        )
        .map_err(|e| ExternalError::Derive(e.to_string()))?;

    provider
        .crypto()
        .derive_hpke_keypair(ciphersuite.hpke_config(), &ikm)
        .map_err(|e| ExternalError::Derive(e.to_string()))
}

/// An unsigned beacon for the epoch the group is in.
pub fn beacon_for_epoch(group: &MlsGroup, external_hpke_pub: Bytes) -> EpochBeacon {
    EpochBeacon {
        epoch: group.epoch().as_u64(),
        external_hpke_pub,
        epoch_id: EpochFingerprint::from(group).into_string(),
        signature: Bytes::new(),
    }
}

/// Sign with the publisher's MLS leaf key.
///
/// Needed because the delivery address is derivable from the conversation id,
/// so anyone can publish to it. A stale tree still holds the leaf keys, so a
/// forked client can verify without decrypting anything.
pub fn sign_beacon<S>(
    beacon: &EpochBeacon,
    convo_id: &str,
    signer: &S,
) -> Result<Bytes, ExternalError>
where
    S: openmls_traits::signatures::Signer,
{
    signer
        .sign(&tbs(beacon, convo_id))
        .map(Bytes::from)
        .map_err(|e| ExternalError::Sign(format!("{e:?}")))
}

/// Whether one of `keys`, leaf signature keys, signed the beacon.
pub fn verify_beacon<C, I, K>(crypto: &C, convo_id: &str, beacon: &EpochBeacon, keys: I) -> bool
where
    C: OpenMlsCrypto,
    I: IntoIterator<Item = K>,
    K: AsRef<[u8]>,
{
    let scheme = CIPHER_SUITE.signature_algorithm();
    let tbs = tbs(beacon, convo_id);

    keys.into_iter().any(|key| {
        crypto
            .verify_signature(scheme, &tbs, key.as_ref(), &beacon.signature)
            .is_ok()
    })
}

/// A beacon that passed the shape checks. The only thing a store accepts, so
/// no receive path can skip them.
#[derive(Debug, Clone, PartialEq)]
pub struct Admitted(EpochBeacon);

impl Admitted {
    pub fn beacon(&self) -> &EpochBeacon {
        &self.0
    }
}

/// Shape checks, cheap enough for anything. Every field ends up fixed-size, so
/// a store of admitted beacons is bounded in bytes as well as entries.
pub fn admit(beacon: EpochBeacon) -> Option<Admitted> {
    // RUSTSEC-2026-0331: a short X-Wing key panics in libcrux-kem.
    let well_formed = check_hpke_public_key(&beacon.external_hpke_pub).is_ok()
        && is_epoch_id(&beacon.epoch_id)
        && beacon.signature.len() == ED25519_SIGNATURE_LEN;

    well_formed.then_some(Admitted(beacon))
}

pub(super) fn is_epoch_id(id: &str) -> bool {
    id.len() == EPOCH_ID_LEN && id.bytes().all(|b| b.is_ascii_hexdigit())
}

/// An external frame that passed the shape checks.
#[derive(Debug)]
pub enum Inbound {
    Beacon(Admitted),
    Sealed(SealedMessage),
}

/// Decode and admit an external frame.
pub fn admit_frame(bytes: &[u8]) -> Option<Inbound> {
    if bytes.len() > MAX_FRAME_LEN {
        return None;
    }
    match GroupV3External::decode(bytes).ok()?.kind? {
        GroupV3ExternalKind::Beacon(beacon) => admit(beacon).map(Inbound::Beacon),
        GroupV3ExternalKind::Sealed(msg) => msg.is_well_formed().then_some(Inbound::Sealed(msg)),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ExternalError {
    #[error("could not derive the epoch's external encryption key: {0}")]
    Derive(String),
    #[error("could not sign: {0}")]
    Sign(String),
    #[error("could not seal a private external message: {0}")]
    Seal(String),
    #[error("could not open a private external message: {0}")]
    Open(String),
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::inbox_v2::MlsEphemeralPqProvider;

    pub fn provider() -> MlsEphemeralPqProvider {
        MlsEphemeralPqProvider::new().expect("provider")
    }

    /// Ids are 14 hex characters, so tests build them from a number.
    pub fn id(n: u64) -> String {
        format!("{n:014x}")
    }

    /// Well formed, with a placeholder signature that verifies against nothing.
    pub fn beacon(epoch: u64, epoch_id: &str) -> EpochBeacon {
        EpochBeacon {
            epoch,
            external_hpke_pub: Bytes::from(vec![9; HPKE_PUBLIC_KEY_LEN]),
            epoch_id: epoch_id.into(),
            signature: Bytes::from(vec![0; ED25519_SIGNATURE_LEN]),
        }
    }

    /// `(private, public)`, standing in for a member's leaf key.
    pub fn leaf_key(p: &MlsEphemeralPqProvider) -> (Vec<u8>, Vec<u8>) {
        p.crypto()
            .signature_key_gen(CIPHER_SUITE.signature_algorithm())
            .expect("signature keypair")
    }

    pub fn signed(p: &MlsEphemeralPqProvider, mut b: EpochBeacon, private: &[u8]) -> EpochBeacon {
        b.signature = p
            .crypto()
            .sign(
                CIPHER_SUITE.signature_algorithm(),
                &tbs(&b, "convo-a"),
                private,
            )
            .expect("sign")
            .into();
        b
    }

    pub fn frame(b: &EpochBeacon) -> Vec<u8> {
        GroupV3External::beacon(b.clone()).encode_to_vec()
    }

    /// The signed bytes must never move, or existing signatures stop verifying.
    #[test]
    fn the_signed_encoding_is_unchanged() {
        let b = EpochBeacon {
            epoch: 41,
            external_hpke_pub: Bytes::from_static(&[0xAB; 4]),
            epoch_id: "0123456789abcd".into(),
            signature: Bytes::from_static(&[0xCD; 3]),
        };

        assert_eq!(
            hex::encode(tbs(&b, "convo-a")),
            "0000001e6c6f676f732d636861742f626561636f6e2d7369676e61747572652f763100000007636f6e766f2d\
             61000000000000002900000004abababab0000000e3031323334353637383961626364"
        );
        assert_eq!(
            hex::encode(b.encode_to_vec()),
            "08291a04abababab220e30313233343536373839616263642a03cdcdcd"
        );
    }

    #[test]
    fn a_member_signed_beacon_verifies() {
        let p = provider();
        let (private, public) = leaf_key(&p);
        let b = signed(&p, beacon(41, &id(1)), &private);

        assert!(verify_beacon(
            p.crypto(),
            "convo-a",
            &b,
            [public, vec![1; 32]]
        ));
    }

    #[test]
    fn an_unsigned_beacon_does_not_verify() {
        let p = provider();
        let (_, public) = leaf_key(&p);

        assert!(!verify_beacon(
            p.crypto(),
            "convo-a",
            &beacon(41, &id(1)),
            [public]
        ));
    }

    #[test]
    fn a_beacon_signed_by_an_outsider_does_not_verify() {
        let p = provider();
        let (outsider, _) = leaf_key(&p);
        let (_, member) = leaf_key(&p);
        let b = signed(&p, beacon(41, &id(2)), &outsider);

        assert!(!verify_beacon(p.crypto(), "convo-a", &b, [member]));
    }

    #[test]
    fn every_signed_field_is_covered() {
        let p = provider();
        let (private, public) = leaf_key(&p);
        let original = signed(&p, beacon(41, &id(1)), &private);

        type Edit = fn(&mut EpochBeacon);
        let edits: [(&str, Edit); 3] = [
            ("epoch", |b| b.epoch += 1),
            ("key", |b| {
                b.external_hpke_pub = Bytes::from(vec![0xAA; HPKE_PUBLIC_KEY_LEN])
            }),
            ("epoch id", |b| b.epoch_id = id(3)),
        ];
        for (field, edit) in edits {
            let mut tampered = original.clone();
            edit(&mut tampered);
            assert!(
                !verify_beacon(p.crypto(), "convo-a", &tampered, [&public]),
                "edited {field} still verified"
            );
        }

        assert!(!verify_beacon(p.crypto(), "convo-b", &original, [&public]));
    }

    #[test]
    fn a_well_formed_beacon_is_admitted() {
        assert!(admit_frame(&frame(&beacon(41, &id(1)))).is_some());
    }

    #[test]
    fn a_malformed_beacon_is_refused() {
        type Edit = fn(&mut EpochBeacon);
        let edits: [(&str, Edit); 7] = [
            ("a short key", |b| b.external_hpke_pub.truncate(1184)),
            ("a long key", |b| {
                b.external_hpke_pub = Bytes::from(vec![9; HPKE_PUBLIC_KEY_LEN + 1])
            }),
            ("a short id", |b| b.epoch_id.truncate(13)),
            ("a non-hex id", |b| b.epoch_id = "zzzzzzzzzzzzzz".into()),
            ("no signature", |b| b.signature = Bytes::new()),
            ("a short signature", |b| b.signature.truncate(63)),
            ("a long signature", |b| {
                b.signature = Bytes::from(vec![0; 65])
            }),
        ];
        for (what, edit) in edits {
            let mut b = beacon(41, &id(1));
            edit(&mut b);
            assert!(admit_frame(&frame(&b)).is_none(), "{what} admitted");
        }
    }

    /// The bound must never refuse a real beacon.
    #[test]
    fn the_largest_well_formed_beacon_fits_the_bound() {
        let b = beacon(u64::MAX, &id(u64::MAX >> 8));

        assert!(b.encode_to_vec().len() <= MAX_BEACON_LEN);
        assert!(frame(&b).len() <= MAX_FRAME_LEN);
        assert!(admit_frame(&frame(&b)).is_some());
    }

    /// A huge key field followed by a well-formed beacon, whose key field
    /// replaces it. Decoded, it passes every shape check; only the bound,
    /// applied before decoding, refuses it.
    #[test]
    fn a_repeated_field_cannot_smuggle_a_large_allocation() {
        let mut crafted = Vec::new();
        prost::encoding::bytes::encode(3, &vec![0u8; 64 * 1024], &mut crafted);
        crafted.extend(beacon(41, &id(1)).encode_to_vec());

        let decoded = EpochBeacon::decode(crafted.as_slice()).expect("decodes");
        assert!(admit(decoded).is_some(), "the shape checks alone pass it");

        let mut frame = Vec::new();
        prost::encoding::encode_key(1, prost::encoding::WireType::LengthDelimited, &mut frame);
        prost::encoding::encode_varint(crafted.len() as u64, &mut frame);
        frame.extend(crafted);
        assert!(admit_frame(&frame).is_none());
    }
}
