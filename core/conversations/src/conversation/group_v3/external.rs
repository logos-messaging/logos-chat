//! The external frames on the wire: epoch beacons and sealed messages, after
//! [draft-mahy-mls-private-external].
//!
//! Each member derives a per-epoch HPKE keypair from the MLS exporter and
//! publishes the public half, signed with its leaf key. A client that can no
//! longer read the group can still see where it is and, later, seal to it.
//!
//! [draft-mahy-mls-private-external]: https://datatracker.ietf.org/doc/html/draft-mahy-mls-private-external-01

use openmls::group::MlsGroup;
use openmls_traits::OpenMlsProvider;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::{Ciphersuite, HpkeKeyPair, SignatureScheme};
use prost::bytes::Bytes;
use prost::{Message, Oneof};

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
    + (1 + 5) // ciphersuite
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

/// Published by every member on entering an epoch.
#[derive(Clone, PartialEq, Message)]
pub struct EpochBeacon {
    #[prost(uint64, tag = "1")]
    pub epoch: u64,
    #[prost(uint32, tag = "2")]
    pub ciphersuite: u32,
    #[prost(bytes = "bytes", tag = "3")]
    pub external_hpke_pub: Bytes,
    #[prost(string, tag = "4")]
    pub epoch_id: String,
    /// Empty on the copy carried in message AAD.
    #[prost(bytes = "bytes", tag = "5")]
    pub signature: Bytes,
}

/// The bytes a beacon signature covers.
#[derive(Clone, PartialEq, Message)]
struct BeaconTbs {
    #[prost(bytes = "bytes", tag = "1")]
    label: Bytes,
    #[prost(string, tag = "2")]
    group_id: String,
    #[prost(uint64, tag = "3")]
    epoch: u64,
    #[prost(uint32, tag = "4")]
    ciphersuite: u32,
    #[prost(bytes = "bytes", tag = "5")]
    external_hpke_pub: Bytes,
    #[prost(string, tag = "6")]
    epoch_id: String,
}

fn tbs(beacon: &EpochBeacon, convo_id: &str) -> Vec<u8> {
    BeaconTbs {
        label: Bytes::from_static(BEACON_SIG_LABEL),
        group_id: convo_id.to_string(),
        epoch: beacon.epoch,
        ciphersuite: beacon.ciphersuite,
        external_hpke_pub: beacon.external_hpke_pub.clone(),
        epoch_id: beacon.epoch_id.clone(),
    }
    .encode_to_vec()
}

/// A frame on the delivery address that is not an MLS message.
#[derive(Clone, PartialEq, Message)]
pub struct GroupV3External {
    #[prost(oneof = "GroupV3ExternalKind", tags = "1, 2")]
    pub kind: Option<GroupV3ExternalKind>,
}

#[derive(Clone, PartialEq, Oneof)]
pub enum GroupV3ExternalKind {
    #[prost(message, tag = "1")]
    Beacon(EpochBeacon),
    #[prost(message, tag = "2")]
    Sealed(SealedMessage),
}

impl GroupV3External {
    pub fn beacon(beacon: EpochBeacon) -> Self {
        Self {
            kind: Some(GroupV3ExternalKind::Beacon(beacon)),
        }
    }

    pub fn sealed(msg: SealedMessage) -> Self {
        Self {
            kind: Some(GroupV3ExternalKind::Sealed(msg)),
        }
    }
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
        ciphersuite: u16::from(group.ciphersuite()) as u32,
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

/// Which of `keys`, the roster's leaf signature keys, signed the beacon.
pub fn verify_beacon<C, I, K>(
    crypto: &C,
    convo_id: &str,
    beacon: &EpochBeacon,
    keys: I,
) -> Option<K>
where
    C: OpenMlsCrypto,
    I: IntoIterator<Item = K>,
    K: AsRef<[u8]>,
{
    if beacon.signature.is_empty() {
        return None;
    }
    // The publisher picks the scheme, but the key comes from our tree, so a
    // wrong scheme can only fail.
    let ciphersuite = u16::try_from(beacon.ciphersuite)
        .ok()
        .and_then(|id| Ciphersuite::try_from(id).ok())?;
    let scheme = ciphersuite.signature_algorithm();
    let tbs = tbs(beacon, convo_id);

    keys.into_iter().find(|key| {
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

/// One state of the group. Branches of a fork share an epoch, so the id too.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Branch {
    pub epoch: u64,
    pub epoch_id: String,
}

/// Shape checks, cheap enough for anything. Every field ends up fixed-size, so
/// a store of admitted beacons is bounded in bytes as well as entries.
pub fn admit(beacon: EpochBeacon, ours: Ciphersuite) -> Option<Admitted> {
    let well_formed = beacon.ciphersuite == u16::from(ours) as u32
        // RUSTSEC-2026-0331: a short X-Wing key panics in libcrux-kem.
        && check_hpke_public_key(&beacon.external_hpke_pub).is_ok()
        && is_epoch_id(&beacon.epoch_id)
        && (beacon.signature.is_empty() || beacon.signature.len() == ED25519_SIGNATURE_LEN);

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
pub fn admit_frame(bytes: &[u8], ours: Ciphersuite) -> Option<Inbound> {
    if bytes.len() > MAX_FRAME_LEN {
        return None;
    }
    match GroupV3External::decode(bytes).ok()?.kind? {
        GroupV3ExternalKind::Beacon(beacon) => admit(beacon, ours).map(Inbound::Beacon),
        GroupV3ExternalKind::Sealed(msg) => msg.is_well_formed().then_some(Inbound::Sealed(msg)),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ExternalError {
    #[error("could not derive the epoch's external encryption key: {0}")]
    Derive(String),
    #[error("could not sign a beacon: {0}")]
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

    pub fn beacon(epoch: u64, epoch_id: &str) -> EpochBeacon {
        EpochBeacon {
            epoch,
            ciphersuite: u16::from(CIPHER_SUITE) as u32,
            external_hpke_pub: Bytes::from(vec![9; HPKE_PUBLIC_KEY_LEN]),
            epoch_id: epoch_id.into(),
            signature: Bytes::new(),
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

    /// Captured before the byte fields became `Bytes`: the signed encoding
    /// must never move, or existing signatures stop verifying.
    #[test]
    fn the_signed_encoding_is_unchanged() {
        let b = EpochBeacon {
            epoch: 41,
            ciphersuite: 0x004D,
            external_hpke_pub: Bytes::from_static(&[0xAB; 4]),
            epoch_id: "0123456789abcd".into(),
            signature: Bytes::from_static(&[0xCD; 3]),
        };

        assert_eq!(
            hex::encode(tbs(&b, "convo-a")),
            "0a1e6c6f676f732d636861742f626561636f6e2d7369676e61747572652f76311207636f6e766f2d61\
             1829204d2a04abababab320e3031323334353637383961626364"
        );
        assert_eq!(
            hex::encode(b.encode_to_vec()),
            "0829104d1a04abababab220e30313233343536373839616263642a03cdcdcd"
        );
    }

    #[test]
    fn a_verified_beacon_names_its_signer() {
        let p = provider();
        let (private, public) = leaf_key(&p);
        let b = signed(&p, beacon(41, &id(1)), &private);

        let signer = verify_beacon(p.crypto(), "convo-a", &b, [vec![1; 32], public.clone()]);

        assert_eq!(signer, Some(public));
    }

    #[test]
    fn an_unsigned_beacon_does_not_verify() {
        let p = provider();
        let (_, public) = leaf_key(&p);

        assert!(verify_beacon(p.crypto(), "convo-a", &beacon(41, &id(1)), [public]).is_none());
    }

    #[test]
    fn a_beacon_signed_by_an_outsider_does_not_verify() {
        let p = provider();
        let (outsider, _) = leaf_key(&p);
        let (_, member) = leaf_key(&p);
        let b = signed(&p, beacon(41, &id(2)), &outsider);

        assert!(verify_beacon(p.crypto(), "convo-a", &b, [member]).is_none());
    }

    #[test]
    fn every_signed_field_is_covered() {
        let p = provider();
        let (private, public) = leaf_key(&p);
        let original = signed(&p, beacon(41, &id(1)), &private);

        type Edit = fn(&mut EpochBeacon);
        let edits: [(&str, Edit); 4] = [
            ("epoch", |b| b.epoch += 1),
            ("key", |b| {
                b.external_hpke_pub = Bytes::from(vec![0xAA; HPKE_PUBLIC_KEY_LEN])
            }),
            ("epoch id", |b| b.epoch_id = id(3)),
            ("ciphersuite", |b| b.ciphersuite = 1),
        ];
        for (field, edit) in edits {
            let mut tampered = original.clone();
            edit(&mut tampered);
            assert!(
                verify_beacon(p.crypto(), "convo-a", &tampered, [&public]).is_none(),
                "edited {field} still verified"
            );
        }

        assert!(verify_beacon(p.crypto(), "convo-b", &original, [&public]).is_none());
    }

    /// A suite id above `u16::MAX` must not truncate onto a real suite. The
    /// signature covers the full `u32`, so with `as u16` this one verified.
    #[test]
    fn an_out_of_range_ciphersuite_does_not_alias_a_real_one() {
        let p = provider();
        let (private, public) = leaf_key(&p);
        let mut b = beacon(41, &id(1));
        b.ciphersuite |= 0x1_0000;
        let b = signed(&p, b, &private);

        assert!(verify_beacon(p.crypto(), "convo-a", &b, [public]).is_none());
        assert!(admit(b, CIPHER_SUITE).is_none());
    }

    #[test]
    fn a_well_formed_beacon_is_admitted_signed_or_not() {
        let p = provider();
        let (private, _) = leaf_key(&p);
        let unsigned = beacon(41, &id(1));
        let signed = signed(&p, unsigned.clone(), &private);

        assert!(admit_frame(&frame(&unsigned), CIPHER_SUITE).is_some());
        assert!(admit_frame(&frame(&signed), CIPHER_SUITE).is_some());
    }

    #[test]
    fn a_malformed_beacon_is_refused() {
        type Edit = fn(&mut EpochBeacon);
        let edits: [(&str, Edit); 6] = [
            ("another ciphersuite", |b| b.ciphersuite = 1),
            ("a short key", |b| b.external_hpke_pub.truncate(1184)),
            ("a long key", |b| {
                b.external_hpke_pub = Bytes::from(vec![9; HPKE_PUBLIC_KEY_LEN + 1])
            }),
            ("a short id", |b| b.epoch_id.truncate(13)),
            ("a non-hex id", |b| b.epoch_id = "zzzzzzzzzzzzzz".into()),
            ("a long signature", |b| {
                b.signature = Bytes::from(vec![0; 65])
            }),
        ];
        for (what, edit) in edits {
            let mut b = beacon(41, &id(1));
            edit(&mut b);
            assert!(
                admit_frame(&frame(&b), CIPHER_SUITE).is_none(),
                "{what} admitted from a frame"
            );
        }
    }

    /// The bound must never refuse a real beacon.
    #[test]
    fn the_largest_well_formed_beacon_fits_the_bound() {
        let mut b = beacon(u64::MAX, &id(u64::MAX >> 8));
        b.signature = Bytes::from(vec![0; ED25519_SIGNATURE_LEN]);

        assert!(b.encode_to_vec().len() <= MAX_BEACON_LEN);
        assert!(frame(&b).len() <= MAX_FRAME_LEN);
        assert!(admit_frame(&frame(&b), CIPHER_SUITE).is_some());
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
        assert!(
            admit(decoded, CIPHER_SUITE).is_some(),
            "the shape checks alone pass it"
        );

        let mut frame = Vec::new();
        prost::encoding::encode_key(1, prost::encoding::WireType::LengthDelimited, &mut frame);
        prost::encoding::encode_varint(crafted.len() as u64, &mut frame);
        frame.extend(crafted);
        assert!(admit_frame(&frame, CIPHER_SUITE).is_none());
    }

    #[test]
    fn a_beacon_round_trips_through_the_external_envelope() {
        let sent = GroupV3External::beacon(beacon(41, &id(1)));
        let received = GroupV3External::decode(sent.encode_to_vec().as_slice()).expect("decode");

        assert_eq!(received, sent);
    }
}
