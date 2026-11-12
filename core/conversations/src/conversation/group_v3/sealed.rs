//! Private external messages: HPKE-sealed to one epoch's external key, so a
//! client that can no longer read the group can still reach it.

use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::signatures::Signer;
use openmls_traits::types::{Ciphersuite, HpkeCiphertext, HpkePrivateKey};
use prost::bytes::Bytes;
use prost::{Message, Oneof};

use super::external::{
    ED25519_SIGNATURE_LEN, EPOCH_ID_LEN, EpochBeacon, ExternalError, is_epoch_id, put_bytes,
};
use crate::inbox_v2::{CIPHER_SUITE, HPKE_PUBLIC_KEY_LEN, check_hpke_public_key};

const HPKE_INFO_LABEL: &[u8] = b"logos-chat/private-external/v1";
const READD_SIG_LABEL: &[u8] = b"logos-chat/readd-signature/v1";

/// X-Wing's encapsulation: ML-KEM-768's 1088 bytes and X25519's 32.
pub const KEM_OUTPUT_LEN: usize = 1088 + 32;

const SIGNER_KEY_LEN: usize = 32;

/// ChaCha20-Poly1305's tag.
const AEAD_TAG_LEN: usize = 16;

/// Branches a request shows signatures for, and signatures per branch.
pub const EVIDENCE_BRANCHES: usize = 3;
pub const EVIDENCE_SIGNATURES: usize = 8;

/// Encoded size of a [`Vouch`] and of the largest [`Vouches`].
const VOUCH_LEN: usize = (1 + 1 + SIGNER_KEY_LEN) + (1 + 1 + ED25519_SIGNATURE_LEN);
const MAX_VOUCHES_LEN: usize = (1 + 1 + EPOCH_ID_LEN)
    + (1 + 2 + HPKE_PUBLIC_KEY_LEN)
    + EVIDENCE_SIGNATURES * (1 + 1 + VOUCH_LEN);

/// Encoded size of the largest [`SealedPayload`], as for `MAX_BEACON_LEN`.
const MAX_PAYLOAD_LEN: usize = 1 + 2 // oneof tag and length
    + (1 + 1 + SIGNER_KEY_LEN)
    + (1 + 10) // epoch
    + (1 + 1 + EPOCH_ID_LEN)
    + (1 + 1 + ED25519_SIGNATURE_LEN)
    + (1 + 1 + SIGNER_KEY_LEN) // answerer
    + EVIDENCE_BRANCHES * (1 + 2 + MAX_VOUCHES_LEN);

/// Encoded size of the largest well-formed [`SealedMessage`].
pub const MAX_SEALED_LEN: usize = (1 + 10) // epoch
    + (1 + 1 + EPOCH_ID_LEN)
    + (1 + 2 + KEM_OUTPUT_LEN)
    + (1 + 2 + MAX_PAYLOAD_LEN + AEAD_TAG_LEN);

/// Sealed to the external key of the state `epoch` and `epoch_id` name. The id
/// lets a member skip the HPKE open for another branch's messages.
#[derive(Clone, PartialEq, Message)]
pub struct SealedMessage {
    #[prost(uint64, tag = "1")]
    pub epoch: u64,
    #[prost(string, tag = "2")]
    pub epoch_id: String,
    #[prost(bytes = "bytes", tag = "3")]
    pub kem_output: Bytes,
    #[prost(bytes = "bytes", tag = "4")]
    pub ciphertext: Bytes,
}

impl SealedMessage {
    pub fn is_well_formed(&self) -> bool {
        is_epoch_id(&self.epoch_id)
            && self.kem_output.len() == KEM_OUTPUT_LEN
            && (AEAD_TAG_LEN..=MAX_PAYLOAD_LEN + AEAD_TAG_LEN).contains(&self.ciphertext.len())
    }
}

#[derive(Clone, PartialEq, Message)]
pub struct SealedPayload {
    #[prost(oneof = "SealedKind", tags = "1")]
    pub kind: Option<SealedKind>,
}

#[derive(Clone, PartialEq, Oneof)]
pub enum SealedKind {
    #[prost(message, tag = "1")]
    ReAdd(ReAddRequest),
}

/// Asks the group to replace the sender's stale leaf with a fresh KeyPackage.
/// Signed with the sender's leaf key and checked against the answerer's
/// roster: sealing alone only shows the sender saw a beacon.
///
/// `answerer` names the one member to repair it: one whose beacon for the
/// target state the sender verified, so it is on the sender's roster and the
/// sender accepts its Welcome. `evidence` is the signed beacons the sender
/// holds at its epoch, so both sides rank the branches on the same signatures.
#[derive(Clone, PartialEq, Message)]
pub struct ReAddRequest {
    #[prost(bytes = "bytes", tag = "1")]
    pub signer_key: Bytes,
    #[prost(uint64, tag = "2")]
    pub epoch: u64,
    #[prost(string, tag = "3")]
    pub epoch_id: String,
    #[prost(bytes = "bytes", tag = "4")]
    pub signature: Bytes,
    #[prost(bytes = "bytes", tag = "5")]
    pub answerer: Bytes,
    #[prost(message, repeated, tag = "6")]
    pub evidence: Vec<Vouches>,
}

/// Members' signatures over one branch's beacon at the request's epoch.
#[derive(Clone, PartialEq, Message)]
pub struct Vouches {
    #[prost(string, tag = "1")]
    pub epoch_id: String,
    #[prost(bytes = "bytes", tag = "2")]
    pub external_hpke_pub: Bytes,
    #[prost(message, repeated, tag = "3")]
    pub vouches: Vec<Vouch>,
}

/// One member's signature, naming the leaf key that made it.
#[derive(Clone, PartialEq, Message)]
pub struct Vouch {
    #[prost(bytes = "bytes", tag = "1")]
    pub signer_key: Bytes,
    #[prost(bytes = "bytes", tag = "2")]
    pub signature: Bytes,
}

/// The bytes a request signature covers, laid out as a beacon's are. Includes
/// the state it is sealed to, so a captured request can't be re-sealed to
/// another branch or epoch.
/// A list's length, prefixed as [`put_bytes`] prefixes bytes.
fn put_count(out: &mut Vec<u8>, n: usize) {
    out.extend_from_slice(&(n as u32).to_be_bytes());
}

fn tbs(req: &ReAddRequest, convo_id: &str, to_epoch: u64, to_epoch_id: &str) -> Vec<u8> {
    let mut out = Vec::new();
    put_bytes(&mut out, READD_SIG_LABEL);
    put_bytes(&mut out, convo_id.as_bytes());
    put_bytes(&mut out, &req.signer_key);
    out.extend_from_slice(&req.epoch.to_be_bytes());
    put_bytes(&mut out, req.epoch_id.as_bytes());
    out.extend_from_slice(&to_epoch.to_be_bytes());
    put_bytes(&mut out, to_epoch_id.as_bytes());
    put_bytes(&mut out, &req.answerer);
    put_count(&mut out, req.evidence.len());
    for branch in &req.evidence {
        put_bytes(&mut out, branch.epoch_id.as_bytes());
        put_bytes(&mut out, &branch.external_hpke_pub);
        put_count(&mut out, branch.vouches.len());
        for vouch in &branch.vouches {
            put_bytes(&mut out, &vouch.signer_key);
            put_bytes(&mut out, &vouch.signature);
        }
    }
    out
}

/// Sign a request for sealing to `to`.
pub fn sign_request(
    mut req: ReAddRequest,
    convo_id: &str,
    to: &EpochBeacon,
    signer: &impl Signer,
) -> Result<ReAddRequest, ExternalError> {
    req.signature = signer
        .sign(&tbs(&req, convo_id, to.epoch, &to.epoch_id))
        .map(Bytes::from)
        .map_err(|e| ExternalError::Sign(format!("{e:?}")))?;
    Ok(req)
}

/// Whether `signer_key` signed the request for the state `msg` was sealed to.
/// The caller still checks that `signer_key` is on its roster.
pub fn verify_request(
    crypto: &impl OpenMlsCrypto,
    convo_id: &str,
    req: &ReAddRequest,
    msg: &SealedMessage,
) -> bool {
    req.signature.len() == ED25519_SIGNATURE_LEN
        && crypto
            .verify_signature(
                CIPHER_SUITE.signature_algorithm(),
                &tbs(req, convo_id, msg.epoch, &msg.epoch_id),
                &req.signer_key,
                &req.signature,
            )
            .is_ok()
}

/// Binds a sealed message to its conversation and to the state it targets.
fn hpke_info(convo_id: &str, epoch: u64, epoch_id: &str) -> Vec<u8> {
    [
        HPKE_INFO_LABEL,
        convo_id.as_bytes(),
        &epoch.to_be_bytes(),
        epoch_id.as_bytes(),
    ]
    .concat()
}

/// Seal `payload` to the key a beacon advertises.
pub fn seal(
    crypto: &impl OpenMlsCrypto,
    ciphersuite: Ciphersuite,
    convo_id: &str,
    to: &EpochBeacon,
    payload: &SealedPayload,
) -> Result<SealedMessage, ExternalError> {
    // RUSTSEC-2026-0331: a short X-Wing key panics in libcrux-kem.
    check_hpke_public_key(&to.external_hpke_pub).map_err(|e| ExternalError::Seal(e.to_string()))?;

    let sealed = crypto
        .hpke_seal(
            ciphersuite.hpke_config(),
            &to.external_hpke_pub,
            &hpke_info(convo_id, to.epoch, &to.epoch_id),
            &[],
            &payload.encode_to_vec(),
        )
        .map_err(|e| ExternalError::Seal(format!("{e:?}")))?;

    Ok(SealedMessage {
        epoch: to.epoch,
        epoch_id: to.epoch_id.clone(),
        kem_output: Bytes::from(sealed.kem_output.as_slice().to_vec()),
        ciphertext: Bytes::from(sealed.ciphertext.as_slice().to_vec()),
    })
}

/// Open a message sealed to our key for its state.
pub fn open(
    crypto: &impl OpenMlsCrypto,
    ciphersuite: Ciphersuite,
    convo_id: &str,
    key: &HpkePrivateKey,
    msg: &SealedMessage,
) -> Result<SealedPayload, ExternalError> {
    let ciphertext = HpkeCiphertext {
        kem_output: msg.kem_output.to_vec().into(),
        ciphertext: msg.ciphertext.to_vec().into(),
    };
    let plaintext = crypto
        .hpke_open(
            ciphersuite.hpke_config(),
            &ciphertext,
            key,
            &hpke_info(convo_id, msg.epoch, &msg.epoch_id),
            &[],
        )
        .map_err(|e| ExternalError::Open(format!("{e:?}")))?;

    SealedPayload::decode(plaintext.as_slice()).map_err(|e| ExternalError::Open(e.to_string()))
}

#[cfg(test)]
mod tests {
    use openmls_traits::OpenMlsProvider as _;
    use openmls_traits::types::HpkeKeyPair;

    use openmls_traits::signatures::SignerError;
    use openmls_traits::types::SignatureScheme;

    use super::*;
    use crate::conversation::group_v3::external::tests::{beacon, id, leaf_key, provider};
    use crate::conversation::group_v3::external::{Inbound, admit_frame};
    use crate::conversation::group_v3::payloads::GroupV3External;
    use crate::inbox_v2::{CIPHER_SUITE, MlsEphemeralPqProvider};

    fn keypair(p: &MlsEphemeralPqProvider) -> HpkeKeyPair {
        p.crypto()
            .derive_hpke_keypair(CIPHER_SUITE.hpke_config(), &[7; 32])
            .expect("keypair")
    }

    /// The largest request a member can send.
    fn request() -> SealedPayload {
        SealedPayload {
            kind: Some(SealedKind::ReAdd(ReAddRequest {
                signer_key: Bytes::from_static(&[1; SIGNER_KEY_LEN]),
                epoch: u64::MAX,
                epoch_id: id(u64::MAX >> 8),
                signature: Bytes::from_static(&[2; ED25519_SIGNATURE_LEN]),
                answerer: Bytes::from_static(&[3; SIGNER_KEY_LEN]),
                evidence: vec![
                    Vouches {
                        epoch_id: id(u64::MAX >> 8),
                        external_hpke_pub: vec![3; HPKE_PUBLIC_KEY_LEN].into(),
                        vouches: vec![
                            Vouch {
                                signer_key: Bytes::from_static(&[5; SIGNER_KEY_LEN]),
                                signature: Bytes::from_static(&[4; ED25519_SIGNATURE_LEN]),
                            };
                            EVIDENCE_SIGNATURES
                        ],
                    };
                    EVIDENCE_BRANCHES
                ],
            })),
        }
    }

    struct LeafSigner<'a>(&'a MlsEphemeralPqProvider, Vec<u8>);

    impl Signer for LeafSigner<'_> {
        fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
            self.0
                .crypto()
                .sign(SignatureScheme::ED25519, payload, &self.1)
                .map_err(|_| SignerError::SigningError)
        }

        fn signature_scheme(&self) -> SignatureScheme {
            SignatureScheme::ED25519
        }
    }

    /// A request from the holder of `public`, signed for sealing to epoch 41.
    fn signed_request(p: &MlsEphemeralPqProvider) -> (ReAddRequest, SealedMessage) {
        let (private, public) = leaf_key(p);
        let to = beacon(41, &id(1));
        let req = ReAddRequest {
            signer_key: public.into(),
            epoch: 41,
            epoch_id: id(2),
            signature: Bytes::new(),
            answerer: Bytes::from_static(&[3; SIGNER_KEY_LEN]),
            evidence: vec![Vouches {
                epoch_id: id(2),
                external_hpke_pub: vec![3; HPKE_PUBLIC_KEY_LEN].into(),
                vouches: vec![Vouch {
                    signer_key: Bytes::from_static(&[5; SIGNER_KEY_LEN]),
                    signature: Bytes::from_static(&[4; ED25519_SIGNATURE_LEN]),
                }],
            }],
        };
        let req = sign_request(req, "convo-a", &to, &LeafSigner(p, private)).expect("signed");
        let msg = SealedMessage {
            epoch: to.epoch,
            epoch_id: to.epoch_id,
            ..Default::default()
        };
        (req, msg)
    }

    /// The signed bytes must never move, or existing signatures stop verifying.
    #[test]
    fn the_signed_encoding_is_unchanged() {
        let req = ReAddRequest {
            signer_key: Bytes::from_static(&[0xAB; 2]),
            epoch: 41,
            epoch_id: "0123456789abcd".into(),
            signature: Bytes::from_static(&[0xCD; 3]),
            answerer: Bytes::from_static(&[0xEF; 2]),
            evidence: vec![Vouches {
                epoch_id: "e".into(),
                external_hpke_pub: Bytes::from_static(&[0x12]),
                vouches: vec![Vouch {
                    signer_key: Bytes::from_static(&[0x34]),
                    signature: Bytes::from_static(&[0x56]),
                }],
            }],
        };

        assert_eq!(
            hex::encode(tbs(&req, "convo-a", 42, "dcba9876543210")),
            "0000001d6c6f676f732d636861742f72656164642d7369676e61747572652f763100000007636f6e\
766f2d6100000002abab00000000000000290000000e3031323334353637383961626364000000000000002a0000000e646362613938373635343332313000000002efef\
00000001000000016500000001120000000100000001340000000156"
        );
    }

    #[test]
    fn a_signed_request_verifies() {
        let p = provider();
        let (req, msg) = signed_request(&p);
        assert!(verify_request(p.crypto(), "convo-a", &req, &msg));
    }

    #[test]
    fn an_unsigned_request_does_not_verify() {
        let p = provider();
        let (mut req, msg) = signed_request(&p);
        req.signature = Bytes::new();
        assert!(!verify_request(p.crypto(), "convo-a", &req, &msg));
    }

    /// Claiming another member's key: the signature was made with ours.
    #[test]
    fn a_request_naming_someone_else_does_not_verify() {
        let p = provider();
        let (mut req, msg) = signed_request(&p);
        req.signer_key = leaf_key(&p).1.into();
        assert!(!verify_request(p.crypto(), "convo-a", &req, &msg));
    }

    /// Covers the request, its conversation, and the state it was sealed to.
    #[test]
    fn every_signed_field_is_covered() {
        let p = provider();
        type Change = fn(&mut ReAddRequest, &mut SealedMessage, &mut &str);
        let changes: [(&str, Change); 7] = [
            ("epoch", |r, _, _| r.epoch += 1),
            ("answerer", |r, _, _| {
                r.answerer = Bytes::from_static(&[4; 32])
            }),
            ("evidence", |r, _, _| r.evidence[0].vouches.clear()),
            ("epoch id", |r, _, _| r.epoch_id = id(3)),
            ("sealed to another epoch", |_, m, _| m.epoch += 1),
            ("sealed to another branch", |_, m, _| m.epoch_id = id(4)),
            ("another conversation", |_, _, c| *c = "convo-b"),
        ];
        for (name, change) in changes {
            let (mut req, mut msg) = signed_request(&p);
            let mut convo_id = "convo-a";
            change(&mut req, &mut msg, &mut convo_id);
            assert!(!verify_request(p.crypto(), convo_id, &req, &msg), "{name}");
        }
    }

    fn sealed_to(p: &MlsEphemeralPqProvider, keys: &HpkeKeyPair, convo_id: &str) -> SealedMessage {
        let mut to = beacon(u64::MAX, &id(1));
        to.external_hpke_pub = keys.public.clone().into();
        seal(p.crypto(), CIPHER_SUITE, convo_id, &to, &request()).expect("sealed")
    }

    fn frame(msg: &SealedMessage) -> Vec<u8> {
        GroupV3External::sealed(msg.clone()).encode_to_vec()
    }

    #[test]
    fn a_request_opens_with_the_key_it_was_sealed_to() {
        let p = provider();
        let keys = keypair(&p);
        let msg = sealed_to(&p, &keys, "convo-a");

        let opened = open(p.crypto(), CIPHER_SUITE, "convo-a", &keys.private, &msg);
        assert_eq!(opened.expect("opens"), request());
    }

    #[test]
    fn a_message_for_another_conversation_does_not_open() {
        let p = provider();
        let keys = keypair(&p);
        let msg = sealed_to(&p, &keys, "convo-a");

        assert!(open(p.crypto(), CIPHER_SUITE, "convo-b", &keys.private, &msg).is_err());
    }

    /// The state is bound into the seal, so relabelling a message cannot point
    /// it at another branch.
    #[test]
    fn a_relabelled_message_does_not_open() {
        let p = provider();
        let keys = keypair(&p);
        for relabel in [
            |m: &mut SealedMessage| m.epoch -= 1,
            |m: &mut SealedMessage| m.epoch_id = id(2),
        ] {
            let mut msg = sealed_to(&p, &keys, "convo-a");
            relabel(&mut msg);
            assert!(open(p.crypto(), CIPHER_SUITE, "convo-a", &keys.private, &msg).is_err());
        }
    }

    #[test]
    fn a_short_key_is_refused_before_sealing() {
        let p = provider();
        let mut to = beacon(41, &id(1));
        to.external_hpke_pub = Bytes::from_static(&[9; 32]);

        assert!(seal(p.crypto(), CIPHER_SUITE, "convo-a", &to, &request()).is_err());
    }

    /// Pins the sizes the bounds are computed from to what sealing produces.
    #[test]
    fn the_largest_request_is_admitted() {
        let p = provider();
        let msg = sealed_to(&p, &keypair(&p), "convo-a");

        assert_eq!(msg.kem_output.len(), KEM_OUTPUT_LEN);
        assert_eq!(msg.encoded_len(), MAX_SEALED_LEN);
        assert!(matches!(
            admit_frame(&frame(&msg)),
            Some(Inbound::Sealed(_))
        ));
    }

    #[test]
    fn a_malformed_sealed_message_is_refused() {
        let p = provider();
        let good = sealed_to(&p, &keypair(&p), "convo-a");
        type Break = fn(&mut SealedMessage);
        let cases: [(&str, Break); 4] = [
            ("short kem output", |m| {
                m.kem_output = Bytes::from_static(&[0; 32])
            }),
            ("long ciphertext", |m| {
                m.ciphertext = vec![0; MAX_PAYLOAD_LEN + AEAD_TAG_LEN + 1].into()
            }),
            ("empty ciphertext", |m| m.ciphertext = Bytes::new()),
            ("epoch id not hex", |m| {
                m.epoch_id = "z".repeat(EPOCH_ID_LEN)
            }),
        ];
        for (name, break_it) in cases {
            let mut msg = good.clone();
            break_it(&mut msg);
            assert!(admit_frame(&frame(&msg)).is_none(), "{name}");
        }
    }
}
