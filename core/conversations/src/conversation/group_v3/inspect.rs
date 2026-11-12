//! Reading GroupV3 frames off the wire, for tests.
//!
//! Each function takes the bytes a delivery service carries for one envelope.

use openmls::framing::ContentType;
use openmls_traits::OpenMlsProvider as _;
use prost::Message as _;

use super::external::{EpochBeacon, verify_beacon};
use super::payloads::{
    GroupV3Body, GroupV3External, GroupV3ExternalKind, GroupV3Payload, protocol_message,
    to_envelope,
};
use super::sealed::{self, ReAddRequest, SealedKind, SealedPayload};
use crate::inbox_v2::MlsEphemeralPqProvider;
use crate::proto::EnvelopeV1;
use crate::{AddressedEnvelope, SignerKey};

/// The address a GroupV3 conversation listens on.
pub fn delivery_address(convo_id: &str) -> String {
    super::delivery_address_from_id(convo_id)
}

fn payload(data: &[u8]) -> Option<GroupV3Payload> {
    let envelope = EnvelopeV1::decode(data).ok()?;
    GroupV3Payload::decode(envelope.payload.as_ref()).ok()
}

fn external_kind(data: &[u8]) -> Option<GroupV3ExternalKind> {
    let Some(GroupV3Body::External(external)) = payload(data)?.body else {
        return None;
    };
    GroupV3External::decode(external.as_ref()).ok()?.kind
}

fn beacon_frame(data: &[u8]) -> Option<EpochBeacon> {
    match external_kind(data)? {
        GroupV3ExternalKind::Beacon(beacon) => Some(beacon),
        GroupV3ExternalKind::Sealed(_) => None,
    }
}

/// Whether the envelope is a sealed private external message.
pub fn is_sealed(data: &[u8]) -> bool {
    matches!(external_kind(data), Some(GroupV3ExternalKind::Sealed(_)))
}

/// Whether the envelope is a beacon frame.
pub fn is_beacon(data: &[u8]) -> bool {
    beacon_frame(data).is_some()
}

/// The epoch of a beacon frame `signer` signed, if this is one.
pub fn beacon_signed_by(data: &[u8], convo_id: &str, signer: &SignerKey) -> Option<u64> {
    let beacon = beacon_frame(data)?;
    let provider = MlsEphemeralPqProvider::new().ok()?;
    verify_beacon(provider.crypto(), convo_id, &beacon, [signer.as_bytes()]).map(|_| beacon.epoch)
}

/// Whether the envelope is an MLS commit.
pub fn is_commit(data: &[u8]) -> bool {
    let Some(GroupV3Body::EncryptedFrame(frame)) = payload(data).and_then(|p| p.body) else {
        return false;
    };
    protocol_message(&frame).is_ok_and(|m| m.content_type() == ContentType::Commit)
}

/// An unsigned re-add request naming `signer`, sealed to the key in the beacon
/// frame `beacon_data`, as a forger who saw that beacon could send.
pub fn unsigned_readd(
    beacon_data: &[u8],
    convo_id: &str,
    signer: &SignerKey,
    epoch_id: &str,
) -> Option<AddressedEnvelope> {
    let to = beacon_frame(beacon_data)?;
    let payload = SealedPayload {
        kind: Some(SealedKind::ReAdd(ReAddRequest {
            signer_key: signer.as_bytes().to_vec().into(),
            epoch: to.epoch,
            epoch_id: epoch_id.into(),
            signature: Default::default(),
            answerer: Default::default(),
        })),
    };
    let provider = MlsEphemeralPqProvider::new().ok()?;
    let msg = sealed::seal(
        provider.crypto(),
        crate::inbox_v2::CIPHER_SUITE,
        convo_id,
        &to,
        &payload,
    )
    .ok()?;
    Some(to_envelope(
        convo_id.to_string(),
        GroupV3Payload::external(GroupV3External::sealed(msg)),
    ))
}
