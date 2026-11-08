//! Reading GroupV3 frames off the wire, for tests.
//!
//! Each function takes the bytes a delivery service carries for one envelope.

use openmls::framing::{ContentType, MlsMessageIn, ProtocolMessage};
use openmls::prelude::tls_codec::DeserializeBytes as _;
use openmls_traits::OpenMlsProvider as _;
use prost::Message as _;

use super::external::{EpochBeacon, GroupV3External, GroupV3ExternalKind, verify_beacon};
use super::payloads::GroupV3Payload;
use crate::SignerKey;
use crate::inbox_v2::MlsEphemeralPqProvider;
use crate::proto::EnvelopeV1;

/// The address a GroupV3 conversation listens on.
pub fn delivery_address(convo_id: &str) -> String {
    super::delivery_address_from_id(convo_id)
}

fn payload(data: &[u8]) -> Option<GroupV3Payload> {
    let envelope = EnvelopeV1::decode(data).ok()?;
    GroupV3Payload::decode(envelope.payload.as_ref()).ok()
}

fn beacon_frame(data: &[u8]) -> Option<EpochBeacon> {
    let external = payload(data)?.external;
    match GroupV3External::decode(external.as_ref()).ok()?.kind? {
        GroupV3ExternalKind::Beacon(beacon) => Some(beacon),
    }
}

/// Whether the envelope is a beacon frame.
pub fn is_beacon(data: &[u8]) -> bool {
    beacon_frame(data).is_some()
}

/// The epoch of a beacon frame `signer` signed, if this is one.
pub fn beacon_signed_by(data: &[u8], convo_id: &str, signer: &SignerKey) -> Option<u64> {
    let beacon = beacon_frame(data)?;
    let provider = MlsEphemeralPqProvider::new().ok()?;
    verify_beacon(provider.crypto(), convo_id, &beacon, [signer.as_bytes()]).then_some(beacon.epoch)
}

/// For an application message: the epoch of the beacon in its AAD, or `None`
/// if it carries none. `None` overall if this is not an application message.
pub fn application_aad_beacon(data: &[u8]) -> Option<Option<u64>> {
    let payload = payload(data)?;
    if !payload.external.is_empty() {
        return None;
    }
    let message = MlsMessageIn::tls_deserialize_exact_bytes(payload.encrypted_frame.as_ref())
        .ok()?
        .try_into_protocol_message()
        .ok()?;
    if message.content_type() != ContentType::Application {
        return None;
    }
    let ProtocolMessage::PrivateMessage(private) = &message else {
        return None;
    };
    Some(EpochBeacon::decode(private.aad()).ok().map(|b| b.epoch))
}
