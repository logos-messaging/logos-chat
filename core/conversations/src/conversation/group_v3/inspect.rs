//! Reading GroupV3 frames off the wire, for tests.
//!
//! Each function takes the bytes a delivery service carries for one envelope.

use openmls_traits::OpenMlsProvider as _;
use prost::Message as _;

use super::external::{EpochBeacon, verify_beacon};
use super::payloads::{EncryptedSdsMessage, GroupV3External, GroupV3ExternalKind};
use crate::SignerKey;
use crate::inbox_v2::MlsEphemeralPqProvider;
use crate::proto::EnvelopeV1;

/// The address a GroupV3 conversation listens on.
pub fn delivery_address(convo_id: &str) -> String {
    super::delivery_address_from_id(convo_id)
}

fn beacon_frame(data: &[u8]) -> Option<EpochBeacon> {
    let envelope = EnvelopeV1::decode(data).ok()?;
    let message = EncryptedSdsMessage::decode(envelope.payload.as_ref()).ok()?;
    let external = message.packet_outside_sds()?.ok()?.into_external().ok()?;
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
