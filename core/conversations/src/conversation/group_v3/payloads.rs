//! Wire framing for GroupV3.
//!
//! ```text
//! AddressedEnvelope                        delivery address + convo id
//! └── GroupV3Payload                       protobuf
//!     ├── encrypted_header                 bytes; placeholder
//!     ├── encrypted_frame                  bytes; TLS-serialized
//!     │   └── MlsMessage                   Commit | ApplicationMessage
//!     │       └── GroupV3Frame             protobuf; ApplicationMessage only
//!     │           └── GroupV3FrameType     Content
//!     └── external                         bytes; instead of encrypted_frame
//!         └── GroupV3External              protobuf; non-MLS frames
//! ```
//!
//! `FrameId` hashes the encoded `GroupV3Frame`, so sender and receivers derive the same id from
//! plaintext. `GroupV3Frame` tags 1–5 are reserved for frame parameters.

use openmls::framing::MlsMessageOut;
use prost::{Message, Oneof, bytes::Bytes};

use crate::{
    AddressedEnvelope,
    errors::SendError,
    utils::{blake2b_hex, hash_size},
};

use super::{FrameId, delivery_address_from_id};

pub(super) fn frame_id(frame_bytes: &[u8]) -> FrameId {
    blake2b_hex::<hash_size::MessageId>(&["logos-chat|message_id|".as_bytes(), frame_bytes])
}

#[derive(Clone, PartialEq, Message)]
pub struct GroupV3Frame {
    //reserved 1, 5 for Frame paramters.
    #[prost(oneof = "GroupV3FrameType", tags = "6,7")]
    pub payload: Option<GroupV3FrameType>,
}

#[derive(Clone, PartialEq, Oneof)]
pub enum GroupV3FrameType {
    #[prost(bytes = "bytes", tag = "6")]
    Content(Bytes),
}

impl GroupV3Frame {
    pub fn from_content(bytes: &[u8]) -> GroupV3Frame {
        GroupV3Frame {
            payload: Some(GroupV3FrameType::Content(Bytes::copy_from_slice(bytes))),
        }
    }

    pub fn encode(self) -> Vec<u8> {
        self.encode_to_vec()
    }
}

fn to_payload(msg: MlsMessageOut) -> Result<Vec<u8>, SendError> {
    let bytes = msg.to_bytes()?;

    let payload = GroupV3Payload {
        encrypted_header: vec![0, 0, 0, 0].into(),
        encrypted_frame: bytes.into(),
        external: Bytes::new(),
    };

    Ok(payload.encode_to_vec())
}

/// Address a non-MLS frame to a conversation.
pub fn to_external_envelope(convo_id: &str, bytes: Vec<u8>) -> AddressedEnvelope {
    let payload = GroupV3Payload {
        external: bytes.into(),
        ..Default::default()
    };

    AddressedEnvelope::with_payload(
        delivery_address_from_id(convo_id),
        convo_id.to_string(),
        payload.encode_to_vec(),
    )
}

pub fn to_envelope(convo_id: String, msg: MlsMessageOut) -> Result<AddressedEnvelope, SendError> {
    Ok(AddressedEnvelope::with_payload(
        delivery_address_from_id(&convo_id),
        convo_id,
        to_payload(msg)?,
    ))
}

#[derive(Clone, PartialEq, Message)]
pub struct GroupV3Payload {
    #[prost(bytes = "bytes", tag = "1")]
    pub encrypted_header: Bytes,
    #[prost(bytes = "bytes", tag = "2")]
    pub encrypted_frame: Bytes,
    /// Set instead of `encrypted_frame` for a non-MLS frame.
    #[prost(bytes = "bytes", tag = "3")]
    pub external: Bytes,
}
