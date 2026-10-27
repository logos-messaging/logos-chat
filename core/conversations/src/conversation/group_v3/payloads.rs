//! Wire framing for GroupV3.
//!
//! ```text
//! AddressedEnvelope                        delivery address + convo id
//! └── GroupV3Payload                       protobuf
//!     ├── encrypted_header                 bytes; placeholder
//!     └── encrypted_frame                  bytes; TLS-serialized
//!         └── MlsMessage                   Commit | ApplicationMessage
//!             └── GroupV3Frame             protobuf; ApplicationMessage only
//!                 └── GroupV3FrameType     Content | ConsensusMessage
//! ```
//!
//! `FrameId` hashes the encoded `GroupV3Frame`, so sender and receivers derive the same id from
//! plaintext. `GroupV3Frame` tags 1–5 are reserved for frame parameters.

use openmls::framing::MlsMessageOut;
use prost::{Message, Oneof, bytes::Bytes};

use crate::{
    AddressedEnvelope,
    conversation::Identified,
    errors::SendError,
    utils::{blake2b_hex, hash_size},
};

use super::{FrameId, GroupV3Convo, delivery_address_from_id};

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
    #[prost(bytes = "bytes", tag = "7")]
    ConsensusMessage(Bytes),
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

impl GroupV3Convo {
    fn to_payload(msg: MlsMessageOut) -> Result<Vec<u8>, SendError> {
        let bytes = msg.to_bytes()?;

        let payload = GroupV3Payload {
            encrypted_header: vec![0, 0, 0, 0].into(),
            encrypted_frame: bytes.into(),
        };

        Ok(payload.encode_to_vec())
    }

    pub fn to_envelope(&self, msg: MlsMessageOut) -> Result<AddressedEnvelope, SendError> {
        let convo_id = self.id();

        Ok(AddressedEnvelope::new(
            delivery_address_from_id(convo_id),
            convo_id.to_string(),
            Self::to_payload(msg)?.as_slice(),
        ))
    }
}

#[derive(Clone, PartialEq, Message)]
pub struct GroupV3Payload {
    #[prost(bytes = "bytes", tag = "1")]
    pub encrypted_header: Bytes,
    #[prost(bytes = "bytes", tag = "2")]
    pub encrypted_frame: Bytes,
}
