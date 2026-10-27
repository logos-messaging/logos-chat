use openmls::framing::MlsMessageOut;
use prost::{Message, Oneof, bytes::Bytes};

use super::{FrameId, delivery_address_from_id};

use crate::{
    AddressedEnvelope,
    errors::SendError,
    utils::{blake2b_hex, hash_size},
};

pub(super) fn frame_id(frame_bytes: &[u8]) -> FrameId {
    blake2b_hex::<hash_size::MessageId>(&["logos-chat|message_id|".as_bytes(), frame_bytes])
}

#[derive(Clone, PartialEq, Message)]
pub struct GroupV3Frame {
    //reserved 1, 5 for Frame paramters.
    #[prost(oneof = "GroupV3Payload", tags = "6,7")]
    pub payload: Option<GroupV3Payload>,
}

#[derive(Clone, PartialEq, Oneof)]
pub enum GroupV3Payload {
    #[prost(bytes = "bytes", tag = "6")]
    Content(Bytes),
}

impl GroupV3Frame {
    pub fn from_content(bytes: &[u8]) -> GroupV3Frame {
        GroupV3Frame {
            payload: Some(GroupV3Payload::Content(Bytes::copy_from_slice(bytes))),
        }
    }

    pub fn encode(self) -> Vec<u8> {
        self.encode_to_vec()
    }
}

pub fn to_envelope(convo_id: String, msg: MlsMessageOut) -> Result<AddressedEnvelope, SendError> {
    let bytes = msg.to_bytes()?;

    Ok(AddressedEnvelope::new(
        delivery_address_from_id(&convo_id),
        convo_id,
        &bytes,
    ))
}
