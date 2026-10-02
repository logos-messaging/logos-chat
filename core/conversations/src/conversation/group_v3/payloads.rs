use chat_proto::logoschat::encryption::{EncryptedPayload, Plaintext, encrypted_payload};
use openmls::framing::MlsMessageOut;
use prost::{Message, Oneof, bytes::Bytes};

use super::{GroupV3Convo, delivery_address_from_id};

use crate::{
    AddressedEnvelope,
    conversation::{Identified, group_v3::FrameId},
    errors::SendError,
    types::AddressedEncryptedPayload,
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
    #[prost(message, tag = "6")]
    Content(Bytes),
    #[prost(message, tag = "7")]
    ConsensusMessage(Bytes),
    #[prost(message, tag = "8")]
    MlsProtoMessage(Bytes),
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

impl GroupV3Convo {
    pub fn to_envelope(&self, msg: MlsMessageOut) -> Result<AddressedEnvelope, SendError> {
        let bytes = msg.to_bytes()?;

        let payload = AddressedEncryptedPayload {
            delivery_address: delivery_address_from_id(self.id()),
            data: EncryptedPayload {
                // TODO: (P3) Don't force the encryption payload on convotypes. They can manage it internally if desired.
                encryption: Some(encrypted_payload::Encryption::Plaintext(Plaintext {
                    payload: bytes.into(),
                })),
            },
        };

        Ok(payload.into_envelope(self.id().to_string()))
    }
}
