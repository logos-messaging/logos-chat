//! Wire framing for GroupV3.
//!
//! ```text
//! AddressedEnvelope                                 delivery address + convo id
//! └── EncryptedSdsMessage                           protobuf
//!     ├── encrypted_sds_header                      bytes
//!     │   └── SdsHeader                             protobuf; the SDS spec's Message without content
//!     └── payload                                   bytes; SDS content; empty for an SDS sync
//!         └── GroupV3Envelope                       protobuf
//!             ├── encrypted_header                  bytes
//!             │   └── GroupV3Header                 protobuf; one field per item
//!             │       └── epoch_data                the sender's epoch
//!             └── encoded_frame                     oneof
//!                 ├── mls_message                   bytes; TLS-serialized
//!                 │   └── MlsMessage                Commit | ApplicationMessage
//!                 │       └── GroupV3Frame          protobuf; ApplicationMessage only
//!                 │           └── GroupV3FrameType  Content
//!                 └── beacon                        bytes; reserved
//! ```
//!
//! `GroupV3Envelope` goes to SDS as bytes, so the SDS message id is a deterministic hash of them.
//! Frames that need no ordering or resends still go in an `EncryptedSdsMessage`, sent ephemeral.

use openmls::framing::{MlsMessageOut, ProtocolMessage};
use openmls::prelude::MlsMessageIn;
use openmls::prelude::tls_codec::DeserializeBytes as _;
use prost::{Message, Oneof, bytes::Bytes};
use sds::OutgoingMessage;

use crate::{
    ChatError, MessageId,
    errors::SendError,
    utils::{blake2b_hex, hash_size},
};

mod sds_message;

pub use sds_message::EncryptedSdsMessage;

fn message_id_for(content: &[u8]) -> MessageId {
    blake2b_hex::<hash_size::MessageId>(&["logos-chat|message_id|".as_bytes(), content])
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

/// Empty until it carries header items, such as the sender's epoch.
#[derive(Clone, PartialEq, Message)]
pub struct GroupV3Header {}

#[derive(Clone, PartialEq, Message)]
pub struct GroupV3Envelope {
    #[prost(bytes = "bytes", tag = "1")]
    encrypted_header: Bytes,
    #[prost(oneof = "EncodedFrame", tags = "2")]
    encoded_frame: Option<EncodedFrame>,
}

/// Tag 3 is reserved for beacons.
#[derive(Clone, PartialEq, Oneof)]
pub enum EncodedFrame {
    #[prost(bytes = "bytes", tag = "2")]
    MlsMessage(Bytes),
}

impl GroupV3Envelope {
    pub fn from_mls_message(mls_message: MlsMessageOut) -> Result<Self, SendError> {
        Ok(Self {
            encrypted_header: GroupV3Header::default().encode_to_vec().into(),
            encoded_frame: Some(EncodedFrame::MlsMessage(mls_message.to_bytes()?.into())),
        })
    }

    pub fn into_outgoing_message(self) -> OutgoingMessage {
        let content = self.encode_to_vec();
        OutgoingMessage {
            message_id: message_id_for(&content),
            content,
            retrieval_hint: None,
        }
    }

    /// Rejects `content` that does not hash to `message_id`, or whose header does not decode.
    pub fn from_sds_content(message_id: &str, content: &[u8]) -> Result<Self, ChatError> {
        if message_id_for(content) != message_id {
            return Err(ChatError::generic("message id does not match its content"));
        }
        let envelope = Self::decode(content)?;
        GroupV3Header::decode(envelope.encrypted_header.as_ref())?;
        Ok(envelope)
    }

    /// `None` for a frame that is not an MLS message.
    pub fn protocol_message(&self) -> Result<Option<ProtocolMessage>, ChatError> {
        let Some(EncodedFrame::MlsMessage(mls_message)) = &self.encoded_frame else {
            return Ok(None);
        };
        MlsMessageIn::tls_deserialize_exact_bytes(mls_message)
            .map_err(ChatError::generic)?
            .try_into_protocol_message()
            .map(Some)
            .map_err(ChatError::generic)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outgoing_message_id_covers_the_whole_envelope() {
        let envelope = GroupV3Envelope {
            encrypted_header: Bytes::from_static(&[1]),
            encoded_frame: Some(EncodedFrame::MlsMessage(Bytes::from_static(&[2]))),
        };
        let message = envelope.clone().into_outgoing_message();
        assert_eq!(
            GroupV3Envelope::decode(message.content.as_slice()).unwrap(),
            envelope
        );

        let other_header = GroupV3Envelope {
            encrypted_header: Bytes::from_static(&[3]),
            ..envelope
        };
        assert_ne!(
            other_header.into_outgoing_message().message_id,
            message.message_id
        );
    }

    fn mls_envelope() -> GroupV3Envelope {
        GroupV3Envelope {
            encrypted_header: GroupV3Header::default().encode_to_vec().into(),
            encoded_frame: Some(EncodedFrame::MlsMessage(Bytes::from_static(&[2]))),
        }
    }

    #[test]
    fn sds_content_decodes_back_to_the_envelope() {
        let envelope = mls_envelope();
        let message = envelope.clone().into_outgoing_message();
        assert_eq!(
            GroupV3Envelope::from_sds_content(&message.message_id, &message.content).unwrap(),
            envelope
        );
    }

    #[test]
    fn sds_content_under_another_message_id_is_rejected() {
        let message = mls_envelope().into_outgoing_message();
        assert!(GroupV3Envelope::from_sds_content("other", &message.content).is_err());
    }
}
