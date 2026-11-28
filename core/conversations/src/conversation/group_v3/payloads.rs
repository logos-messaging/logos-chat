//! Wire framing for GroupV3.
//!
//! ```text
//! AddressedEnvelope                                 delivery address + convo id
//! └── EncryptedSdsMessage                           protobuf
//!     ├── encrypted_sds_header                      bytes
//!     │   └── SdsHeader                             protobuf; the SDS spec's Message without content
//!     └── payload                                   bytes; SDS content; empty for an SDS sync
//!         └── GroupV3Packet                       protobuf
//!             ├── encrypted_header                  bytes
//!             │   └── GroupV3Header                 protobuf; one field per item
//!             │       ├── epoch_data                the sender's epoch
//!             │       └── sender                    the sender's signer key
//!             └── encoded_frame                     oneof
//!                 └── mls_message                   bytes; TLS-serialized
//!                     └── MlsMessage                Commit | ApplicationMessage
//!                         └── GroupV3Frame          protobuf; ApplicationMessage only
//!                             └── GroupV3FrameType  Content
//!
//! AddressedEnvelope                                 delivery address + recovery convo id
//! └── GroupV3External                               protobuf; non-MLS frames: Beacon | Sealed
//! ```
//!
//! `GroupV3Packet` goes to SDS as bytes, so the SDS message id is a deterministic hash of them.
//! An external frame skips SDS and names no sender.

use openmls::framing::{MlsMessageOut, ProtocolMessage};
use openmls::prelude::MlsMessageIn;
use openmls::prelude::tls_codec::DeserializeBytes as _;
use prost::{Message, Oneof, bytes::Bytes};
use sds::OutgoingMessage;

use super::external::EpochBeacon;

use crate::{
    ChatError, MessageId, SignerKey, SignerRef,
    errors::SendError,
    utils::{blake2b_hex, hash_size},
};

use super::sealed::SealedMessage;

mod epoch_data;
mod sds_message;

pub use epoch_data::EpochData;
use epoch_data::EpochDataProto;
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

/// The sender and its epoch, as the sender claims them: the header is unsigned.
#[derive(Clone, PartialEq, Message)]
pub struct GroupV3Header {
    #[prost(message, optional, tag = "1")]
    epoch_data: Option<EpochDataProto>,
    #[prost(bytes = "vec", optional, tag = "2")]
    sender: Option<Vec<u8>>,
}

impl GroupV3Header {
    pub fn new(sender: SignerRef, epoch_data: &EpochData) -> Self {
        Self {
            epoch_data: Some(epoch_data.into()),
            sender: Some(sender.as_bytes().to_vec()),
        }
    }
}

#[derive(Clone, PartialEq, Message)]
pub struct GroupV3Packet {
    #[prost(bytes = "bytes", tag = "1")]
    encrypted_header: Bytes,
    #[prost(oneof = "EncodedFrame", tags = "2")]
    encoded_frame: Option<EncodedFrame>,
}

/// Tag 3, which carried external frames, is reserved.
#[derive(Clone, PartialEq, Oneof)]
pub enum EncodedFrame {
    #[prost(bytes = "bytes", tag = "2")]
    MlsMessage(Bytes),
}

impl GroupV3Packet {
    pub fn from_mls_message(
        header: GroupV3Header,
        mls_message: MlsMessageOut,
    ) -> Result<Self, SendError> {
        Ok(Self {
            encrypted_header: header.encode_to_vec().into(),
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
    pub fn from_sds_content(
        message_id: &str,
        content: &[u8],
    ) -> Result<ReceivedGroupV3Packet, ChatError> {
        if message_id_for(content) != message_id {
            return Err(ChatError::generic("message id does not match its content"));
        }
        let packet = Self::decode(content)?;
        GroupV3Header::decode(packet.encrypted_header.as_ref())?;
        Ok(ReceivedGroupV3Packet {
            message_id: message_id.to_owned(),
            packet,
        })
    }

    /// The sender's epoch data, from the header.
    pub fn epoch_data(&self) -> Result<EpochData, ChatError> {
        let header = GroupV3Header::decode(self.encrypted_header.as_ref())?;
        header
            .epoch_data
            .ok_or(ChatError::BadParsing("packet header without epoch data"))?
            .try_into()
    }

    /// The sender's signer key, from the header.
    pub fn sender(&self) -> Result<SignerKey, ChatError> {
        let header = GroupV3Header::decode(self.encrypted_header.as_ref())?;
        header
            .sender
            .map(|sender| SignerKey::from(sender.as_slice()))
            .ok_or(ChatError::BadParsing("packet header without a sender"))
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

/// A packet as it arrived, with the message id its bytes hash to.
#[derive(Debug, PartialEq)]
pub struct ReceivedGroupV3Packet {
    message_id: MessageId,
    packet: GroupV3Packet,
}

impl ReceivedGroupV3Packet {
    pub fn message_id(&self) -> &MessageId {
        &self.message_id
    }

    pub fn packet(&self) -> &GroupV3Packet {
        &self.packet
    }
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

    pub fn encode(self) -> Vec<u8> {
        self.encode_to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outgoing_message_id_covers_the_whole_envelope() {
        let envelope = GroupV3Packet {
            encrypted_header: Bytes::from_static(&[1]),
            encoded_frame: Some(EncodedFrame::MlsMessage(Bytes::from_static(&[2]))),
        };
        let message = envelope.clone().into_outgoing_message();
        assert_eq!(
            GroupV3Packet::decode(message.content.as_slice()).unwrap(),
            envelope
        );

        let other_header = GroupV3Packet {
            encrypted_header: Bytes::from_static(&[3]),
            ..envelope
        };
        assert_ne!(
            other_header.into_outgoing_message().message_id,
            message.message_id
        );
    }

    fn mls_envelope() -> GroupV3Packet {
        GroupV3Packet {
            encrypted_header: GroupV3Header::default().encode_to_vec().into(),
            encoded_frame: Some(EncodedFrame::MlsMessage(Bytes::from_static(&[2]))),
        }
    }

    #[test]
    fn sds_content_decodes_back_to_the_envelope() {
        let envelope = mls_envelope();
        let message = envelope.clone().into_outgoing_message();
        let received =
            GroupV3Packet::from_sds_content(&message.message_id, &message.content).unwrap();
        assert_eq!(received.packet(), &envelope);
        assert_eq!(received.message_id(), &message.message_id);
    }

    #[test]
    fn sds_content_under_another_message_id_is_rejected() {
        let message = mls_envelope().into_outgoing_message();
        assert!(GroupV3Packet::from_sds_content("other", &message.content).is_err());
    }
}
