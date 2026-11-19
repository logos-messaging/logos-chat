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
//!             │       └── epoch_data                the sender's epoch
//!             └── encoded_frame                     oneof
//!                 ├── mls_message                   bytes; TLS-serialized
//!                 │   └── MlsMessage                Commit | ApplicationMessage
//!                 │       └── GroupV3Frame          protobuf; ApplicationMessage only
//!                 │           └── GroupV3FrameType  Content
//!                 └── external                      bytes; outside SDS
//!                     └── GroupV3External           protobuf; non-MLS frames: Beacon | Sealed
//! ```
//!
//! `GroupV3Packet` goes to SDS as bytes, so the SDS message id is a deterministic hash of them.
//! An external frame skips SDS: its `EncryptedSdsMessage` has an empty header, so it names no
//! sender, and a member on another branch can still read it.

use openmls::framing::{MlsMessageOut, ProtocolMessage};
use openmls::prelude::MlsMessageIn;
use openmls::prelude::tls_codec::DeserializeBytes as _;
use prost::{Message, Oneof, bytes::Bytes};
use sds::OutgoingMessage;

use super::external::EpochBeacon;

use crate::{
    ChatError, MessageId,
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

/// Outgoing headers leave `epoch_data` unset for now.
#[derive(Clone, PartialEq, Message)]
pub struct GroupV3Header {
    #[prost(message, optional, tag = "1")]
    epoch_data: Option<EpochDataProto>,
}

impl GroupV3Header {
    pub fn with_epoch_data(epoch_data: &EpochData) -> Self {
        Self {
            epoch_data: Some(epoch_data.into()),
        }
    }
}

#[derive(Clone, PartialEq, Message)]
pub struct GroupV3Packet {
    #[prost(bytes = "bytes", tag = "1")]
    encrypted_header: Bytes,
    #[prost(oneof = "EncodedFrame", tags = "2, 3")]
    encoded_frame: Option<EncodedFrame>,
}

#[derive(Clone, PartialEq, Oneof)]
pub enum EncodedFrame {
    #[prost(bytes = "bytes", tag = "2")]
    MlsMessage(Bytes),
    /// Kept as bytes so the receiver can bound it before decoding.
    #[prost(bytes = "bytes", tag = "3")]
    External(Bytes),
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

    pub fn external(frame: GroupV3External) -> Self {
        Self {
            encrypted_header: GroupV3Header::default().encode_to_vec().into(),
            encoded_frame: Some(EncodedFrame::External(frame.encode_to_vec().into())),
        }
    }

    /// The frame of a packet sent outside SDS. Its header must decode too.
    pub fn into_external(self) -> Result<Bytes, ChatError> {
        GroupV3Header::decode(self.encrypted_header.as_ref())?;
        match self.encoded_frame {
            Some(EncodedFrame::External(frame)) => Ok(frame),
            _ => Err(ChatError::generic("an MLS message outside SDS")),
        }
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

    /// The sender's epoch data, from the header.
    pub fn epoch_data(&self) -> Result<EpochData, ChatError> {
        let header = GroupV3Header::decode(self.encrypted_header.as_ref())?;
        header
            .epoch_data
            .ok_or(ChatError::BadParsing("packet header without epoch data"))?
            .try_into()
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
        assert_eq!(
            GroupV3Packet::from_sds_content(&message.message_id, &message.content).unwrap(),
            envelope
        );
    }

    fn external_packet() -> GroupV3Packet {
        GroupV3Packet::external(GroupV3External::default())
    }

    #[test]
    fn a_packet_outside_sds_decodes_back() {
        let packet = external_packet();
        let wire = EncryptedSdsMessage::outside_sds(&packet).encode_to_vec();
        let message = EncryptedSdsMessage::decode(wire.as_slice()).unwrap();
        assert_eq!(message.packet_outside_sds().unwrap().unwrap(), packet);
    }

    /// SDS always names the sender, message and channel, so its header is
    /// never empty, a sync included.
    #[test]
    fn an_sds_record_is_never_outside_sds() {
        let header = sds::Header {
            sender_id: "a".into(),
            message_id: "b".into(),
            channel_id: "c".into(),
            lamport_timestamp: None,
            causal_history: vec![],
            bloom_filter: None,
            repair_request: vec![],
        };
        let sync = sds::SDSRecord {
            header,
            content: None,
        };
        assert!(
            EncryptedSdsMessage::from_record(sync)
                .packet_outside_sds()
                .is_none()
        );
    }

    #[test]
    fn an_mls_message_is_not_an_external_frame() {
        assert!(mls_envelope().into_external().is_err());
        assert!(external_packet().into_external().is_ok());
    }

    #[test]
    fn sds_content_under_another_message_id_is_rejected() {
        let message = mls_envelope().into_outgoing_message();
        assert!(GroupV3Packet::from_sds_content("other", &message.content).is_err());
    }
}
