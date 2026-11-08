//! Wire framing for GroupV3.
//!
//! ```text
//! AddressedEnvelope                        delivery address + convo id
//! └── GroupV3Payload                       protobuf
//!     ├── encrypted_header                 bytes
//!     │   └── SdsHeader                    protobuf; the SDS spec's Message without content
//!     ├── encrypted_frame                  bytes; TLS-serialized; empty for an SDS sync
//!     │   └── MlsMessage                   Commit | ApplicationMessage
//!     │       └── GroupV3Frame             protobuf; ApplicationMessage only
//!     │           └── GroupV3FrameType     Content
//!     └── external                         bytes; instead of encrypted_frame
//!         └── GroupV3External              protobuf; non-MLS frames
//! ```
//!
//! Commits and application messages travel through SDS, which orders them and resends what goes
//! unacknowledged. The SDS message id, `message_id`, hashes the MLS message, so two sends of
//! the same content get different ids, and receivers read it from the SDS header. `GroupV3Frame`
//! tags 1–5 are reserved for frame parameters.

use openmls::framing::ProtocolMessage;
use openmls::prelude::MlsMessageIn;
use openmls::prelude::tls_codec::DeserializeBytes as _;
use prost::{Message, Oneof, bytes::Bytes};
use sds::SDSRecord;

use crate::{
    AddressedEnvelope, ChatError, MessageId,
    utils::{blake2b_hex, hash_size},
};

use super::delivery_address_from_id;

pub(super) fn message_id(mls_message: &[u8]) -> MessageId {
    blake2b_hex::<hash_size::MessageId>(&["logos-chat|message_id|".as_bytes(), mls_message])
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

pub fn to_envelope(convo_id: String, payload: GroupV3Payload) -> AddressedEnvelope {
    AddressedEnvelope::with_payload(
        delivery_address_from_id(&convo_id),
        convo_id,
        payload.encode_to_vec(),
    )
}

/// Address a non-MLS frame to a conversation.
pub fn to_external_envelope(convo_id: &str, bytes: Vec<u8>) -> AddressedEnvelope {
    let payload = GroupV3Payload {
        external: bytes.into(),
        ..Default::default()
    };
    to_envelope(convo_id.to_string(), payload)
}

pub fn protocol_message(mls_message: &[u8]) -> Result<ProtocolMessage, ChatError> {
    MlsMessageIn::tls_deserialize_exact_bytes(mls_message)
        .map_err(ChatError::generic)?
        .try_into_protocol_message()
        .map_err(ChatError::generic)
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

impl From<SDSRecord> for GroupV3Payload {
    fn from(record: SDSRecord) -> Self {
        Self {
            encrypted_header: SdsHeader::from(record.header).encode_to_vec().into(),
            encrypted_frame: record.content.unwrap_or_default().into(),
            external: Bytes::new(),
        }
    }
}

impl TryFrom<GroupV3Payload> for SDSRecord {
    type Error = prost::DecodeError;

    fn try_from(payload: GroupV3Payload) -> Result<Self, Self::Error> {
        let content = payload.encrypted_frame;
        Ok(Self {
            header: SdsHeader::decode(payload.encrypted_header)?.into(),
            content: (!content.is_empty()).then(|| content.into()),
        })
    }
}

/// The SDS spec's `Message` without its content, which travels as `encrypted_frame`.
#[derive(Clone, PartialEq, Message)]
struct SdsHeader {
    #[prost(string, tag = "1")]
    sender_id: String,
    #[prost(string, tag = "2")]
    message_id: String,
    #[prost(string, tag = "3")]
    channel_id: String,
    #[prost(uint64, optional, tag = "10")]
    lamport_timestamp: Option<u64>,
    #[prost(message, repeated, tag = "11")]
    causal_history: Vec<SdsHistoryEntry>,
    #[prost(bytes = "vec", optional, tag = "12")]
    bloom_filter: Option<Vec<u8>>,
    #[prost(message, repeated, tag = "13")]
    repair_request: Vec<SdsHistoryEntry>,
}

#[derive(Clone, PartialEq, Message)]
struct SdsHistoryEntry {
    #[prost(string, tag = "1")]
    message_id: String,
    #[prost(bytes = "vec", optional, tag = "2")]
    retrieval_hint: Option<Vec<u8>>,
    #[prost(string, optional, tag = "3")]
    sender_id: Option<String>,
}

impl From<sds::Header> for SdsHeader {
    fn from(header: sds::Header) -> Self {
        Self {
            sender_id: header.sender_id,
            message_id: header.message_id,
            channel_id: header.channel_id,
            lamport_timestamp: header.lamport_timestamp,
            causal_history: header.causal_history.into_iter().map(Into::into).collect(),
            bloom_filter: header.bloom_filter,
            repair_request: header.repair_request.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<SdsHeader> for sds::Header {
    fn from(header: SdsHeader) -> Self {
        Self {
            sender_id: header.sender_id,
            message_id: header.message_id,
            channel_id: header.channel_id,
            lamport_timestamp: header.lamport_timestamp,
            causal_history: header.causal_history.into_iter().map(Into::into).collect(),
            bloom_filter: header.bloom_filter,
            repair_request: header.repair_request.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<sds::HistoryEntry> for SdsHistoryEntry {
    fn from(entry: sds::HistoryEntry) -> Self {
        Self {
            message_id: entry.message_id,
            retrieval_hint: entry.retrieval_hint,
            sender_id: entry.sender_id,
        }
    }
}

impl From<SdsHistoryEntry> for sds::HistoryEntry {
    fn from(entry: SdsHistoryEntry) -> Self {
        Self {
            message_id: entry.message_id,
            retrieval_hint: entry.retrieval_hint,
            sender_id: entry.sender_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_the_sds_header_with_the_spec_field_numbers() {
        let record = SDSRecord {
            header: sds::Header {
                sender_id: "a".into(),
                message_id: "b".into(),
                channel_id: "c".into(),
                lamport_timestamp: Some(1),
                causal_history: vec![sds::HistoryEntry {
                    message_id: "d".into(),
                    retrieval_hint: Some(vec![8]),
                    sender_id: Some("e".into()),
                }],
                bloom_filter: Some(vec![9]),
                repair_request: vec![sds::HistoryEntry {
                    message_id: "f".into(),
                    retrieval_hint: None,
                    sender_id: None,
                }],
            },
            content: Some(vec![7]),
        };

        let payload = GroupV3Payload::from(record.clone());

        let expected = [
            0x0a, 1, b'a', // 1: sender_id
            0x12, 1, b'b', // 2: message_id
            0x1a, 1, b'c', // 3: channel_id
            0x50, 1, // 10: lamport_timestamp
            0x5a, 9, 0x0a, 1, b'd', 0x12, 1, 8, 0x1a, 1, b'e', // 11: causal_history
            0x62, 1, 9, // 12: bloom_filter
            0x6a, 3, 0x0a, 1, b'f', // 13: repair_request
        ];
        assert_eq!(payload.encrypted_header, expected[..]);
        assert_eq!(SDSRecord::try_from(payload).unwrap(), record);
    }
}
