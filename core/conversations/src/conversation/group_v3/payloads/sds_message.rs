//! SDS layer of the GroupV3 wire framing; see the parent module.

use prost::{Message, bytes::Bytes};
use sds::SDSRecord;

use crate::AddressedEnvelope;

use super::super::delivery_address_from_id;

#[derive(Clone, PartialEq, Message)]
pub struct EncryptedSdsMessage {
    #[prost(bytes = "bytes", tag = "1")]
    encrypted_sds_header: Bytes,
    #[prost(bytes = "bytes", tag = "2")]
    payload: Bytes,
}

impl EncryptedSdsMessage {
    pub fn from_record(record: SDSRecord) -> Self {
        Self {
            encrypted_sds_header: SdsHeader::from(record.header).encode_to_vec().into(),
            payload: record.content.unwrap_or_default().into(),
        }
    }

    pub fn try_into_record(self) -> Result<SDSRecord, prost::DecodeError> {
        let content = self.payload;
        Ok(SDSRecord {
            header: SdsHeader::decode(self.encrypted_sds_header)?.into(),
            content: (!content.is_empty()).then(|| content.into()),
        })
    }

    pub fn into_envelope(self, convo_id: String) -> AddressedEnvelope {
        AddressedEnvelope::new(
            delivery_address_from_id(&convo_id),
            convo_id,
            self.encode_to_vec().as_slice(),
        )
    }
}

/// The SDS spec's `Message` without its content, which travels as `payload`.
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

        let message = EncryptedSdsMessage::from_record(record.clone());

        let expected = [
            0x0a, 1, b'a', // 1: sender_id
            0x12, 1, b'b', // 2: message_id
            0x1a, 1, b'c', // 3: channel_id
            0x50, 1, // 10: lamport_timestamp
            0x5a, 9, 0x0a, 1, b'd', 0x12, 1, 8, 0x1a, 1, b'e', // 11: causal_history
            0x62, 1, 9, // 12: bloom_filter
            0x6a, 3, 0x0a, 1, b'f', // 13: repair_request
        ];
        assert_eq!(message.encrypted_sds_header, expected[..]);
        assert_eq!(message.try_into_record().unwrap(), record);
    }
}
