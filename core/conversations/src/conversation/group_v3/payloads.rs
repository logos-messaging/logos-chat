//! Wire framing for GroupV3.
//!
//! ```text
//! AddressedEnvelope                        delivery address + convo id
//! └── GroupV3Payload                       protobuf
//!     ├── encrypted_header                 bytes; encrypted GroupV3Header
//!     │   ├── sds_header                   bytes
//!     │   └── epoch_data                   the sender's epoch and its history
//!     └── encrypted_frame                  bytes; TLS-serialized; empty for an SDS sync
//!         └── MlsMessage                   Commit | ApplicationMessage
//!             └── GroupV3Frame             protobuf; ApplicationMessage only
//!                 └── GroupV3FrameType     Content | Noop
//! ```
//!
//! Application messages travel through SDS, which orders them and resends what goes
//! unacknowledged. The SDS message id, `message_id`, hashes the MLS message, so two sends of
//! the same content get different ids, and receivers read it from the SDS header. `GroupV3Frame`
//! tags 1–5 are reserved for frame parameters.

use openmls::framing::{MlsMessageOut, ProtocolMessage};
use openmls::prelude::MlsMessageIn;
use openmls::prelude::tls_codec::DeserializeBytes as _;
use prost::{Message, Oneof, bytes::Bytes};
use sds::SDSRecord;
use tls_codec::{Serialize as _, TlsDeserializeBytes, TlsSerialize, TlsSize, VLBytes};

use crate::conversation::mls_utils::EpochFingerprint;
use crate::{
    AddressedEnvelope, ChatError, MessageId,
    errors::SendError,
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
    #[prost(message, tag = "7")]
    Noop(Noop),
}

/// A frame with no content.
#[derive(Clone, PartialEq, Message)]
pub struct Noop {}

impl GroupV3Frame {
    pub fn from_content(bytes: &[u8]) -> GroupV3Frame {
        GroupV3Frame {
            payload: Some(GroupV3FrameType::Content(Bytes::copy_from_slice(bytes))),
        }
    }

    pub fn noop() -> GroupV3Frame {
        GroupV3Frame {
            payload: Some(GroupV3FrameType::Noop(Noop {})),
        }
    }

    pub fn encode(self) -> Vec<u8> {
        self.encode_to_vec()
    }
}

// TODO: remove once commits travel through SDS.
/// Commits travel outside SDS, with an empty header.
pub fn commit_record(msg: MlsMessageOut) -> Result<SDSRecord, SendError> {
    Ok(SDSRecord {
        header: Vec::new(),
        content: Some(msg.to_bytes()?),
    })
}

pub fn to_envelope(convo_id: String, payload: GroupV3Payload) -> AddressedEnvelope {
    AddressedEnvelope::new(
        delivery_address_from_id(&convo_id),
        convo_id,
        payload.encode_to_vec().as_slice(),
    )
}

pub fn protocol_message(mls_message: &[u8]) -> Result<ProtocolMessage, ChatError> {
    MlsMessageIn::tls_deserialize_exact_bytes(mls_message)
        .map_err(ChatError::generic)?
        .try_into_protocol_message()
        .map_err(ChatError::generic)
}

#[derive(Clone, PartialEq, Message)]
pub struct GroupV3Payload {
    // TODO: encrypt and authenticate the header; it is plaintext for now.
    #[prost(bytes = "bytes", tag = "1")]
    pub encrypted_header: Bytes,
    #[prost(bytes = "bytes", tag = "2")]
    pub encrypted_frame: Bytes,
}

impl GroupV3Payload {
    pub fn new(record: SDSRecord, epoch_data: EpochData) -> Result<Self, SendError> {
        let header = GroupV3Header::new(record.header, epoch_data);

        Ok(Self {
            encrypted_header: header.tls_serialize_detached()?.into(),
            encrypted_frame: record.content.unwrap_or_default().into(),
        })
    }

    pub fn parse(bytes: &[u8]) -> Result<(SDSRecord, EpochData), ChatError> {
        let payload = Self::decode(bytes)?;
        let GroupV3Header::V1(header) =
            GroupV3Header::tls_deserialize_exact_bytes(&payload.encrypted_header)?;
        let frame = payload.encrypted_frame;

        let record = SDSRecord {
            header: header.sds_header.into(),
            content: (!frame.is_empty()).then(|| frame.into()),
        };
        Ok((record, header.epoch_data))
    }
}

/// TLS-encoded for canonical bytes.
#[derive(Debug, PartialEq, TlsSerialize, TlsDeserializeBytes, TlsSize)]
#[repr(u8)]
pub enum GroupV3Header {
    #[tls_codec(discriminant = 1)]
    V1(GroupV3HeaderV1),
}

impl GroupV3Header {
    pub fn new(sds_header: Vec<u8>, epoch_data: EpochData) -> Self {
        Self::V1(GroupV3HeaderV1 {
            sds_header: sds_header.into(),
            epoch_data,
        })
    }
}

#[derive(Debug, PartialEq, TlsSerialize, TlsDeserializeBytes, TlsSize)]
pub struct GroupV3HeaderV1 {
    sds_header: VLBytes,
    epoch_data: EpochData,
}

#[derive(Debug, Clone, PartialEq, TlsSerialize, TlsDeserializeBytes, TlsSize)]
pub struct EpochData {
    epoch_num: u64,
    history: Vec<EpochFingerprint>,
}

impl EpochData {
    pub fn starting_at(epoch_num: u64) -> Self {
        Self {
            epoch_num: epoch_num,
            history: vec![],
        }
    }

    pub fn update(&mut self, epoch: u64, fingerprint: EpochFingerprint) {
        self.epoch_num = epoch;
        self.history.push(fingerprint);
    }
}

#[cfg(test)]
mod tests {
    use tls_codec::{DeserializeBytes, Serialize};

    use super::*;

    #[test]
    fn header_bytes_are_pinned() {
        let fingerprint = EpochFingerprint::tls_deserialize_exact_bytes(&[7; 7]).unwrap();
        let header = GroupV3Header::V1(GroupV3HeaderV1 {
            sds_header: vec![1, 2, 3].into(),
            epoch_data: EpochData {
                epoch_num: 9,
                history: vec![fingerprint],
            },
        });

        let bytes = header.tls_serialize_detached().unwrap();
        assert_eq!(
            hex::encode(&bytes),
            "01" // V1
                .to_owned()
                + "03010203" // sds_header
                + "0000000000000009" // epoch_num
                + "0707070707070707" // history: len 7, one fingerprint
        );
        assert_eq!(
            GroupV3Header::tls_deserialize_exact_bytes(&bytes).unwrap(),
            header
        );

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(GroupV3Header::tls_deserialize_exact_bytes(&trailing).is_err());
    }

    fn assert_round_trips(record: SDSRecord) {
        let epoch_data = EpochData::starting_at(9);
        let bytes = GroupV3Payload::new(record.clone(), epoch_data.clone())
            .unwrap()
            .encode_to_vec();

        assert_eq!(GroupV3Payload::parse(&bytes).unwrap(), (record, epoch_data));
    }

    #[test]
    fn sds_message_round_trips() {
        assert_round_trips(SDSRecord {
            header: vec![1, 2, 3],
            content: Some(vec![4, 5]),
        });
    }

    #[test]
    fn sds_sync_round_trips_without_content() {
        assert_round_trips(SDSRecord {
            header: vec![1, 2, 3],
            content: None,
        });
    }

    #[test]
    fn malformed_header_is_rejected() {
        let payload = GroupV3Payload {
            encrypted_header: vec![0xff].into(),
            encrypted_frame: Bytes::new(),
        };
        assert!(GroupV3Payload::parse(&payload.encode_to_vec()).is_err());
    }
}
