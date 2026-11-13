use std::fmt::Debug;

use crate::proto::{self, Message};

// Public type definitions

// This struct represents Outbound data.
// It wraps an encoded payload with a delivery address, so it can be handled by the delivery service.
#[derive(Clone)]
pub struct AddressedEnvelope {
    pub delivery_address: String,
    pub data: Vec<u8>,
    /// Set when the conversation keeps the payload's id: a delivery service whose `publish`
    /// returns no id hands this back with the id once it learns it.
    pub tag: Option<DeliveryTag>,
}

impl AddressedEnvelope {
    pub fn new(delivery_address: String, convo_id: String, data: &[u8]) -> Self {
        let envelope = proto::EnvelopeV1 {
            // TODO: conversation_id should be obscured
            conversation_hint: convo_id,
            salt: 0,
            payload: proto::Bytes::copy_from_slice(data),
        };

        AddressedEnvelope {
            delivery_address,
            data: envelope.encode_to_vec(),
            tag: None,
        }
    }
}

impl Debug for AddressedEnvelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let data = &self.data;
        let hex = if data.len() <= 8 {
            hex::encode(data)
        } else {
            format!(
                "{}..{}",
                hex::encode(&data[..4]),
                hex::encode(&data[data.len() - 4..])
            )
        };

        f.debug_struct("AddressedEnvelope")
            .field("addr", &self.delivery_address)
            .field("data", &hex)
            .finish()
    }
}

/// Names a payload on the delivery network, so any client's delivery service can fetch it again.
/// Opaque to chat, which only keeps it and hands it back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeliveryMsgId(Vec<u8>);

impl DeliveryMsgId {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<Vec<u8>> for DeliveryMsgId {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

/// What the delivery service knows of a payload it carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeliveryInfo {
    pub delivery_msg_id: DeliveryMsgId,
}

/// Names the message an envelope carries, for a delivery service that learns the payload's id
/// only after `publish` returns: the service hands the tag back with the id, and the client
/// passes both to [`Core::handle_delivery_report`](crate::Core::handle_delivery_report). Opaque
/// to the service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeliveryTag {
    pub(crate) convo_id: String,
    pub(crate) message_id: String,
}

// Internal type Definitions

// Used by Conversations to attach addresses to outbound encrypted payloads
pub struct AddressedEncryptedPayload {
    pub delivery_address: String,
    pub data: proto::EncryptedPayload,
}

impl AddressedEncryptedPayload {
    // Wrap in an envelope and prepare for transmission
    pub fn into_envelope(self, convo_id: String) -> AddressedEnvelope {
        AddressedEnvelope::new(
            self.delivery_address,
            convo_id,
            self.data.encode_to_vec().as_slice(),
        )
    }
}

#[derive(Debug)]
pub struct ConvoMetadata {
    pub name: String,
    pub desc: String,
}
