use std::fmt::Debug;

use crate::proto::{self, Message};

// Public type definitions

// This struct represents Outbound data.
// It wraps an encoded payload with a delivery address, so it can be handled by the delivery service.
#[derive(Clone)]
pub struct AddressedEnvelope {
    pub delivery_address: String,
    pub data: Vec<u8>,
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

#[derive(Debug, Clone)]
pub struct ConvoMetadata {
    pub name: String,
    pub desc: String,
}
