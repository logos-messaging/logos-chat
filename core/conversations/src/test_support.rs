//! Test doubles for the store contract: an in-memory store, and the suite
//! that holds any store to it. Also the delivery tags a conversation sets, for
//! testing a delivery service.

use crate::types::DeliveryTag;

pub use crate::storage::{MemStore, assert_identity_store_contract, assert_kv_contract};

/// A tag naming `message_id` in `convo_id`, as a conversation sets it on an envelope.
pub fn delivery_tag(convo_id: &str, message_id: &str) -> DeliveryTag {
    DeliveryTag {
        convo_id: convo_id.into(),
        message_id: message_id.into(),
    }
}
