//! The embedded logos-delivery transport service.
//!
//! [`EmbeddedLogosDelivery`] implements [`DeliveryService`] over a
//! [`BlockingDeliveryNode`], and supplies the chat-specific mapping: content
//! topics and `/logos-chat/1/…` filtering.
//!
//! The native node is linked transitively via the `logos-delivery` crate, so this
//! crate lives outside the workspace's default members; depend on it (e.g. via the
//! `logos-chat` crate) only when shipping the embedded node.
//!
//! ## Content topic mapping
//!
//! `AddressedEnvelope::delivery_address` maps to logos-delivery content topic
//! `/logos-chat/1/{delivery_address}/proto`.
//!
//! The synchronous methods must not be called from inside a tokio runtime.

use std::time::Duration;

use crossbeam_channel::Receiver;
use libchat::{AddressedEnvelope, DeliveryService};
use logos_delivery::blocking::BlockingDeliveryNode;
use tracing::debug;

pub use logos_delivery::{DeliveryConfig, DeliveryError};

/// The content-topic prefix carrying logos-chat traffic.
const CHAT_TOPIC_PREFIX: &str = "/logos-chat/1/";
/// How long startup waits for a first peer before carrying on regardless.
const CONNECT_WAIT: Duration = Duration::from_secs(10);

pub fn content_topic_for(delivery_address: &str) -> String {
    format!("{CHAT_TOPIC_PREFIX}{delivery_address}/proto")
}

/// The logos-delivery network preset joined by default.
pub const DEFAULT_PRESET: &str = "logos.test";

/// The node configuration logos-chat starts from: the `logos.test` network on
/// OS-assigned ports, so several instances can run side by side.
pub fn default_delivery_config() -> DeliveryConfig {
    DeliveryConfig::default()
        .preset(DEFAULT_PRESET)
        .tcp_port(0)
        .discv5_udp_port(0)
        .wait_for_connection(CONNECT_WAIT)
}

/// logos-delivery backed delivery service. Cheap to clone — all clones share
/// the same background node.
#[derive(Clone)]
pub struct EmbeddedLogosDelivery {
    node: BlockingDeliveryNode,
    inbound: Receiver<Vec<u8>>,
}

impl std::fmt::Debug for EmbeddedLogosDelivery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmbeddedLogosDelivery")
            .finish_non_exhaustive()
    }
}

impl EmbeddedLogosDelivery {
    /// Start the embedded logos-delivery node. Only chat payloads (on a
    /// `/logos-chat/1/…` content topic) reach the inbound queue.
    pub fn start(config: DeliveryConfig) -> Result<Self, DeliveryError> {
        let node = BlockingDeliveryNode::start(config)?;
        let inbound = node.inbound_queue(|m| {
            m.content_topic
                .starts_with(CHAT_TOPIC_PREFIX)
                .then_some(m.payload)
        });
        Ok(Self { node, inbound })
    }

    /// Stops the node. Clones share it, so this ends delivery for all of them.
    pub fn shutdown(&self) -> Result<(), DeliveryError> {
        self.node.shutdown()
    }

    /// Stop delivering messages addressed to `delivery_address`.
    pub fn unsubscribe(&self, delivery_address: &str) -> Result<(), DeliveryError> {
        self.node.unsubscribe(&content_topic_for(delivery_address))
    }
}

impl DeliveryService for EmbeddedLogosDelivery {
    type Error = DeliveryError;

    fn publish(&mut self, envelope: AddressedEnvelope) -> Result<(), DeliveryError> {
        let topic = content_topic_for(&envelope.delivery_address);
        debug!(topic = &topic, "Publish");
        self.node.publish(&topic, &envelope.data).map(|_| ())
    }

    fn subscribe(&mut self, delivery_address: &str) -> Result<(), DeliveryError> {
        self.node.subscribe(&content_topic_for(delivery_address))
    }
}

// The impl lives here (the crate owning the type) because the orphan rule bars
// it from the `logos-chat` crate, which owns neither the trait nor the type.
impl logos_generic_chat::Transport for EmbeddedLogosDelivery {
    fn inbound(&mut self) -> Receiver<Vec<u8>> {
        self.inbound.clone()
    }
}
