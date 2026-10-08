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

use std::sync::Arc;
use std::time::Duration;

use crossbeam_channel::Receiver;
use libchat::{AddressedEnvelope, DeliveryService};
use logos_delivery::DeliveryConfig;
use logos_delivery::blocking::BlockingDeliveryNode;
use tokio::runtime::Runtime;
use tracing::debug;

pub use logos_delivery::DeliveryError;

/// The content-topic prefix carrying logos-chat traffic.
const CHAT_TOPIC_PREFIX: &str = "/logos-chat/1/";
/// How long startup waits for a first peer before carrying on regardless.
const CONNECT_WAIT: Duration = Duration::from_secs(10);

pub fn content_topic_for(delivery_address: &str) -> String {
    format!("{CHAT_TOPIC_PREFIX}{delivery_address}/proto")
}

#[derive(Debug, Clone)]
pub struct P2pConfig {
    pub preset: String,
    pub port: u16,
    pub log_level: String,
}

impl Default for P2pConfig {
    // Connects to the `logos.test` network on an OS-assigned port, so several
    // instances can run side by side.
    fn default() -> Self {
        Self {
            preset: "logos.test".into(),
            port: 0,
            log_level: "ERROR".into(),
        }
    }
}

/// logos-delivery backed delivery service. Cheap to clone — all clones share
/// the same background node.
#[derive(Clone)]
pub struct EmbeddedLogosDelivery {
    // Declared before `_runtime`: the node is torn down while the runtime exists.
    inner: BlockingDeliveryNode,
    inbound: Receiver<Vec<u8>>,
    // The node runs on this runtime, which only needs to outlive it.
    _runtime: Arc<Runtime>,
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
    pub fn start(cfg: P2pConfig) -> Result<Self, DeliveryError> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|e| DeliveryError::Startup(e.to_string()))?;
        let inner = BlockingDeliveryNode::start(
            DeliveryConfig::default()
                .preset(cfg.preset)
                .tcp_port(cfg.port)
                .discv5_udp_port(0)
                .log_level(cfg.log_level)
                .wait_for_connection(CONNECT_WAIT),
            runtime.handle().clone(),
        )?;
        let inbound = inner.inbound_queue(|m| {
            m.content_topic
                .starts_with(CHAT_TOPIC_PREFIX)
                .then_some(m.payload)
        });
        Ok(Self {
            inner,
            inbound,
            _runtime: Arc::new(runtime),
        })
    }

    /// Stops the node. Clones share it, so this ends delivery for all of them.
    pub fn shutdown(&self) -> Result<(), DeliveryError> {
        self.inner.shutdown()
    }

    /// Stop delivering messages addressed to `delivery_address`.
    pub fn unsubscribe(&self, delivery_address: &str) -> Result<(), DeliveryError> {
        self.inner.unsubscribe(&content_topic_for(delivery_address))
    }
}

impl DeliveryService for EmbeddedLogosDelivery {
    type Error = DeliveryError;

    fn publish(&mut self, envelope: AddressedEnvelope) -> Result<(), DeliveryError> {
        let topic = content_topic_for(&envelope.delivery_address);
        debug!(topic = &topic, "Publish");
        self.inner.publish(&topic, &envelope.data)?;
        Ok(())
    }

    fn subscribe(&mut self, delivery_address: &str) -> Result<(), DeliveryError> {
        self.inner.subscribe(&content_topic_for(delivery_address))
    }
}

// The impl lives here (the crate owning the type) because the orphan rule bars
// it from the `logos-chat` crate, which owns neither the trait nor the type.
impl logos_generic_chat::Transport for EmbeddedLogosDelivery {
    fn inbound(&mut self) -> Receiver<Vec<u8>> {
        self.inbound.clone()
    }
}
