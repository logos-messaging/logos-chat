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
use tracing::{debug, warn};

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

/// The node and the runtime it runs on, shared by all clones of the service.
struct Shared {
    // Declared before `_runtime`: the node is destroyed while the runtime exists.
    inner: BlockingDeliveryNode,
    _runtime: Runtime,
}

impl Drop for Shared {
    // The old wrapper stopped the node before destroying it; destroying a node
    // that is still connected makes the library wait out its teardown timeout.
    fn drop(&mut self) {
        // Blocking is not allowed on a runtime thread; destroy then does the stopping.
        if tokio::runtime::Handle::try_current().is_ok() {
            return;
        }
        if let Err(e) = self.inner.shutdown() {
            warn!("stopping the delivery node failed: {e}");
        }
    }
}

/// logos-delivery backed delivery service. Cheap to clone — all clones share
/// the same background node, which is stopped once the last clone is dropped.
#[derive(Clone)]
pub struct EmbeddedLogosDelivery {
    shared: Arc<Shared>,
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
    pub fn start(cfg: P2pConfig) -> Result<Self, DeliveryError> {
        // Blocking on our own runtime from a runtime thread panics, and unwinding
        // then drops that runtime in the async context: a second panic, so abort.
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(DeliveryError::Startup(
                "start blocks the calling thread: call it outside a tokio runtime, \
                 e.g. from tokio::task::spawn_blocking"
                    .into(),
            ));
        }
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
            shared: Arc::new(Shared {
                inner,
                _runtime: runtime,
            }),
            inbound,
        })
    }

    /// Stops the node. Clones share it, so this ends delivery for all of them.
    pub fn shutdown(&self) -> Result<(), DeliveryError> {
        self.shared.inner.shutdown()
    }

    /// Stop delivering messages addressed to `delivery_address`.
    pub fn unsubscribe(&self, delivery_address: &str) -> Result<(), DeliveryError> {
        self.shared
            .inner
            .unsubscribe(&content_topic_for(delivery_address))
    }
}

impl DeliveryService for EmbeddedLogosDelivery {
    type Error = DeliveryError;

    fn publish(&mut self, envelope: AddressedEnvelope) -> Result<(), DeliveryError> {
        let topic = content_topic_for(&envelope.delivery_address);
        debug!(topic = &topic, "Publish");
        self.shared.inner.publish(&topic, &envelope.data)?;
        Ok(())
    }

    fn subscribe(&mut self, delivery_address: &str) -> Result<(), DeliveryError> {
        self.shared
            .inner
            .subscribe(&content_topic_for(delivery_address))
    }
}

// The impl lives here (the crate owning the type) because the orphan rule bars
// it from the `logos-chat` crate, which owns neither the trait nor the type.
impl logos_generic_chat::Transport for EmbeddedLogosDelivery {
    fn inbound(&mut self) -> Receiver<Vec<u8>> {
        self.inbound.clone()
    }
}
