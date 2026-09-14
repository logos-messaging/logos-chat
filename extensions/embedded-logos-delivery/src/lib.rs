//! The embedded logos-delivery transport service.
//!
//! [`EmbeddedLogosDelivery`] implements [`DeliveryService`] over the embedded
//! node owned by [`ThreadedDeliveryWrapper`]. The wrapper handles the node
//! thread and hands back raw [`WakuEvent`]s; this crate supplies the
//! delivery-specific mapping — content topics, `/logos-chat/1/…` filtering, and
//! payload decoding.
//!
//! The native node is linked transitively via the `logos-delivery-rust` crate,
//! so this crate lives outside the workspace's default members; depend on it
//! (e.g. via the `logos-chat` crate) only when shipping the embedded node.
//!
//! ## Content topic mapping
//!
//! `AddressedEnvelope::delivery_address` maps to logos-delivery content topic
//! `/logos-chat/1/{delivery_address}/proto`.

use crossbeam_channel::Receiver;
use libchat::{AddressedEnvelope, DeliveryService};

use logos_delivery::{ThreadedDeliveryWrapper, WakuEvent};

pub use logos_delivery::{DeliveryError, P2pConfig};
use tracing::debug;

/// The content-topic prefix carrying logos-chat traffic.
const CHAT_TOPIC_PREFIX: &str = "/logos-chat/1/";

pub fn content_topic_for(delivery_address: &str) -> String {
    format!("{CHAT_TOPIC_PREFIX}{delivery_address}/proto")
}

// ── EmbeddedLogosDelivery ──────────────────────────────────────────────────

/// logos-delivery backed delivery service. Cheap to clone — all clones share
/// the same background node.
#[derive(Clone, Debug)]
pub struct EmbeddedLogosDelivery {
    inner: ThreadedDeliveryWrapper<Vec<u8>>,
}

impl EmbeddedLogosDelivery {
    /// Start the embedded logos-delivery node. Only chat payloads (on a
    /// `/logos-chat/1/…` content topic) are kept on the inbound queue, decoded
    /// to raw bytes.
    pub fn start(cfg: P2pConfig) -> Result<Self, DeliveryError> {
        let inner = ThreadedDeliveryWrapper::start(cfg, |event: WakuEvent| {
            let msg = event.into_received()?;
            if !msg.content_topic().starts_with(CHAT_TOPIC_PREFIX) {
                return None;
            }
            msg.into_payload()
        })?;

        Ok(Self { inner })
    }

    /// Stop delivering messages addressed to `delivery_address`.
    pub fn unsubscribe(&self, delivery_address: &str) -> Result<(), DeliveryError> {
        self.inner.unsubscribe(&content_topic_for(delivery_address))
    }
}

impl DeliveryService for EmbeddedLogosDelivery {
    type Error = DeliveryError;

    fn publish(&mut self, envelope: AddressedEnvelope) -> Result<(), DeliveryError> {
        debug!(
            topic = &content_topic_for(&envelope.delivery_address),
            "Publish"
        );
        self.inner.publish(
            &content_topic_for(&envelope.delivery_address),
            &envelope.data,
        )
    }

    fn subscribe(
        &mut self,
        delivery_address: &str,
    ) -> Result<(), <Self as DeliveryService>::Error> {
        self.inner.subscribe(&content_topic_for(delivery_address))
    }
}

// Teaching the service the inbound half makes it a full client transport, so
// callers need no wrapper newtype. The impl lives here (the crate owning the
// type) because the orphan rule bars it from the `logos-chat` crate, which
// owns neither the trait nor the type.
impl logos_generic_chat::Transport for EmbeddedLogosDelivery {
    fn inbound(&mut self) -> Receiver<Vec<u8>> {
        self.inner.inbound_queue()
    }
}
