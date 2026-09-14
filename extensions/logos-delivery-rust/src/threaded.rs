use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use crossbeam_channel::{Receiver, Sender};
use tracing::{debug, error, info};

use crate::wrapper::LogosNodeCtx;

// ── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum DeliveryError {
    #[error("node startup failed: {0}")]
    StartupFailed(String),
    #[error("publish failed: {0}")]
    PublishFailed(String),
    #[error("subscribe failed: {0}")]
    SubscribeFailed(String),
    #[error("unsubscribe failed: {0}")]
    UnsubscribeFailed(String),
    #[error("send channel closed")]
    ChannelClosed,
}

// ── Internals ────────────────────────────────────────────────────────────────

/// A node operation to run on the serialized node thread.
#[derive(Debug)]
enum NodeOp {
    Publish(String),     // message_json
    Subscribe(String),   // content_topic
    Unsubscribe(String), // content_topic
}

#[derive(Debug)]
struct NodeCmd {
    op: NodeOp,
    reply: mpsc::SyncSender<Result<(), DeliveryError>>,
}

type SubscriberList<T> = Arc<Mutex<Vec<Sender<T>>>>;

// ── P2pConfig ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct P2pConfig {
    pub preset: String,
    pub port: u16,
    pub log_level: String,
}

impl Default for P2pConfig {
    // Generate a P2pConfig that connects to the `logos.test` network and  uses a randomly assigned port.
    // Random port avoids conflicts with other services on the machine, and allows multiple instances
    // to run in parallel.
    fn default() -> Self {
        /// The logos-delivery network preset joined by default.
        const DEFAULT_NETWORK_PRESET: &str = "logos.test";
        /// Default to an OS assigned port, that is available
        const DEFAULT_PORT: u16 = 0;
        Self {
            preset: DEFAULT_NETWORK_PRESET.into(),
            port: DEFAULT_PORT,
            log_level: "ERROR".into(),
        }
    }
}

// ── Wire types ──────────────────────────────────────────────────────────────

/// Outbound message sent to the logos-delivery node.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct WakuMessage {
    #[serde(rename = "contentTopic")]
    content_topic: String,
    /// Base64-encoded payload.
    payload: String,
    ephemeral: bool,
}

/// Top-level event envelope received from the logos-delivery node callback.
#[derive(Debug, serde::Deserialize, Clone)]
pub struct WakuEvent {
    #[serde(rename = "eventType")]
    event_type: String,
    message: Option<ReceivedMessage>,
}

impl WakuEvent {
    /// The received message iff this is a `message_received` event.
    pub fn into_received(self) -> Option<ReceivedMessage> {
        (self.event_type == "message_received")
            .then_some(self.message)
            .flatten()
    }
}

/// Message payload from a `message_received` event.
#[derive(Debug, serde::Deserialize, Clone)]
pub struct ReceivedMessage {
    #[serde(rename = "contentTopic")]
    content_topic: String,
    /// The node may deliver the payload as either a base64 string or a JSON
    /// array of byte values.
    payload: WakuPayload,
}

impl ReceivedMessage {
    pub fn content_topic(&self) -> &str {
        &self.content_topic
    }

    /// Decode the payload to raw bytes, whichever wire form the node used.
    pub fn into_payload(self) -> Option<Vec<u8>> {
        self.payload.decode()
    }
}

/// Untagged union that handles both payload representations.
#[derive(Debug, serde::Deserialize, Clone)]
#[serde(untagged)]
enum WakuPayload {
    Base64(String),
    Bytes(Vec<u8>),
}

impl WakuPayload {
    fn decode(self) -> Option<Vec<u8>> {
        match self {
            WakuPayload::Base64(s) => BASE64.decode(s).ok(),
            WakuPayload::Bytes(b) => Some(b),
        }
    }
}

// ── ThreadedDeliveryWrapper ─────────────────────────────────────────────────

/// Owns the embedded node on a dedicated thread. Generic over the inbound item
/// type `T`: a caller-supplied mapper turns each raw [`WakuEvent`] into an
/// `Option<T>` on the callback thread, so filtering and decoding happen inline
/// with no relay thread. Cheap to clone — all clones share the same node.
pub struct ThreadedDeliveryWrapper<T = WakuEvent> {
    outbound: mpsc::SyncSender<NodeCmd>,
    #[allow(dead_code)]
    subscribers: SubscriberList<T>,
    inbound_rx: Option<Receiver<T>>,
}

// Manual impls so `T` carries no `Clone`/`Debug` bound at the struct level —
// `Sender<T>`/`Receiver<T>` are `Clone` for every `T`.
impl<T> Clone for ThreadedDeliveryWrapper<T> {
    fn clone(&self) -> Self {
        Self {
            outbound: self.outbound.clone(),
            subscribers: self.subscribers.clone(),
            inbound_rx: self.inbound_rx.clone(),
        }
    }
}

impl<T> std::fmt::Debug for ThreadedDeliveryWrapper<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThreadedDeliveryWrapper")
            .field("has_inbound", &self.inbound_rx.is_some())
            .finish_non_exhaustive()
    }
}

impl<T> ThreadedDeliveryWrapper<T> {
    /// Start the embedded logos-delivery node. `map` runs on the node's event
    /// callback for every received event; return `Some(item)` to enqueue it for
    /// [`Self::inbound_queue`], or `None` to drop it. It must be non-blocking.
    pub fn start<F>(cfg: P2pConfig, map: F) -> Result<Self, DeliveryError>
    where
        T: Clone + Send + 'static,
        F: FnMut(WakuEvent) -> Option<T> + Send + 'static,
    {
        let (out_tx, out_rx) = mpsc::sync_channel::<NodeCmd>(256);
        let subscribers: SubscriberList<T> = Arc::new(Mutex::new(Vec::new()));
        let (ready_tx, ready_rx) = mpsc::channel::<Result<(), DeliveryError>>();
        // Create the inbound channel before spawning so the receiver is
        // registered inside the thread, before any event callback fires.
        let (inbound_tx, inbound_rx) = crossbeam_channel::bounded::<T>(1024);

        let subs_for_thread = subscribers.clone();

        let handle = thread::Builder::new()
            .name("logos-node".into())
            .spawn(move || {
                if let Err(panic) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    Self::node_thread(cfg, out_rx, subs_for_thread, inbound_tx, ready_tx, map);
                })) {
                    let msg = panic
                        .downcast_ref::<&str>()
                        .map(|s| s.to_string())
                        .or_else(|| panic.downcast_ref::<String>().cloned())
                        .unwrap_or_else(|| "unknown panic".into());
                    error!("logos-node thread panicked: {msg}");
                }
            })
            .map_err(|e| DeliveryError::StartupFailed(e.to_string()))?;

        // On failure, the node thread drops LogosNodeCtx (stop+destroy against
        // a half-initialized Nim node). Join it so the process doesn't begin
        // teardown mid-destroy — that race SIGSEGVs inside the Nim async loop.
        let ready = ready_rx.recv().unwrap_or_else(|_| {
            Err(DeliveryError::StartupFailed(
                "node thread exited before ready".into(),
            ))
        });
        if let Err(e) = ready {
            let _ = handle.join();
            return Err(e);
        }

        Ok(Self {
            outbound: out_tx,
            subscribers,
            inbound_rx: Some(inbound_rx),
        })
    }

    /// Queue `op` on the node thread and block until it acknowledges.
    fn send_cmd(&self, op: NodeOp) -> Result<(), DeliveryError> {
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        self.outbound
            .send(NodeCmd {
                op,
                reply: reply_tx,
            })
            .map_err(|_| DeliveryError::ChannelClosed)?;
        reply_rx.recv().map_err(|_| DeliveryError::ChannelClosed)?
    }

    /// Start delivering messages on `content_topic`. Blocks until acknowledged.
    pub fn subscribe(&self, content_topic: &str) -> Result<(), DeliveryError> {
        debug!(?content_topic, "Subscribe");
        self.send_cmd(NodeOp::Subscribe(content_topic.to_string()))
    }

    /// Stop delivering messages on `content_topic`. Blocks until acknowledged.
    pub fn unsubscribe(&self, content_topic: &str) -> Result<(), DeliveryError> {
        debug!(?content_topic, "Unsubscribe");
        self.send_cmd(NodeOp::Unsubscribe(content_topic.to_string()))
    }

    /// Publish `payload` on `content_topic`. Blocks until the node acknowledges.
    pub fn publish(&self, content_topic: &str, payload: &[u8]) -> Result<(), DeliveryError> {
        let msg = WakuMessage {
            content_topic: content_topic.to_string(),
            payload: BASE64.encode(payload),
            ephemeral: false,
        };

        debug!(content_topic = ?msg.content_topic, payload = ?msg.payload, ephemeral = ?msg.ephemeral, "Publish");

        let message_json =
            serde_json::to_string(&msg).map_err(|e| DeliveryError::PublishFailed(e.to_string()))?;
        self.send_cmd(NodeOp::Publish(message_json))
    }

    /// Take the inbound queue of mapped items. Callable once.
    pub fn inbound_queue(&mut self) -> Receiver<T> {
        self.inbound_rx
            .take()
            .expect("inbound_queue called more than once")
    }

    fn node_thread<F>(
        cfg: P2pConfig,
        out_rx: mpsc::Receiver<NodeCmd>,
        subscribers: SubscriberList<T>,
        inbound_tx: Sender<T>,
        ready_tx: mpsc::Sender<Result<(), DeliveryError>>,
        mut map: F,
    ) where
        T: Clone + Send + 'static,
        F: FnMut(WakuEvent) -> Option<T> + Send + 'static,
    {
        // discv5UdpPort defaults to 9000 in libwaku, so a second instance with
        // a distinct --port still collides on UDP. Bind it to tcp_port so a
        // single --port knob keeps both ports distinct across instances.
        let config_json = serde_json::json!({
            "logLevel": cfg.log_level,
            "mode": "Core",
            "preset": cfg.preset,
            "tcpPort": cfg.port,
            "discv5UdpPort": cfg.port,
        })
        .to_string();

        let mut node = match LogosNodeCtx::new(&config_json) {
            Ok(n) => n,
            Err(e) => {
                let _ = ready_tx.send(Err(DeliveryError::StartupFailed(e)));
                return;
            }
        };

        // Register the inbound sender before installing the event callback so
        // there is no window where the callback is live but the channel is not
        // yet in the subscriber list.
        subscribers.lock().unwrap().push(inbound_tx);

        let subs_for_cb = subscribers.clone();
        let event_closure = move |_ret: i32, data: &str| {
            let Ok(event) = serde_json::from_str::<WakuEvent>(data) else {
                return;
            };
            let Some(item) = map(event) else {
                return;
            };
            let mut guard = match subs_for_cb.lock() {
                Ok(g) => g,
                Err(e) => {
                    error!("subscriber mutex poisoned: {e}");
                    return;
                }
            };
            guard.retain(|tx| match tx.try_send(item.clone()) {
                Ok(()) => true,
                Err(crossbeam_channel::TrySendError::Full(_)) => true,
                Err(crossbeam_channel::TrySendError::Disconnected(_)) => false,
            });
        };
        node.set_event_callback(event_closure);

        if let Err(e) = node.start() {
            let _ = ready_tx.send(Err(DeliveryError::StartupFailed(e)));
            return;
        }
        info!("logos-delivery node started (preset={})", cfg.preset);

        // FIXME: This unconditional sleep is a stand-in for proper
        // peer-connectivity detection. The right approach is to listen for a
        // `peer_connected` (or equivalent status-change) event from the node
        // callback and only proceed once at least one peer is reachable,
        // falling back to a configurable timeout. logos-delivery would need to
        // surface such an event via its callback mechanism for this to work.
        thread::sleep(Duration::from_secs(3));

        let _ = ready_tx.send(Ok(()));

        while let Ok(cmd) = out_rx.recv() {
            let result = match cmd.op {
                NodeOp::Publish(msg) => node
                    .send(&msg)
                    .map(|_| ())
                    .map_err(DeliveryError::PublishFailed),
                NodeOp::Subscribe(topic) => node
                    .subscribe(&topic)
                    .map_err(DeliveryError::SubscribeFailed),
                NodeOp::Unsubscribe(topic) => node
                    .unsubscribe(&topic)
                    .map_err(DeliveryError::UnsubscribeFailed),
            };
            let _ = cmd.reply.try_send(result);
        }

        info!("logos-node command loop finished");
    }
}
