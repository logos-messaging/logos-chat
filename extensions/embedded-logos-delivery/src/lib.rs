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
//! ## Delivery message ids
//!
//! A payload's [`DeliveryMsgId`] is the bytes of the node's message hash. The node
//! reports a sent payload's hash in an event, not from `publish`, so a tagged envelope's
//! comes back through [`Transport::delivery_reports`](logos_generic_chat::Transport::delivery_reports).
//! [`DeliveryService::fetch_messages`] asks a connected store peer for payloads by hash.
//!
//! The synchronous methods must not be called from inside a tokio runtime.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use crossbeam_channel::{Receiver, Sender, TrySendError, bounded};
use libchat::{AddressedEnvelope, DeliveryInfo, DeliveryMsgId, DeliveryService, DeliveryTag};
use logos_delivery::blocking::BlockingDeliveryNode;
use logos_delivery::{DeliveryConfig, DeliveryEvent, STORE_CODEC, StoreQuery};
use logos_generic_chat::{DeliveryReport, InboundPayload};
use tokio::runtime::Runtime;
use tracing::{debug, warn};

pub use logos_delivery::DeliveryError;

/// The content-topic prefix carrying logos-chat traffic.
const CHAT_TOPIC_PREFIX: &str = "/logos-chat/1/";
/// How long startup waits for a first peer before carrying on regardless: the
/// same worst case as the fixed sleep it replaces, and less when peers connect sooner.
const CONNECT_WAIT: Duration = Duration::from_secs(3);
/// Items a queue between the node and the client holds before new ones are
/// dropped: the bound the node puts on its own queues.
const QUEUE_CAPACITY: usize = 1024;
/// How long a fetch waits on a store peer: the library's own default for the store
/// requests that backfill the messages a node missed.
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// The tag of each tagged publish whose hash the node has not reported yet, by request id.
type Pending = Arc<Mutex<HashMap<String, DeliveryTag>>>;

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
    // Feeds the fetch thread, which ends once this is dropped.
    fetches: Sender<Fetch>,
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
    // Taken by the first `Transport::inbound` call, shared by all clones.
    inbound: Arc<Mutex<Option<Receiver<InboundPayload>>>>,
    // Taken by the first `Transport::delivery_reports` call, shared by all clones.
    reports: Arc<Mutex<Option<Receiver<DeliveryReport>>>>,
    pending: Pending,
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
                // QUIC listens on UDP at the TCP port number, so discv5 cannot share it.
                .discv5_udp_port(0)
                .log_level(cfg.log_level)
                .wait_for_connection(CONNECT_WAIT),
            runtime.handle().clone(),
        )?;
        let (inbound_tx, inbound) = bounded(QUEUE_CAPACITY);
        let (reports_tx, reports) = bounded(QUEUE_CAPACITY);
        let (fetches, fetches_rx) = bounded::<Fetch>(QUEUE_CAPACITY);
        let pending = Pending::default();
        let events = inner.events();
        let (routed, routed_pending) = (inbound_tx.clone(), pending.clone());
        spawn("delivery-events", move || {
            route_events(events, &routed, &reports_tx, &routed_pending)
        })?;
        let shared = Arc::new(Shared {
            inner,
            fetches,
            _runtime: runtime,
        });
        let node = Arc::downgrade(&shared);
        spawn("delivery-fetch", move || {
            for fetch in fetches_rx {
                // Held only while a fetch runs: an idle thread keeps no node alive, and
                // a running fetch keeps the runtime its query blocks on.
                let Some(shared) = node.upgrade() else { return };
                fetch.run(&shared.inner, &inbound_tx);
            }
        })?;
        Ok(Self {
            shared,
            inbound: Arc::new(Mutex::new(Some(inbound))),
            reports: Arc::new(Mutex::new(Some(reports))),
            pending,
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

    /// The addresses of a connected store peer, in the form a store query takes.
    fn store_peer(&self) -> Result<String, DeliveryError> {
        let peers = self.shared.inner.connected_peers_info()?;
        let (peer_id, info) = peers
            .iter()
            .find(|(_, info)| {
                !info.addresses.is_empty() && info.protocols.iter().any(|p| p == STORE_CODEC)
            })
            .ok_or_else(|| DeliveryError::Store("no connected store peer".into()))?;
        Ok(info
            .addresses
            .iter()
            .map(|address| format!("{address}/p2p/{peer_id}"))
            .collect::<Vec<_>>()
            .join(","))
    }
}

impl DeliveryService for EmbeddedLogosDelivery {
    type Error = DeliveryError;

    fn publish(
        &mut self,
        envelope: AddressedEnvelope,
    ) -> Result<Option<DeliveryMsgId>, DeliveryError> {
        let topic = content_topic_for(&envelope.delivery_address);
        debug!(topic = &topic, "Publish");
        // The node reports the message hash only in a later event, which can come before
        // the request id does: the lock holds that event back until the tag is in place.
        let mut pending = lock(&self.pending);
        let request_id = self.shared.inner.publish(&topic, &envelope.data)?;
        if let Some(tag) = envelope.tag {
            pending.insert(request_id.0, tag);
        }
        Ok(None)
    }

    fn subscribe(&mut self, delivery_address: &str) -> Result<(), DeliveryError> {
        self.shared
            .inner
            .subscribe(&content_topic_for(delivery_address))
    }

    fn fetch_messages(
        &mut self,
        delivery_address: &str,
        delivery_msg_ids: &[DeliveryMsgId],
    ) -> Result<(), DeliveryError> {
        // A store query without hashes matches every message.
        if delivery_msg_ids.is_empty() {
            return Ok(());
        }
        let fetch = Fetch {
            peer: self.store_peer()?,
            content_topic: content_topic_for(delivery_address),
            query: StoreQuery {
                include_data: true,
                message_hashes: delivery_msg_ids
                    .iter()
                    .map(|id| format!("0x{}", hex::encode(id.as_bytes())))
                    .collect(),
                ..Default::default()
            },
        };
        self.shared
            .fetches
            .try_send(fetch)
            .map_err(|e| DeliveryError::Store(format!("fetch not queued: {e}")))
    }
}

// The impl lives here (the crate owning the type) because the orphan rule bars
// it from the `logos-chat` crate, which owns neither the trait nor the type.
impl logos_generic_chat::Transport for EmbeddedLogosDelivery {
    /// Callable once: a second receiver would split the messages with the first.
    fn inbound(&mut self) -> Receiver<InboundPayload> {
        self.inbound
            .lock()
            .expect("inbound lock is never held across a panic")
            .take()
            .expect("inbound called more than once")
    }

    /// Callable once: a second receiver would split the reports with the first.
    fn delivery_reports(&mut self) -> Receiver<DeliveryReport> {
        self.reports
            .lock()
            .expect("reports lock is never held across a panic")
            .take()
            .expect("delivery_reports called more than once")
    }
}

/// A store query for the fetch thread, for the payloads on one content topic.
struct Fetch {
    peer: String,
    content_topic: String,
    query: StoreQuery,
}

impl Fetch {
    /// Hands each payload the store peer returns on the content topic to `inbound`, page
    /// by page.
    fn run(mut self, node: &BlockingDeliveryNode, inbound: &Sender<InboundPayload>) {
        loop {
            let page = match node.store_query(&self.query, &self.peer, FETCH_TIMEOUT) {
                Ok(page) => page,
                Err(e) => {
                    warn!("fetching from the store failed: {e}");
                    return;
                }
            };
            for stored in page.messages {
                let Some(message) = stored
                    .message
                    .filter(|message| message.content_topic == self.content_topic)
                else {
                    continue;
                };
                let payload = InboundPayload {
                    data: message.payload,
                    delivery_info: delivery_info(&stored.message_hash),
                };
                offer(inbound, payload, "inbound");
            }
            let Some(cursor) = page.pagination_cursor else {
                return;
            };
            self.query.pagination_cursor = Some(cursor);
        }
    }
}

/// Hands each chat message the node receives to `inbound`, with its hash, and the first
/// hash the node reports for a tagged publish to `reports`. Returns once the events end.
fn route_events(
    events: Receiver<DeliveryEvent>,
    inbound: &Sender<InboundPayload>,
    reports: &Sender<DeliveryReport>,
    pending: &Pending,
) {
    for event in events {
        match event {
            DeliveryEvent::MessageReceived {
                message_hash,
                message,
                ..
            } if message.content_topic.starts_with(CHAT_TOPIC_PREFIX) => {
                let payload = InboundPayload {
                    data: message.payload,
                    delivery_info: delivery_info(&message_hash),
                };
                offer(inbound, payload, "inbound");
            }
            DeliveryEvent::MessageQueued {
                request_id,
                message_hash,
            }
            | DeliveryEvent::MessageSent {
                request_id,
                message_hash,
            }
            | DeliveryEvent::MessagePropagated {
                request_id,
                message_hash,
            } => {
                let tag = lock(pending).remove(&request_id);
                if let Some(tag) = tag
                    && let Some(delivery_info) = delivery_info(&message_hash)
                {
                    offer(reports, DeliveryReport { tag, delivery_info }, "report");
                }
            }
            DeliveryEvent::MessageError {
                request_id, error, ..
            } => {
                lock(pending).remove(&request_id);
                warn!(%request_id, %error, "the node failed a send");
            }
            _ => {}
        }
    }
}

/// The id of the payload the node's message hash names: the hash's bytes.
fn delivery_info(message_hash: &str) -> Option<DeliveryInfo> {
    let bytes = message_hash
        .strip_prefix("0x")
        .and_then(|hex| hex::decode(hex).ok());
    if bytes.is_none() {
        warn!(message_hash, "the node reported an unreadable message hash");
    }
    bytes.map(|bytes| DeliveryInfo {
        delivery_msg_id: DeliveryMsgId::from(bytes),
    })
}

/// Queues `item` without blocking, so the node's events keep flowing: a full queue drops it.
fn offer<T>(queue: &Sender<T>, item: T, name: &str) {
    if let Err(TrySendError::Full(_)) = queue.try_send(item) {
        warn!("{name} queue full, dropping an item");
    }
}

/// Its entries stay whole through a panic, so a poisoned lock still serves.
fn lock(pending: &Pending) -> MutexGuard<'_, HashMap<String, DeliveryTag>> {
    pending.lock().unwrap_or_else(PoisonError::into_inner)
}

fn spawn(name: &str, f: impl FnOnce() + Send + 'static) -> Result<(), DeliveryError> {
    std::thread::Builder::new()
        .name(name.into())
        .spawn(f)
        .map(drop)
        .map_err(|e| DeliveryError::Startup(e.to_string()))
}
