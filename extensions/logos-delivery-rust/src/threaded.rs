use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::Ipv4Addr;
use std::num::NonZeroU32;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use crossbeam_channel::{Receiver, Sender, TrySendError};
use tracing::{debug, error, info, warn};

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
    #[error("node info failed: {0}")]
    NodeInfoFailed(String),
    #[error("send channel closed")]
    ChannelClosed,
}

// ── Internals ────────────────────────────────────────────────────────────────

/// A node operation to run on the serialized node thread.
#[derive(Debug)]
enum NodeOp {
    Publish(String, usize), // message_json, payload bytes
    Subscribe(String),      // content_topic
    Unsubscribe(String),    // content_topic
    /// Answered on a channel of its own: the others answer with nothing.
    State(mpsc::SyncSender<Result<NodeState, DeliveryError>>),
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
    pub network: Network,
    pub port: u16,
    pub log_level: String,
}

/// The network an embedded node joins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Network {
    /// One the library knows by name, with the nodes and limits it holds for it.
    Preset(String),
    /// One of nodes told each other's addresses, which no node of a preset is
    /// on.
    Local(LocalNetwork),
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Network::Preset(preset) => write!(f, "preset={preset}"),
            Network::Local(local) => write!(f, "cluster={}", local.cluster_id.0),
        }
    }
}

/// What differs between one local network and the next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalNetwork {
    pub cluster_id: ClusterId,
    /// The address the node listens on and is dialed at: loopback, or one of
    /// its own on a network of containers.
    pub address: Ipv4Addr,
    /// The nodes this one dials at its start.
    pub static_nodes: Vec<NodeAddress>,
    /// The largest message the node takes, in KiB.
    pub max_message_kib: NonZeroU32,
}

/// The cluster id of a local network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClusterId(u16);

/// The cluster ids the library reads as a preset: a node handed one joins
/// that preset's network.
const PRESET_CLUSTER_IDS: [u16; 2] = [1, 2];

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("cluster id {0} names a preset network")]
pub struct PresetClusterId(u16);

impl TryFrom<u16> for ClusterId {
    type Error = PresetClusterId;

    fn try_from(id: u16) -> Result<Self, Self::Error> {
        if PRESET_CLUSTER_IDS.contains(&id) {
            Err(PresetClusterId(id))
        } else {
            Ok(Self(id))
        }
    }
}

/// The multiaddress a node of a local network is dialed at:
/// `/ip4/<address>/tcp/<port>/p2p/<peer id>`. The library leaves out a static
/// node it cannot read and starts all the same, so one is read here.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct NodeAddress(String);

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0:?} is not /ip4/<address>/tcp/<port>/p2p/<peer id>")]
pub struct NotANodeAddress(String);

/// The characters a peer id is written in.
const BASE58: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

impl FromStr for NodeAddress {
    type Err = NotANodeAddress;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = text.split('/').collect();
        let dialed = match parts.as_slice() {
            ["", "ip4", address, "tcp", port, "p2p", peer_id] => {
                address
                    .parse()
                    .is_ok_and(|address: Ipv4Addr| !address.is_unspecified())
                    && port.parse().is_ok_and(|port: u16| port != 0)
                    && !peer_id.is_empty()
                    && peer_id.chars().all(|c| BASE58.contains(c))
            }
            _ => false,
        };
        if dialed {
            Ok(Self(text.to_string()))
        } else {
            Err(NotANodeAddress(text.to_string()))
        }
    }
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
            network: Network::Preset(DEFAULT_NETWORK_PRESET.into()),
            port: DEFAULT_PORT,
            log_level: "ERROR".into(),
        }
    }
}

/// The configuration the library is handed for `cfg`, as JSON.
fn node_config(cfg: &P2pConfig) -> String {
    // discv5UdpPort defaults to 9000 in libwaku, so a second instance with
    // a distinct --port still collides on UDP. Bind it to tcp_port so a
    // single --port knob keeps both ports distinct across instances.
    match &cfg.network {
        Network::Preset(preset) => serde_json::json!({
            "logLevel": cfg.log_level,
            "mode": "Core",
            "preset": preset,
            "tcpPort": cfg.port,
            "discv5UdpPort": cfg.port,
        }),
        Network::Local(local) => serde_json::json!({
            "logLevel": cfg.log_level,
            "mode": "Core",
            "tcpPort": cfg.port,
            "discv5UdpPort": cfg.port,
            "clusterId": local.cluster_id.0,
            "staticnodes": local.static_nodes,
            // The library reads a size in B, KB or KiB and no larger unit.
            "maxMessageSize": format!("{}KiB", local.max_message_kib),
            // A content topic needs shards the library assigns, and with one
            // shard every node of the network is in the one mesh.
            "numShardsInNetwork": 1,
            // On loopback every node of the network shares one address, and the
            // library keeps five peers to an address unless told otherwise.
            "colocationLimit": 0,
            // The node listens on its own address alone: on loopback nothing
            // outside the machine can dial it.
            "listenAddress": local.address.to_string(),
            // Naming the address keeps the library from asking the router for
            // one, and `none` it refuses. The node announces another address
            // all the same, so `NodeState::address` is built from its port.
            "nat": format!("extip:{}", local.address),
            // The network has no store node, and a node waiting for one to
            // confirm keeps every message it published.
            "reliabilityEnabled": false,
            // A node without a peer asks a name server whether the machine
            // is online: Cloudflare's, also when it is handed an empty list.
            // Asked on loopback, the question does not leave this machine.
            "dnsAddrsNameServers": ["127.0.0.1"],
        }),
    }
    .to_string()
}

// ── Node state ──────────────────────────────────────────────────────────────

/// What an embedded node says of itself when asked.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct NodeState {
    /// The multiaddress another node dials this one at. On a preset it is
    /// the first the node announces, which on a machine without a network
    /// is no address to dial.
    pub address: String,
    /// Peers the node holds a connection to. `None` when the library's
    /// metrics do not hold the count.
    pub peers: Option<u64>,
    /// Peers in the node's gossip mesh at its last heartbeat, over every
    /// shard it is on. `None` when the library's metrics do not hold the
    /// count.
    pub mesh_peers: Option<u64>,
    /// Connections the node opened, since it started. `None` when the
    /// library's metrics do not hold the count.
    pub dials_ok: Option<u64>,
    /// Connections the node could not open, since it started. `None` when
    /// the library's metrics do not hold the count.
    pub dials_failed: Option<u64>,
    /// Publishes the node refused, since it started.
    pub publish_refused: u64,
    /// Received frames the full inbound queue dropped, since the node started.
    pub inbound_dropped: u64,
}

const PEERS_GAUGE: &str = "libp2p_peers";
const MESH_PEERS_GAUGE: &str = "libp2p_gossipsub_peers_per_topic_mesh";
const DIALS_OK_COUNTER: &str = "libp2p_successful_dials_total";
const DIALS_FAILED_COUNTER: &str = "libp2p_failed_dials_total";

impl NodeState {
    fn new(address: String, metrics: &str, losses: &Losses) -> Self {
        Self {
            address,
            peers: gauge(metrics, PEERS_GAUGE),
            mesh_peers: gauge(metrics, MESH_PEERS_GAUGE),
            dials_ok: gauge(metrics, DIALS_OK_COUNTER),
            dials_failed: gauge(metrics, DIALS_FAILED_COUNTER),
            publish_refused: losses.publish_refused.load(Ordering::Relaxed),
            inbound_dropped: losses.inbound_dropped.load(Ordering::Relaxed),
        }
    }

    /// Ask a node for its state. `info` answers one of the library's node
    /// info ids. A node that does not give its metrics still has an address.
    fn ask(
        info: impl Fn(&str) -> Result<String, String>,
        network: &Network,
        losses: &Losses,
    ) -> Result<Self, DeliveryError> {
        let needed = |id: &str| info(id).map_err(DeliveryError::NodeInfoFailed);
        let address = match network {
            Network::Preset(_) => announced_address(&needed("MyMultiaddresses")?),
            Network::Local(local) => local_address(
                local.address,
                &needed("MyBoundPorts")?,
                &needed("MyPeerId")?,
            ),
        }
        .map_err(DeliveryError::NodeInfoFailed)?;
        let metrics = info("Metrics").unwrap_or_else(|error| {
            warn!(error, "the node did not give its metrics");
            String::new()
        });
        Ok(Self::new(address, &metrics, losses))
    }
}

/// The first address in a node's answer for `MyMultiaddresses`.
fn announced_address(multiaddresses: &str) -> Result<String, String> {
    multiaddresses
        .split(',')
        .map(str::trim)
        .find(|address| !address.is_empty())
        .map(str::to_string)
        .ok_or_else(|| "the node announces no address".to_string())
}

/// The multiaddress a node of a local network is dialed at, from its address
/// and its answers for `MyBoundPorts` and `MyPeerId`.
fn local_address(address: Ipv4Addr, bound_ports: &str, peer_id: &str) -> Result<String, String> {
    #[derive(serde::Deserialize)]
    struct BoundPorts {
        tcp: u16,
    }

    let ports: BoundPorts = serde_json::from_str(bound_ports)
        .map_err(|e| format!("unreadable bound ports ({e}): {bound_ports}"))?;
    Ok(format!("/ip4/{address}/tcp/{}/p2p/{peer_id}", ports.tcp))
}

/// Gauge or counter `name` in the library's metrics text, summed over its
/// label sets.
fn gauge(metrics: &str, name: &str) -> Option<u64> {
    let mut values = metrics
        .lines()
        .filter_map(|line| line.strip_prefix(name))
        .filter(|rest| rest.starts_with([' ', '{']))
        .filter_map(|rest| rest.rsplit(' ').next()?.parse::<f64>().ok())
        .peekable();
    values.peek()?;
    Some(values.sum::<f64>() as u64)
}

/// The longest a node that has started waits for its peers before it is ready.
const CONNECT_WAIT: Duration = Duration::from_secs(3);

/// Between two looks at the links of a local node that waits for them.
const DIAL_POLL: Duration = Duration::from_millis(50);

/// Waits until a node that has started is ready to be used.
///
/// A node of a local network is given out to nobody before it is ready, so
/// the links it holds until then are its own dials: it is ready once it holds
/// one for each node it was told to dial, and when the wait has lasted
/// `CONNECT_WAIT` and they have not come up. `peers` answers how many links
/// the node holds, and `waited` how long the wait has lasted.
fn await_connected(
    network: &Network,
    mut peers: impl FnMut() -> Option<u64>,
    mut waited: impl FnMut() -> Duration,
    mut sleep: impl FnMut(Duration),
) {
    let Network::Local(local) = network else {
        // FIXME: This unconditional sleep is a stand-in for proper
        // peer-connectivity detection. The right approach is to listen for a
        // `peer_connected` (or equivalent status-change) event from the node
        // callback and only proceed once at least one peer is reachable,
        // falling back to a configurable timeout. logos-delivery would need to
        // surface such an event via its callback mechanism for this to work.
        sleep(CONNECT_WAIT);
        return;
    };
    // A node holds one link to a node, however often it was told to dial it.
    let dialed: HashSet<&str> = local.static_nodes.iter().map(|node| &*node.0).collect();
    let dialed = dialed.len() as u64;
    while waited() < CONNECT_WAIT && peers().unwrap_or(0) < dialed {
        sleep(DIAL_POLL.min(CONNECT_WAIT.saturating_sub(waited())));
    }
}

// ── Losses ──────────────────────────────────────────────────────────────────

/// Frames lost without anyone choosing to lose them, counted from the node's
/// start. The node thread and the event callback share one.
#[derive(Debug, Default)]
struct Losses {
    publish_refused: AtomicU64,
    inbound_dropped: AtomicU64,
    publishes: Mutex<Publishes>,
}

/// Publishes the node has not reported the outcome of.
#[derive(Debug, Default)]
struct Publishes {
    /// Payload bytes of each, by the request id the node gave it.
    open: HashMap<String, usize>,
    /// Outcomes reported while a publish waits for its request id: the node
    /// reports a refusal it can tell at once before it answers the call.
    /// `None` while no publish waits.
    early: Option<Vec<(String, PublishOutcome)>>,
}

#[derive(Debug, PartialEq, Eq)]
enum PublishOutcome {
    Propagated,
    Refused(String),
}

impl Losses {
    fn publishes(&self) -> std::sync::MutexGuard<'_, Publishes> {
        self.publishes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// A publish is on its way to the node.
    fn publish_begins(&self) {
        self.publishes().early = Some(Vec::new());
    }

    /// The node answered the call that handed it a publish of `bytes`: with
    /// a request id, or with why it did not take the publish. One it took is
    /// `Ok` whatever an event says of it.
    fn publish_answered(
        &self,
        answer: Result<String, String>,
        bytes: usize,
    ) -> Result<(), DeliveryError> {
        let refused = {
            let mut publishes = self.publishes();
            let early = publishes.early.take().unwrap_or_default();
            match &answer {
                Ok(request_id) => match early.into_iter().find(|(id, _)| id == request_id) {
                    Some((_, PublishOutcome::Refused(reason))) => Some(reason),
                    Some((_, PublishOutcome::Propagated)) => None,
                    None => {
                        publishes.open.insert(request_id.clone(), bytes);
                        None
                    }
                },
                Err(reason) => Some(reason.clone()),
            }
        };
        if let Some(reason) = refused {
            self.publish_refused(bytes, &reason);
        }
        answer.map(drop).map_err(DeliveryError::PublishFailed)
    }

    /// The node reported `outcome` for a request. A request it reported
    /// propagated is closed, so an error that follows is no refusal.
    fn publish_settled(&self, request_id: &str, outcome: PublishOutcome) {
        let bytes = {
            let mut publishes = self.publishes();
            let bytes = publishes.open.remove(request_id);
            if bytes.is_none()
                && let Some(early) = publishes.early.as_mut()
            {
                early.push((request_id.to_string(), outcome));
                return;
            }
            bytes
        };
        if let (Some(bytes), PublishOutcome::Refused(reason)) = (bytes, outcome) {
            self.publish_refused(bytes, &reason);
        }
    }

    /// The node refused a publish of `bytes`, at the call or in an event.
    fn publish_refused(&self, bytes: usize, reason: &str) {
        self.publish_refused.fetch_add(1, Ordering::Relaxed);
        warn!(bytes, reason, "the node refused a publish");
    }

    /// A received frame of `bytes` found the inbound queue full.
    fn inbound_dropped(&self, bytes: usize) {
        self.inbound_dropped.fetch_add(1, Ordering::Relaxed);
        warn!(
            bytes,
            reason = "the inbound queue is full",
            "dropped a received frame"
        );
    }
}

/// Hand `item`, a frame of `bytes`, to every subscriber still listening. One
/// whose queue is full loses it.
fn deliver<T: Clone>(subscribers: &mut Vec<Sender<T>>, item: &T, bytes: usize, losses: &Losses) {
    subscribers.retain(|tx| match tx.try_send(item.clone()) {
        Ok(()) => true,
        Err(TrySendError::Full(_)) => {
            losses.inbound_dropped(bytes);
            true
        }
        Err(TrySendError::Disconnected(_)) => false,
    });
}

/// One event the node wrote: the outcome of a publish is settled, and what
/// `map` keeps of the event goes to the subscribers.
fn on_event<T: Clone>(
    data: &str,
    map: &mut impl FnMut(WakuEvent) -> Option<T>,
    subscribers: &SubscriberList<T>,
    losses: &Losses,
) {
    let Ok(event) = serde_json::from_str::<WakuEvent>(data) else {
        return;
    };
    if let Some((request_id, outcome)) = event.publish_outcome() {
        losses.publish_settled(request_id, outcome);
    }
    let bytes = event.payload_len();
    let Some(item) = map(event) else {
        return;
    };
    let mut guard = match subscribers.lock() {
        Ok(g) => g,
        Err(e) => {
            error!("subscriber mutex poisoned: {e}");
            return;
        }
    };
    deliver(&mut guard, &item, bytes, losses);
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
    /// The publish an event reports on, as the node answered its call.
    #[serde(rename = "requestId")]
    request_id: Option<String>,
    error: Option<String>,
}

impl WakuEvent {
    /// The request an event closes and what became of it, iff it closes one.
    fn publish_outcome(&self) -> Option<(&str, PublishOutcome)> {
        let request_id = self.request_id.as_deref()?;
        match self.event_type.as_str() {
            "message_propagated" => Some((request_id, PublishOutcome::Propagated)),
            "message_error" => {
                let reason = self.error.clone().unwrap_or_default();
                Some((request_id, PublishOutcome::Refused(reason)))
            }
            _ => None,
        }
    }

    /// Bytes of the payload of the message this event carries, if any.
    fn payload_len(&self) -> usize {
        self.message.as_ref().map_or(0, |msg| msg.payload.len())
    }

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
    fn len(&self) -> usize {
        match self {
            WakuPayload::Base64(s) => {
                let padding = s.bytes().rev().take_while(|b| *b == b'=').count();
                (s.len() / 4 * 3).saturating_sub(padding)
            }
            WakuPayload::Bytes(b) => b.len(),
        }
    }

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
    /// `Ok` says the node took the publish: one it refuses in an event is
    /// counted in [`NodeState`] and logged, and is no error here.
    pub fn publish(&self, content_topic: &str, payload: &[u8]) -> Result<(), DeliveryError> {
        let msg = WakuMessage {
            content_topic: content_topic.to_string(),
            payload: BASE64.encode(payload),
            ephemeral: false,
        };

        debug!(content_topic = ?msg.content_topic, payload = ?msg.payload, ephemeral = ?msg.ephemeral, "Publish");

        let message_json =
            serde_json::to_string(&msg).map_err(|e| DeliveryError::PublishFailed(e.to_string()))?;
        self.send_cmd(NodeOp::Publish(message_json, payload.len()))
    }

    /// Ask the node its address, its peers and what it lost. Blocks until it
    /// answers.
    pub fn node_state(&self) -> Result<NodeState, DeliveryError> {
        let (state_tx, state_rx) = mpsc::sync_channel(1);
        self.send_cmd(NodeOp::State(state_tx))?;
        state_rx.recv().map_err(|_| DeliveryError::ChannelClosed)?
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
        let mut node = match LogosNodeCtx::new(&node_config(&cfg)) {
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

        let losses = Arc::new(Losses::default());

        let subs_for_cb = subscribers.clone();
        let losses_for_cb = losses.clone();
        let event_closure = move |_ret: i32, data: &str| {
            on_event(data, &mut map, &subs_for_cb, &losses_for_cb);
        };
        node.set_event_callback(event_closure);

        if let Err(e) = node.start() {
            let _ = ready_tx.send(Err(DeliveryError::StartupFailed(e)));
            return;
        }
        info!("logos-delivery node started ({})", cfg.network);

        let started = Instant::now();
        await_connected(
            &cfg.network,
            || gauge(&node.node_info("Metrics").ok()?, PEERS_GAUGE),
            || started.elapsed(),
            thread::sleep,
        );

        let _ = ready_tx.send(Ok(()));

        while let Ok(cmd) = out_rx.recv() {
            let result = match cmd.op {
                NodeOp::Publish(msg, bytes) => {
                    losses.publish_begins();
                    losses.publish_answered(node.send(&msg), bytes)
                }
                NodeOp::Subscribe(topic) => node
                    .subscribe(&topic)
                    .map_err(DeliveryError::SubscribeFailed),
                NodeOp::Unsubscribe(topic) => node
                    .unsubscribe(&topic)
                    .map_err(DeliveryError::UnsubscribeFailed),
                NodeOp::State(reply) => {
                    let state = NodeState::ask(|id| node.node_info(id), &cfg.network, &losses);
                    let _ = reply.try_send(state);
                    Ok(())
                }
            };
            let _ = cmd.reply.try_send(result);
        }

        info!("logos-node command loop finished");
    }
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};

    use super::*;

    /// What liblogosdelivery v0.38.1 answered for each node info id: a node
    /// of a ten-node local network where every node dials each one before it.
    const BOUND_PORTS: &str = include_str!("../tests/fixtures/node_info/MyBoundPorts");
    const PEER_ID: &str = include_str!("../tests/fixtures/node_info/MyPeerId");
    const MULTIADDRESSES: &str = include_str!("../tests/fixtures/node_info/MyMultiaddresses");
    const METRICS: &str = include_str!("../tests/fixtures/node_info/Metrics");
    /// What a node told to dial a port nobody listens on answered for `Metrics`.
    const METRICS_OF_A_FAILED_DIAL: &str =
        include_str!("../tests/fixtures/node_info/Metrics.failed_dial");

    /// Events as liblogosdelivery v0.38.1 wrote them.
    const MESSAGE_ERROR: &str = r#"{"eventType":"message_error","requestId":"d1a02e86c98a1b9fed64","messageHash":"0xdac61e419007efe2a3031c7690f8881ab42f27693259c42e70987bfbc4ca65cf","error":"Message size exceeded maximum of 1024 bytes"}"#;
    const MESSAGE_PROPAGATED: &str = r#"{"eventType":"message_propagated","requestId":"2a7e6e651fb015c24722","messageHash":"0x31850dd9041edd6bd05ed33120d121bfd4529b4a437fe301b9a30bd6ef4c60c0"}"#;
    const MESSAGE_RECEIVED: &str = r#"{"eventType":"message_received","messageHash":"0x9d54f09f4041095a7a88fa44189052744e852846a190bdd1825bb4e9a5725fa0","message":{"payload":[120,120,120,120,120,120,120,120,120,120],"contentTopic":"/logos-chat/1/x/proto","meta":[],"version":0,"timestamp":1791610056187380992,"ephemeral":false,"proof":[]}}"#;

    const RAYA: &str =
        "/ip4/127.0.0.1/tcp/4001/p2p/16Uiu2HAm65ah8ABpi9PiX79T6PthDwhmknXi3161ZKT1ZbeeX1Rd";
    const PAX: &str =
        "/ip4/127.0.0.1/tcp/4002/p2p/16Uiu2HAkwVXqMJzJLxhpLL2QtZrdU9theKgbjMcyBKCzxV1dyjUM";

    #[derive(Clone, Default)]
    struct Buffer(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Buffer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// What `write` logs, as the default formatter renders it.
    fn rendered(write: impl FnOnce()) -> String {
        let buffer = Buffer::default();
        let writer = buffer.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .without_time()
            .finish();
        tracing::subscriber::with_default(subscriber, write);
        let bytes = buffer.0.lock().unwrap().clone();
        String::from_utf8(bytes).unwrap().trim().to_string()
    }

    fn event(json: &str) -> WakuEvent {
        serde_json::from_str(json).expect("an event the library wrote")
    }

    /// A node that answers each node info id as the recorded one did, but for
    /// the ids in `failing`.
    fn recorded(failing: &'static [&'static str]) -> impl Fn(&str) -> Result<String, String> {
        move |id| {
            if failing.contains(&id) {
                return Err(format!("no {id}"));
            }
            Ok(match id {
                "MyBoundPorts" => BOUND_PORTS,
                "MyPeerId" => PEER_ID,
                "MyMultiaddresses" => MULTIADDRESSES,
                "Metrics" => METRICS,
                _ => return Err(format!("Invalid node info id: {id}")),
            }
            .to_string())
        }
    }

    fn local() -> LocalNetwork {
        LocalNetwork {
            cluster_id: ClusterId::try_from(77).unwrap(),
            address: Ipv4Addr::LOCALHOST,
            static_nodes: Vec::new(),
            max_message_kib: NonZeroU32::new(512).unwrap(),
        }
    }

    fn local_network() -> Network {
        Network::Local(local())
    }

    fn refused(losses: &Losses) -> u64 {
        losses.publish_refused.load(Ordering::Relaxed)
    }

    #[test]
    fn a_preset_hands_the_node_its_name_and_its_ports() {
        assert_eq!(
            node_config(&P2pConfig::default()),
            r#"{"discv5UdpPort":0,"logLevel":"ERROR","mode":"Core","preset":"logos.test","tcpPort":0}"#
        );

        let cfg = P2pConfig {
            network: Network::Preset("logos.dev".into()),
            port: 4001,
            log_level: "DEBUG".into(),
        };
        assert_eq!(
            node_config(&cfg),
            r#"{"discv5UdpPort":4001,"logLevel":"DEBUG","mode":"Core","preset":"logos.dev","tcpPort":4001}"#
        );
    }

    #[test]
    fn a_local_network_hands_the_node_each_of_its_keys() {
        let cfg = P2pConfig {
            network: Network::Local(LocalNetwork {
                cluster_id: ClusterId::try_from(77).unwrap(),
                address: Ipv4Addr::LOCALHOST,
                static_nodes: vec![RAYA.parse().unwrap(), PAX.parse().unwrap()],
                max_message_kib: NonZeroU32::new(512).unwrap(),
            }),
            port: 4003,
            log_level: "ERROR".into(),
        };
        let config: serde_json::Value = serde_json::from_str(&node_config(&cfg)).unwrap();
        let config = config.as_object().expect("an object");

        let expected = serde_json::json!({
            "logLevel": "ERROR",
            "mode": "Core",
            "tcpPort": 4003,
            "discv5UdpPort": 4003,
            "clusterId": 77,
            "staticnodes": [RAYA, PAX],
            "maxMessageSize": "512KiB",
            "numShardsInNetwork": 1,
            "colocationLimit": 0,
            "listenAddress": "127.0.0.1",
            "nat": "extip:127.0.0.1",
            "reliabilityEnabled": false,
            "dnsAddrsNameServers": ["127.0.0.1"],
        });
        let expected = expected.as_object().expect("an object");

        for (key, value) in expected {
            assert_eq!(config.get(key), Some(value), "{key}");
        }
        let unexpected: Vec<_> = config
            .keys()
            .filter(|key| !expected.contains_key(*key))
            .collect();
        assert!(unexpected.is_empty(), "{unexpected:?}");
    }

    #[test]
    fn a_node_of_a_local_network_listens_on_its_address_and_names_it() {
        let cfg = P2pConfig {
            network: Network::Local(LocalNetwork {
                address: Ipv4Addr::new(10, 89, 0, 7),
                ..local()
            }),
            port: 0,
            log_level: "ERROR".into(),
        };
        let config: serde_json::Value = serde_json::from_str(&node_config(&cfg)).unwrap();
        assert_eq!(config["listenAddress"], "10.89.0.7");
        assert_eq!(config["nat"], "extip:10.89.0.7");
    }

    #[test]
    fn a_cluster_id_the_library_reads_as_a_preset_is_refused() {
        assert_eq!(ClusterId::try_from(1), Err(PresetClusterId(1)));
        assert_eq!(ClusterId::try_from(2), Err(PresetClusterId(2)));
        for id in [0, 3, 77, u16::MAX] {
            assert_eq!(ClusterId::try_from(id), Ok(ClusterId(id)));
        }
    }

    #[test]
    fn a_node_address_is_an_ipv4_address_a_port_and_a_peer_id() {
        let peer_id = RAYA.rsplit('/').next().unwrap();
        for address in [
            RAYA.to_string(),
            PAX.to_string(),
            "/ip4/127.0.0.1/tcp/65535/p2p/Qm".to_string(),
            format!("/ip4/127.0.0.2/tcp/4001/p2p/{peer_id}"),
            format!("/ip4/10.89.0.7/tcp/4001/p2p/{peer_id}"),
        ] {
            assert_eq!(address.parse(), Ok(NodeAddress(address.clone())));
        }
        for text in [
            String::new(),
            "notanaddress".to_string(),
            "/ip4/127.0.0.1/tcp/4001".to_string(),
            "/ip4/127.0.0.1/tcp/4001/p2p/".to_string(),
            format!("/ip4/127.0.0.1/tcp/4001/p2p/{peer_id}/"),
            format!("/ip4/127.0.0.1/tcp/4001/p2p/{peer_id}0"),
            format!("/ip4/127.0.0.1/tcp/0/p2p/{peer_id}"),
            format!("/ip4/127.0.0.1/tcp/65536/p2p/{peer_id}"),
            format!("/ip4/127.0.0.1/udp/4001/p2p/{peer_id}"),
            format!("/ip4/localhost/tcp/4001/p2p/{peer_id}"),
            format!("/ip4/127.0.0.01/tcp/4001/p2p/{peer_id}"),
            format!("/ip4/10.89.0.256/tcp/4001/p2p/{peer_id}"),
            format!("/ip4/10.89.0/tcp/4001/p2p/{peer_id}"),
            format!("/ip4/0.0.0.0/tcp/4001/p2p/{peer_id}"),
            format!("/ip6/::1/tcp/4001/p2p/{peer_id}"),
            format!("ip4/127.0.0.1/tcp/4001/p2p/{peer_id}"),
            format!(" {RAYA}"),
            "a\"b".to_string(),
            "]".to_string(),
        ] {
            assert_eq!(
                text.parse::<NodeAddress>(),
                Err(NotANodeAddress(text.clone())),
                "{text}"
            );
        }
    }

    #[test]
    fn a_node_of_a_local_network_is_asked_its_port_and_its_peer_id() {
        let state = NodeState::ask(recorded(&[]), &local_network(), &Losses::default()).unwrap();
        assert_eq!(
            state.address,
            "/ip4/127.0.0.1/tcp/34739/p2p/16Uiu2HAkwVXqMJzJLxhpLL2QtZrdU9theKgbjMcyBKCzxV1dyjUM"
        );
        assert_eq!((state.peers, state.mesh_peers), (Some(9), Some(8)));

        let own = Network::Local(LocalNetwork {
            address: Ipv4Addr::new(10, 89, 0, 7),
            ..local()
        });
        let state = NodeState::ask(recorded(&[]), &own, &Losses::default()).unwrap();
        assert_eq!(
            state.address,
            "/ip4/10.89.0.7/tcp/34739/p2p/16Uiu2HAkwVXqMJzJLxhpLL2QtZrdU9theKgbjMcyBKCzxV1dyjUM"
        );

        // What the node announces is not asked for.
        let unasked = recorded(&["MyMultiaddresses"]);
        assert!(NodeState::ask(unasked, &local_network(), &Losses::default()).is_ok());
        for needed in [&["MyBoundPorts"], &["MyPeerId"]] {
            let asked = NodeState::ask(recorded(needed), &local_network(), &Losses::default());
            assert!(
                matches!(asked, Err(DeliveryError::NodeInfoFailed(_))),
                "{needed:?}: {asked:?}"
            );
        }
    }

    #[test]
    fn a_node_of_a_preset_is_asked_the_address_it_announces() {
        let preset = Network::Preset("logos.test".into());
        let state = NodeState::ask(recorded(&[]), &preset, &Losses::default()).unwrap();
        assert_eq!(
            state.address,
            "/ip4/0.0.0.0/tcp/34739/p2p/16Uiu2HAkwVXqMJzJLxhpLL2QtZrdU9theKgbjMcyBKCzxV1dyjUM"
        );

        let unasked = recorded(&["MyBoundPorts", "MyPeerId"]);
        assert!(NodeState::ask(unasked, &preset, &Losses::default()).is_ok());
        let asked = NodeState::ask(recorded(&["MyMultiaddresses"]), &preset, &Losses::default());
        assert!(
            matches!(asked, Err(DeliveryError::NodeInfoFailed(_))),
            "{asked:?}"
        );
    }

    #[test]
    fn a_node_that_does_not_give_its_metrics_has_an_address_and_unknown_peers() {
        let mut state = None;
        let warning = rendered(|| {
            state = Some(NodeState::ask(
                recorded(&["Metrics"]),
                &local_network(),
                &Losses::default(),
            ));
        });
        assert_eq!(
            state.unwrap().unwrap(),
            NodeState {
                address:
                    "/ip4/127.0.0.1/tcp/34739/p2p/16Uiu2HAkwVXqMJzJLxhpLL2QtZrdU9theKgbjMcyBKCzxV1dyjUM"
                        .into(),
                peers: None,
                mesh_peers: None,
                dials_ok: None,
                dials_failed: None,
                publish_refused: 0,
                inbound_dropped: 0,
            }
        );
        assert_eq!(
            warning,
            "WARN logos_delivery::threaded: the node did not give its metrics error=\"no Metrics\""
        );
    }

    #[test]
    fn a_recorded_node_info_answer_reads_as_the_nodes_state() {
        let address = local_address(Ipv4Addr::LOCALHOST, BOUND_PORTS, PEER_ID).unwrap();
        assert_eq!(
            NodeState::new(address, METRICS, &Losses::default()),
            NodeState {
                address:
                    "/ip4/127.0.0.1/tcp/34739/p2p/16Uiu2HAkwVXqMJzJLxhpLL2QtZrdU9theKgbjMcyBKCzxV1dyjUM"
                        .into(),
                peers: Some(9),
                mesh_peers: Some(8),
                dials_ok: Some(5),
                dials_failed: Some(0),
                publish_refused: 0,
                inbound_dropped: 0,
            }
        );
    }

    #[test]
    fn a_dial_that_did_not_come_up_is_counted_as_failed() {
        let state = NodeState::new(String::new(), METRICS_OF_A_FAILED_DIAL, &Losses::default());
        assert_eq!(
            (state.peers, state.dials_ok, state.dials_failed),
            (Some(0), Some(0), Some(1))
        );
    }

    #[test]
    fn dials_the_metrics_do_not_count_are_unknown() {
        let metrics: String = METRICS
            .lines()
            .filter(|line| !line.contains("_dials"))
            .map(|line| format!("{line}\n"))
            .collect();
        let state = NodeState::new(String::new(), &metrics, &Losses::default());
        assert_eq!(
            (state.peers, state.dials_ok, state.dials_failed),
            (Some(9), None, None)
        );
    }

    #[test]
    fn the_announced_address_is_the_first_the_node_lists() {
        assert_eq!(
            announced_address(MULTIADDRESSES).unwrap(),
            "/ip4/0.0.0.0/tcp/34739/p2p/16Uiu2HAkwVXqMJzJLxhpLL2QtZrdU9theKgbjMcyBKCzxV1dyjUM"
        );
        assert_eq!(announced_address(&format!("{RAYA},{PAX}")).unwrap(), RAYA);
        assert!(announced_address("").is_err());
    }

    #[test]
    fn bound_ports_that_are_not_the_librarys_json_are_an_error() {
        assert!(local_address(Ipv4Addr::LOCALHOST, "tcp=4001", PEER_ID).is_err());
    }

    /// What a wait for a node's peers does when the node answers `links` for
    /// its links, the last of them from then on, and takes `asking` to answer:
    /// each sleep it takes, and how often it asks.
    fn connecting_slowly(
        network: &Network,
        links: &[Option<u64>],
        asking: Duration,
    ) -> (Vec<Duration>, usize) {
        let clock = Cell::new(Duration::ZERO);
        let sleeps = RefCell::new(Vec::new());
        let mut asked = 0;
        await_connected(
            network,
            || {
                asked += 1;
                clock.set(clock.get() + asking);
                links[(asked - 1).min(links.len() - 1)]
            },
            || clock.get(),
            |duration| {
                clock.set(clock.get() + duration);
                sleeps.borrow_mut().push(duration);
            },
        );
        (sleeps.into_inner(), asked)
    }

    /// [`connecting_slowly`], with a node that answers at once.
    fn connecting(network: &Network, links: &[Option<u64>]) -> (Vec<Duration>, usize) {
        connecting_slowly(network, links, Duration::ZERO)
    }

    fn dialing(static_nodes: &[&str]) -> Network {
        Network::Local(LocalNetwork {
            cluster_id: ClusterId::try_from(77).unwrap(),
            address: Ipv4Addr::LOCALHOST,
            static_nodes: static_nodes
                .iter()
                .map(|node| node.parse().unwrap())
                .collect(),
            max_message_kib: NonZeroU32::new(512).unwrap(),
        })
    }

    #[test]
    fn a_node_of_a_preset_is_ready_three_seconds_after_its_start() {
        let preset = Network::Preset("logos.test".into());

        assert_eq!(
            connecting(&preset, &[Some(40)]),
            (vec![Duration::from_secs(3)], 0)
        );
    }

    #[test]
    fn a_local_node_that_dials_nobody_is_ready_at_once() {
        let (sleeps, _) = connecting(&dialing(&[]), &[None]);

        assert_eq!(sleeps, []);
    }

    #[test]
    fn a_local_node_is_ready_once_it_holds_a_link_for_each_node_it_dials() {
        let links = [None, Some(0), Some(1), Some(2)];

        assert_eq!(
            connecting(&dialing(&[RAYA, PAX]), &links),
            (vec![DIAL_POLL; 3], 4)
        );
        assert_eq!(connecting(&dialing(&[RAYA, PAX]), &[Some(2)]), (vec![], 1));
        assert_eq!(connecting(&dialing(&[RAYA]), &[Some(4)]), (vec![], 1));
    }

    #[test]
    fn a_local_node_told_to_dial_one_node_twice_is_ready_once_it_holds_its_link() {
        assert_eq!(connecting(&dialing(&[RAYA, RAYA]), &[Some(1)]), (vec![], 1));
        assert_eq!(
            connecting(&dialing(&[RAYA, PAX, RAYA]), &[Some(1), Some(2)]),
            (vec![DIAL_POLL], 2)
        );
    }

    #[test]
    fn a_local_node_whose_dials_stay_down_is_ready_after_three_seconds() {
        for links in [Some(1), None] {
            let (sleeps, asked) = connecting(&dialing(&[RAYA, PAX]), &[links]);

            assert_eq!(sleeps.iter().sum::<Duration>(), Duration::from_secs(3));
            // It asks twenty times a second.
            assert_eq!(asked, 60);
        }
    }

    #[test]
    fn the_time_a_node_takes_to_answer_is_part_of_the_three_seconds() {
        let answer = Duration::from_millis(30);
        let (sleeps, asked) = connecting_slowly(&dialing(&[RAYA]), &[Some(0)], answer);

        let waited = sleeps.iter().sum::<Duration>() + answer * asked as u32;
        assert_eq!(waited, Duration::from_secs(3));
        // An answer that comes after the three seconds is the last one asked for.
        let answer = Duration::from_millis(1700);
        let (sleeps, asked) = connecting_slowly(&dialing(&[RAYA]), &[Some(0)], answer);

        assert_eq!(asked, 2);
        assert_eq!(sleeps.iter().sum::<Duration>(), DIAL_POLL);
    }

    #[test]
    fn a_gauge_the_metrics_do_not_hold_is_unknown() {
        assert_eq!(gauge("", PEERS_GAUGE), None);
        assert_eq!(gauge("libp2p_peers_seen 4.0\n", PEERS_GAUGE), None);
        assert_eq!(gauge("# TYPE libp2p_peers gauge\n", PEERS_GAUGE), None);
    }

    #[test]
    fn a_gauge_is_summed_over_its_label_sets() {
        let metrics = "libp2p_gossipsub_peers_per_topic_mesh{topic=\"a\"} 6.0\n\
                       libp2p_gossipsub_peers_per_topic_mesh{topic=\"b\"} 4.0\n";
        assert_eq!(gauge(metrics, MESH_PEERS_GAUGE), Some(10));
    }

    #[test]
    fn the_librarys_events_say_what_became_of_a_publish() {
        assert_eq!(
            event(MESSAGE_ERROR).publish_outcome(),
            Some((
                "d1a02e86c98a1b9fed64",
                PublishOutcome::Refused("Message size exceeded maximum of 1024 bytes".into())
            ))
        );
        assert_eq!(
            event(MESSAGE_PROPAGATED).publish_outcome(),
            Some(("2a7e6e651fb015c24722", PublishOutcome::Propagated))
        );
        assert_eq!(event(MESSAGE_RECEIVED).publish_outcome(), None);
    }

    #[test]
    fn a_received_message_knows_the_bytes_of_its_payload() {
        assert_eq!(event(MESSAGE_RECEIVED).payload_len(), 10);
        assert_eq!(event(MESSAGE_ERROR).payload_len(), 0);
        for bytes in 0..7 {
            let payload = WakuPayload::Base64(BASE64.encode(vec![0u8; bytes]));
            assert_eq!(payload.len(), bytes);
        }
    }

    #[test]
    fn a_refusal_reported_after_the_request_id_is_counted() {
        let losses = Losses::default();
        losses.publish_begins();
        assert!(losses.publish_answered(Ok("a".into()), 5000).is_ok());
        assert_eq!(refused(&losses), 0);

        let warning = rendered(|| {
            losses.publish_settled("a", PublishOutcome::Refused("too large".into()));
        });
        assert_eq!(refused(&losses), 1);
        assert!(losses.publishes().open.is_empty());
        assert_eq!(
            warning,
            "WARN logos_delivery::threaded: the node refused a publish bytes=5000 reason=\"too large\""
        );
    }

    /// The order the library keeps for a publish over its size limit. The
    /// call that handed it over is answered as taken all the same.
    #[test]
    fn a_refusal_reported_before_the_request_id_is_counted() {
        let losses = Losses::default();
        losses.publish_begins();
        losses.publish_settled("a", PublishOutcome::Refused("too large".into()));
        assert_eq!(refused(&losses), 0);

        let mut answered = None;
        let warning = rendered(|| answered = Some(losses.publish_answered(Ok("a".into()), 5000)));
        assert!(answered.unwrap().is_ok());
        assert_eq!(refused(&losses), 1);
        assert!(losses.publishes().open.is_empty());
        assert_eq!(
            warning,
            "WARN logos_delivery::threaded: the node refused a publish bytes=5000 reason=\"too large\""
        );
    }

    #[test]
    fn a_publish_the_node_does_not_take_is_an_error_and_counted() {
        let losses = Losses::default();
        losses.publish_begins();

        let mut answered = None;
        let warning = rendered(|| {
            answered = Some(losses.publish_answered(Err("Send failed: no node".into()), 5000));
        });
        assert!(
            matches!(answered, Some(Err(DeliveryError::PublishFailed(ref why))) if why == "Send failed: no node"),
            "{answered:?}"
        );
        assert_eq!(refused(&losses), 1);
        assert_eq!(losses.publishes().early, None);
        assert!(losses.publishes().open.is_empty());
        assert_eq!(
            warning,
            "WARN logos_delivery::threaded: the node refused a publish bytes=5000 reason=\"Send failed: no node\""
        );
    }

    #[test]
    fn a_propagated_publish_is_not_a_refusal_and_stays_none() {
        let losses = Losses::default();
        losses.publish_begins();
        assert!(losses.publish_answered(Ok("a".into()), 5000).is_ok());
        losses.publish_settled("a", PublishOutcome::Propagated);
        losses.publish_settled("a", PublishOutcome::Refused("not stored".into()));

        losses.publish_begins();
        losses.publish_settled("b", PublishOutcome::Propagated);
        assert!(losses.publish_answered(Ok("b".into()), 5000).is_ok());

        assert_eq!(refused(&losses), 0);
        assert!(losses.publishes().open.is_empty());
    }

    #[test]
    fn an_outcome_for_no_open_publish_is_not_kept() {
        let losses = Losses::default();
        losses.publish_settled("a", PublishOutcome::Refused("too large".into()));
        assert_eq!(losses.publishes().early, None);

        losses.publish_begins();
        losses.publish_settled("a", PublishOutcome::Refused("too large".into()));
        assert!(losses.publish_answered(Ok("b".into()), 5000).is_ok());
        assert_eq!(refused(&losses), 0);
        assert_eq!(losses.publishes().early, None);
        assert_eq!(losses.publishes().open.len(), 1);
    }

    #[test]
    fn a_publish_is_handed_to_the_node_with_the_bytes_of_its_payload() {
        let (outbound, node) = mpsc::sync_channel(1);
        let wrapper = ThreadedDeliveryWrapper::<Vec<u8>> {
            outbound,
            subscribers: Arc::new(Mutex::new(Vec::new())),
            inbound_rx: None,
        };
        let node = thread::spawn(move || {
            let command: NodeCmd = node.recv().unwrap();
            command.reply.send(Ok(())).unwrap();
            command.op
        });

        wrapper
            .publish("/logos-chat/1/x/proto", &[7u8; 1000])
            .unwrap();
        let NodeOp::Publish(message, bytes) = node.join().unwrap() else {
            panic!("not a publish");
        };
        assert_eq!(bytes, 1000);
        let message: WakuMessage = serde_json::from_str(&message).unwrap();
        assert_eq!(message.content_topic, "/logos-chat/1/x/proto");
        assert_eq!(BASE64.decode(message.payload).unwrap(), [7u8; 1000]);
    }

    #[test]
    fn an_event_that_settles_a_publish_reaches_the_count() {
        let losses = Losses::default();
        let subscribers: SubscriberList<Vec<u8>> = Arc::default();
        let mut map = |event: WakuEvent| event.into_received()?.into_payload();
        losses.publish_begins();
        assert!(
            losses
                .publish_answered(Ok("d1a02e86c98a1b9fed64".into()), 2000)
                .is_ok()
        );

        on_event(MESSAGE_ERROR, &mut map, &subscribers, &losses);
        assert_eq!(refused(&losses), 1);

        on_event("not the library's JSON", &mut map, &subscribers, &losses);
        assert_eq!(refused(&losses), 1);
    }

    #[test]
    fn a_received_message_goes_to_the_queue_with_what_the_map_keeps_of_it() {
        let losses = Losses::default();
        let (tx, rx) = crossbeam_channel::bounded(1);
        let subscribers: SubscriberList<Vec<u8>> = Arc::new(Mutex::new(vec![tx]));
        let mut map = |event: WakuEvent| event.into_received()?.into_payload();

        on_event(MESSAGE_PROPAGATED, &mut map, &subscribers, &losses);
        assert!(rx.try_recv().is_err());

        on_event(MESSAGE_RECEIVED, &mut map, &subscribers, &losses);
        assert_eq!(rx.try_recv(), Ok(vec![b'x'; 10]));
        assert_eq!(losses.inbound_dropped.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn a_frame_the_full_inbound_queue_drops_is_counted() {
        let losses = Losses::default();
        let (tx, rx) = crossbeam_channel::bounded(1);
        let mut subscribers = vec![tx];

        deliver(&mut subscribers, &vec![1u8], 1, &losses);
        assert_eq!(losses.inbound_dropped.load(Ordering::Relaxed), 0);

        deliver(&mut subscribers, &vec![2u8, 2], 2, &losses);
        assert_eq!(losses.inbound_dropped.load(Ordering::Relaxed), 1);
        assert_eq!(subscribers.len(), 1);
        assert_eq!(rx.try_recv(), Ok(vec![1u8]));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn a_received_message_the_full_queue_drops_is_logged_with_the_bytes_of_its_payload() {
        let losses = Losses::default();
        let (tx, rx) = crossbeam_channel::bounded(1);
        tx.send(vec![1u8]).unwrap();
        let subscribers: SubscriberList<Vec<u8>> = Arc::new(Mutex::new(vec![tx]));
        let mut map = |event: WakuEvent| event.into_received()?.into_payload();

        let warning = rendered(|| on_event(MESSAGE_RECEIVED, &mut map, &subscribers, &losses));
        assert_eq!(losses.inbound_dropped.load(Ordering::Relaxed), 1);
        assert_eq!(rx.try_recv(), Ok(vec![1u8]));
        assert_eq!(
            warning,
            "WARN logos_delivery::threaded: dropped a received frame bytes=10 reason=\"the inbound queue is full\""
        );
    }

    #[test]
    fn a_subscriber_that_went_away_is_dropped_without_a_count() {
        let losses = Losses::default();
        let (tx, rx) = crossbeam_channel::bounded(1);
        drop(rx);
        let mut subscribers = vec![tx];

        deliver(&mut subscribers, &vec![1u8], 1, &losses);
        assert!(subscribers.is_empty());
        assert_eq!(losses.inbound_dropped.load(Ordering::Relaxed), 0);
    }
}
