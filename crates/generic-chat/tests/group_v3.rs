//! GroupV3, the group `create_group_conversation` makes, through the threaded
//! client: accounts on the in-process transport, driven over the public
//! `ChatClient` API and its event channel. A member applies a commit when it
//! finalizes it on a wakeup tick, so assertions wait for events and rosters.

use std::convert::Infallible;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chat_sqlite::SqliteStore;
use components::EphemeralRegistry;
use crossbeam_channel::{Receiver, Sender};
use integration_tests_core::AcceptAllAuth;
use libchat::ChatError;
use logos_account::AccountAddr;
use logos_generic_chat::{
    AddressedEnvelope, ChatClient, ChatClientBuilder, ClientError, ConversationClass, DeliveryInfo,
    DeliveryMsgId, DeliveryReport, DeliveryService, Event, GroupMetadata, GroupV3Config,
    InProcessDelivery, InboundPayload, MessageBus, PendingInstallation, Transport,
};

/// A finalize delay under GroupV3's one-second tick, so a commit lands on the
/// next tick instead of after the 30 s default.
fn fast_group_v3_config() -> GroupV3Config {
    GroupV3Config {
        commit_finalize_delay: Duration::from_millis(100),
    }
}

type TestClient<T = InProcessDelivery> =
    ChatClient<T, EphemeralRegistry, AcceptAllAuth, SqliteStore>;

/// A client for a fresh account: mints the account and an installation, publishes
/// the endorsing bundle, and builds the client on the shared bus/registry with
/// the fast GroupV3 timing. Returns the account address peers invite by.
fn create_test_client(
    message_bus: MessageBus,
    reg: EphemeralRegistry,
    auth: &AcceptAllAuth,
) -> (TestClient, Receiver<Event>, String) {
    create_test_client_on(InProcessDelivery::new(message_bus), reg, auth)
}

/// [`create_test_client`] on `transport`.
fn create_test_client_on<T: Transport>(
    transport: T,
    reg: EphemeralRegistry,
    auth: &AcceptAllAuth,
) -> (TestClient<T>, Receiver<Event>, String) {
    let installation = PendingInstallation::generate().complete(TestLogosAccount::new().addr());
    auth.register(&installation);
    let (client, events) = ChatClientBuilder::new(installation)
        .transport(transport)
        .registration(reg)
        .auth(auth.clone())
        .group_v3_config(fast_group_v3_config())
        .build()
        .expect("client create");
    let addr = client.addr().to_string();
    (client, events, addr)
}

/// Wait until an event matching `f` arrives, skipping unrelated events; panic
/// after `timeout`.
fn wait_for_event<F, T>(events: &Receiver<Event>, label: &str, timeout: Duration, mut f: F) -> T
where
    F: FnMut(&Event) -> Option<T>,
{
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let remaining = deadline
            .checked_duration_since(std::time::Instant::now())
            .unwrap_or_else(|| panic!("timed out waiting for {label}"));
        match events.recv_timeout(remaining) {
            Ok(event) => {
                if let Some(out) = f(&event) {
                    return out;
                }
            }
            Err(_) => panic!("timed out waiting for {label}"),
        }
    }
}

/// Wait for the group conversation to start on a joiner and return its id.
fn wait_for_group_started(events: &Receiver<Event>, label: &str) -> String {
    wait_for_event(events, label, Duration::from_secs(10), |e| match e {
        Event::ConversationStarted { convo_id, class } => {
            assert_eq!(*class, ConversationClass::Group);
            Some(convo_id.to_string())
        }
        _ => None,
    })
}

/// Poll a client's roster for `convo_id` until its committed accounts equal
/// `expected` (order-independent), or panic after a timeout. Each member
/// applies an add when it finalizes the commit, so the roster is polled.
fn wait_for_participants<T: Transport>(
    client: &mut TestClient<T>,
    convo_id: &str,
    expected: &[&str],
) {
    use std::collections::BTreeSet;

    let want: BTreeSet<String> = expected.iter().map(|a| a.to_string()).collect();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let participants = client.participants(convo_id).expect("participants");
        let got: BTreeSet<String> = participants.iter().map(AccountAddr::to_string).collect();
        if got == want {
            return;
        }
        if std::time::Instant::now() >= deadline {
            panic!("roster did not converge for {convo_id}: got {got:?}, want {want:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Wait for `content` to arrive and return the sender's verified account.
fn wait_for_message(events: &Receiver<Event>, content: &[u8]) -> String {
    let label = format!("MessageReceived({})", String::from_utf8_lossy(content));
    wait_for_event(events, &label, Duration::from_secs(10), |e| match e {
        Event::MessageReceived {
            content: got,
            sender,
            ..
        } if got == content => Some(sender.account().to_string()),
        _ => None,
    })
}

/// Saro creates a group with Raya and they exchange messages; Raya, a
/// non-creator, then adds Pax, and a message from each reaches the other two.
#[test]
fn a_group_carries_messages_and_grows() {
    let bus = MessageBus::default();
    let reg = EphemeralRegistry::new();
    let auth = AcceptAllAuth::default();

    let (mut saro, saro_events, saro_addr) = create_test_client(bus.clone(), reg.clone(), &auth);
    let (mut raya, raya_events, raya_addr) = create_test_client(bus.clone(), reg.clone(), &auth);
    let (mut pax, pax_events, pax_addr) = create_test_client(bus.clone(), reg.clone(), &auth);

    let convo_id = saro
        .create_group_conversation(&[&raya_addr], GroupMetadata::new("", ""))
        .expect("saro create group");

    // The invite goes out once saro finalizes the add.
    assert_eq!(
        wait_for_group_started(&raya_events, "raya ConversationStarted"),
        convo_id
    );
    wait_for_participants(&mut saro, &convo_id, &[&saro_addr, &raya_addr]);

    saro.send_message(&convo_id, b"hello raya").unwrap();
    assert_eq!(wait_for_message(&raya_events, b"hello raya"), saro_addr);

    raya.send_message(&convo_id, b"hi saro").unwrap();
    assert_eq!(wait_for_message(&saro_events, b"hi saro"), raya_addr);

    // A message sent before its sender applies the add would not reach Pax,
    // so every roster settles first.
    raya.add_group_participants(&convo_id, &[&pax_addr])
        .expect("raya add pax");
    assert_eq!(
        wait_for_group_started(&pax_events, "pax ConversationStarted"),
        convo_id
    );
    let all = [saro_addr.as_str(), raya_addr.as_str(), pax_addr.as_str()];
    wait_for_participants(&mut saro, &convo_id, &all);
    wait_for_participants(&mut raya, &convo_id, &all);
    wait_for_participants(&mut pax, &convo_id, &all);

    saro.send_message(&convo_id, b"all three?").unwrap();
    assert_eq!(wait_for_message(&raya_events, b"all three?"), saro_addr);
    assert_eq!(wait_for_message(&pax_events, b"all three?"), saro_addr);

    pax.send_message(&convo_id, b"pax is in").unwrap();
    assert_eq!(wait_for_message(&saro_events, b"pax is in"), pax_addr);
    assert_eq!(wait_for_message(&raya_events, b"pax is in"), pax_addr);
}

/// GroupV3 cannot remove a member yet: the call returns an error, and the
/// group keeps working.
#[test]
fn removing_a_member_is_unsupported() {
    let bus = MessageBus::default();
    let reg = EphemeralRegistry::new();
    let auth = AcceptAllAuth::default();

    let (mut saro, _saro_events, saro_addr) = create_test_client(bus.clone(), reg.clone(), &auth);
    let (_raya, raya_events, raya_addr) = create_test_client(bus.clone(), reg.clone(), &auth);

    let convo_id = saro
        .create_group_conversation(&[&raya_addr], GroupMetadata::new("", ""))
        .expect("saro create group");
    wait_for_group_started(&raya_events, "raya ConversationStarted");
    wait_for_participants(&mut saro, &convo_id, &[&saro_addr, &raya_addr]);

    let err = saro
        .remove_group_participants(&convo_id, &[&raya_addr])
        .expect_err("GroupV3 cannot remove members");
    assert!(
        matches!(err, ClientError::Chat(ChatError::UnsupportedFunction(..))),
        "{err:?}"
    );

    wait_for_participants(&mut saro, &convo_id, &[&saro_addr, &raya_addr]);
    saro.send_message(&convo_id, b"still here").unwrap();
    wait_for_message(&raya_events, b"still here");
}

/// Saro's transport learns each id after `publish` returns, as a delivery node does, and
/// Raya loses m1 on the way. Saro's later m2 names m1 by the id the transport reported, so
/// Raya fetches m1 by it.
#[test]
fn a_lost_message_arrives_by_the_id_its_sender_learned_after_the_send() {
    let bus = MessageBus::default();
    let reg = EphemeralRegistry::new();
    let auth = AcceptAllAuth::default();

    let saro_transport = LateIdDelivery::new(InProcessDelivery::new(bus.clone()));
    let saro_reports = saro_transport.reports_tx.clone();
    let saro_published = saro_transport.published.clone();
    let (mut saro, saro_events, saro_addr) =
        create_test_client_on(saro_transport, reg.clone(), &auth);
    let raya_transport = LossyDelivery::new(InProcessDelivery::new(bus.clone()));
    let (raya_offline, raya_dropped) = (
        raya_transport.offline.clone(),
        raya_transport.dropped.clone(),
    );
    let (mut raya, raya_events, raya_addr) =
        create_test_client_on(raya_transport, reg.clone(), &auth);

    let convo_id = saro
        .create_group_conversation(&[&raya_addr], GroupMetadata::new("", ""))
        .expect("saro create group");
    wait_for_group_started(&raya_events, "raya ConversationStarted");
    wait_for_participants(&mut saro, &convo_id, &[&saro_addr, &raya_addr]);

    raya_offline.store(true, Ordering::SeqCst);
    saro.send_message(&convo_id, b"m1").unwrap();
    let m1 = saro_published
        .lock()
        .unwrap()
        .last()
        .cloned()
        .expect("m1 published");
    wait_until("raya drops m1", || {
        raya_dropped.lock().unwrap().contains(&m1)
    });
    raya_offline.store(false, Ordering::SeqCst);

    // Saro's worker took m1's report once the stream is empty, and has handled it once a
    // payload that arrives later reaches Saro.
    wait_until("saro takes the report", || saro_reports.is_empty());
    raya.send_message(&convo_id, b"r1").unwrap();
    assert_eq!(wait_for_message(&saro_events, b"r1"), raya_addr);

    saro.send_message(&convo_id, b"m2").unwrap();
    assert_eq!(wait_for_message(&raya_events, b"m1"), saro_addr);
    assert_eq!(wait_for_message(&raya_events, b"m2"), saro_addr);
}

/// Poll `done` until it holds, or panic after a timeout.
fn wait_until(label: &str, done: impl Fn() -> bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !done() {
        if std::time::Instant::now() >= deadline {
            panic!("timed out waiting until {label}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// [`InProcessDelivery`] as a delivery node behaves: `publish` returns no id, and a tagged
/// envelope's id follows on the report stream. Keeps those ids in the order published.
#[derive(Debug)]
struct LateIdDelivery {
    inner: InProcessDelivery,
    reports_tx: Sender<DeliveryReport>,
    reports_rx: Option<Receiver<DeliveryReport>>,
    published: Arc<Mutex<Vec<DeliveryMsgId>>>,
}

impl LateIdDelivery {
    fn new(inner: InProcessDelivery) -> Self {
        let (reports_tx, reports_rx) = crossbeam_channel::unbounded();
        Self {
            inner,
            reports_tx,
            reports_rx: Some(reports_rx),
            published: Arc::default(),
        }
    }
}

impl DeliveryService for LateIdDelivery {
    type Error = Infallible;

    fn publish(
        &mut self,
        envelope: AddressedEnvelope,
    ) -> Result<Option<DeliveryMsgId>, Infallible> {
        let tag = envelope.tag.clone();
        let delivery_msg_id = self
            .inner
            .publish(envelope)?
            .expect("the bus names every message");
        if let Some(tag) = tag {
            self.published.lock().unwrap().push(delivery_msg_id.clone());
            let delivery_info = DeliveryInfo { delivery_msg_id };
            self.reports_tx
                .send(DeliveryReport { tag, delivery_info })
                .expect("the stream outlives the transport");
        }
        Ok(None)
    }

    fn subscribe(&mut self, delivery_address: &str) -> Result<(), Infallible> {
        self.inner.subscribe(delivery_address)
    }

    fn fetch_messages(
        &mut self,
        delivery_address: &str,
        delivery_msg_ids: &[DeliveryMsgId],
    ) -> Result<(), Infallible> {
        self.inner
            .fetch_messages(delivery_address, delivery_msg_ids)
    }
}

impl Transport for LateIdDelivery {
    fn inbound(&mut self) -> Receiver<InboundPayload> {
        self.inner.inbound()
    }

    fn delivery_reports(&mut self) -> Receiver<DeliveryReport> {
        self.reports_rx
            .take()
            .expect("LateIdDelivery::delivery_reports called more than once")
    }
}

/// [`InProcessDelivery`] that drops inbound payloads while `offline` is set, keeping the id of
/// each; the bus still holds them, so a fetch by that id delivers them.
#[derive(Debug)]
struct LossyDelivery {
    inner: InProcessDelivery,
    offline: Arc<AtomicBool>,
    dropped: Arc<Mutex<Vec<DeliveryMsgId>>>,
}

impl LossyDelivery {
    fn new(inner: InProcessDelivery) -> Self {
        Self {
            inner,
            offline: Arc::default(),
            dropped: Arc::default(),
        }
    }
}

impl DeliveryService for LossyDelivery {
    type Error = Infallible;

    fn publish(
        &mut self,
        envelope: AddressedEnvelope,
    ) -> Result<Option<DeliveryMsgId>, Infallible> {
        self.inner.publish(envelope)
    }

    fn subscribe(&mut self, delivery_address: &str) -> Result<(), Infallible> {
        self.inner.subscribe(delivery_address)
    }

    fn fetch_messages(
        &mut self,
        delivery_address: &str,
        delivery_msg_ids: &[DeliveryMsgId],
    ) -> Result<(), Infallible> {
        self.inner
            .fetch_messages(delivery_address, delivery_msg_ids)
    }
}

impl Transport for LossyDelivery {
    fn inbound(&mut self) -> Receiver<InboundPayload> {
        let upstream = self.inner.inbound();
        let (tx, rx) = crossbeam_channel::unbounded();
        let (offline, dropped) = (self.offline.clone(), self.dropped.clone());
        std::thread::spawn(move || {
            for payload in upstream {
                if !offline.load(Ordering::SeqCst) {
                    if tx.send(payload).is_err() {
                        return;
                    }
                } else if let Some(info) = payload.delivery_info {
                    dropped.lock().unwrap().push(info.delivery_msg_id);
                }
            }
        });
        rx
    }
}

/// A stand-in account while the account layer is out: only a well-formed
/// address.
struct TestLogosAccount(crypto::Ed25519SigningKey);

impl TestLogosAccount {
    fn new() -> Self {
        Self(crypto::Ed25519SigningKey::generate())
    }

    /// This account's address.
    fn addr(&self) -> AccountAddr {
        AccountAddr::try_from(self.0.verifying_key().as_ref())
            .expect("a generated key is an address")
    }
}
