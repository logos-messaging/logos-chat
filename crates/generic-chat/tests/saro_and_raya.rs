//! Direct conversations through the client: wiring, address resolution, and
//! how core outcomes surface as events. Protocol behaviour is tested in
//! `integration_tests_core`.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use components::EphemeralRegistry;
use crossbeam_channel::{Receiver, Sender};
use integration_tests_core::AcceptAllAuth;
use libchat::ChatError;
use logos_account::AccountAddr;
use logos_generic_chat::{
    AddressedEnvelope, ChatClient, ChatClientBuilder, ClientError, DeliveryMsgId, DeliveryService,
    Event, InProcessDelivery, InboundPayload, Installation, MessageBus, PendingInstallation,
    PublishedId, Transport,
};

const TIMEOUT: Duration = Duration::from_secs(10);

type TestClient =
    ChatClient<InProcessDelivery, EphemeralRegistry, AcceptAllAuth, chat_sqlite::SqliteStore>;

/// A client for `installation` on the shared bus and registry.
fn build_client(
    installation: Installation,
    bus: &MessageBus,
    reg: &EphemeralRegistry,
    auth: &AcceptAllAuth,
) -> (TestClient, Receiver<Event>) {
    auth.register(&installation);
    ChatClientBuilder::new(installation)
        .transport(InProcessDelivery::new(bus.clone()))
        .registration(reg.clone())
        .auth(auth.clone())
        .build()
        .expect("client create")
}

/// A client for a fresh account.
fn create_test_client(
    bus: &MessageBus,
    reg: &EphemeralRegistry,
    auth: &AcceptAllAuth,
) -> (TestClient, Receiver<Event>) {
    let installation = PendingInstallation::generate().complete(TestLogosAccount::new().addr());
    build_client(installation, bus, reg, auth)
}

/// Wait for an event `f` picks out, skipping every other event; panic on timeout.
fn wait_for<T>(events: &Receiver<Event>, label: &str, mut f: impl FnMut(Event) -> Option<T>) -> T {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let event = events
            .recv_timeout(remaining)
            .unwrap_or_else(|_| panic!("timed out waiting for {label}"));
        if let Some(out) = f(event) {
            return out;
        }
    }
}

/// Poll `done` until it holds; panic on timeout.
fn wait_until(label: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + TIMEOUT;
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {label}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Saro opens a DM by Raya's account address and they exchange a message each
/// way. Each side sees the other's verified account, and the receiver gets the
/// id the sender's `send_message` returned.
#[test]
fn a_direct_conversation_carries_messages_both_ways() {
    let bus = MessageBus::default();
    let reg = EphemeralRegistry::new();
    let auth = AcceptAllAuth::default();

    let saro_account = TestLogosAccount::new();
    let saro_pending = PendingInstallation::generate();
    let saro_signer = saro_pending.endorsement_request();
    let (mut saro, saro_events) = build_client(
        saro_pending.complete(saro_account.addr()),
        &bus,
        &reg,
        &auth,
    );
    let (mut raya, raya_events) = create_test_client(&bus, &reg, &auth);

    let saro_convo_id = saro
        .create_direct_conversation(raya.addr())
        .expect("convo create");

    // MessageBus only fans out to current subscribers, so Raya must join before
    // Saro sends.
    let raya_convo_id = wait_for(&raya_events, "ConversationStarted", |e| match e {
        Event::ConversationStarted { convo_id, .. } => Some(convo_id),
        _ => None,
    });

    let sent_id = saro.send_message(&saro_convo_id, b"hello raya").unwrap();
    let (sender, message_id) = wait_for(&raya_events, "hello raya", |e| match e {
        Event::MessageReceived {
            content,
            sender,
            message_id,
            ..
        } if content == b"hello raya" => Some((sender, message_id)),
        _ => None,
    });
    assert_eq!(message_id, sent_id);
    assert_eq!(sender.account().to_string(), saro_account.address());
    assert_eq!(sender.signer().as_bytes(), saro_signer);

    raya.send_message(&raya_convo_id, b"hi saro").unwrap();
    let sender = wait_for(&saro_events, "hi saro", |e| match e {
        Event::MessageReceived {
            content, sender, ..
        } if content == b"hi saro" => Some(sender),
        _ => None,
    });
    assert_eq!(sender.account().to_string(), raya.addr());
}

/// The participants of a DM are its two accounts, not their installations.
#[test]
fn a_direct_conversation_lists_both_accounts() {
    let bus = MessageBus::default();
    let reg = EphemeralRegistry::new();
    let auth = AcceptAllAuth::default();

    let (mut saro, _saro_events) = create_test_client(&bus, &reg, &auth);
    let (raya, _raya_events) = create_test_client(&bus, &reg, &auth);

    let convo_id = saro
        .create_direct_conversation(raya.addr())
        .expect("convo create");

    let expected: HashSet<AccountAddr> = [saro.addr(), raya.addr()]
        .into_iter()
        .map(|addr| {
            addr.parse()
                .expect("a client address is an account address")
        })
        .collect();
    wait_until("both accounts", || {
        saro.participants(&convo_id).expect("participants") == expected
    });
}

#[test]
fn membership_changes_are_unsupported_on_a_direct_conversation() {
    let bus = MessageBus::default();
    let reg = EphemeralRegistry::new();
    let auth = AcceptAllAuth::default();

    let (mut saro, _saro_events) = create_test_client(&bus, &reg, &auth);
    let (raya, _raya_events) = create_test_client(&bus, &reg, &auth);

    let convo_id = saro
        .create_direct_conversation(raya.addr())
        .expect("convo create");

    let added = saro.add_group_participants(&convo_id, &[raya.addr()]);
    let removed = saro.remove_group_participants(&convo_id, &[raya.addr()]);
    for result in [added, removed] {
        assert!(matches!(
            result,
            Err(ClientError::Chat(ChatError::UnsupportedFunction(..)))
        ));
    }
}

/// Opening a conversation by an address the auth service cannot resolve to
/// any installation fails at resolution, not with a late key-package miss.
#[test]
fn unpublished_account_address_is_an_error() {
    let bus = MessageBus::default();
    let reg = EphemeralRegistry::new();
    let auth = AcceptAllAuth::default();

    let (mut saro, _saro_events) = create_test_client(&bus, &reg, &auth);

    let unpublished = TestLogosAccount::new();
    let err = saro
        .create_direct_conversation(&unpublished.address())
        .expect_err("the account is unknown");
    assert!(matches!(
        err,
        ClientError::Chat(ChatError::ParticipantResolution(_))
    ));

    let err = saro
        .create_direct_conversation("not-an-account-address")
        .expect_err("not an account key");
    assert!(matches!(err, ClientError::InvalidAccountAddress(_)));
}

#[derive(Debug)]
struct FailingDelivery {
    inbound_tx: Sender<InboundPayload>,
    inbound_rx: Option<Receiver<InboundPayload>>,
}

impl FailingDelivery {
    fn new() -> Self {
        let (inbound_tx, inbound_rx) = crossbeam_channel::unbounded();
        Self {
            inbound_tx,
            inbound_rx: Some(inbound_rx),
        }
    }

    /// A sender into this transport's inbound stream — for tests to feed the
    /// worker, or to hold open so it doesn't see a disconnect.
    fn inbound_sender(&self) -> Sender<InboundPayload> {
        self.inbound_tx.clone()
    }
}

impl DeliveryService for FailingDelivery {
    type Error = &'static str;

    fn publish(&mut self, _: AddressedEnvelope) -> Result<PublishedId, Self::Error> {
        Err("simulated transport failure")
    }

    fn subscribe(&mut self, _: &str) -> Result<(), Self::Error> {
        Ok(())
    }

    fn fetch_messages(&mut self, _: &str, _: &[DeliveryMsgId]) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl Transport for FailingDelivery {
    fn inbound(&mut self) -> Receiver<InboundPayload> {
        self.inbound_rx
            .take()
            .expect("FailingDelivery::inbound called more than once")
    }
}

#[test]
fn dropping_client_shuts_down_worker() {
    let (client, events) = create_test_client(
        &MessageBus::default(),
        &EphemeralRegistry::new(),
        &AcceptAllAuth::default(),
    );

    drop(client);
    // Drop joins the worker; once joined its Sender<Event> is gone, so recv
    // reports the channel as disconnected.
    let res = events.recv_timeout(Duration::from_secs(5));
    assert!(matches!(
        res,
        Err(crossbeam_channel::RecvTimeoutError::Disconnected)
    ));
}

/// Undecodable inbound bytes surface as an `InboundError` rather than being
/// dropped silently.
#[test]
fn malformed_inbound_surfaces_as_error_event() {
    let delivery = FailingDelivery::new();
    let inbound_tx = delivery.inbound_sender();

    let (_client, events) = ChatClientBuilder::new(
        PendingInstallation::generate().complete(TestLogosAccount::new().addr()),
    )
    .transport(delivery)
    .auth(AcceptAllAuth::default())
    .build()
    .expect("client create");

    inbound_tx
        .send(InboundPayload {
            data: b"not a valid payload".to_vec(),
            delivery_info: None,
        })
        .unwrap();

    let message = wait_for(&events, "InboundError", |e| match e {
        Event::InboundError { message } => Some(message),
        _ => None,
    });
    assert!(!message.is_empty(), "error event should carry a message");
}

/// A stand-in account while the account layer is out: only a well-formed
/// address.
struct TestLogosAccount(crypto::Ed25519SigningKey);

impl TestLogosAccount {
    fn new() -> Self {
        Self(crypto::Ed25519SigningKey::generate())
    }

    fn address(&self) -> String {
        hex::encode(self.0.verifying_key().as_ref())
    }

    /// This account's address.
    fn addr(&self) -> AccountAddr {
        AccountAddr::try_from(self.0.verifying_key().as_ref())
            .expect("a generated key is an address")
    }
}
