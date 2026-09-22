// `expect_event` hands a non-matching event back through `Err`, and an `Event`
// carrying an `AccountAddr` is 272 bytes — enough to trip `result_large_err`,
// which is about error paths, not this match-or-return one.
#![allow(clippy::result_large_err)]

use std::time::Duration;

use components::EphemeralRegistry;
use crossbeam_channel::{Receiver, Sender};
use integration_tests_core::AcceptAllAuth;
use libchat::ChatError;
use logos_account::AccountAddr;
use logos_generic_chat::{
    AddressedEnvelope, ChatClient, ChatClientBuilder, ConversationClass, DeliveryService, Event,
    InProcessDelivery, MessageBus, PendingInstallation, Transport,
};

/// A client for a fresh account: mints the account and an installation, then builds
/// the client on the shared bus/registry.
#[allow(clippy::type_complexity)]
fn create_test_client(
    message_bus: MessageBus,
    reg: EphemeralRegistry,
    auth: &AcceptAllAuth,
) -> Result<
    (
        ChatClient<InProcessDelivery, EphemeralRegistry, AcceptAllAuth, chat_sqlite::SqliteStore>,
        Receiver<Event>,
    ),
    logos_generic_chat::ClientError,
> {
    let installation = PendingInstallation::generate().complete(TestLogosAccount::new().addr());
    auth.register(&installation);
    ChatClientBuilder::new(installation)
        .transport(InProcessDelivery::new(message_bus))
        .registration(reg)
        .auth(auth.clone())
        .build()
}

/// Block until the next event arrives and matches; panic on timeout/mismatch.
fn expect_event<F, T>(events: &Receiver<Event>, label: &str, mut f: F) -> T
where
    F: FnMut(Event) -> Result<T, Event>,
{
    let event = events
        .recv_timeout(Duration::from_secs(5))
        .unwrap_or_else(|_| panic!("timed out waiting for {label}"));
    f(event).unwrap_or_else(|other| panic!("expected {label}, got {other:?}"))
}

/// [`expect_event`] for a back-and-forth exchange, skipping acknowledgements.
///
/// Each reply acknowledges the message it was sent after, so `MessageAcked`
/// lands at points a test driving one direction at a time does not control.
fn expect_event_ignoring_acks<F, T>(events: &Receiver<Event>, label: &str, mut f: F) -> T
where
    F: FnMut(Event) -> Result<T, Event>,
{
    loop {
        let event = events
            .recv_timeout(Duration::from_secs(5))
            .unwrap_or_else(|_| panic!("timed out waiting for {label}"));
        if matches!(event, Event::MessageAcked { .. }) {
            continue;
        }
        return f(event).unwrap_or_else(|other| panic!("expected {label}, got {other:?}"));
    }
}

#[test]
fn direct_v1_integration() {
    let bus = MessageBus::default();
    let reg_service = EphemeralRegistry::new();
    let auth = AcceptAllAuth::default();

    let (mut saro, _saro_events) =
        create_test_client(bus.clone(), reg_service.clone(), &auth).expect("client create");
    let (raya, raya_events) =
        create_test_client(bus.clone(), reg_service.clone(), &auth).expect("client create");

    let convo_id = saro.create_direct_conversation(raya.addr()).unwrap();

    // The invite payload yields ConversationStarted then MessageReceived.
    expect_event(&raya_events, "ConversationStarted", |e| match e {
        Event::ConversationStarted { convo_id, .. } => Ok(convo_id),
        other => Err(other),
    });

    saro.send_message(&convo_id, b"Hey from saro")
        .expect("payload mismatch");
    expect_event(&raya_events, "MessageReceived", |e| match e {
        Event::MessageReceived { content, .. } => {
            assert_eq!(content.as_slice(), b"Hey from saro");
            Ok(())
        }
        other => Err(other),
    });
}

#[test]
fn direct_v1_standalone_integration() {
    let bus = MessageBus::default();

    let reg_service = EphemeralRegistry::new();
    let auth = AcceptAllAuth::default();

    // Create accounts and their installations, and register each installation
    // with the auth service so a peer can resolve the account to it.
    let saro_account = TestLogosAccount::new();
    let saro_account_id = saro_account.address();
    let saro_pending = PendingInstallation::generate();
    let saro_device_id = saro_pending.endorsement_request();

    // Build saro's client with its account so its outbound messages carry a
    // credential the receiver can verify against the published bundle.
    let saro_installation = saro_pending.complete(saro_account.addr());
    auth.register(&saro_installation);
    let (mut saro, _saro_events) = ChatClientBuilder::new(saro_installation)
        .transport(InProcessDelivery::new(bus.clone()))
        .registration(reg_service.clone())
        .auth(auth.clone())
        .build()
        .expect("client create");
    let (raya, raya_events) =
        create_test_client(bus.clone(), reg_service.clone(), &auth).expect("client create");

    let raya_addr = raya.addr();
    let convo_id = saro.create_direct_conversation(raya_addr).unwrap();

    // The invite payload yields ConversationStarted then MessageReceived.
    expect_event(&raya_events, "ConversationStarted", |e| match e {
        Event::ConversationStarted { convo_id, .. } => Ok(convo_id),
        other => Err(other),
    });

    saro.send_message(&convo_id, b"Hey from saro")
        .expect("payload mismatch");
    expect_event(&raya_events, "MessageReceived", |e| match e {
        Event::MessageReceived {
            content, sender, ..
        } => {
            assert_eq!(content.as_slice(), b"Hey from saro");
            // saro associated an account and published a matching bundle, so the
            // sender surfaces with a verified account and its installation.
            assert_eq!(sender.account().to_string(), saro_account_id);
            assert_eq!(sender.signer().as_bytes(), saro_device_id);
            Ok(())
        }
        other => Err(other),
    });
}

/// A peer is reachable by its *account address* alone: the initiator resolves
/// the account to its signer ids through the directory (client layer), fetches
/// each signer's key package, and the Welcome arrives on the signer-scoped
/// inbox. The registry keys key packages by device id (hex verifying key),
/// exactly like the deployed HTTP registry.
#[test]
fn direct_v1_by_account_address() {
    let bus = MessageBus::default();
    let reg_service = EphemeralRegistry::new();
    let auth = AcceptAllAuth::default();

    let raya_account = TestLogosAccount::new();
    let raya_account_addr = raya_account.address();

    let raya_installation = PendingInstallation::generate().complete(raya_account.addr());
    auth.register(&raya_installation);
    let (mut raya, raya_events) = ChatClientBuilder::new(raya_installation)
        .transport(InProcessDelivery::new(bus.clone()))
        .registration(reg_service.clone())
        .auth(auth.clone())
        .build()
        .expect("client create");
    let (mut saro, saro_events) =
        create_test_client(bus.clone(), reg_service.clone(), &auth).expect("client create");

    // Raya's shared address is her account address, not her signer id.
    assert_eq!(raya.addr(), raya_account_addr.as_str());
    let convo_id = saro.create_direct_conversation(&raya_account_addr).unwrap();

    // DirectV1 is the pairwise shape, so the joiner sees it classed Private even
    // though its welcome rides the InboxV2 (GroupV1 invite) path.
    let raya_convo_id = expect_event(&raya_events, "ConversationStarted", |e| match e {
        Event::ConversationStarted { convo_id, class } => {
            assert_eq!(class, ConversationClass::Dm);
            Ok(convo_id)
        }
        other => Err(other),
    });

    saro.send_message(&convo_id, b"hello raya").unwrap();
    expect_event(&raya_events, "MessageReceived", |e| match e {
        Event::MessageReceived { content, .. } => {
            assert_eq!(content.as_slice(), b"hello raya");
            Ok(())
        }
        other => Err(other),
    });

    raya.send_message(&raya_convo_id, b"hi saro").unwrap();
    expect_event(&saro_events, "MessageReceived", |e| match e {
        Event::MessageReceived {
            content, sender, ..
        } => {
            assert_eq!(content.as_slice(), b"hi saro");
            // raya's bundle endorses her delegate, so her sender surfaces with
            // the verified account.
            assert_eq!(sender.account().to_string(), raya_account_addr);
            Ok(())
        }
        other => Err(other),
    });
}

#[test]
fn saro_raya_message_exchange() {
    let bus = MessageBus::default();
    let reg_service = EphemeralRegistry::new();
    let auth = AcceptAllAuth::default();

    let (mut saro, saro_events) =
        create_test_client(bus.clone(), reg_service.clone(), &auth).expect("client create");
    let (mut raya, raya_events) =
        create_test_client(bus.clone(), reg_service.clone(), &auth).expect("client create");

    let saro_convo_id = saro
        .create_direct_conversation(raya.addr())
        .expect("convo create");

    // Wait for raya to process the Welcome and subscribe to the convo delivery
    // address before saro sends — MessageBus only fans out to current subscribers,
    // so a message sent before raya subscribes would be silently dropped.
    let raya_convo_id = expect_event(&raya_events, "ConversationStarted", |e| match e {
        Event::ConversationStarted { convo_id, .. } => Ok(convo_id),
        other => Err(other),
    });

    saro.send_message(&saro_convo_id, b"hello raya").unwrap();
    expect_event(&raya_events, "MessageReceived", |e| match e {
        Event::MessageReceived {
            convo_id,
            content,
            sender,
        } => {
            assert_eq!(convo_id, raya_convo_id);
            assert_eq!(content.as_slice(), b"hello raya");
            assert!(!sender.signer().as_bytes().is_empty());
            Ok(())
        }
        other => Err(other),
    });

    raya.send_message(&raya_convo_id, b"hi saro").unwrap();
    expect_event(&saro_events, "MessageReceived", |e| match e {
        Event::MessageReceived { content, .. } => {
            assert_eq!(content.as_slice(), b"hi saro");
            Ok(())
        }
        other => Err(other),
    });

    for i in 0u8..5 {
        let msg = format!("msg {i}");
        saro.send_message(&saro_convo_id, msg.as_bytes()).unwrap();
        expect_event_ignoring_acks(
            &raya_events,
            &format!("MessageReceived(msg {i})"),
            |e| match e {
                Event::MessageReceived { content, .. } => {
                    assert_eq!(content.as_slice(), msg.as_bytes());
                    Ok(())
                }
                other => Err(other),
            },
        );

        let reply = format!("reply {i}");
        raya.send_message(&raya_convo_id, reply.as_bytes()).unwrap();
        expect_event_ignoring_acks(
            &saro_events,
            &format!("MessageReceived(reply {i})"),
            |e| match e {
                Event::MessageReceived { content, .. } => {
                    assert_eq!(content.as_slice(), reply.as_bytes());
                    Ok(())
                }
                other => Err(other),
            },
        );
    }

    assert_eq!(saro.list_all_conversations().unwrap().len(), 1);
    assert_eq!(raya.list_all_conversations().unwrap().len(), 1);

    // A live conversation is both sendable and retrievable, and shows up in the
    // sendable roster; an unknown id is neither.
    assert!(saro.can_send(&saro_convo_id));
    assert!(saro.can_receive(&saro_convo_id));
    assert_eq!(
        saro.list_sendable_conversations().unwrap(),
        vec![saro_convo_id.clone()]
    );
    assert!(!saro.can_send("deadbeef"));
    assert!(!saro.can_receive("deadbeef"));
}

/// Group metadata is a group concept: a direct conversation has none, so the
/// fetch is an error callers must handle.
#[test]
fn group_metadata_on_direct_conversation_errors() {
    let bus = MessageBus::default();
    let reg = EphemeralRegistry::new();
    let auth = AcceptAllAuth::default();

    let (mut saro, _saro_events) =
        create_test_client(bus.clone(), reg.clone(), &auth).expect("client create");
    let (raya, _raya_events) =
        create_test_client(bus.clone(), reg.clone(), &auth).expect("client create");

    let convo_id = saro
        .create_direct_conversation(raya.addr())
        .expect("convo create");
    saro.group_metadata(&convo_id)
        .expect_err("direct conversation has no group metadata");
}

/// A direct conversation reports its participants like any conversation. Add
/// Member errors on the creator's handle, though the joiner holds the same
/// conversation as a plain group, so the rejection is not conversation-wide.
#[test]
fn direct_conversation_lists_its_participants() {
    let bus = MessageBus::default();
    let reg = EphemeralRegistry::new();
    let auth = AcceptAllAuth::default();

    let (mut saro, _saro_events) =
        create_test_client(bus.clone(), reg.clone(), &auth).expect("client create");
    let (raya, _raya_events) =
        create_test_client(bus.clone(), reg.clone(), &auth).expect("client create");

    let saro_addr = saro.addr().to_string();
    let raya_addr = raya.addr().to_string();
    let convo_id = saro
        .create_direct_conversation(&raya_addr)
        .expect("convo create");

    let participants = saro.participants(&convo_id).expect("participants");
    let mut accounts: Vec<String> = participants.iter().map(AccountAddr::to_string).collect();
    accounts.sort();
    let mut expected = vec![saro_addr.clone(), raya_addr.clone()];
    expected.sort();
    assert_eq!(accounts, expected);

    let err = saro
        .add_group_participants(&convo_id, &[&raya_addr])
        .expect_err("add member is unsupported on a direct conversation");
    assert!(matches!(
        err,
        logos_generic_chat::ClientError::Chat(libchat::ChatError::UnsupportedFunction(..))
    ));
}

/// A direct conversation is 1:1, so removing the other party is not a supported
/// operation — the core rejects it rather than tearing the pair apart.
#[test]
fn removing_a_member_is_unsupported_on_a_direct_conversation() {
    let bus = MessageBus::default();
    let reg = EphemeralRegistry::new();
    let auth = AcceptAllAuth::default();

    let (mut saro, _saro_events) =
        create_test_client(bus.clone(), reg.clone(), &auth).expect("client create");
    let (raya, _raya_events) =
        create_test_client(bus.clone(), reg.clone(), &auth).expect("client create");

    let raya_addr = raya.addr().to_string();
    let convo_id = saro
        .create_direct_conversation(&raya_addr)
        .expect("convo create");

    let err = saro
        .remove_group_participants(&convo_id, &[&raya_addr])
        .expect_err("remove member is unsupported on a direct conversation");
    assert!(matches!(
        err,
        logos_generic_chat::ClientError::Chat(libchat::ChatError::UnsupportedFunction(..))
    ));
}

#[derive(Debug)]
struct FailingDelivery {
    inbound_tx: Sender<Vec<u8>>,
    inbound_rx: Option<Receiver<Vec<u8>>>,
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
    fn inbound_sender(&self) -> Sender<Vec<u8>> {
        self.inbound_tx.clone()
    }
}

impl DeliveryService for FailingDelivery {
    type Error = &'static str;

    fn publish(&mut self, _: AddressedEnvelope) -> Result<(), Self::Error> {
        Err("simulated transport failure")
    }

    fn subscribe(&mut self, _: &str) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl Transport for FailingDelivery {
    fn inbound(&mut self) -> Receiver<Vec<u8>> {
        self.inbound_rx
            .take()
            .expect("FailingDelivery::inbound called more than once")
    }
}

#[test]
fn dropping_client_shuts_down_worker() {
    let (client, events) = create_test_client(
        MessageBus::default(),
        EphemeralRegistry::new(),
        &AcceptAllAuth::default(),
    )
    .expect("client create");

    drop(client);
    // Drop joins the worker; once joined its Sender<Event> is gone, so recv
    // reports the channel as disconnected.
    let res = events.recv_timeout(Duration::from_secs(5));
    assert!(matches!(
        res,
        Err(crossbeam_channel::RecvTimeoutError::Disconnected)
    ));
}

#[test]
fn malformed_inbound_surfaces_as_error_event() {
    // Feed the worker's inbound channel bytes that can't be decoded and assert
    // it emits an InboundError instead of silently dropping the failure.
    let delivery = FailingDelivery::new();
    let inbound_tx = delivery.inbound_sender();

    let (_client, events) = ChatClientBuilder::new(
        PendingInstallation::generate().complete(TestLogosAccount::new().addr()),
    )
    .transport(delivery)
    .auth(AcceptAllAuth::default())
    .build()
    .expect("client create");

    inbound_tx.send(b"not a valid payload".to_vec()).unwrap();

    expect_event(&events, "InboundError", |e| match e {
        Event::InboundError { message } => {
            assert!(!message.is_empty(), "error event should carry a message");
            Ok(())
        }
        other => Err(other),
    });
}

/// Opening a conversation by an address the auth service cannot resolve to
/// any installation fails at resolution, not with a late key-package miss.
#[test]
fn unpublished_account_address_is_an_error() {
    let bus = MessageBus::default();
    let reg_service = EphemeralRegistry::new();
    let auth = AcceptAllAuth::default();

    let (mut saro, _saro_events) =
        create_test_client(bus.clone(), reg_service.clone(), &auth).expect("client create");

    let unpublished = TestLogosAccount::new();
    let err = saro
        .create_direct_conversation(&unpublished.address())
        .expect_err("the account is unknown");
    assert!(matches!(
        err,
        logos_generic_chat::ClientError::Chat(ChatError::ParticipantResolution(_))
    ));

    let err = saro
        .create_direct_conversation("not-an-account-address")
        .expect_err("not an account key");
    assert!(matches!(
        err,
        logos_generic_chat::ClientError::InvalidAccountAddress(_)
    ));
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
