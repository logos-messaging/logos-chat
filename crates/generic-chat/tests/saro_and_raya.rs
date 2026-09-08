use std::time::Duration;

use components::EphemeralRegistry;
use crossbeam_channel::{Receiver, Sender};
use crypto::Ed25519VerifyingKey;
use logos_account::TestLogosAccount;
use logos_generic_chat::{
    AddressedEnvelope, ChatClient, ChatClientBuilder, ConversationClass, DelegateSigner,
    DeliveryService, Event, InProcessDelivery, MessageBus, Transport,
};

/// Publish a signed device bundle endorsing `device` as a device of `account`,
/// so a receiver can verify the sender's account → device mapping.
fn publish_device_bundle(
    reg: &mut EphemeralRegistry,
    account: &TestLogosAccount,
    device: &Ed25519VerifyingKey,
) {
    account.add_delegate_signer(reg, device).unwrap();
}

/// A client for a fresh account: mints the account and a delegate, publishes
/// the endorsing bundle, and builds the client on the shared bus/registry.
#[allow(clippy::type_complexity)]
fn create_test_client(
    message_bus: MessageBus,
    mut reg: EphemeralRegistry,
) -> Result<
    (
        ChatClient<InProcessDelivery, EphemeralRegistry, libchat::SqliteStore>,
        Receiver<Event>,
    ),
    logos_generic_chat::ClientError,
> {
    let account = TestLogosAccount::new();
    let delegate = DelegateSigner::random();
    publish_device_bundle(&mut reg, &account, delegate.public_key());
    let d = InProcessDelivery::new(message_bus);
    ChatClientBuilder::new(account.address())
        .ident(delegate)
        .transport(d)
        .registration(reg)
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

    let (mut saro, _saro_events) =
        create_test_client(bus.clone(), reg_service.clone()).expect("client create");
    let (raya, raya_events) =
        create_test_client(bus.clone(), reg_service.clone()).expect("client create");

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

    let mut reg_service = EphemeralRegistry::new();

    // Create accounts and delegates, and publish device bundles so the
    // receiver can verify the account → device mapping carried in the
    // sender's credential.
    let saro_account = TestLogosAccount::new();
    let saro_account_id = saro_account.address();
    let saro_delegate = DelegateSigner::random();
    let saro_device_id = hex::encode(saro_delegate.public_key().as_ref());
    publish_device_bundle(&mut reg_service, &saro_account, saro_delegate.public_key());

    // Build saro's client with its account so its outbound messages carry a
    // credential the receiver can verify against the published bundle.
    let (mut saro, _saro_events) = ChatClientBuilder::new(saro_account_id.clone())
        .ident(saro_delegate)
        .transport(InProcessDelivery::new(bus.clone()))
        .registration(reg_service.clone())
        .build()
        .expect("client create");
    let (raya, raya_events) =
        create_test_client(bus.clone(), reg_service.clone()).expect("client create");

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
            // sender surfaces with a verified account and its device.
            assert_eq!(
                sender.account.as_ref().map(|a| a.as_str()),
                Some(saro_account_id.as_str())
            );
            assert_eq!(sender.local_identity.as_str(), saro_device_id.as_str());
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
    let mut reg_service = EphemeralRegistry::new();

    let raya_account = TestLogosAccount::new();
    let raya_account_addr = raya_account.address();
    let raya_delegate = DelegateSigner::random();
    publish_device_bundle(&mut reg_service, &raya_account, raya_delegate.public_key());

    let (mut raya, raya_events) = ChatClientBuilder::new(raya_account_addr.clone())
        .ident(raya_delegate)
        .transport(InProcessDelivery::new(bus.clone()))
        .registration(reg_service.clone())
        .build()
        .expect("client create");
    let (mut saro, saro_events) =
        create_test_client(bus.clone(), reg_service.clone()).expect("client create");

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
            assert_eq!(
                sender.account.as_ref().map(|a| a.as_str()),
                Some(raya_account_addr.as_str())
            );
            Ok(())
        }
        other => Err(other),
    });
}

#[test]
fn saro_raya_message_exchange() {
    let bus = MessageBus::default();
    let reg_service = EphemeralRegistry::new();

    let (mut saro, saro_events) =
        create_test_client(bus.clone(), reg_service.clone()).expect("client create");
    let (mut raya, raya_events) =
        create_test_client(bus.clone(), reg_service.clone()).expect("client create");

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
            // saro's account published a bundle endorsing its delegate, so the
            // sender surfaces a verified account.
            assert!(sender.account.is_some());
            assert!(!sender.local_identity.as_str().is_empty());
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

    assert_eq!(saro.list_conversations().unwrap().len(), 1);
    assert_eq!(raya.list_conversations().unwrap().len(), 1);
}

/// Group metadata is a group concept: a direct conversation has none, so the
/// fetch is an error callers must handle.
#[test]
fn group_metadata_on_direct_conversation_errors() {
    let bus = MessageBus::default();
    let reg = EphemeralRegistry::new();

    let (mut saro, _saro_events) =
        create_test_client(bus.clone(), reg.clone()).expect("client create");
    let (raya, _raya_events) = create_test_client(bus.clone(), reg.clone()).expect("client create");

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

    let (mut saro, _saro_events) =
        create_test_client(bus.clone(), reg.clone()).expect("client create");
    let (raya, _raya_events) = create_test_client(bus.clone(), reg.clone()).expect("client create");

    let saro_addr = saro.addr().to_string();
    let raya_addr = raya.addr().to_string();
    let convo_id = saro
        .create_direct_conversation(&raya_addr)
        .expect("convo create");

    let roster = saro.group_members(&convo_id).expect("group_members");
    let mut accounts: Vec<Option<&str>> = roster
        .iter()
        .map(|m| m.account.as_ref().map(|a| a.as_str()))
        .collect();
    accounts.sort();
    let mut expected = vec![Some(saro_addr.as_str()), Some(raya_addr.as_str())];
    expected.sort();
    assert_eq!(accounts, expected);

    let err = saro
        .add_group_members(&convo_id, &[&raya_addr])
        .expect_err("add member is unsupported on a direct conversation");
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
    let (client, events) =
        create_test_client(MessageBus::default(), EphemeralRegistry::new()).expect("client create");

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

    let (_client, events) = ChatClientBuilder::new(TestLogosAccount::new().address())
        .transport(delivery)
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

/// Opening a conversation by an address whose account never published a
/// device bundle fails at resolution, not with a late key-package miss.
#[test]
fn unpublished_account_address_is_an_error() {
    let bus = MessageBus::default();
    let reg_service = EphemeralRegistry::new();

    let (mut saro, _saro_events) =
        create_test_client(bus.clone(), reg_service.clone()).expect("client create");

    let unpublished = TestLogosAccount::new();
    let err = saro
        .create_direct_conversation(&unpublished.address())
        .expect_err("no bundle published for the account");
    assert!(matches!(
        err,
        logos_generic_chat::ClientError::AccountResolution(_)
    ));

    let err = saro
        .create_direct_conversation("not-an-account-address")
        .expect_err("not an account key");
    assert!(matches!(
        err,
        logos_generic_chat::ClientError::AccountResolution(_)
    ));
}
