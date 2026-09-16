use components::EphemeralRegistry;
use logos_generic_chat::{ChatClientBuilder, DelegateSigner, Event, InProcessDelivery, MessageBus};
use std::time::Duration;

fn main() {
    let bus = MessageBus::default();
    let mut reg = EphemeralRegistry::new();

    // Mint two accounts, each with a delegate signer, and publish their device
    // bundles so a peer can resolve an account address to its device.
    let saro_account = TestLogosAccount::new();
    let saro_delegate = DelegateSigner::random();

    let raya_account = TestLogosAccount::new();
    let raya_delegate = DelegateSigner::random();

    let (mut saro, saro_events) = ChatClientBuilder::new(saro_account.address())
        .ident(saro_delegate)
        .transport(InProcessDelivery::new(bus.clone()))
        .registration(reg.clone())
        .build()
        .unwrap();

    let (mut raya, raya_events) = ChatClientBuilder::new(raya_account.address())
        .ident(raya_delegate)
        .transport(InProcessDelivery::new(bus))
        .registration(reg)
        .build()
        .unwrap();

    // Saro opens a direct conversation with Raya by her account address.
    let saro_convo_id = saro.create_direct_conversation(raya.addr()).unwrap();

    // Wait for Raya to process the Welcome and subscribe before Saro sends, since
    // InProcessDelivery only fans out to current subscribers.
    let raya_convo_id = match raya_events.recv_timeout(Duration::from_secs(5)).unwrap() {
        Event::ConversationStarted { convo_id, .. } => convo_id,
        other => panic!("expected ConversationStarted, got {other:?}"),
    };

    saro.send_message(&saro_convo_id, b"hello raya").unwrap();
    if let Event::MessageReceived { content, .. } =
        raya_events.recv_timeout(Duration::from_secs(5)).unwrap()
    {
        println!(
            "Raya received: {:?}",
            std::str::from_utf8(&content).unwrap()
        );
    }

    raya.send_message(&raya_convo_id, b"hi saro").unwrap();
    if let Event::MessageReceived { content, .. } =
        saro_events.recv_timeout(Duration::from_secs(5)).unwrap()
    {
        println!(
            "Saro received: {:?}",
            std::str::from_utf8(&content).unwrap()
        );
    }

    println!("Message exchange complete.");
}

/// A stand-in account address while the account layer is out.
///
/// The device-bundle directory that resolved an account to its devices was
/// removed; nothing publishes or endorses until account-log replaces it, so
/// this is only a well-formed address string.
struct TestLogosAccount(crypto::Ed25519SigningKey);

impl TestLogosAccount {
    fn new() -> Self {
        Self(crypto::Ed25519SigningKey::generate())
    }

    fn address(&self) -> String {
        hex::encode(self.0.verifying_key().as_ref())
    }
}
