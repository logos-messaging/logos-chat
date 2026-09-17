use components::EphemeralRegistry;
use logos_generic_chat::{
    AccountAddr, ChatClientBuilder, Event, InProcessDelivery, MessageBus, PendingInstallation,
    UncheckedAuth,
};
use std::time::Duration;

fn main() {
    let bus = MessageBus::default();
    let reg = EphemeralRegistry::new();

    // Each client runs as a fresh installation of a fresh account.
    let (mut saro, saro_events) = ChatClientBuilder::new(
        PendingInstallation::generate().complete(TestLogosAccount::new().addr()),
    )
    .transport(InProcessDelivery::new(bus.clone()))
    .registration(reg.clone())
    .auth(UncheckedAuth)
    .build()
    .unwrap();

    let (mut raya, raya_events) = ChatClientBuilder::new(
        PendingInstallation::generate().complete(TestLogosAccount::new().addr()),
    )
    .transport(InProcessDelivery::new(bus))
    .registration(reg)
    .auth(UncheckedAuth)
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
