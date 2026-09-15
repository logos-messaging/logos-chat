use components::EphemeralRegistry;
use logos_account_DELETE::TestLogosAccount;
use logos_generic_chat::{ChatClientBuilder, DelegateSigner, Event, InProcessDelivery, MessageBus};
use std::time::Duration;

fn main() {
    let bus = MessageBus::default();
    let mut reg = EphemeralRegistry::new();

    // Mint two accounts, each with a delegate signer, and publish their device
    // bundles so a peer can resolve an account address to its device.
    let saro_account = TestLogosAccount::new();
    let saro_delegate = DelegateSigner::random();
    saro_account
        .add_delegate_signer(&mut reg, saro_delegate.public_key())
        .unwrap();

    let raya_account = TestLogosAccount::new();
    let raya_delegate = DelegateSigner::random();
    raya_account
        .add_delegate_signer(&mut reg, raya_delegate.public_key())
        .unwrap();

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
