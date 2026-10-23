use std::time::Duration;

use embedded_logos_delivery::{EmbeddedLogosDelivery, P2pConfig};
use libchat::{AddressedEnvelope, DeliveryService};
use logos_generic_chat::Transport;

#[test]
#[ignore = "needs network access and a linked liblogosdelivery"]
fn two_embedded_nodes_exchange_a_message() {
    let mut receiver = EmbeddedLogosDelivery::start(P2pConfig::default()).expect("receiver");
    let mut sender = EmbeddedLogosDelivery::start(P2pConfig::default()).expect("sender");

    receiver.subscribe("addr-roundtrip").expect("subscribe");
    sender.subscribe("addr-roundtrip").expect("subscribe");
    let inbound = receiver.inbound();
    // Let the mesh form on the public network.
    std::thread::sleep(Duration::from_secs(20));

    for _ in 0..5 {
        sender
            .publish(AddressedEnvelope {
                delivery_address: "addr-roundtrip".into(),
                data: b"hello chat".to_vec(),
            })
            .expect("publish");
        if let Ok(data) = inbound.recv_timeout(Duration::from_secs(10)) {
            assert_eq!(data, b"hello chat");
            sender.shutdown().expect("shutdown sender");
            receiver.shutdown().expect("shutdown receiver");
            return;
        }
    }
    panic!("no message received");
}

#[test]
#[ignore = "needs network access and a linked liblogosdelivery"]
fn dropping_a_started_node_returns_promptly() {
    let service = EmbeddedLogosDelivery::start(P2pConfig::default()).expect("start");
    let started = std::time::Instant::now();
    drop(service);
    // A node that hangs on teardown shows up as the library's 15 s timeout.
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "drop took {:?}",
        started.elapsed()
    );
}
