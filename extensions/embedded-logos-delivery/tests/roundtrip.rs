use std::time::{Duration, SystemTime};

use crossbeam_channel::Receiver;
use embedded_logos_delivery::{EmbeddedLogosDelivery, P2pConfig};
use libchat::test_support::delivery_tag;
use libchat::{AddressedEnvelope, DeliveryMsgId, DeliveryService};
use logos_generic_chat::{InboundPayload, Transport};

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
                tag: None,
            })
            .expect("publish");
        if let Ok(InboundPayload { data, .. }) = inbound.recv_timeout(Duration::from_secs(10)) {
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
fn a_payload_keeps_one_id_from_its_report_to_a_fetch() {
    let mut receiver = EmbeddedLogosDelivery::start(P2pConfig::default()).expect("receiver");
    let mut sender = EmbeddedLogosDelivery::start(P2pConfig::default()).expect("sender");
    // An address of this run alone, so no other payload arrives on it.
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("clock after the epoch")
        .as_nanos();
    let address = format!("addr-fetch-{nanos}");

    receiver.subscribe(&address).expect("subscribe");
    sender.subscribe(&address).expect("subscribe");
    let inbound = receiver.inbound();
    let reports = sender.delivery_reports();
    // Let the mesh form on the public network.
    std::thread::sleep(Duration::from_secs(20));

    let tag = delivery_tag("convo", "m1");
    let received = (0..5)
        .find_map(|_| {
            sender
                .publish(AddressedEnvelope {
                    delivery_address: address.clone(),
                    data: b"fetch me".to_vec(),
                    tag: Some(tag.clone()),
                })
                .expect("publish");
            inbound.recv_timeout(Duration::from_secs(10)).ok()
        })
        .expect("no message received");
    assert_eq!(received.data, b"fetch me");
    let id = received
        .delivery_info
        .expect("a received payload's id")
        .delivery_msg_id;
    assert_eq!(id.as_bytes().len(), 32, "the id is the hash's bytes");

    // Every attempt is reported under the tag; the one that arrived, under its id.
    let report = std::iter::from_fn(|| reports.recv_timeout(Duration::from_secs(10)).ok())
        .find(|report| report.delivery_info.delivery_msg_id == id)
        .expect("a report of the received payload");
    assert_eq!(report.tag, tag);

    // The store keeps the payload once relay hands it over, so ask again until it answers.
    let fetched = (0..3)
        .find_map(|_| {
            receiver
                .fetch_messages(&address, std::slice::from_ref(&id))
                .expect("fetch");
            next_with_id(&inbound, &id, Duration::from_secs(10))
        })
        .expect("the payload fetched by its id");
    assert_eq!(fetched.data, b"fetch me");

    sender.shutdown().expect("shutdown sender");
    receiver.shutdown().expect("shutdown receiver");
}

/// The next payload on `inbound` that arrives under `id`, skipping others.
fn next_with_id(
    inbound: &Receiver<InboundPayload>,
    id: &DeliveryMsgId,
    timeout: Duration,
) -> Option<InboundPayload> {
    std::iter::from_fn(|| inbound.recv_timeout(timeout).ok()).find(|payload| {
        payload
            .delivery_info
            .as_ref()
            .is_some_and(|info| &info.delivery_msg_id == id)
    })
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
