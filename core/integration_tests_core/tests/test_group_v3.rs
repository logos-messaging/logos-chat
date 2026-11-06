use std::collections::HashSet;
use std::time::Duration;

use integration_tests_core::TestHarness;
use tracing::info;

#[test]
fn groupv3_2way_roundtrip() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();

    const S_M1: &[u8] = b"aaaaa";
    const R_M1: &[u8] = b"Hello";

    // Initialize TestHarness with 2 clients
    let mut harness = TestHarness::<2>::new(|_, _| {});

    //Saro Create Convo
    let particpants = &[harness.raya().account()];
    let convo_id = harness
        .saro()
        .create_group_convo_v3(particpants, "", "")
        .expect("saro create group");

    // Carry the invite through (commit, WelcomeReady, routing to Raya's inbox,
    // accept_welcome); settle until Raya has joined.
    harness.process_until_label("Saro Send", |h| h.raya().convo_count() == 1);

    // Saro sends a message; settle until Raya receives it.
    info!(target: "chat", "Saro -> sending: {S_M1:?}");
    harness
        .saro()
        .send_content(&convo_id, S_M1)
        .expect("saro send");

    harness.process_until(|h| h.raya().check(&convo_id, S_M1));

    // Raya replies; settle until Saro receives it.
    info!(target: "chat", "Raya -> sending:{R_M1:?}");
    harness.raya().send_content(&convo_id, R_M1).unwrap();
    harness.process_until(|h| h.saro().check(&convo_id, R_M1));
}

/// Saro creates a group with Raya and settles until Raya has joined.
fn create_group(harness: &mut TestHarness<2>) -> String {
    let participants = &[harness.raya().account()];
    let convo_id = harness
        .saro()
        .create_group_convo_v3(participants, "", "")
        .expect("saro create group");
    harness.process_until_label("Raya join", |h| h.raya().convo_count() == 1);
    convo_id
}

#[test]
fn groupv3_repeated_content_gets_distinct_ids() {
    let mut harness = TestHarness::<2>::new(|_, _| {});
    let convo_id = create_group(&mut harness);

    let ids = [
        harness
            .saro()
            .send_content(&convo_id, b"ok")
            .expect("saro send"),
        harness
            .raya()
            .send_content(&convo_id, b"ok")
            .expect("raya send"),
        harness
            .saro()
            .send_content(&convo_id, b"ok")
            .expect("saro send again"),
    ];
    assert_eq!(ids.iter().collect::<HashSet<_>>().len(), 3, "{ids:?}");

    // SDS drops a message whose id is already in its log, so with equal ids none would arrive.
    harness.process_until_label("all delivered", |h| {
        h.raya().received_messages().len() == 2 && h.saro().received_messages().len() == 1
    });
}

#[test]
fn groupv3_resend_heals_a_lost_message() {
    let mut harness = TestHarness::<2>::new(|_, _| {});
    let convo_id = create_group(&mut harness);

    harness
        .saro()
        .send_content(&convo_id, b"m1")
        .expect("saro send m1");
    harness.raya().drop_pending_payloads();
    harness
        .saro()
        .send_content(&convo_id, b"m2")
        .expect("saro send m2");

    // Raya holds m2 until m1 arrives; Saro resends m1 after 60 s without an acknowledgement.
    harness.process(Duration::from_secs(61));
    harness.process_until_label("raya gets both", |h| {
        h.raya().received_messages().len() == 2
    });
    let contents: Vec<&[u8]> = harness
        .raya()
        .received_messages()
        .iter()
        .map(|message| message.contents.as_slice())
        .collect();
    assert_eq!(contents, [b"m1", b"m2"]);
}
