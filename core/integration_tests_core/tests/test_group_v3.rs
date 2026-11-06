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

#[test]
fn groupv3_creator_opens_a_late_resend() {
    let mut harness = TestHarness::<2>::new(|_, _| {});
    let convo_id = create_group(&mut harness);

    harness
        .raya()
        .send_content(&convo_id, b"lost")
        .expect("raya send lost");
    harness.saro().drop_pending_payloads();
    // A second on, so Raya's SDS log orders Saro's next messages after "lost".
    harness.process(Duration::from_secs(1));

    // Ten newer entries, a message's whole causal history, so Raya's next messages no longer
    // name "lost" and SDS hands them to Saro without it.
    for i in 0..10 {
        harness
            .saro()
            .send_content(&convo_id, format!("s{i}").as_bytes())
            .expect("saro send");
    }
    harness.process_until_label("raya gets saro's", |h| {
        h.raya().received_messages().len() == 10
    });
    // Past OpenMLS's default window of 5 keys per sender, within the 32 a joiner keeps.
    for i in 0..8 {
        harness
            .raya()
            .send_content(&convo_id, format!("r{i}").as_bytes())
            .expect("raya send");
    }
    harness.process_until_label("saro gets raya's", |h| {
        h.saro().received_messages().len() == 8
    });

    // Raya resends "lost" after 60 s without an acknowledgement.
    harness.process(Duration::from_secs(61));
    harness.process_until_label("saro opens the resend", |h| {
        h.saro().check(&convo_id, b"lost")
    });
}

/// Saro creates a group with Raya and settles until Raya has joined.
fn create_group_for_adds(harness: &mut TestHarness<4>) -> String {
    let participants = &[harness.raya().account()];
    let convo_id = harness
        .saro()
        .create_group_convo_v3(participants, "", "")
        .expect("saro create group");
    harness.process_until_label("Raya join", |h| h.raya().convo_count() == 1);
    convo_id
}

#[test]
fn groupv3_members_added_later_receive_the_next_message() {
    let mut harness = TestHarness::<4>::new(|_, _| {});
    let convo_id = create_group_for_adds(&mut harness);
    // One more than a message's causal history, so an invite must carry the newest.
    for i in 0..11 {
        harness
            .saro()
            .send_content(&convo_id, format!("m{i}").as_bytes())
            .expect("saro send");
    }
    harness.process_until(|h| h.raya().received_messages().len() == 11);

    let pax = harness.pax().account();
    harness
        .saro()
        .group_add_participants(&convo_id, &[pax])
        .expect("saro adds pax");
    harness.process_until_label("Pax join", |h| {
        h.pax().convo_count() == 1 && h.raya().group_signers(&convo_id).map_or(0, |s| s.len()) == 3
    });
    // Pax's next invite then mixes their seed with a message of their own.
    harness
        .pax()
        .send_content(&convo_id, b"p1")
        .expect("pax send p1");
    harness.process_until(|h| h.saro().check(&convo_id, b"p1") && h.raya().check(&convo_id, b"p1"));
    let mira = harness.mira().account();
    harness
        .pax()
        .group_add_participants(&convo_id, &[mira])
        .expect("pax adds mira");
    harness.process_until_label("Saro and Raya apply both adds", |h| {
        h.mira().convo_count() == 1
            && h.saro().group_signers(&convo_id).map_or(0, |s| s.len()) == 4
            && h.raya().group_signers(&convo_id).map_or(0, |s| s.len()) == 4
    });

    // Both name m2..m10 and p1: the newcomers received none of m2..m10, and Mira not p1 either.
    harness
        .saro()
        .send_content(&convo_id, b"from saro")
        .expect("saro send");
    harness
        .raya()
        .send_content(&convo_id, b"from raya")
        .expect("raya send");
    harness.process_until_label("newcomers get both", |h| {
        h.pax().check(&convo_id, b"from saro")
            && h.pax().check(&convo_id, b"from raya")
            && h.mira().check(&convo_id, b"from saro")
            && h.mira().check(&convo_id, b"from raya")
    });
}
