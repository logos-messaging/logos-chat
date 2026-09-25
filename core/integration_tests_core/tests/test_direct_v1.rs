use chat_proto::logoschat::envelope::EnvelopeV1;
use integration_tests_core::TestHarness;
use libchat::{ChatError, PayloadOutcome};
use prost::Message;
use tracing::info;

#[test]
fn happypath_roundtrip() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();

    const S_M1: &[u8] = b"Marco";
    const R_M1: &[u8] = b"Polo";

    // Initialize TestHarness with 2 clients
    let mut harness = TestHarness::<2>::new(|_, _| {});

    //Saro Create Convo
    let particpant = harness.raya().account();
    let convo_id = harness
        .saro()
        .create_direct_convo_v1(particpant)
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

    assert!(harness.saro().check(&convo_id, R_M1));
}

#[test]
fn replayed_invite_is_rejected() {
    // Delivery can hand the same invite over twice, e.g. on a store catch-up.
    const MSG: &[u8] = b"still here";

    let mut harness = TestHarness::<2>::new(|_, _| {});

    let raya_account = harness.raya().account();
    let convo_id = harness
        .saro()
        .create_direct_convo_v1(raya_account)
        .expect("saro create convo");

    let invite = harness.raya().ds().poll().expect("invite for raya");
    let joined = harness.raya().handle_payload(&invite).expect("raya joins");
    assert!(matches!(joined, PayloadOutcome::Inbox(_)), "{joined:?}");

    harness
        .raya()
        .handle_payload(&invite)
        .expect_err("the copy is rejected");

    harness
        .saro()
        .send_content(&convo_id, MSG)
        .expect("saro send");
    harness.process_until(|h| h.raya().check(&convo_id, MSG));
}

#[test]
fn invite_for_another_installation_is_rejected() {
    let mut harness = TestHarness::<3>::new(|_, _| {});

    let (raya_account, pax_account) = (harness.raya().account(), harness.pax().account());
    harness
        .saro()
        .create_direct_convo_v1(raya_account)
        .expect("saro create convo with raya");
    harness
        .saro()
        .create_direct_convo_v1(pax_account)
        .expect("saro create convo with pax");

    let for_raya = harness.raya().ds().poll().expect("invite for raya");
    let for_pax = harness.pax().ds().poll().expect("invite for pax");

    // Raya's Welcome, addressed to Pax's inbox.
    let mut forged = EnvelopeV1::decode(for_raya.as_slice()).expect("envelope");
    forged.conversation_hint = EnvelopeV1::decode(for_pax.as_slice())
        .expect("envelope")
        .conversation_hint;

    harness
        .pax()
        .handle_payload(&forged.encode_to_vec())
        .expect_err("a Welcome for someone else is rejected");

    let joined = harness.pax().handle_payload(&for_pax).expect("pax joins");
    assert!(matches!(joined, PayloadOutcome::Inbox(_)), "{joined:?}");
}

#[test]
fn direct_convo_with_yourself_is_refused() {
    let mut harness = TestHarness::<1>::new(|_, _| {});

    let saro_account = harness.saro().account();
    let err = harness
        .saro()
        .create_direct_convo_v1(saro_account)
        .expect_err("no direct convo with yourself");
    assert!(matches!(err, ChatError::CannotMessageSelf), "{err:?}");
}
