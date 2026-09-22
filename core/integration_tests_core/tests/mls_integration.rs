use integration_tests_core::TestHarness;
use libchat::ChatError;
use std::time::Duration;

#[test]
fn create_group() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();

    let mut harness = TestHarness::<3>::new(|_, _| {});

    let raya_account = harness.raya().account();
    let pax_id = harness.pax().addr();

    const M_R1: &[u8; 12] = b"Hi From Raya";
    const M_P1: &[u8; 13] = b"Hey it's Pax!";

    // Step: Saro Create Convo with Raya

    let convo_id = harness
        .saro()
        .create_group_convo_v1(&[raya_account])
        .expect("Saro invite Raya ");
    harness.process_until(|h| h.raya().list_all_conversations().unwrap().len() == 1);

    // Step: Raya Send Content

    harness
        .raya()
        .send_content(&convo_id, M_R1)
        .expect("Raya send Msg");

    harness.process_until(|h| h.saro().received_messages().len() == 1);

    // Step: Saro add Pax

    harness
        .saro()
        .group_add_signers(&convo_id, &[pax_id])
        .expect("Saro invite pax");
    harness.process_until(|h| h.pax().list_all_conversations().unwrap().len() == 1);

    // Step: Pax send Content

    harness
        .pax()
        .send_content(&convo_id, M_P1)
        .expect("Pax send");
    harness.process(Duration::from_millis(500));

    assert!(harness.saro().check(&convo_id, M_R1));
    assert!(harness.saro().check(&convo_id, M_P1));

    assert!(!harness.raya().check(&convo_id, M_R1));
    assert!(harness.raya().check(&convo_id, M_P1));

    assert!(!harness.pax().check(&convo_id, M_R1));
    assert!(!harness.pax().check(&convo_id, M_P1));
}

#[test]
fn remove_group_signers() {
    // GroupV1 commits in-call: Pax is off Saro's roster as soon as
    // `group_remove_member` returns, and learns it is out when the commit —
    // sealed at the pre-removal epoch — reaches it.
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();

    const MSG: &[u8; 11] = b"Saro to all";

    let mut harness = TestHarness::<3>::new(|_, _| {});

    let pax_id = harness.pax().addr().clone();
    let (raya_account, pax_account) = (harness.raya().account(), harness.pax().account());

    let convo_id = harness
        .saro()
        .create_group_convo_v1(&[raya_account, pax_account])
        .expect("Saro create with Raya and Pax");
    harness.process_until(|h| h.raya().convo_count() == 1 && h.pax().convo_count() == 1);

    harness
        .saro()
        .group_remove_signers(&convo_id, &[&pax_id])
        .expect("Saro remove Pax");
    assert_eq!(
        harness
            .saro()
            .group_signers(&convo_id)
            .expect("members")
            .len(),
        2
    );

    // Pax applies the commit that ejects it and stops being able to send.
    harness.process_until(|h| !h.pax().can_send(&convo_id));

    // The members left behind are at the same epoch and still exchanging.
    harness.saro().send_content(&convo_id, MSG).expect("send");
    harness.process_until(|h| h.raya().check(&convo_id, MSG));
    assert!(!harness.pax().check(&convo_id, MSG));
}

#[test]
fn remove_group_signer_rejects_a_non_signer() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();

    let mut harness = TestHarness::<3>::new(|_, _| {});

    let raya_id = harness.raya().addr().clone();
    let pax_id = harness.pax().addr().clone();
    let saro_id = harness.saro().addr().clone();
    let raya_account = harness.raya().account();

    let convo_id = harness
        .saro()
        .create_group_convo_v1(&[raya_account])
        .expect("Saro create with Raya");
    harness.process_until(|h| h.raya().convo_count() == 1);

    let err = harness
        .saro()
        .group_remove_signer(&convo_id, &[&pax_id])
        .expect_err("Pax is not a member");
    assert!(matches!(err, ChatError::NotAGroupMember), "{err:?}");

    // MLS has no way to commit your own removal.
    let err = harness
        .saro()
        .group_remove_signer(&convo_id, &[&saro_id])
        .expect_err("cannot remove self");
    assert!(matches!(err, ChatError::CannotRemoveSelf), "{err:?}");

    // Naming yourself alongside a removable member removes nobody.
    let err = harness
        .saro()
        .group_remove_signer(&convo_id, &[&saro_id, &raya_id])
        .expect_err("cannot remove self");
    assert!(matches!(err, ChatError::CannotRemoveSelf), "{err:?}");
    assert_eq!(
        harness
            .saro()
            .group_signers(&convo_id)
            .expect("members")
            .len(),
        2
    );
}
