use std::collections::HashSet;
use std::time::Duration;

use integration_tests_core::{Observation, TestHarness, TestIdent, Trigger};
use libchat::{
    AuthenticatedSigner, ChatError, ConvoOutcome, DeliveryAck, DeliveryService, IdentityProvider,
    MissingMessage, PayloadOutcome, SignerKey,
};
use tracing::info;

/// What drove each outcome that reported `convo_id` left at `ident`, in order.
fn left_triggers(observations: &[Observation], ident: &SignerKey, convo_id: &str) -> Vec<Trigger> {
    observations
        .iter()
        .filter_map(|observation| match &observation.outcome {
            PayloadOutcome::Convo(ConvoOutcome {
                convo_id: id,
                left: true,
                ..
            }) if observation.ident == *ident && id == convo_id => Some(observation.trigger),
            _ => None,
        })
        .collect()
}

/// Step the harness through `duration` of virtual time, so every timer armed
/// in that span fires.
fn run_for<const N: usize>(harness: &mut TestHarness<N>, duration: Duration) {
    let step = Duration::from_millis(50);
    for _ in 0..duration.as_millis() / step.as_millis() {
        harness.process(step);
    }
}

/// Saro's group, which Raya joins at genesis and Pax after it. The genesis
/// commit made Saro and Raya the stewards, so both mint a candidate for Pax's
/// removal, and Pax's round ends on the frame that brings the second.
fn group_with_pax_added_after_genesis(harness: &mut TestHarness<3>) -> String {
    let raya_account = harness.raya().account();
    let pax_account = harness.pax().account();
    let convo_id = harness
        .saro()
        .create_group_convo_v2(&[raya_account], "", "")
        .expect("Saro create");
    harness.process_until_label("Raya join", |h| h.raya().convo_count() == 1);

    harness
        .saro()
        .group_add_participants(&convo_id, &[pax_account])
        .expect("Saro add Pax");
    harness.process_until_label("Pax join", |h| h.pax().convo_count() == 1);
    harness
        .saro()
        .send_content(&convo_id, b"all three")
        .expect("Saro send");
    harness.process_until_label("all three", |h| {
        h.raya().check(&convo_id, b"all three") && h.pax().check(&convo_id, b"all three")
    });
    convo_id
}

/// How many conversations the inbox started at `ident`.
fn conversations_started(observations: &[Observation], ident: &SignerKey) -> usize {
    observations
        .iter()
        .filter(|o| o.ident == *ident && matches!(o.outcome, PayloadOutcome::Inbox(_)))
        .count()
}

/// Saro removes Pax; returns once Pax has applied the commit and Saro's
/// roster is a member shorter.
fn saro_removes_pax(harness: &mut TestHarness<3>, convo_id: &str) {
    let pax_account = harness.pax().account();
    let members = harness
        .saro()
        .group_signers(convo_id)
        .expect("members")
        .len();
    harness
        .saro()
        .group_remove_participants(convo_id, &[pax_account])
        .expect("Saro remove Pax");
    harness.process_until_label("Pax removed", |h| {
        !h.pax().can_send(convo_id)
            && h.saro().group_signers(convo_id).map_or(0, |m| m.len()) == members - 1
    });
}

/// Saro removes Pax, whose leave `trigger` reports and tears its conversation
/// down, then adds Pax back: the welcome starts a new conversation in its
/// place, which receives and sends.
fn pax_rejoins_after_removal(harness: &mut TestHarness<3>, convo_id: &str, trigger: Trigger) {
    let pax_signer = harness.pax().signer_key();
    let pax_account = harness.pax().account();
    saro_removes_pax(harness, convo_id);
    assert_eq!(
        left_triggers(&harness.observed_outcomes, &pax_signer, convo_id),
        [trigger]
    );

    harness
        .saro()
        .group_add_participants(convo_id, &[pax_account])
        .expect("Saro add Pax back");
    harness.process_until_label("Pax back", |h| h.pax().can_send(convo_id));
    assert_eq!(
        conversations_started(&harness.observed_outcomes, &pax_signer),
        2,
        "the welcome back starts the conversation again"
    );

    harness
        .saro()
        .send_content(convo_id, b"welcome back")
        .expect("Saro send");
    harness.process_until_label("Pax receives", |h| h.pax().check(convo_id, b"welcome back"));
    harness
        .pax()
        .send_content(convo_id, b"glad to be back")
        .expect("Pax send");
    harness.process_until_label("Saro receives", |h| {
        h.saro().check(convo_id, b"glad to be back")
    });
    assert_eq!(
        left_triggers(&harness.observed_outcomes, &pax_signer, convo_id),
        [trigger]
    );
}

#[test]
fn groupv2_2way_roundtrip() {
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
        .create_group_convo_v2(particpants, "", "")
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

#[test]
fn core_client() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();

    const S_M1: &[u8] = b"HI";
    const R_M1: &[u8] = b"hi back";
    const S_M2: &[u8] = b"EPOCHCHK";

    let mut harness = TestHarness::<3>::new(|_, _| {});

    let particpants = &[harness.raya().account()];
    let convo_id = harness
        .saro()
        .create_group_convo_v2(particpants, "", "")
        .expect("Saro create");

    // Carry the invite through (commit, WelcomeReady, routing to Raya's inbox,
    // accept_welcome); settle until Raya has joined.
    harness.process_until_label("saro create", |h| h.raya().convo_count() == 1);

    // Saro sends a message; settle until Raya receives it.
    info!(target: "chat", "Saro -> sending: {S_M1:?}");
    harness
        .saro()
        .send_content(&convo_id, S_M1)
        .expect("saro send");

    harness.process_until_label("Recv S_M1", |h| h.raya().check(&convo_id, S_M1));

    // Raya replies; settle until Saro receives it.
    info!(target: "chat", "Raya -> sending: {R_M1:?}");
    harness
        .raya()
        .send_content(&convo_id, R_M1)
        .expect("raya send");

    harness.process_until_label("Recv R_M1", |h| h.saro().check(&convo_id, R_M1));

    // Raya (a non-creator) invites Pax; settle until Pax has joined.
    let particpants = &[harness.pax().account()];
    harness
        .raya()
        .group_add_participants(&convo_id, particpants)
        .expect("Raya add Pax");

    harness.process_until_label("Raya add Pax", |h| h.pax().convo_count() == 1);

    // Everyone must be at the SAME epoch after Pax joined: a marker Saro sends
    // now decrypts only for members that applied the Add commit.
    info!(target: "chat", "Saro -> sending: EPOCHCHK");
    harness.saro().send_content(&convo_id, S_M2).unwrap();

    harness.process_until_label("epoch check", |h| {
        h.raya().check(&convo_id, S_M2) && h.pax().check(&convo_id, S_M2)
    });
}

#[test]
fn core_client_batch_add() {
    // Saro creates the group and adds BOTH Raya and Pax at the same time: one
    // Add commit producing a single welcome that names both joiners.

    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer();

    let mut harness = TestHarness::<3>::new(|_, _| {});

    let particpants = &[harness.raya().account(), harness.pax().account()];
    harness
        .saro()
        .create_group_convo_v2(particpants, "", "")
        .expect("Saro create");

    // Carry the invite through (commit, WelcomeReady, routing to Raya's inbox,
    // accept_welcome); settle until Raya has joined.
    harness.process_until_label("saro create", |h| {
        h.raya().convo_count() == 1 && h.pax().convo_count() == 1
    });
}

#[test]
fn core_client_four_members_two_epochs() {
    // Epoch 1: Saro creates and batch-adds Raya + Pax (3 members). Epoch 2: Raya
    // (a non-creator) adds a 4th member, Mira. Afterwards every member must be
    // at the same epoch (each can decrypt a freshly-sent message) and settled
    // back in Working (the >sn_max election that the 4th member triggers must
    // have completed — no one stuck in Freezing/Selection/Reelection).

    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();

    const MSG: &[u8] = b"CONVERGED";

    let mut harness = TestHarness::<4>::new(|_, _| {});

    let particpants = &[harness.raya().account(), harness.pax().account()];
    let convo_id = harness
        .saro()
        .create_group_convo_v2(particpants, "", "")
        .expect("Saro create");

    // Carry the invite through (commit, WelcomeReady, routing to Raya's inbox,
    // accept_welcome); settle until Raya has joined.
    harness.process_until_label("Raya + Pax join", |h| {
        h.raya().convo_count() == 1 && h.pax().convo_count() == 1
    });

    // Epoch 2: Raya adds the 4th member; settle until Mira has joined and the
    // >sn_max election has returned everyone to Working.
    let members = &[harness.mira().account()];
    harness
        .raya()
        .group_add_participants(&convo_id, members)
        .expect("Add Mira");

    // TODO: Add State == Working for all clients
    harness.process_until_label("Mira join", |h| h.mira().convo_count() == 1);

    // Same epoch: a message Saro sends now must reach all three peers.
    harness
        .saro()
        .send_content(&convo_id, MSG)
        .expect("Saro send");

    harness.process_until_label("all chats converge", |h| {
        h.raya().check(&convo_id, MSG)
            && h.pax().check(&convo_id, MSG)
            && h.mira().check(&convo_id, MSG)
    });
}

#[test]
fn core_client_remove_signer() {
    // Saro removes Pax. The removal goes to consensus, so it lands on a later
    // commit: settle until Pax is off every roster, then check Pax knows it
    // can no longer send and the group left behind still works.
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();

    const MSG: &[u8] = b"STILL HERE";

    let mut harness = TestHarness::<3>::new(|_, _| {});

    let pax_account = harness.pax().account();
    let particpants = &[harness.raya().account(), harness.pax().account()];
    let convo_id = harness
        .saro()
        .create_group_convo_v2(particpants, "", "")
        .expect("Saro create");

    harness.process_until_label("Raya + Pax join", |h| {
        h.raya().convo_count() == 1 && h.pax().convo_count() == 1
    });
    assert_eq!(
        harness
            .saro()
            .group_signers(&convo_id)
            .expect("members")
            .len(),
        3
    );

    harness
        .saro()
        .group_remove_participants(&convo_id, &[pax_account])
        .expect("Saro remove Pax");

    harness.process_until_label("Pax removed", |h| {
        h.saro().group_signers(&convo_id).map_or(0, |m| m.len()) == 2
            && h.raya().group_signers(&convo_id).map_or(0, |m| m.len()) == 2
    });

    // Pax applied the same commit and sees its own leaf gone.
    assert!(!harness.pax().can_send(&convo_id));

    // The remaining members are at the same epoch and still talking.
    harness
        .saro()
        .send_content(&convo_id, MSG)
        .expect("Saro send");
    harness.process_until_label("Raya receives", |h| h.raya().check(&convo_id, MSG));
}

#[test]
fn a_removal_applied_by_a_frame_reports_the_leave_once() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();

    let mut harness = TestHarness::<3>::new(|_, _| {});
    let convo_id = group_with_pax_added_after_genesis(&mut harness);

    let pax_signer = harness.pax().signer_key();
    saro_removes_pax(&mut harness, &convo_id);

    // The group goes on talking on the address Pax still listens on.
    harness
        .saro()
        .send_content(&convo_id, b"just us now")
        .expect("Saro send");
    harness.process_until_label("Raya receives", |h| {
        h.raya().check(&convo_id, b"just us now")
    });
    run_for(&mut harness, Duration::from_secs(5));

    assert!(!harness.pax().check(&convo_id, b"just us now"));
    assert_eq!(
        left_triggers(&harness.observed_outcomes, &pax_signer, &convo_id),
        [Trigger::Frame]
    );
}

#[test]
fn a_removal_applied_by_a_wakeup_reports_the_leave_once() {
    // In a group of two both members are stewards, and Raya cannot commit its
    // own removal: its round never fills, and ends on the wakeup armed for the
    // end of its freeze.
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();

    let mut harness = TestHarness::<2>::new(|_, _| {});

    let raya_signer = harness.raya().signer_key();
    let raya_account = harness.raya().account();
    let convo_id = harness
        .saro()
        .create_group_convo_v2(std::slice::from_ref(&raya_account), "", "")
        .expect("Saro create");
    harness.process_until_label("Raya join", |h| h.raya().convo_count() == 1);

    harness
        .saro()
        .group_remove_participants(&convo_id, &[raya_account])
        .expect("Saro remove Raya");
    harness.process_until_label("Raya removed", |h| !h.raya().can_send(&convo_id));
    run_for(&mut harness, Duration::from_secs(5));

    assert_eq!(
        left_triggers(&harness.observed_outcomes, &raya_signer, &convo_id),
        [Trigger::Wakeup]
    );
}

#[test]
fn a_member_removed_by_a_frame_rejoins_when_added_back() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();

    let mut harness = TestHarness::<3>::new(|_, _| {});
    let convo_id = group_with_pax_added_after_genesis(&mut harness);

    pax_rejoins_after_removal(&mut harness, &convo_id, Trigger::Frame);
}

#[test]
fn a_member_removed_again_after_coming_back_leaves_again() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();

    let mut harness = TestHarness::<3>::new(|_, _| {});
    let convo_id = group_with_pax_added_after_genesis(&mut harness);
    pax_rejoins_after_removal(&mut harness, &convo_id, Trigger::Frame);

    let pax_signer = harness.pax().signer_key();
    saro_removes_pax(&mut harness, &convo_id);

    assert_eq!(
        left_triggers(&harness.observed_outcomes, &pax_signer, &convo_id).len(),
        2
    );
    let err = harness
        .pax()
        .send_content(&convo_id, b"still here?")
        .expect_err("Pax's send is refused");
    assert!(matches!(err, ChatError::NoLongerAMember), "{err:?}");
}

#[test]
fn a_member_removed_by_a_wakeup_rejoins_when_added_back() {
    // In a group of two both members are stewards, and Pax cannot commit its
    // own removal: its round never fills, and ends on the wakeup armed for the
    // end of its freeze.
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();

    let mut harness = TestHarness::<3>::new(|_, _| {});

    let pax_account = harness.pax().account();
    let convo_id = harness
        .saro()
        .create_group_convo_v2(&[pax_account], "", "")
        .expect("Saro create");
    harness.process_until_label("Pax join", |h| h.pax().convo_count() == 1);

    pax_rejoins_after_removal(&mut harness, &convo_id, Trigger::Wakeup);
}

#[test]
fn a_removed_member_refuses_its_first_welcome_replayed() {
    // Anyone who captured the welcome that first added Pax can publish it
    // again once Pax is removed; it is older than the removal.
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();

    let mut harness = TestHarness::<3>::new(|_, _| {});
    // A second reader of Pax's inbox, to capture the welcome Pax receives.
    let mut pax_inbox = harness.pax().ds().clone();
    let convo_id = group_with_pax_added_after_genesis(&mut harness);
    let welcome = pax_inbox.poll_envelope().expect("Pax's welcome");

    let pax_signer = harness.pax().signer_key();
    let pax_account = harness.pax().account();
    saro_removes_pax(&mut harness, &convo_id);

    harness.tolerate_inbound_errors();
    pax_inbox.publish(welcome).expect("replay the welcome");
    run_for(&mut harness, Duration::from_secs(1));

    assert_eq!(
        harness.pax().inbound_errors(),
        [format!("{:?}", ChatError::StaleRejoin)]
    );
    assert!(!harness.pax().can_send(&convo_id));
    assert_eq!(
        conversations_started(&harness.observed_outcomes, &pax_signer),
        1,
        "only the first join started a conversation"
    );

    // Refused before joining, so it stored nothing that would stand in the
    // way of a real welcome back.
    harness
        .saro()
        .group_add_participants(&convo_id, &[pax_account])
        .expect("Saro add Pax back");
    harness.process_until_label("Pax back", |h| h.pax().can_send(&convo_id));
}

#[test]
fn a_member_refuses_its_welcome_replayed() {
    // Pax's client holds the group live, so its own welcome sent again is
    // refused and Pax stays in the group.
    let mut harness = TestHarness::<3>::new(|_, _| {});
    let mut pax_inbox = harness.pax().ds().clone();
    let convo_id = group_with_pax_added_after_genesis(&mut harness);
    let welcome = pax_inbox.poll_envelope().expect("Pax's welcome");

    harness.tolerate_inbound_errors();
    pax_inbox.publish(welcome).expect("replay the welcome");
    run_for(&mut harness, Duration::from_secs(1));

    assert_eq!(harness.pax().inbound_errors().len(), 1);
    harness
        .pax()
        .send_content(&convo_id, b"still here")
        .expect("Pax send");
    harness.process_until_label("Saro receives", |h| {
        h.saro().check(&convo_id, b"still here")
    });
}

#[test]
fn a_removed_member_is_told_it_is_no_longer_one() {
    // Once the commit lands, Pax's client holds what is left of the group and
    // no conversation to call.
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();

    let mut harness = TestHarness::<4>::new(|_, _| {});

    let raya_account = harness.raya().account();
    let pax_account = harness.pax().account();
    let mira_account = harness.mira().account();
    // An account that resolves to an installation, but no client was built
    // for that installation, so it registered no key package.
    let keyless = TestIdent::new("keyless");
    harness.auth().register(&keyless);
    let convo_id = harness
        .saro()
        .create_group_convo_v2(&[raya_account.clone(), pax_account.clone()], "", "")
        .expect("Saro create");

    harness.process_until_label("Raya + Pax join", |h| {
        h.raya().convo_count() == 1 && h.pax().convo_count() == 1
    });

    harness
        .saro()
        .group_remove_participants(&convo_id, &[pax_account])
        .expect("Saro remove Pax");
    harness.process_until_label("Pax removed", |h| !h.pax().can_send(&convo_id));

    let err = harness
        .pax()
        .send_content(&convo_id, b"still here?")
        .expect_err("Pax's send is refused");
    assert!(matches!(err, ChatError::NoLongerAMember), "{err:?}");

    let err = harness
        .pax()
        .group_add_participants(&convo_id, &[mira_account])
        .expect_err("Pax's add is refused");
    assert!(matches!(err, ChatError::NoLongerAMember), "{err:?}");

    // Refused before the registry is asked for a key package.
    let err = harness
        .pax()
        .group_add_participants(&convo_id, &[keyless.participant_id()])
        .expect_err("Pax's add of an installation with no key package is refused");
    assert!(matches!(err, ChatError::NoLongerAMember), "{err:?}");

    let err = harness
        .pax()
        .group_remove_participants(&convo_id, &[raya_account])
        .expect_err("Pax's removal is refused");
    assert!(matches!(err, ChatError::NoLongerAMember), "{err:?}");
}

#[test]
fn a_removed_member_still_reads_the_group_it_left() {
    let mut harness = TestHarness::<3>::new(|_, _| {});

    let raya_account = harness.raya().account();
    let pax_account = harness.pax().account();
    let convo_id = harness
        .saro()
        .create_group_convo_v2(
            &[raya_account, pax_account],
            "Jankiest Friends",
            "A cool group chat",
        )
        .expect("Saro create");
    harness.process_until_label("Raya + Pax join", |h| {
        h.raya().convo_count() == 1 && h.pax().convo_count() == 1
    });
    saro_removes_pax(&mut harness, &convo_id);

    let roster = |members: Vec<AuthenticatedSigner>| -> HashSet<SignerKey> {
        members.iter().map(|m| m.signer().clone()).collect()
    };
    let stayed = roster(harness.saro().group_signers(&convo_id).expect("members"));
    assert_eq!(stayed.len(), 2);
    assert_eq!(
        roster(harness.pax().group_signers(&convo_id).expect("members")),
        stayed
    );
    let metadata = harness.pax().convo_metadata(&convo_id).expect("metadata");
    assert_eq!(
        (metadata.name.as_str(), metadata.desc.as_str()),
        ("Jankiest Friends", "A cool group chat")
    );
    assert!(
        harness
            .pax()
            .group_pending_signers(&convo_id)
            .expect("pending")
            .is_empty()
    );
}

#[test]
fn a_send_refused_after_the_removal_leaves_no_gap_once_back() {
    // The causal history outlives the removal, and a message names the ones
    // its sender sent before it: a refused send must leave no id for Pax's
    // first message back to name.
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();

    let mut harness = TestHarness::<3>::new(|_, _| {});
    let convo_id = group_with_pax_added_after_genesis(&mut harness);

    let pax_account = harness.pax().account();
    saro_removes_pax(&mut harness, &convo_id);

    harness
        .pax()
        .send_content(&convo_id, b"still here?")
        .expect_err("Pax's send is refused");

    harness
        .saro()
        .group_add_participants(&convo_id, &[pax_account])
        .expect("Saro add Pax back");
    harness.process_until_label("Pax back", |h| h.pax().can_send(&convo_id));
    harness
        .pax()
        .send_content(&convo_id, b"glad to be back")
        .expect("Pax send");
    harness.process_until_label("Saro and Raya receive", |h| {
        h.saro().check(&convo_id, b"glad to be back")
            && h.raya().check(&convo_id, b"glad to be back")
    });

    assert!(harness.saro().take_missing_messages().is_empty());
    assert!(harness.raya().take_missing_messages().is_empty());
}

#[test]
fn remove_member_refuses_to_target_self() {
    // de-mls has `leave` for your own seat — a one-voter round — so a
    // `remove_member` aimed at it is refused rather than put to the group.
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();

    let mut harness = TestHarness::<2>::new(|_, _| {});

    let saro_addr = harness.saro().account();
    let particpants = &[harness.raya().account()];
    let convo_id = harness
        .saro()
        .create_group_convo_v2(particpants, "", "")
        .expect("Saro create");

    harness.process_until_label("Raya join", |h| h.raya().convo_count() == 1);

    let err = harness
        .saro()
        .group_remove_participants(&convo_id, &[saro_addr])
        .expect_err("self-removal is refused");
    assert!(matches!(err, ChatError::CannotRemoveSelf), "{err:?}");

    // The refused call changed nothing.
    assert!(harness.saro().can_send(&convo_id));
    assert_eq!(
        harness
            .saro()
            .group_signers(&convo_id)
            .expect("members")
            .len(),
        2
    );
}

#[test]
fn remove_signer_rejects_a_non_signer() {
    // Someone who never joined holds no leaf, so the call fails before any
    // round opens.
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();

    let mut harness = TestHarness::<3>::new(|_, _| {});

    let pax_account = harness.pax().account();
    let particpants = &[harness.raya().account()];
    let convo_id = harness
        .saro()
        .create_group_convo_v2(particpants, "", "")
        .expect("Saro create");

    harness.process_until_label("Raya join", |h| h.raya().convo_count() == 1);

    let err = harness
        .saro()
        .group_remove_participants(&convo_id, &[pax_account])
        .expect_err("Pax is not a member");
    assert!(matches!(err, ChatError::NotAGroupMember), "{err:?}");
}

#[test]
fn a_removal_during_the_freeze_reports_the_group_busy() {
    // In a group of two both members are stewards, and Raya cannot commit its
    // own removal, so Saro's freeze never gets the second candidate that would
    // end it early: it runs its whole window, many harness steps long.
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();

    let mut harness = TestHarness::<2>::new(|_, _| {});

    let raya_account = harness.raya().account();
    let convo_id = harness
        .saro()
        .create_group_convo_v2(std::slice::from_ref(&raya_account), "", "")
        .expect("Saro create");

    harness.process_until_label("Raya join", |h| h.raya().convo_count() == 1);

    harness
        .saro()
        .group_remove_participants(&convo_id, std::slice::from_ref(&raya_account))
        .expect("Saro remove Raya");

    // Asking again is a no-op while the first removal is in flight, and
    // refused from the moment Saro freezes for its commit.
    harness.process_until_label("Saro freezes", |h| {
        h.saro()
            .group_remove_participants(&convo_id, std::slice::from_ref(&raya_account))
            .is_err()
    });
    let err = harness
        .saro()
        .group_remove_participants(&convo_id, std::slice::from_ref(&raya_account))
        .expect_err("refused during the freeze");
    assert!(matches!(err, ChatError::GroupBusy), "{err:?}");

    // The refusal passes: the removal in flight still lands.
    harness.process_until_label("Raya removed", |h| {
        h.saro().group_signers(&convo_id).map_or(0, |m| m.len()) == 1
    });
}

#[test]
fn group_name_propagation() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();

    let name = "Jankiest Friends";
    let desc = "A cool group chat, with cool people";

    let mut harness = TestHarness::<4>::new(|_, _| {});

    let members = &[harness.raya().account()];
    let convo_id = harness
        .saro()
        .create_group_convo_v2(members, name, desc)
        .expect("Saro create");

    // Carry the invite through (commit, WelcomeReady, routing to Raya's inbox,
    // accept_welcome); settle until Raya has joined.
    harness.process_until_label("Raya join", |h| h.raya().convo_count() == 1);

    // Verfiy that Saro's Metadata is correct
    assert_eq!(
        harness.saro().convo_metadata(&convo_id).expect("meta").name,
        name
    );
    assert_eq!(
        harness.saro().convo_metadata(&convo_id).expect("meta").desc,
        desc
    );

    // Verify that Raya has the same MetaData
    assert_eq!(
        harness.saro().convo_metadata(&convo_id).expect("meta").name,
        harness.raya().convo_metadata(&convo_id).expect("meta").name
    );
    assert_eq!(
        harness.saro().convo_metadata(&convo_id).expect("meta").desc,
        harness.raya().convo_metadata(&convo_id).expect("meta").desc
    );

    // Epoch 2: Raya adds the 3rd member; settle until Pax has joined
    let members = &[harness.pax().account()];
    harness
        .raya()
        .group_add_participants(&convo_id, members)
        .expect("Add Pax");

    harness.process_until_label("Pax join", |h| h.pax().convo_count() == 1);

    // Verify that Pax has the same MetaData
    assert_eq!(
        harness.saro().convo_metadata(&convo_id).expect("meta").name,
        harness.pax().convo_metadata(&convo_id).expect("meta").name
    );
    assert_eq!(
        harness.saro().convo_metadata(&convo_id).expect("meta").desc,
        harness.pax().convo_metadata(&convo_id).expect("meta").desc
    );
}

#[test]
fn member_joins_two_groups() {
    // The same installation is invited to two separate groups. Its single
    // registered key package is consumed by the first join, so the second
    // group's welcome must still admit it — otherwise it is rejected with
    // "welcome not addressed to this member" and never joins. Regression for
    // key-package reuse across groups.
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();

    let mut harness = TestHarness::<2>::new(|_, _| {});
    let raya_account = harness.raya().account();

    // Group 1: Saro invites Raya.
    harness
        .saro()
        .create_group_convo_v2(std::slice::from_ref(&raya_account), "", "")
        .expect("saro create group 1");
    harness.process_until_label("raya joins group 1", |h| h.raya().convo_count() == 1);

    // Group 2: Saro invites Raya again, into a fresh group.
    harness
        .saro()
        .create_group_convo_v2(&[raya_account], "", "")
        .expect("saro create group 2");
    harness.process_until_label("raya joins group 2", |h| h.raya().convo_count() == 2);

    assert_eq!(
        harness.raya().convo_count(),
        2,
        "raya did not join the second group"
    );
}

#[test]
fn direct_v1_then_group_v2_reuses_key_package() {
    // The reported flake: a DirectV1 (pairwise) conversation is opened with a
    // peer first, then the same peer is invited to a GroupV2. Both fetch the
    // peer's single registered key package; the DirectV1 join consumes it, so
    // without a last-resort key package the group welcome finds no key package
    // and is rejected ("welcome not addressed to this member").
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();

    let mut harness = TestHarness::<2>::new(|_, _| {});
    let raya_account = harness.raya().account();

    // 1. DirectV1 with Raya.
    harness
        .saro()
        .create_direct_convo_v1(raya_account.clone())
        .expect("saro create direct");
    harness.process_until_label("raya joins direct", |h| h.raya().convo_count() == 1);

    // 2. GroupV2 inviting the same Raya.
    harness
        .saro()
        .create_group_convo_v2(&[raya_account], "", "")
        .expect("saro create group");
    harness.process_until_label("raya joins group", |h| h.raya().convo_count() == 2);

    assert_eq!(
        harness.raya().convo_count(),
        2,
        "raya did not join the group after a direct chat"
    );
}

/// End-to-end causal-history gap detection on GroupV2.
///
/// Saro and Raya share a GroupV2 conversation. Saro sends three messages; the
/// second never reaches Raya. The third carries the second in its causal
/// history, so Raya must detect and report the gap.
#[test]
fn missing_group_v2_message_is_detected() {
    let mut harness = TestHarness::<2>::new(|_, _| {});

    let participants = &[harness.raya().account()];
    let convo_id = harness
        .saro()
        .create_group_convo_v2(participants, "", "")
        .expect("saro create group");

    // Carry the invite through (commit, WelcomeReady, inbox routing, welcome
    // accept) until Raya has joined.
    harness.process_until_label("raya joins", |h| h.raya().convo_count() == 1);

    // M1 is delivered normally.
    harness
        .saro()
        .send_content(&convo_id, b"first")
        .expect("saro send m1");
    harness.process_until_label("raya gets m1", |h| h.raya().check(&convo_id, b"first"));
    assert!(
        harness.raya().take_missing_messages().is_empty(),
        "no gap expected while every message is delivered"
    );

    // M2 is published but never reaches Raya. The settle above drained Raya's
    // queue, and `send_content` publishes synchronously, so discarding what is
    // pending now drops that message and nothing of the group protocol.
    harness
        .saro()
        .send_content(&convo_id, b"second")
        .expect("saro send m2");
    harness.raya().drop_pending_payloads();

    // M3 is delivered; its causal history references the dropped M2.
    harness
        .saro()
        .send_content(&convo_id, b"third")
        .expect("saro send m3");
    harness.process_until_label("raya gets m3", |h| h.raya().check(&convo_id, b"third"));

    let saro_signer = harness.saro().signer_key();
    let missing: Vec<MissingMessage> = harness.raya().take_missing_messages();
    assert_eq!(missing.len(), 1, "exactly one message should be missing");
    assert_eq!(missing[0].conversation_id, convo_id);
    assert!(
        !missing[0].frontier.message_id().is_empty(),
        "the missing message must be identified"
    );
    // The hint names the sender by its signer.
    assert_eq!(
        missing[0].frontier.sender(),
        &saro_signer,
        "missing-message sender hint should attribute to Saro"
    );

    // Draining clears the report; a reported gap is not surfaced again.
    assert!(harness.raya().take_missing_messages().is_empty());
}

/// End-to-end acknowledgement detection on GroupV2.
///
/// Saro sends a message; Raya and Pax reply. Each reply carries Saro's message
/// in its causal history, so Saro learns both peers hold it — without either
/// sending anything back on purpose.
#[test]
fn replies_acknowledge_the_message_they_were_sent_after() {
    let mut harness = TestHarness::<3>::new(|_, _| {});

    let participants = &[harness.raya().account(), harness.pax().account()];
    let convo_id = harness
        .saro()
        .create_group_convo_v2(participants, "", "")
        .expect("saro create group");

    harness.process_until_label("peers join", |h| {
        h.raya().convo_count() == 1 && h.pax().convo_count() == 1
    });

    let message_id = harness
        .saro()
        .send_content(&convo_id, b"anyone there?")
        .expect("saro send");
    harness.process_until_label("peers get the message", |h| {
        h.raya().check(&convo_id, b"anyone there?") && h.pax().check(&convo_id, b"anyone there?")
    });
    assert!(
        harness.saro().take_acks().is_empty(),
        "holding a message is only observable once the peer sends"
    );

    // Each reply names Saro's message in its causal history.
    harness
        .raya()
        .send_content(&convo_id, b"raya here")
        .expect("raya reply");
    harness
        .pax()
        .send_content(&convo_id, b"pax here")
        .expect("pax reply");
    harness.process_until_label("saro gets both replies", |h| {
        h.saro().check(&convo_id, b"raya here") && h.saro().check(&convo_id, b"pax here")
    });

    let raya_signer = harness.raya().signer_key();
    let pax_signer = harness.pax().signer_key();
    let acks: Vec<DeliveryAck> = harness.saro().take_acks();
    let mut holders: Vec<String> = acks
        .iter()
        .filter(|a| a.conversation_id == convo_id && a.message_id == message_id)
        .map(|a| a.acked_by.to_string())
        .collect();
    holders.sort_unstable();
    let mut expected = [pax_signer.to_string(), raya_signer.to_string()];
    expected.sort_unstable();
    assert_eq!(
        holders, expected,
        "both peers that replied should be reported as holding the message"
    );

    // Draining clears the reports, and neither peer acknowledges twice.
    assert!(harness.saro().take_acks().is_empty());
    harness
        .raya()
        .send_content(&convo_id, b"raya again")
        .expect("raya second reply");
    harness.process_until_label("saro gets the second reply", |h| {
        h.saro().check(&convo_id, b"raya again")
    });
    assert!(
        harness
            .saro()
            .take_acks()
            .iter()
            .all(|a| a.message_id != message_id),
        "a peer acknowledges one message only once"
    );
}
