//! Removing a conversation empties its scope and leaves its siblings untouched.
//!
//! Saro starts two GroupV1 conversations with Raya and removes one. Both hold the same key shapes
//! under different addresses, so what survives shows the address is all that keeps them apart:
//! the other scope holds exactly what it held, and the conversation still sends what Raya reads.
//!
//! A removal that fails once its record is gone can be run again, and finishes the job, even after
//! the half-removed conversation was addressed in between.

use std::time::Duration;

use components::{EphemeralRegistry, LocalBroadcaster};
use integration_tests_core::{Faults, TestHarness, TestIdent, open_core, open_peer, scope_entries};
use libchat::{ChatError, ConversationKind, KvStore};

/// The keys a GroupV1 conversation's own scope holds.
fn scope_keys(store: &impl KvStore, convo_id: &str) -> Vec<Vec<u8>> {
    scope_entries(store, ConversationKind::GroupV1, convo_id)
        .into_iter()
        .map(|(key, _)| key)
        .collect()
}

#[test]
fn removing_a_conversation_empties_its_scope_and_leaves_its_sibling_usable() {
    let mut harness = TestHarness::<2>::new(|_, _| {});
    let raya_id = harness.raya().addr();

    let kept = harness.saro().create_group_convo_v1(&[&raya_id]).unwrap();
    let removed = harness.saro().create_group_convo_v1(&[&raya_id]).unwrap();
    harness.process_until(|h| h.raya().convo_count() == 2);

    let kept_keys = scope_keys(harness.saro().store(), &kept);
    assert!(!kept_keys.is_empty());
    assert!(!scope_keys(harness.saro().store(), &removed).is_empty());

    harness.saro().remove_conversation(&removed).unwrap();

    assert!(scope_keys(harness.saro().store(), &removed).is_empty());
    assert_eq!(scope_keys(harness.saro().store(), &kept), kept_keys);
    assert!(
        !harness
            .saro()
            .list_all_conversations()
            .unwrap()
            .contains(&removed)
    );
    assert!(matches!(
        harness.saro().send_content(&removed, b"gone"),
        Err(ChatError::NoConvo(_))
    ));

    harness.saro().send_content(&kept, b"still here").unwrap();
    harness.process(Duration::from_millis(50));
    assert!(harness.raya().check(&kept, b"still here"));
}

#[test]
fn a_removal_that_fails_partway_can_be_run_again() {
    let ds = LocalBroadcaster::new();
    let rs = EphemeralRegistry::new();

    let raya = open_peer("raya", ds.new_consumer(), rs.clone());
    let raya_id = raya.ident_id().clone();

    let faults = Faults::new();
    let mut saro = open_core(
        TestIdent::new("saro"),
        ds.new_consumer(),
        rs.clone(),
        faults.store(),
    );
    let convo_id = saro.create_group_convo_v1(&[&raya_id]).unwrap();

    // The record is gone by the time the scope's deletion fails to land, so nothing can rebuild
    // the conversation for a call made before the retry.
    faults.fail_commit(true);
    assert!(saro.remove_conversation(&convo_id).is_err());
    assert!(matches!(
        saro.send_content(&convo_id, b"meanwhile"),
        Err(ChatError::NoConvo(_))
    ));
    faults.fail_commit(false);

    saro.remove_conversation(&convo_id).unwrap();
    assert!(scope_keys(saro.store(), &convo_id).is_empty());
    assert!(!saro.list_all_conversations().unwrap().contains(&convo_id));
}
