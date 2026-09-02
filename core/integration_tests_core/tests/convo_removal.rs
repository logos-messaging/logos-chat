//! Removing a conversation empties its scope and leaves its siblings untouched.
//!
//! Saro starts two GroupV1 conversations with Raya and removes one. Both hold the same key shapes
//! under different addresses, so what survives shows the address is all that keeps them apart:
//! the other scope holds exactly what it held, and the conversation still sends what Raya reads.

use std::time::Duration;

use integration_tests_core::TestHarness;
use libchat::test_support::MemStore;
use libchat::{ChatError, KvTransaction, Protocol};

/// The keys a GroupV1 conversation's own scope holds.
fn scope_keys(store: &MemStore, convo_id: &str) -> Vec<Vec<u8>> {
    let tx = KvTransaction::begin(store).unwrap();
    tx.scope(Protocol::GroupV1, convo_id)
        .scan_prefix(b"")
        .unwrap()
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
            .list_conversations()
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
