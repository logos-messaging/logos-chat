//! What a failed operation costs the conversation it touched: the store keeps what it had, and
//! the conversation is rebuilt from it at once, so even an entry point that reads only the cache
//! finds it.
//!
//! Saro runs over a store whose transactions can be made to fail when they land. He builds a
//! GroupV1 group with Raya, then adds Pax with the store refusing to commit: the add merges its
//! own commit in memory, an epoch ahead of Raya, and fails only as its transaction lands. Saro's
//! next message is what proves the reload, because Raya decrypts it: only the epoch the store kept
//! could produce it. A reload that fails too leaves the conversation out of the cache, and the
//! next call addressing it rebuilds it. A call the conversation simply does not support costs it
//! nothing at all.

use components::{EphemeralRegistry, LocalBroadcaster};
use integration_tests_core::{
    FaultStore, Faults, PeerCore, TestIdent, content, drain, open_core, open_peer, scope_entries,
};
use libchat::{ChatError, ConversationKind};
use shared_traits::IdentId;

#[test]
fn a_failed_operation_keeps_the_store_and_reloads_the_conversation() {
    let ds = LocalBroadcaster::new();
    let rs = EphemeralRegistry::new();

    let mut raya = open_peer("raya", ds.new_consumer(), rs.clone());
    let raya_id = raya.ident_id().clone();
    let pax = open_peer("pax", ds.new_consumer(), rs.clone());
    let pax_id = pax.ident_id().clone();

    let faults = Faults::new();
    let mut saro = open_core(
        TestIdent::new("saro"),
        ds.new_consumer(),
        rs.clone(),
        faults.store(),
    );

    let convo_id = saro.create_group_convo_v1(&[&raya_id]).unwrap();
    drain(&mut raya);
    assert_eq!(
        raya.list_all_conversations().unwrap(),
        vec![convo_id.clone()]
    );
    let before = scope_entries(saro.store(), ConversationKind::GroupV1, &convo_id);

    faults.fail_commit(true);
    assert!(saro.group_add_member(&convo_id, &[&pax_id]).is_err());
    faults.fail_commit(false);

    // `can_send` reads only the cache, so it holds the conversation before any call rebuilds it.
    assert!(saro.can_send(&convo_id));
    assert_eq!(
        scope_entries(saro.store(), ConversationKind::GroupV1, &convo_id),
        before
    );

    saro.send_content(&convo_id, b"after the rollback").unwrap();
    assert_eq!(
        content(&drain(&mut raya)),
        vec![b"after the rollback".to_vec()]
    );
}

#[test]
fn a_reloaded_conversation_reports_the_roster_the_store_kept() {
    let ds = LocalBroadcaster::new();
    let rs = EphemeralRegistry::new();

    let mut raya = open_peer("raya", ds.new_consumer(), rs.clone());
    let raya_id = raya.ident_id().clone();
    let pax = open_peer("pax", ds.new_consumer(), rs.clone());
    let pax_id = pax.ident_id().clone();

    let faults = Faults::new();
    let mut saro = open_core(
        TestIdent::new("saro"),
        ds.new_consumer(),
        rs.clone(),
        faults.store(),
    );

    let convo_id = saro.create_group_convo_v1(&[&raya_id]).unwrap();
    drain(&mut raya);
    let mut before = saro.group_members(&convo_id).unwrap();
    before.sort();

    faults.fail_commit(true);
    assert!(saro.group_add_member(&convo_id, &[&pax_id]).is_err());
    faults.fail_commit(false);

    // The reload rebuilt the roster the store kept, not the one the failed add merged.
    let mut after = saro.group_members(&convo_id).unwrap();
    after.sort();
    assert_eq!(after, before);
}

#[test]
fn a_conversation_whose_reload_fails_is_rebuilt_by_the_next_call() {
    let ds = LocalBroadcaster::new();
    let rs = EphemeralRegistry::new();

    let mut raya = open_peer("raya", ds.new_consumer(), rs.clone());
    let raya_id = raya.ident_id().clone();
    let pax = open_peer("pax", ds.new_consumer(), rs.clone());
    let pax_id = pax.ident_id().clone();

    let faults = Faults::new();
    let mut saro = open_core(
        TestIdent::new("saro"),
        ds.new_consumer(),
        rs.clone(),
        faults.store(),
    );

    let convo_id = saro.create_group_convo_v1(&[&raya_id]).unwrap();
    drain(&mut raya);

    fail_add_and_its_reload(&mut saro, &faults, &convo_id, &pax_id);
    assert!(!saro.can_send(&convo_id));

    // A read rebuilds it, with the roster the store kept.
    assert_eq!(saro.group_members(&convo_id).unwrap().len(), 2);
    assert!(saro.can_send(&convo_id));

    // So does an operation, with the epoch the store kept.
    fail_add_and_its_reload(&mut saro, &faults, &convo_id, &pax_id);
    saro.send_content(&convo_id, b"after the failed reload")
        .unwrap();
    assert_eq!(
        content(&drain(&mut raya)),
        vec![b"after the failed reload".to_vec()]
    );
}

/// Fails an add as its transaction lands, and the reload after it as it reads the record naming
/// the conversation's kind, which leaves the conversation out of the cache.
fn fail_add_and_its_reload(
    saro: &mut PeerCore<FaultStore>,
    faults: &Faults,
    convo_id: &str,
    member: &IdentId,
) {
    faults.fail_commit(true);
    faults.fail_load(true);
    assert!(saro.group_add_member(convo_id, &[member]).is_err());
    faults.fail_commit(false);
    faults.fail_load(false);
}

#[test]
fn a_call_the_conversation_does_not_support_costs_it_nothing() {
    let ds = LocalBroadcaster::new();
    let rs = EphemeralRegistry::new();

    let mut raya = open_peer("raya", ds.new_consumer(), rs.clone());
    let raya_id = raya.ident_id().clone();
    let pax = open_peer("pax", ds.new_consumer(), rs.clone());
    let pax_id = pax.ident_id().clone();

    let faults = Faults::new();
    let mut saro = open_core(
        TestIdent::new("saro"),
        ds.new_consumer(),
        rs.clone(),
        faults.store(),
    );
    let convo_id = saro.create_direct_convo_v1(&[&raya_id]).unwrap();
    drain(&mut raya);

    // The refusal opens the one transaction the call begins with; a reload would open another.
    let begun = faults.begins();
    assert!(matches!(
        saro.group_add_member(&convo_id, &[&pax_id]),
        Err(ChatError::UnsupportedFunction(..))
    ));
    assert_eq!(faults.begins(), begun + 1);

    assert_eq!(saro.group_members(&convo_id).unwrap().len(), 2);
    saro.send_content(&convo_id, b"after the refusal").unwrap();
    assert_eq!(
        content(&drain(&mut raya)),
        vec![b"after the refusal".to_vec()]
    );
}
