//! What a failed operation costs the conversation it touched: the store keeps what it had, and
//! the conversation stays addressable, through whichever entry point comes next.
//!
//! Saro runs over a store whose transactions can be made to fail when they land. He builds a
//! GroupV1 group with Raya, then adds Pax with the store refusing to commit: the add merges its
//! own commit in memory, an epoch ahead of Raya, and fails only as its unit lands. Saro's next
//! message is what proves the reload, because Raya decrypts it: only the epoch the store kept
//! could produce it. A call the conversation simply does not support costs it nothing at all.

use components::{EphemeralRegistry, LocalBroadcaster};
use integration_tests_core::{
    FaultStore, Faults, NoopWakeupService, PeerCore, TestIdent, open_peer,
};
use libchat::{ChatError, Core, KvPair, KvTransaction, PayloadOutcome, Protocol};

type FaultyCore = Core<(
    TestIdent,
    LocalBroadcaster,
    EphemeralRegistry,
    NoopWakeupService,
    FaultStore,
)>;

/// The same peer over a store that refuses what `faults` names.
fn open_faulty_peer(
    name: &str,
    ds: LocalBroadcaster,
    rs: EphemeralRegistry,
    faults: &Faults,
) -> FaultyCore {
    Core::new_from_store(
        TestIdent::new(name),
        ds,
        rs,
        NoopWakeupService,
        faults.store(),
    )
    .unwrap()
}

/// Hands `core` every payload published since the last call.
fn drain(core: &mut PeerCore) -> Vec<PayloadOutcome> {
    let mut payloads = Vec::new();
    while let Some(payload) = core.ds().poll() {
        payloads.push(payload);
    }
    payloads
        .iter()
        .map(|payload| core.handle_payload(payload).unwrap())
        .collect()
}

/// Everything a conversation's own scope holds.
fn scope_entries(store: &FaultStore, ns: Protocol, convo_id: &str) -> Vec<KvPair> {
    let tx = KvTransaction::begin(store).unwrap();
    tx.scope(ns, convo_id).scan_prefix(b"").unwrap()
}

fn received(outcomes: &[PayloadOutcome], content: &[u8]) -> bool {
    outcomes.iter().any(|outcome| match outcome {
        PayloadOutcome::Convo(convo) => convo
            .content
            .as_ref()
            .is_some_and(|received| received.bytes.as_slice() == content),
        _ => false,
    })
}

#[test]
fn a_failed_operation_keeps_the_store_and_reloads_the_conversation() {
    let ds = LocalBroadcaster::new();
    let rs = EphemeralRegistry::new();

    let mut raya = open_peer("raya", ds.new_consumer(), rs.clone());
    let raya_id = raya.ident_id().clone();
    let pax = open_peer("pax", ds.new_consumer(), rs.clone());
    let pax_id = pax.ident_id().clone();

    let faults = Faults::new();
    let mut saro = open_faulty_peer("saro", ds.new_consumer(), rs.clone(), &faults);

    let convo_id = saro.create_group_convo_v1(&[&raya_id]).unwrap();
    drain(&mut raya);
    assert_eq!(raya.list_conversations().unwrap(), vec![convo_id.clone()]);
    let before = scope_entries(saro.store(), Protocol::GroupV1, &convo_id);

    faults.fail_commit(true);
    assert!(saro.group_add_member(&convo_id, &[&pax_id]).is_err());
    faults.fail_commit(false);

    assert_eq!(
        scope_entries(saro.store(), Protocol::GroupV1, &convo_id),
        before
    );

    saro.send_content(&convo_id, b"after the rollback").unwrap();
    assert!(received(&drain(&mut raya), b"after the rollback"));
}

#[test]
fn a_read_rebuilds_the_conversation_a_failed_operation_dropped() {
    let ds = LocalBroadcaster::new();
    let rs = EphemeralRegistry::new();

    let mut raya = open_peer("raya", ds.new_consumer(), rs.clone());
    let raya_id = raya.ident_id().clone();
    let pax = open_peer("pax", ds.new_consumer(), rs.clone());
    let pax_id = pax.ident_id().clone();

    let faults = Faults::new();
    let mut saro = open_faulty_peer("saro", ds.new_consumer(), rs.clone(), &faults);

    let convo_id = saro.create_group_convo_v1(&[&raya_id]).unwrap();
    drain(&mut raya);
    let mut before = saro.group_members(&convo_id).unwrap();
    before.sort();

    faults.fail_commit(true);
    assert!(saro.group_add_member(&convo_id, &[&pax_id]).is_err());
    faults.fail_commit(false);

    // A read that opens no unit of its own rebuilds the conversation too, and reports the roster
    // the store kept rather than the one the failed add merged.
    let mut after = saro.group_members(&convo_id).unwrap();
    after.sort();
    assert_eq!(after, before);
}

#[test]
fn a_call_the_conversation_does_not_support_costs_it_nothing() {
    let ds = LocalBroadcaster::new();
    let rs = EphemeralRegistry::new();

    let mut raya = open_peer("raya", ds.new_consumer(), rs.clone());
    let raya_id = raya.ident_id().clone();
    let pax = open_peer("pax", ds.new_consumer(), rs.clone());
    let pax_id = pax.ident_id().clone();

    let mut saro = open_peer("saro", ds.new_consumer(), rs.clone());
    let convo_id = saro.create_direct_convo_v1(&[&raya_id]).unwrap();
    drain(&mut raya);

    assert!(matches!(
        saro.group_add_member(&convo_id, &[&pax_id]),
        Err(ChatError::UnsupportedFunction(..))
    ));

    assert_eq!(saro.group_members(&convo_id).unwrap().len(), 2);
    saro.send_content(&convo_id, b"after the refusal").unwrap();
    assert!(received(&drain(&mut raya), b"after the refusal"));
}
