//! A `Core` reopened on a store rebuilds the conversations that store lists (issue #113).
//!
//! Saro opens a `Core` over a file database, starts a DirectV1 and a GroupV1 conversation with
//! Raya, then drops the `Core` and opens a new one over the same file. Both conversations come
//! back in the cache, each as the type its record names. A GroupV2 conversation's record survives
//! the same way, but nothing can rebuild the conversation from it yet, so addressing it reports
//! `UnsupportedConvoType`.
//!
//! A record the store lists but cannot be rebuilt from is reported rather than passed over, so the
//! open never yields a `Core` missing a conversation its own store lists.
//!
//! Saro reopens under the signer he had, so a rebuilt conversation is sendable exactly when the
//! open cached it. Reopened under another signer, a conversation still reads but signs nothing,
//! neither a message nor a commit: its own leaf names the old key, and every member would reject
//! what the new one signs.

use chat_sqlite::{SqliteStore, StorageConfig};
use components::{EphemeralRegistry, LocalBroadcaster};
use integration_tests_core::{NoopWakeupService, PeerCore, TestIdent, open_peer};
use libchat::test_support::MemStore;
use libchat::{ChatError, ConversationKind, ConversationMeta, ConversationStore, Core};

type SaroCore = Core<(
    TestIdent,
    LocalBroadcaster,
    EphemeralRegistry,
    NoopWakeupService,
    SqliteStore,
)>;

const SARO_SEED: [u8; 32] = [1; 32];

/// Opens Saro over `db_path`; calling it again after a drop reopens the same installation.
fn open_saro(ds: LocalBroadcaster, rs: EphemeralRegistry, db_path: &str) -> SaroCore {
    open_saro_as(TestIdent::from_seed("saro", &SARO_SEED), ds, rs, db_path)
}

fn open_saro_as(
    ident: TestIdent,
    ds: LocalBroadcaster,
    rs: EphemeralRegistry,
    db_path: &str,
) -> SaroCore {
    let store = SqliteStore::new(StorageConfig::File(db_path.to_string())).unwrap();
    Core::new_from_store(ident, ds, rs, NoopWakeupService, store).unwrap()
}

/// Raya is here to publish a key package Saro can invite; she never processes a payload.
fn open_raya(ds: LocalBroadcaster, rs: EphemeralRegistry) -> PeerCore {
    open_peer("raya", ds, rs)
}

#[test]
fn direct_and_group_v1_conversations_are_rebuilt_at_open() {
    let dir = tempfile::tempdir().unwrap();
    let saro_db = dir.path().join("saro.db").to_string_lossy().into_owned();

    let ds = LocalBroadcaster::new();
    let rs = EphemeralRegistry::new();

    let raya = open_raya(ds.new_consumer(), rs.clone());
    let raya_id = raya.ident_id().clone();
    let pax = open_peer("pax", ds.new_consumer(), rs.clone());
    let pax_id = pax.ident_id().clone();

    let mut saro = open_saro(ds.new_consumer(), rs.clone(), &saro_db);
    let direct_id = saro.create_direct_convo_v1(&[&raya_id]).unwrap();
    let group_id = saro.create_group_convo_v1(&[&raya_id]).unwrap();

    drop(saro);
    let mut saro = open_saro(ds.new_consumer(), rs.clone(), &saro_db);

    // Only a cached conversation answers `can_send`, so it proves the conversation was rebuilt
    // at open and not merely listed by the store.
    assert!(saro.can_send(&direct_id));
    assert!(saro.can_send(&group_id));
    assert_eq!(saro.group_members(&direct_id).unwrap().len(), 2);
    assert_eq!(saro.group_members(&group_id).unwrap().len(), 2);

    // `add_member` is refused by a direct conversation and taken by a group, so it names the type
    // each record rebuilt.
    assert!(matches!(
        saro.group_add_member(&direct_id, &[&pax_id]),
        Err(ChatError::UnsupportedFunction(..))
    ));
    saro.group_add_member(&group_id, &[&pax_id]).unwrap();
}

#[test]
fn a_conversation_rebuilt_under_another_signer_reads_but_signs_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let saro_db = dir.path().join("saro.db").to_string_lossy().into_owned();

    let ds = LocalBroadcaster::new();
    let rs = EphemeralRegistry::new();

    let raya = open_raya(ds.new_consumer(), rs.clone());
    let raya_id = raya.ident_id().clone();
    let pax = open_peer("pax", ds.new_consumer(), rs.clone());
    let pax_id = pax.ident_id().clone();

    let mut saro = open_saro(ds.new_consumer(), rs.clone(), &saro_db);
    let direct_id = saro.create_direct_convo_v1(&[&raya_id]).unwrap();
    let group_id = saro.create_group_convo_v1(&[&raya_id]).unwrap();

    drop(saro);
    let mut saro = open_saro_as(
        TestIdent::new("saro"),
        ds.new_consumer(),
        rs.clone(),
        &saro_db,
    );

    assert_eq!(saro.group_members(&direct_id).unwrap().len(), 2);
    assert!(!saro.can_send(&direct_id));
    assert!(matches!(
        saro.send_content(&direct_id, b"under a new key"),
        Err(ChatError::ForeignSigner(_))
    ));

    // A commit is signed too, so the group adds and removes no one under the new key.
    assert!(!saro.can_send(&group_id));
    assert!(matches!(
        saro.group_add_member(&group_id, &[&pax_id]),
        Err(ChatError::ForeignSigner(_))
    ));
    assert!(matches!(
        saro.group_remove_member(&group_id, &[&raya_id]),
        Err(ChatError::ForeignSigner(_))
    ));
}

#[test]
fn a_group_v2_conversation_is_listed_but_not_rebuilt() {
    let dir = tempfile::tempdir().unwrap();
    let saro_db = dir.path().join("saro.db").to_string_lossy().into_owned();

    let ds = LocalBroadcaster::new();
    let rs = EphemeralRegistry::new();

    let raya = open_raya(ds.new_consumer(), rs.clone());
    let raya_id = raya.ident_id().clone();

    let mut saro = open_saro(ds.new_consumer(), rs.clone(), &saro_db);
    let convo_id = saro
        .create_group_convo_v2(&[&raya_id], "libchat", "storage")
        .unwrap();

    drop(saro);
    let mut saro = open_saro(ds.new_consumer(), rs.clone(), &saro_db);

    assert!(saro.list_all_conversations().unwrap().contains(&convo_id));
    assert!(matches!(
        saro.send_content(&convo_id, b"after reopen"),
        Err(ChatError::UnsupportedConvoType(_))
    ));
}

#[test]
fn a_record_whose_scope_holds_nothing_fails_the_open() {
    let ds = LocalBroadcaster::new();
    let rs = EphemeralRegistry::new();

    // A listed record whose scope was never written: nothing can rebuild the conversation it
    // names, so the open reports it rather than handing back a core that is missing it. The id is
    // the hex of an MLS group id, the shape a record carries wherever it came from.
    let mut store = MemStore::new();
    store
        .save_conversation(&ConversationMeta {
            local_convo_id: "7f3a9c2b5d8e1046".into(),
            kind: ConversationKind::GroupV1,
        })
        .unwrap();

    let opened = PeerCore::new_from_store(
        TestIdent::new("saro"),
        ds.new_consumer(),
        rs,
        NoopWakeupService,
        store,
    );

    assert!(
        matches!(&opened, Err(ChatError::NoConvo(_))),
        "{:?}",
        opened.as_ref().err()
    );
}
