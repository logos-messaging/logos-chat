//! A `Core` reopened on a store rebuilds the conversations that store lists (issue #113).
//!
//! Saro opens a `Core` over a file database, starts a DirectV1 and a GroupV1 conversation with
//! Raya, then drops the `Core` and opens a new one over the same file. Both conversations come
//! back in the cache, each as the type its record names. A GroupV2 conversation's record survives
//! the same way, but nothing can rebuild the conversation from it yet, so addressing it reports
//! `UnsupportedConvoType`.
//!
//! Saro's signer is not carried across the reopen, so what the rebuilt conversations can send is
//! out of view here.

use chat_sqlite::{SqliteStore, StorageConfig};
use components::{EphemeralRegistry, LocalBroadcaster};
use integration_tests_core::{NoopWakeupService, PeerCore, TestIdent, open_peer};
use libchat::{ChatError, Core};

type SaroCore = Core<(
    TestIdent,
    LocalBroadcaster,
    EphemeralRegistry,
    NoopWakeupService,
    SqliteStore,
)>;

/// Opens Saro over `db_path`; calling it again after a drop reopens the same store.
fn open_saro(ds: LocalBroadcaster, rs: EphemeralRegistry, db_path: &str) -> SaroCore {
    let store = SqliteStore::new(StorageConfig::File(db_path.to_string())).unwrap();
    Core::new_from_store(TestIdent::new("saro"), ds, rs, NoopWakeupService, store).unwrap()
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

    let mut saro = open_saro(ds.new_consumer(), rs.clone(), &saro_db);
    let direct_id = saro.create_direct_convo_v1(&[&raya_id]).unwrap();
    let group_id = saro.create_group_convo_v1(&[&raya_id]).unwrap();

    drop(saro);
    let mut saro = open_saro(ds.new_consumer(), rs.clone(), &saro_db);

    // A roster is answered from the cache alone, so it proves the conversation was rebuilt at
    // open and not merely listed by the store.
    assert_eq!(saro.group_members(&direct_id).unwrap().len(), 2);
    assert_eq!(saro.group_members(&group_id).unwrap().len(), 2);

    // Refusing `add_member` is what a direct conversation does and a group does not, so it
    // names the type the record rebuilt.
    assert!(matches!(
        saro.group_add_member(&direct_id, &[&raya_id]),
        Err(ChatError::UnsupportedFunction(..))
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
