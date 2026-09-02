//! A conversation carries on across a `Core` restart (issue #112).
//!
//! Saro and Raya hold a DirectV1 conversation, then one side drops its `Core` and reopens it on
//! the same database with the same signer. The peer's next message reaches the reopened side
//! without it sending anything first, which takes both the group rebuilt from its scope and the
//! delivery subscription that rebuild restores. Answering that message then shows the rebuilt
//! group still encrypts to the peer.
//!
//! Both sides are covered, because a creator and a joiner write their group state through
//! different paths. A reopened member also passes over its own message when a transport hands it
//! back, though the rebuilt group has no memory of sending it. A member removed before the restart
//! stays removed, and is refused as such rather than as a signer its group does not know.

use chat_sqlite::{SqliteStore, StorageConfig};
use components::{EphemeralRegistry, LocalBroadcaster};
use integration_tests_core::{NoopWakeupService, TestIdent};
use libchat::{ChatError, ConvoOutcome, Core, PayloadOutcome};

type TestCore = Core<(
    TestIdent,
    LocalBroadcaster,
    EphemeralRegistry,
    NoopWakeupService,
    SqliteStore,
)>;

const SARO_SEED: [u8; 32] = [1; 32];
const RAYA_SEED: [u8; 32] = [2; 32];

/// Opens an installation over `db_path`. Calling it again after a drop restarts that same
/// installation: the store holds its state and the seed reproduces the signer it is addressed by.
fn open(
    name: &str,
    seed: &[u8; 32],
    ds: LocalBroadcaster,
    rs: EphemeralRegistry,
    db_path: &str,
) -> TestCore {
    let store = SqliteStore::new(StorageConfig::File(db_path.to_string())).unwrap();
    Core::new_from_store(
        TestIdent::from_seed(name, seed),
        ds,
        rs,
        NoopWakeupService,
        store,
    )
    .unwrap()
}

/// Handles everything the transport is holding for `core`, returning the conversation content it
/// decrypted.
fn drain(core: &mut TestCore) -> Vec<Vec<u8>> {
    let payloads: Vec<_> = {
        let ds = core.ds();
        std::iter::from_fn(|| ds.poll()).collect()
    };

    let mut received = vec![];
    for payload in payloads {
        if let PayloadOutcome::Convo(ConvoOutcome {
            content: Some(content),
            ..
        }) = core.handle_payload(&payload).unwrap()
        {
            received.push(content.bytes);
        }
    }
    received
}

#[test]
fn a_direct_v1_creator_resumes_after_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let saro_db = dir.path().join("saro.db").to_string_lossy().into_owned();
    let raya_db = dir.path().join("raya.db").to_string_lossy().into_owned();

    let ds = LocalBroadcaster::new();
    let rs = EphemeralRegistry::new();

    let mut raya = open("raya", &RAYA_SEED, ds.new_consumer(), rs.clone(), &raya_db);
    let mut saro = open("saro", &SARO_SEED, ds.new_consumer(), rs.clone(), &saro_db);

    let raya_id = raya.ident_id().clone();
    let convo_id = saro.create_direct_convo_v1(&[&raya_id]).unwrap();
    drain(&mut raya);

    drop(saro);
    let mut saro = open("saro", &SARO_SEED, ds.new_consumer(), rs.clone(), &saro_db);

    raya.send_content(&convo_id, b"while you were out").unwrap();
    assert_eq!(
        drain(&mut saro),
        vec![b"while you were out".to_vec()],
        "the reopened core has sent nothing, so only a conversation rebuilt at open can be \
         listening for this"
    );

    saro.send_content(&convo_id, b"back now").unwrap();
    assert_eq!(drain(&mut raya), vec![b"back now".to_vec()]);
}

#[test]
fn a_direct_v1_joiner_resumes_after_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let saro_db = dir.path().join("saro.db").to_string_lossy().into_owned();
    let raya_db = dir.path().join("raya.db").to_string_lossy().into_owned();

    let ds = LocalBroadcaster::new();
    let rs = EphemeralRegistry::new();

    let mut raya = open("raya", &RAYA_SEED, ds.new_consumer(), rs.clone(), &raya_db);
    let mut saro = open("saro", &SARO_SEED, ds.new_consumer(), rs.clone(), &saro_db);

    let raya_id = raya.ident_id().clone();
    let convo_id = saro.create_direct_convo_v1(&[&raya_id]).unwrap();
    drain(&mut raya);

    drop(raya);
    let mut raya = open("raya", &RAYA_SEED, ds.new_consumer(), rs.clone(), &raya_db);

    saro.send_content(&convo_id, b"still there?").unwrap();
    assert_eq!(
        drain(&mut raya),
        vec![b"still there?".to_vec()],
        "the reopened core has sent nothing, so only a conversation rebuilt at open can be \
         listening for this"
    );

    raya.send_content(&convo_id, b"still here").unwrap();
    assert_eq!(drain(&mut saro), vec![b"still here".to_vec()]);
}

#[test]
fn a_resumed_conversation_passes_over_its_own_message() {
    let dir = tempfile::tempdir().unwrap();
    let saro_db = dir.path().join("saro.db").to_string_lossy().into_owned();
    let raya_db = dir.path().join("raya.db").to_string_lossy().into_owned();

    let ds = LocalBroadcaster::new();
    let rs = EphemeralRegistry::new();

    let mut raya = open("raya", &RAYA_SEED, ds.new_consumer(), rs.clone(), &raya_db);
    let mut saro = open("saro", &SARO_SEED, ds.new_consumer(), rs.clone(), &saro_db);

    let raya_id = raya.ident_id().clone();
    let convo_id = saro.create_direct_convo_v1(&[&raya_id]).unwrap();
    drain(&mut raya);

    // Opened before the send and never used to publish, this consumer hands the reopened core the
    // message it sent, as a transport that echoes a member's own frames does.
    let echoing = ds.new_consumer();
    saro.send_content(&convo_id, b"before the restart").unwrap();

    drop(saro);
    let mut saro = open("saro", &SARO_SEED, echoing, rs.clone(), &saro_db);

    let echoes: Vec<_> = std::iter::from_fn(|| saro.ds().poll()).collect();
    assert_eq!(echoes.len(), 1);
    assert!(matches!(
        saro.handle_payload(&echoes[0]).unwrap(),
        PayloadOutcome::Convo(ConvoOutcome { content: None, .. })
    ));
}

#[test]
fn a_member_removed_before_a_restart_is_refused_as_removed() {
    let dir = tempfile::tempdir().unwrap();
    let saro_db = dir.path().join("saro.db").to_string_lossy().into_owned();
    let raya_db = dir.path().join("raya.db").to_string_lossy().into_owned();

    let ds = LocalBroadcaster::new();
    let rs = EphemeralRegistry::new();

    let mut raya = open("raya", &RAYA_SEED, ds.new_consumer(), rs.clone(), &raya_db);
    let mut saro = open("saro", &SARO_SEED, ds.new_consumer(), rs.clone(), &saro_db);

    let saro_id = saro.ident_id().clone();
    let convo_id = raya.create_group_convo_v1(&[&saro_id]).unwrap();
    drain(&mut saro);
    raya.group_remove_member(&convo_id, &[&saro_id]).unwrap();
    drain(&mut saro);

    drop(saro);
    let mut saro = open("saro", &SARO_SEED, ds.new_consumer(), rs.clone(), &saro_db);

    // Removal left Saro no leaf, which is not a leaf naming another signer.
    assert!(!saro.can_send(&convo_id));
    let refused = saro.send_content(&convo_id, b"still here?");
    assert!(refused.is_err());
    assert!(!matches!(refused, Err(ChatError::ForeignSigner(_))));
}
