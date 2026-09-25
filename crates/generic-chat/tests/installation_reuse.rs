//! An installation outlives the client that created it (issue #28).
//!
//! Every open used to mint a new key, so a restarted client was a stranger: a new account
//! address for peers to learn, a new rendezvous address for invites to miss, and a new signer
//! that no stored conversation's leaf names.

use chat_sqlite::{DbKey, SqliteStore, StorageConfig};
use components::EphemeralRegistry;
use integration_tests_core::AcceptAllAuth;
use libchat::{IdentityProvider, IdentityStore, StoredInstallation};
use logos_account::AccountAddr;
use logos_generic_chat::{
    ChatClientBuilder, ClientError, InProcessDelivery, Installation, MessageBus,
    PendingInstallation,
};

/// A store on a real file, so that dropping it and opening it again is a restart rather than a
/// handle being passed around.
fn open_store(path: &str) -> SqliteStore {
    SqliteStore::new(StorageConfig::EncryptedWithKey {
        path: path.to_string(),
        key: DbKey::from([9u8; 32]),
    })
    .expect("a store on a temporary path opens")
}

fn an_account() -> AccountAddr {
    AccountAddr::try_from(
        crypto::Ed25519SigningKey::generate()
            .verifying_key()
            .as_ref(),
    )
    .expect("a generated key is an address")
}

/// Load-or-create, as a client stack does at startup.
fn open_installation(store: &mut SqliteStore) -> Installation {
    match Installation::load(store).expect("the store is readable") {
        Some(installation) => installation,
        None => {
            let installation = PendingInstallation::generate().complete(an_account());
            installation.save(store).expect("the store is writable");
            installation
        }
    }
}

fn db_path(dir: &tempfile::TempDir) -> String {
    dir.path().join("saro.db").to_string_lossy().into_owned()
}

/// The headline. `addr` is what a peer was told to reach and `installation_name` is the
/// rendezvous an invite is addressed to, so a restart changing either strands every peer.
#[test]
fn a_client_reopens_as_the_installation_its_store_holds() {
    let dir = tempfile::tempdir().unwrap();
    let path = db_path(&dir);
    let bus = MessageBus::default();
    let reg = EphemeralRegistry::new();
    let auth = AcceptAllAuth::default();

    let open = |bus: MessageBus, reg: EphemeralRegistry| {
        let mut store = open_store(&path);
        let installation = open_installation(&mut store);
        auth.register(&installation);
        let (client, _events) = ChatClientBuilder::new(installation)
            .transport(InProcessDelivery::new(bus))
            .registration(reg)
            .auth(auth.clone())
            .storage(store)
            .build()
            .expect("the client opens");
        (client.addr().to_string(), client.installation_name())
    };

    let first = open(bus.clone(), reg.clone());
    let second = open(bus, reg);

    assert_eq!(second, first, "the identity peers reach must not change");
}

/// What a stored conversation's leaf names: the same signer, still signing the same bytes.
#[test]
fn the_stored_signer_is_the_one_that_signs() {
    let dir = tempfile::tempdir().unwrap();
    let path = db_path(&dir);

    let (signer, signature) = {
        let installation = open_installation(&mut open_store(&path));
        (
            installation.signer_key().clone(),
            installation.sign(b"before the restart"),
        )
    };

    let reopened = open_installation(&mut open_store(&path));

    assert_eq!(reopened.signer_key(), &signer);
    assert_eq!(
        reopened.sign(b"before the restart").as_ref(),
        signature.as_ref()
    );
}

/// A record shaped by another build must stop the open. Reading it as "nothing stored" would
/// register a second installation over the first's conversations, and the only symptom would be
/// peers no longer able to decrypt.
#[test]
fn an_unreadable_record_stops_the_open_rather_than_replacing_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = db_path(&dir);

    open_store(&path)
        .save_installation(&StoredInstallation::new(b"from another build".to_vec()))
        .unwrap();

    assert!(matches!(
        Installation::load(&open_store(&path)),
        Err(ClientError::MalformedInstallationRecord(_))
    ));
}

/// The database key protects the identity, not just the conversations.
#[test]
fn the_installation_is_unreachable_without_the_database_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = db_path(&dir);
    open_installation(&mut open_store(&path));

    let Err(err) = SqliteStore::new(StorageConfig::EncryptedWithKey {
        path,
        key: DbKey::from([1u8; 32]),
    }) else {
        panic!("a store must not open under a key that did not write it");
    };
    assert!(err.to_string().contains("key is incorrect"), "got: {err}");
}
