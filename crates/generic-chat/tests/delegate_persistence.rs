//! The delegate outlives the client that minted it (issue #28).
//!
//! A client's address is the account its delegate signs for, and its device id is that
//! delegate's public key, so both survive a restart only if the signer is rebuilt from the
//! database rather than minted again. An open finds a stored delegate or mints one, endorsing
//! it in the directory; these tests cover both branches and the address a rebuilt client
//! reports.

use chat_sqlite::{SqliteStore, StorageConfig};
use components::EphemeralRegistry;
use crypto::Ed25519VerifyingKey;
use logos_account::{AccountDirectory, DeviceSet, SignedDeviceBundle};
use logos_generic_chat::{ChatClientBuilder, DelegateSigner, InProcessDelivery, MessageBus};
use tempfile::TempDir;

/// A database file of its own, kept alive by the returned directory.
fn database() -> (TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.db").to_string_lossy().into_owned();
    (dir, path)
}

fn open(path: &str) -> SqliteStore {
    SqliteStore::new(StorageConfig::File(path.to_string())).unwrap()
}

/// The account key an address is the hex of.
fn account_key(address: &str) -> Ed25519VerifyingKey {
    let bytes: [u8; 32] = hex::decode(address).unwrap().try_into().unwrap();
    Ed25519VerifyingKey::from_bytes(&bytes).unwrap()
}

/// Counts the bundles published through it, so a test can tell an open that
/// endorsed a delegate from one that reused the stored pair.
#[derive(Debug, Default)]
struct CountingDirectory {
    inner: EphemeralRegistry,
    publishes: usize,
}

impl AccountDirectory for CountingDirectory {
    type Error = String;

    fn publish(&mut self, bundle: &SignedDeviceBundle) -> Result<(), Self::Error> {
        self.publishes += 1;
        self.inner.publish(bundle)
    }

    fn fetch(&self, account: &Ed25519VerifyingKey) -> Result<Option<DeviceSet>, Self::Error> {
        self.inner.fetch(account)
    }
}

#[test]
fn a_fresh_database_mints_a_delegate_and_endorses_it() {
    let (_dir, path) = database();
    let mut directory = CountingDirectory::default();

    let (delegate, address) = DelegateSigner::load_or_mint(&open(&path), &mut directory).unwrap();

    assert_eq!(directory.publishes, 1);
    let endorsed = directory
        .fetch(&account_key(&address))
        .unwrap()
        .expect("the endorsing bundle");
    assert_eq!(
        endorsed.devices,
        vec![hex::encode(delegate.public_key().as_ref())]
    );
}

#[test]
fn a_reopened_database_returns_the_stored_delegate_and_endorses_nothing() {
    let (_dir, path) = database();
    let mut directory = CountingDirectory::default();

    let (minted, address) = DelegateSigner::load_or_mint(&open(&path), &mut directory).unwrap();
    let device = minted.public_key().clone();

    let (reopened, reopened_address) =
        DelegateSigner::load_or_mint(&open(&path), &mut directory).unwrap();

    assert_eq!(reopened.public_key(), &device);
    assert_eq!(reopened_address, address);
    assert_eq!(directory.publishes, 1);
}

#[test]
fn separate_databases_mint_separate_delegates() {
    let (_dir, path) = database();
    let (_other_dir, other_path) = database();
    let mut directory = CountingDirectory::default();

    let (first, first_address) =
        DelegateSigner::load_or_mint(&open(&path), &mut directory).unwrap();
    let (second, second_address) =
        DelegateSigner::load_or_mint(&open(&other_path), &mut directory).unwrap();

    assert_ne!(first.public_key(), second.public_key());
    assert_ne!(first_address, second_address);
    assert_eq!(directory.publishes, 2);
}

#[test]
fn a_client_rebuilt_on_the_same_database_keeps_its_address() {
    let (_dir, path) = database();
    let bus = MessageBus::default();
    let mut registry = EphemeralRegistry::new();

    let store = open(&path);
    let (delegate, address) = DelegateSigner::load_or_mint(&store, &mut registry).unwrap();
    let (client, _events) = ChatClientBuilder::new(address.clone())
        .ident(delegate)
        .transport(InProcessDelivery::new(bus.clone()))
        .registration(registry.clone())
        .storage(store)
        .build()
        .expect("client create");
    assert_eq!(client.addr(), address);
    drop(client);

    let store = open(&path);
    let (delegate, reopened_address) = DelegateSigner::load_or_mint(&store, &mut registry).unwrap();
    let (rebuilt, _events) = ChatClientBuilder::new(reopened_address)
        .ident(delegate)
        .transport(InProcessDelivery::new(bus))
        .registration(registry)
        .storage(store)
        .build()
        .expect("client rebuild");

    assert_eq!(rebuilt.addr(), address);
}
