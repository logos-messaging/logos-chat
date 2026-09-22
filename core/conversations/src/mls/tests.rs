use crate::ConversationKind;
use crate::storage::{MemStore, Namespace, Scope};
use crypto::{Ed25519SigningKey, Ed25519VerifyingKey};
use openmls::prelude::*;
use openmls_libcrux_crypto::CryptoProvider as LibcruxCryptoProvider;
use openmls_traits::OpenMlsProvider;
use shared_traits::{IdentId, IdentIdRef, IdentityProvider};

use crate::kv::KvTransaction;

use super::{KeyPackages, MlsAdapter, MlsProvider, MlsStorageError};
use crate::conversation::mls_extensions::GROUP_METADATA_EXTENSION_TYPE;
use crate::inbox_v2::{CIPHER_SUITE, MlsIdentityProvider};

struct TestIdentity {
    id: IdentId,
    signing_key: Ed25519SigningKey,
    verifying_key: Ed25519VerifyingKey,
}

impl TestIdentity {
    fn new(name: &str) -> MlsIdentityProvider<Self> {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        MlsIdentityProvider::new(Self {
            id: IdentId::new(name),
            signing_key,
            verifying_key,
        })
    }
}

impl IdentityProvider for TestIdentity {
    fn id(&self) -> IdentIdRef<'_> {
        &self.id
    }

    fn display_name(&self) -> String {
        self.id.to_string()
    }

    fn sign(&self, payload: &[u8]) -> crypto::Ed25519Signature {
        self.signing_key.sign(payload)
    }

    fn public_key(&self) -> &Ed25519VerifyingKey {
        &self.verifying_key
    }
}

/// The scope for the key packages these tests mint, instanced by the one signer that mints them.
fn key_packages<'a>(tx: &'a KvTransaction<'_>) -> KeyPackages<'a> {
    KeyPackages::new(tx.scope(Namespace::new("key_packages"), "signer"))
}

fn create_config() -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHER_SUITE)
        .use_ratchet_tree_extension(true)
        .build()
}

/// The last-resort key package libchat publishes, so a welcome addressed to it validates.
fn build_key_package_in(
    provider: &impl OpenMlsProvider,
    identity: &MlsIdentityProvider<TestIdentity>,
) -> Result<KeyPackageBundle, KeyPackageNewError> {
    let capabilities = Capabilities::builder()
        .ciphersuites(vec![CIPHER_SUITE])
        .extensions(vec![
            ExtensionType::ApplicationId,
            ExtensionType::LastResort,
            ExtensionType::Unknown(GROUP_METADATA_EXTENSION_TYPE),
        ])
        .build();

    KeyPackage::builder()
        .mark_as_last_resort()
        .leaf_node_capabilities(capabilities)
        .build(CIPHER_SUITE, provider, identity, identity.get_credential())
}

/// Create a group in `ns`'s scope for a freshly minted group id, committed before returning it.
fn create_group(store: &MemStore, crypto: &LibcruxCryptoProvider, ns: ConversationKind) -> GroupId {
    let identity = TestIdentity::new("creator");
    let tx = KvTransaction::begin(store).unwrap();
    let group_id = GroupId::random(crypto);
    let instance = hex::encode(group_id.as_slice());
    let provider = MlsProvider::new(crypto, MlsAdapter::Convo(tx.scope(ns, &instance)));

    MlsGroup::new_with_group_id(
        &provider,
        &identity,
        &create_config(),
        group_id.clone(),
        identity.get_credential(),
    )
    .unwrap();
    tx.commit().unwrap();

    group_id
}

#[test]
fn a_group_created_through_the_adapter_loads_back_from_its_scope() {
    let store = MemStore::new();
    let crypto = LibcruxCryptoProvider::new().unwrap();
    let group_id = create_group(&store, &crypto, ConversationKind::GroupV1);

    let tx = KvTransaction::begin(&store).unwrap();
    let instance = hex::encode(group_id.as_slice());
    let adapter = MlsAdapter::Convo(tx.scope(ConversationKind::GroupV1, &instance));

    let loaded = MlsGroup::load(&adapter, &group_id).unwrap();
    assert_eq!(loaded.unwrap().group_id(), &group_id);
}

#[test]
fn an_adapter_without_a_conversation_reports_an_error_for_group_state() {
    let store = MemStore::new();
    let tx = KvTransaction::begin(&store).unwrap();
    let adapter = MlsAdapter::KeyPackages(key_packages(&tx));

    let err = MlsGroup::load(&adapter, &GroupId::from_slice(b"absent")).unwrap_err();
    assert!(matches!(err, MlsStorageError::Unscoped(_)), "{err:?}");
}

#[test]
fn an_adapter_without_key_packages_reports_an_error_for_one() {
    let store = MemStore::new();
    let crypto = LibcruxCryptoProvider::new().unwrap();
    let identity = TestIdentity::new("minter");
    let tx = KvTransaction::begin(&store).unwrap();
    let provider = MlsProvider::new(
        &crypto,
        MlsAdapter::Convo(tx.scope(ConversationKind::GroupV1, "absent")),
    );

    let err = build_key_package_in(&provider, &identity).unwrap_err();
    assert!(matches!(err, KeyPackageNewError::StorageError), "{err:?}");
}

#[test]
fn two_conversations_hold_the_same_keys_and_purging_one_leaves_the_other() {
    let store = MemStore::new();
    let crypto = LibcruxCryptoProvider::new().unwrap();
    let direct = create_group(&store, &crypto, ConversationKind::DirectV1);
    let group = create_group(&store, &crypto, ConversationKind::GroupV2);

    let direct_instance = hex::encode(direct.as_slice());
    let group_instance = hex::encode(group.as_slice());
    let direct_scope = Scope {
        ns: ConversationKind::DirectV1.into(),
        instance: &direct_instance,
    };

    let tx = KvTransaction::begin(&store).unwrap();
    let keys = |scope: Scope| -> Vec<Vec<u8>> {
        tx.scope(scope.ns, scope.instance)
            .scan_prefix(b"mls/")
            .unwrap()
            .into_iter()
            .map(|(key, _)| key)
            .collect()
    };
    let group_scope = Scope {
        ns: ConversationKind::GroupV2.into(),
        instance: &group_instance,
    };
    let direct_keys = keys(direct_scope);
    assert!(!direct_keys.is_empty());
    assert_eq!(direct_keys, keys(group_scope));

    tx.delete_scope(ConversationKind::DirectV1, &direct_instance)
        .unwrap();

    assert!(keys(direct_scope).is_empty());
    let adapter = MlsAdapter::Convo(tx.scope(ConversationKind::GroupV2, &group_instance));
    assert!(MlsGroup::load(&adapter, &group).unwrap().is_some());
}

#[test]
fn a_key_package_minted_outside_any_conversation_is_found_by_the_welcome_that_uses_it() {
    let saro_store = MemStore::new();
    let raya_store = MemStore::new();
    let crypto = LibcruxCryptoProvider::new().unwrap();
    let saro = TestIdentity::new("saro");
    let raya = TestIdentity::new("raya");

    // Raya has no conversation yet, so her key package is minted without one.
    let raya_tx = KvTransaction::begin(&raya_store).unwrap();
    let raya_key_package = {
        let provider = MlsProvider::new(&crypto, MlsAdapter::KeyPackages(key_packages(&raya_tx)));
        build_key_package_in(&provider, &raya)
            .unwrap()
            .key_package()
            .clone()
    };
    raya_tx.commit().unwrap();

    let saro_tx = KvTransaction::begin(&saro_store).unwrap();
    let group_id = GroupId::random(&crypto);
    let instance = hex::encode(group_id.as_slice());
    let provider = MlsProvider::new(
        &crypto,
        MlsAdapter::Convo(saro_tx.scope(ConversationKind::GroupV1, &instance)),
    );
    let mut group = MlsGroup::new_with_group_id(
        &provider,
        &saro,
        &create_config(),
        group_id.clone(),
        saro.get_credential(),
    )
    .unwrap();
    let (_commit, welcome, _group_info) = group
        .add_members(&provider, &saro, &[raya_key_package])
        .unwrap();
    group.merge_pending_commit(&provider).unwrap();
    saro_tx.commit().unwrap();

    let raya_tx = KvTransaction::begin(&raya_store).unwrap();
    let provider = MlsProvider::new(&crypto, MlsAdapter::KeyPackages(key_packages(&raya_tx)));
    let (welcome, _rest) =
        MlsMessageIn::tls_deserialize_bytes(&welcome.to_bytes().unwrap()).unwrap();
    let MlsMessageBodyIn::Welcome(welcome) = welcome.extract() else {
        panic!("adding a member produces a welcome");
    };
    let processed = ProcessedWelcome::new_from_welcome(
        &provider,
        &MlsGroupJoinConfig::builder().build(),
        welcome,
    )
    .unwrap();

    assert_eq!(processed.unverified_group_info().group_id(), &group_id);
}
