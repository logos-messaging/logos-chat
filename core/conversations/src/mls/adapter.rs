use crate::kv::ScopedKvStore;
use openmls_traits::storage::{CURRENT_VERSION, StorageProvider, traits};
use serde::Serialize;
use serde::de::DeserializeOwned;

use super::MlsStorageError;
use super::format::{decode, encode, key, sub_key, sub_key_prefix};
use super::key_packages::KeyPackages;

const TREE: &str = "tree";
const GROUP_CONTEXT: &str = "context";
const INTERIM_TRANSCRIPT_HASH: &str = "interim_transcript_hash";
const CONFIRMATION_TAG: &str = "confirmation_tag";
const GROUP_STATE: &str = "group_state";
const MESSAGE_SECRETS: &str = "message_secrets";
const RESUMPTION_PSK_STORE: &str = "resumption_psk_store";
const OWN_LEAF_INDEX: &str = "own_leaf_index";
const EPOCH_SECRETS: &str = "epoch_secrets";
const JOIN_CONFIG: &str = "join_config";
const OWN_LEAF_NODES: &str = "own_leaf_nodes";
const QUEUED_PROPOSAL: &str = "queued_proposal";
const EPOCH_KEY_PAIRS: &str = "epoch_key_pairs";
const SIGNATURE_KEY_PAIR: &str = "signature_key_pair";
const ENCRYPTION_KEY_PAIR: &str = "encryption_key_pair";
const PSK: &str = "psk";

/// The OpenMLS storage provider over one conversation's scope, key packages excepted: those go to
/// the service holding them for every protocol.
///
/// Group state carries no group id in its keys, since the scope already names the conversation.
/// Each destination is reachable only where the operation has one: a welcome is read for the group
/// id it carries before that conversation exists, and a group operation never mints or consumes a
/// key package. Reaching for the destination an adapter lacks is an error, not a panic.
pub(crate) struct MlsAdapter<'a> {
    convo: Option<ScopedKvStore<'a>>,
    key_packages: Option<KeyPackages<'a>>,
}

impl<'a> MlsAdapter<'a> {
    pub(crate) fn new(convo: ScopedKvStore<'a>, key_packages: KeyPackages<'a>) -> Self {
        Self {
            convo: Some(convo),
            key_packages: Some(key_packages),
        }
    }

    /// An adapter for the key packages alone: minting one, and reading the welcome that consumes
    /// it, both happen outside any conversation.
    pub(crate) fn for_key_packages(key_packages: KeyPackages<'a>) -> Self {
        Self {
            convo: None,
            key_packages: Some(key_packages),
        }
    }

    /// An adapter for one conversation's state alone.
    pub(crate) fn for_convo(convo: ScopedKvStore<'a>) -> Self {
        Self {
            convo: Some(convo),
            key_packages: None,
        }
    }

    fn convo(&self) -> Result<ScopedKvStore<'a>, MlsStorageError> {
        self.convo
            .ok_or(MlsStorageError::Unscoped("mls group state"))
    }

    fn key_packages(&self) -> Result<KeyPackages<'a>, MlsStorageError> {
        self.key_packages
            .ok_or(MlsStorageError::Unscoped("mls key packages"))
    }

    fn write(&self, label: &str, value: &impl Serialize) -> Result<(), MlsStorageError> {
        Ok(self.convo()?.put(&key(label), &encode(value)?)?)
    }

    fn read<T: DeserializeOwned>(&self, label: &str) -> Result<Option<T>, MlsStorageError> {
        self.convo()?
            .get(&key(label))?
            .map(|bytes| decode(&bytes))
            .transpose()
    }

    fn delete(&self, label: &str) -> Result<(), MlsStorageError> {
        Ok(self.convo()?.delete(&key(label))?)
    }

    fn write_sub(
        &self,
        label: &str,
        sub: &impl Serialize,
        value: &impl Serialize,
    ) -> Result<(), MlsStorageError> {
        Ok(self.convo()?.put(&sub_key(label, sub)?, &encode(value)?)?)
    }

    fn read_sub<T: DeserializeOwned>(
        &self,
        label: &str,
        sub: &impl Serialize,
    ) -> Result<Option<T>, MlsStorageError> {
        self.convo()?
            .get(&sub_key(label, sub)?)?
            .map(|bytes| decode(&bytes))
            .transpose()
    }

    fn delete_sub(&self, label: &str, sub: &impl Serialize) -> Result<(), MlsStorageError> {
        Ok(self.convo()?.delete(&sub_key(label, sub)?)?)
    }

    /// One entry per epoch and leaf, the pair the keys were generated for.
    fn epoch_key_pairs_key(
        epoch: &impl Serialize,
        leaf_index: u32,
    ) -> Result<Vec<u8>, MlsStorageError> {
        let mut out = sub_key(EPOCH_KEY_PAIRS, epoch)?;
        out.push(b'/');
        out.extend_from_slice(leaf_index.to_string().as_bytes());
        Ok(out)
    }

    /// The queued proposals in key order, each stored beside the reference it is queued under.
    fn queued<ProposalRef, QueuedProposal>(
        &self,
    ) -> Result<Vec<(ProposalRef, QueuedProposal)>, MlsStorageError>
    where
        ProposalRef: DeserializeOwned,
        QueuedProposal: DeserializeOwned,
    {
        self.convo()?
            .scan_prefix(&sub_key_prefix(QUEUED_PROPOSAL))?
            .iter()
            .map(|(_, value)| decode(value))
            .collect()
    }
}

impl StorageProvider<CURRENT_VERSION> for MlsAdapter<'_> {
    type Error = MlsStorageError;

    fn write_mls_join_config<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MlsGroupJoinConfig: traits::MlsGroupJoinConfig<CURRENT_VERSION>,
    >(
        &self,
        _group_id: &GroupId,
        config: &MlsGroupJoinConfig,
    ) -> Result<(), Self::Error> {
        self.write(JOIN_CONFIG, config)
    }

    fn append_own_leaf_node<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNode: traits::LeafNode<CURRENT_VERSION>,
    >(
        &self,
        _group_id: &GroupId,
        leaf_node: &LeafNode,
    ) -> Result<(), Self::Error> {
        let mut nodes: Vec<Vec<u8>> = self.read(OWN_LEAF_NODES)?.unwrap_or_default();
        nodes.push(encode(leaf_node)?);
        self.write(OWN_LEAF_NODES, &nodes)
    }

    fn queue_proposal<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
        QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
        _group_id: &GroupId,
        proposal_ref: &ProposalRef,
        proposal: &QueuedProposal,
    ) -> Result<(), Self::Error> {
        self.write_sub(QUEUED_PROPOSAL, proposal_ref, &(proposal_ref, proposal))
    }

    fn write_tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        TreeSync: traits::TreeSync<CURRENT_VERSION>,
    >(
        &self,
        _group_id: &GroupId,
        tree: &TreeSync,
    ) -> Result<(), Self::Error> {
        self.write(TREE, tree)
    }

    fn write_interim_transcript_hash<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        _group_id: &GroupId,
        interim_transcript_hash: &InterimTranscriptHash,
    ) -> Result<(), Self::Error> {
        self.write(INTERIM_TRANSCRIPT_HASH, interim_transcript_hash)
    }

    fn write_context<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupContext: traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        _group_id: &GroupId,
        group_context: &GroupContext,
    ) -> Result<(), Self::Error> {
        self.write(GROUP_CONTEXT, group_context)
    }

    fn write_confirmation_tag<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        _group_id: &GroupId,
        confirmation_tag: &ConfirmationTag,
    ) -> Result<(), Self::Error> {
        self.write(CONFIRMATION_TAG, confirmation_tag)
    }

    fn write_group_state<
        GroupState: traits::GroupState<CURRENT_VERSION>,
        GroupId: traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        _group_id: &GroupId,
        group_state: &GroupState,
    ) -> Result<(), Self::Error> {
        self.write(GROUP_STATE, group_state)
    }

    fn write_message_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MessageSecrets: traits::MessageSecrets<CURRENT_VERSION>,
    >(
        &self,
        _group_id: &GroupId,
        message_secrets: &MessageSecrets,
    ) -> Result<(), Self::Error> {
        self.write(MESSAGE_SECRETS, message_secrets)
    }

    fn write_resumption_psk_store<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ResumptionPskStore: traits::ResumptionPskStore<CURRENT_VERSION>,
    >(
        &self,
        _group_id: &GroupId,
        resumption_psk_store: &ResumptionPskStore,
    ) -> Result<(), Self::Error> {
        self.write(RESUMPTION_PSK_STORE, resumption_psk_store)
    }

    fn write_own_leaf_index<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNodeIndex: traits::LeafNodeIndex<CURRENT_VERSION>,
    >(
        &self,
        _group_id: &GroupId,
        own_leaf_index: &LeafNodeIndex,
    ) -> Result<(), Self::Error> {
        self.write(OWN_LEAF_INDEX, own_leaf_index)
    }

    fn write_group_epoch_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupEpochSecrets: traits::GroupEpochSecrets<CURRENT_VERSION>,
    >(
        &self,
        _group_id: &GroupId,
        group_epoch_secrets: &GroupEpochSecrets,
    ) -> Result<(), Self::Error> {
        self.write(EPOCH_SECRETS, group_epoch_secrets)
    }

    fn write_signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
        SignatureKeyPair: traits::SignatureKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
        signature_key_pair: &SignatureKeyPair,
    ) -> Result<(), Self::Error> {
        self.write_sub(SIGNATURE_KEY_PAIR, public_key, signature_key_pair)
    }

    fn write_encryption_key_pair<
        EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
        key_pair: &HpkeKeyPair,
    ) -> Result<(), Self::Error> {
        self.write_sub(ENCRYPTION_KEY_PAIR, public_key, key_pair)
    }

    fn write_encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        _group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
        key_pairs: &[HpkeKeyPair],
    ) -> Result<(), Self::Error> {
        Ok(self.convo()?.put(
            &Self::epoch_key_pairs_key(epoch, leaf_index)?,
            &encode(&key_pairs)?,
        )?)
    }

    fn write_key_package<
        HashReference: traits::HashReference<CURRENT_VERSION>,
        KeyPackage: traits::KeyPackage<CURRENT_VERSION>,
    >(
        &self,
        hash_ref: &HashReference,
        key_package: &KeyPackage,
    ) -> Result<(), Self::Error> {
        self.key_packages()?.write(hash_ref, key_package)
    }

    fn write_psk<
        PskId: traits::PskId<CURRENT_VERSION>,
        PskBundle: traits::PskBundle<CURRENT_VERSION>,
    >(
        &self,
        psk_id: &PskId,
        psk: &PskBundle,
    ) -> Result<(), Self::Error> {
        self.write_sub(PSK, psk_id, psk)
    }

    fn mls_group_join_config<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MlsGroupJoinConfig: traits::MlsGroupJoinConfig<CURRENT_VERSION>,
    >(
        &self,
        _group_id: &GroupId,
    ) -> Result<Option<MlsGroupJoinConfig>, Self::Error> {
        self.read(JOIN_CONFIG)
    }

    fn own_leaf_nodes<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNode: traits::LeafNode<CURRENT_VERSION>,
    >(
        &self,
        _group_id: &GroupId,
    ) -> Result<Vec<LeafNode>, Self::Error> {
        self.read::<Vec<Vec<u8>>>(OWN_LEAF_NODES)?
            .unwrap_or_default()
            .iter()
            .map(|bytes| decode(bytes))
            .collect()
    }

    fn queued_proposal_refs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        _group_id: &GroupId,
    ) -> Result<Vec<ProposalRef>, Self::Error> {
        Ok(self
            .queued::<ProposalRef, serde::de::IgnoredAny>()?
            .into_iter()
            .map(|(proposal_ref, _)| proposal_ref)
            .collect())
    }

    fn queued_proposals<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
        QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
        _group_id: &GroupId,
    ) -> Result<Vec<(ProposalRef, QueuedProposal)>, Self::Error> {
        self.queued()
    }

    fn tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        TreeSync: traits::TreeSync<CURRENT_VERSION>,
    >(
        &self,
        _group_id: &GroupId,
    ) -> Result<Option<TreeSync>, Self::Error> {
        self.read(TREE)
    }

    fn group_context<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupContext: traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        _group_id: &GroupId,
    ) -> Result<Option<GroupContext>, Self::Error> {
        self.read(GROUP_CONTEXT)
    }

    fn interim_transcript_hash<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        _group_id: &GroupId,
    ) -> Result<Option<InterimTranscriptHash>, Self::Error> {
        self.read(INTERIM_TRANSCRIPT_HASH)
    }

    fn confirmation_tag<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        _group_id: &GroupId,
    ) -> Result<Option<ConfirmationTag>, Self::Error> {
        self.read(CONFIRMATION_TAG)
    }

    fn group_state<
        GroupState: traits::GroupState<CURRENT_VERSION>,
        GroupId: traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        _group_id: &GroupId,
    ) -> Result<Option<GroupState>, Self::Error> {
        self.read(GROUP_STATE)
    }

    fn message_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MessageSecrets: traits::MessageSecrets<CURRENT_VERSION>,
    >(
        &self,
        _group_id: &GroupId,
    ) -> Result<Option<MessageSecrets>, Self::Error> {
        self.read(MESSAGE_SECRETS)
    }

    fn resumption_psk_store<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ResumptionPskStore: traits::ResumptionPskStore<CURRENT_VERSION>,
    >(
        &self,
        _group_id: &GroupId,
    ) -> Result<Option<ResumptionPskStore>, Self::Error> {
        self.read(RESUMPTION_PSK_STORE)
    }

    fn own_leaf_index<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNodeIndex: traits::LeafNodeIndex<CURRENT_VERSION>,
    >(
        &self,
        _group_id: &GroupId,
    ) -> Result<Option<LeafNodeIndex>, Self::Error> {
        self.read(OWN_LEAF_INDEX)
    }

    fn group_epoch_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupEpochSecrets: traits::GroupEpochSecrets<CURRENT_VERSION>,
    >(
        &self,
        _group_id: &GroupId,
    ) -> Result<Option<GroupEpochSecrets>, Self::Error> {
        self.read(EPOCH_SECRETS)
    }

    fn signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
        SignatureKeyPair: traits::SignatureKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<Option<SignatureKeyPair>, Self::Error> {
        self.read_sub(SIGNATURE_KEY_PAIR, public_key)
    }

    fn encryption_key_pair<
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
        EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<Option<HpkeKeyPair>, Self::Error> {
        self.read_sub(ENCRYPTION_KEY_PAIR, public_key)
    }

    fn encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        _group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<Vec<HpkeKeyPair>, Self::Error> {
        match self
            .convo()?
            .get(&Self::epoch_key_pairs_key(epoch, leaf_index)?)?
        {
            Some(bytes) => decode(&bytes),
            None => Ok(Vec::new()),
        }
    }

    fn key_package<
        KeyPackageRef: traits::HashReference<CURRENT_VERSION>,
        KeyPackage: traits::KeyPackage<CURRENT_VERSION>,
    >(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<Option<KeyPackage>, Self::Error> {
        self.key_packages()?.get(hash_ref)
    }

    fn psk<PskBundle: traits::PskBundle<CURRENT_VERSION>, PskId: traits::PskId<CURRENT_VERSION>>(
        &self,
        psk_id: &PskId,
    ) -> Result<Option<PskBundle>, Self::Error> {
        self.read_sub(PSK, psk_id)
    }

    fn remove_proposal<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        _group_id: &GroupId,
        proposal_ref: &ProposalRef,
    ) -> Result<(), Self::Error> {
        self.delete_sub(QUEUED_PROPOSAL, proposal_ref)
    }

    fn delete_own_leaf_nodes<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        _group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete(OWN_LEAF_NODES)
    }

    fn delete_group_config<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        _group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete(JOIN_CONFIG)
    }

    fn delete_tree<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        _group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete(TREE)
    }

    fn delete_confirmation_tag<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        _group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete(CONFIRMATION_TAG)
    }

    fn delete_group_state<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        _group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete(GROUP_STATE)
    }

    fn delete_context<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        _group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete(GROUP_CONTEXT)
    }

    fn delete_interim_transcript_hash<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        _group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete(INTERIM_TRANSCRIPT_HASH)
    }

    fn delete_message_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        _group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete(MESSAGE_SECRETS)
    }

    fn delete_all_resumption_psk_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        _group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete(RESUMPTION_PSK_STORE)
    }

    fn delete_own_leaf_index<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        _group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete(OWN_LEAF_INDEX)
    }

    fn delete_group_epoch_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        _group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete(EPOCH_SECRETS)
    }

    fn clear_proposal_queue<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        _group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        Ok(self
            .convo()?
            .delete_prefix(&sub_key_prefix(QUEUED_PROPOSAL))?)
    }

    fn delete_signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<(), Self::Error> {
        self.delete_sub(SIGNATURE_KEY_PAIR, public_key)
    }

    fn delete_encryption_key_pair<EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>>(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<(), Self::Error> {
        self.delete_sub(ENCRYPTION_KEY_PAIR, public_key)
    }

    fn delete_encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
    >(
        &self,
        _group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<(), Self::Error> {
        Ok(self
            .convo()?
            .delete(&Self::epoch_key_pairs_key(epoch, leaf_index)?)?)
    }

    fn delete_key_package<KeyPackageRef: traits::HashReference<CURRENT_VERSION>>(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<(), Self::Error> {
        self.key_packages()?.delete(hash_ref)
    }

    fn delete_psk<PskKey: traits::PskId<CURRENT_VERSION>>(
        &self,
        psk_id: &PskKey,
    ) -> Result<(), Self::Error> {
        self.delete_sub(PSK, psk_id)
    }
}
