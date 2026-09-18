use openmls::framing::MlsMessageOut;
use openmls_libcrux_crypto::CryptoProvider as LibcruxCryptoProvider;
use openmls_memory_storage::MemoryStorage;
use openmls_traits::OpenMlsProvider;
use openmls_traits::types::CryptoError;
use prost::Message;
use shared_traits::SignerRef;

use crate::{ChatError, DeliveryService};

use super::{
    AddressedEnvelope, EnvelopeV1, GroupV1HeavyInvite, InboxV2Frame, InviteType, MlsProvider,
    conversation_id_for, delivery_address_for,
};

/// This is a Post-Quantum based MLS provider with in memory storage
pub struct MlsEphemeralPqProvider {
    crypto: LibcruxCryptoProvider,
    storage: MemoryStorage,
}

impl MlsEphemeralPqProvider {
    pub fn new() -> Result<Self, CryptoError> {
        let crypto = LibcruxCryptoProvider::new()?;
        let storage = MemoryStorage::default();

        Ok(Self { crypto, storage })
    }
}

impl MlsProvider for MlsEphemeralPqProvider {
    fn invite_user<DS: DeliveryService>(
        &self,
        ds: &mut DS,
        signer: SignerRef,
        welcome: &MlsMessageOut,
    ) -> Result<(), ChatError> {
        let invite = GroupV1HeavyInvite {
            welcome_bytes: welcome.to_bytes()?,
        };

        let frame = InboxV2Frame {
            payload: Some(InviteType::GroupV1(invite)),
        };

        let envelope = EnvelopeV1 {
            conversation_hint: conversation_id_for(signer),
            salt: 0,
            payload: frame.encode_to_vec().into(),
        };

        let outbound_msg = AddressedEnvelope {
            delivery_address: delivery_address_for(signer),
            data: envelope.encode_to_vec(),
        };

        ds.publish(outbound_msg).map_err(ChatError::generic)?;
        Ok(())
    }
}

impl OpenMlsProvider for MlsEphemeralPqProvider {
    type CryptoProvider = LibcruxCryptoProvider;
    type RandProvider = LibcruxCryptoProvider;
    type StorageProvider = openmls_memory_storage::MemoryStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}
