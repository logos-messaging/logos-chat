use openmls::{
    extensions::{Extension, Extensions, UnknownExtension},
    group::{MlsGroup, MlsGroupCreateConfig, MlsGroupJoinConfig},
    prelude::SenderRatchetConfiguration,
};

use crate::{
    ChatError, ExternalServices, Signer,
    conversation::{
        ConvoBase,
        mls_extensions::{
            ConvoMetaInfo, GROUP_METADATA_EXTENSION_TYPE, capabilities_with_group_metadata,
        },
    },
    errors::TypeConversionError,
    service_context::ServiceContext,
};

pub trait HasMlsConvo {
    fn mls_group(&self) -> &MlsGroup;
}

impl<T: HasMlsConvo + ?Sized> ConvoBase for T {
    fn signers(&self) -> Result<Vec<crate::Signer>, ChatError> {
        let signers: Result<Vec<Signer>, TypeConversionError> = self
            .mls_group()
            .members()
            .map(|m| Signer::from_member(&m))
            .collect();

        Ok(signers?)
    }

    fn pending_signers(&self) -> Result<Vec<crate::Signer>, super::ChatError> {
        todo!()
    }

    fn can_send(&self) -> bool {
        true
    }

    fn metadata(&self) -> Option<crate::ConvoMetadata> {
        let res = self.mls_group().extensions().iter().find_map(|ext| {
            if let Extension::Unknown(ext_type, UnknownExtension(bytes)) = ext
                && *ext_type == GROUP_METADATA_EXTENSION_TYPE
            {
                return ConvoMetaInfo::from_extension_bytes(bytes).ok();
            };
            None
        });

        res.map(Into::into)
    }
}

// A message stays readable until one this many newer from its sender is
// decrypted. Covers logos-delivery's reconnect backfill: up to 20 missed
// messages, handed over after newer live ones.
const OUT_OF_ORDER_TOLERANCE: u32 = 32;

pub fn group_create_config(name: &str, desc: &str) -> MlsGroupCreateConfig {
    let meta = ConvoMetaInfo::new(name, desc);

    let extensions = Extensions::from_vec(vec![Extension::Unknown(
        GROUP_METADATA_EXTENSION_TYPE,
        UnknownExtension(meta.to_extension_bytes()),
    )])
    .expect("compile time validated");

    MlsGroupCreateConfig::builder()
        .ciphersuite(crate::inbox_v2::CIPHER_SUITE)
        .capabilities(capabilities_with_group_metadata())
        .use_ratchet_tree_extension(true) // Embed the ratchet tree in the Welcome so joiners can build the group
        .with_group_context_extensions(extensions)
        .build()
}

pub fn mls_join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .sender_ratchet_configuration(sender_ratchet_config())
        .use_ratchet_tree_extension(true)
        .build()
}

pub fn sender_ratchet_config() -> SenderRatchetConfiguration {
    let default = SenderRatchetConfiguration::default();
    SenderRatchetConfiguration::new(OUT_OF_ORDER_TOLERANCE, default.maximum_forward_distance())
}

pub fn create_group<S: ExternalServices>(
    cx: &mut ServiceContext<S>,
    name: &str,
    desc: &str,
) -> Result<MlsGroup, ChatError> {
    MlsGroup::new(
        &cx.mls_provider,
        &cx.mls_identity,
        &group_create_config(name, desc),
        cx.mls_identity.get_credential(),
    )
    .map_err(|e| ChatError::GroupCreate(e.to_string()))
}
