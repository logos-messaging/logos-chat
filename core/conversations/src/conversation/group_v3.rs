use openmls::extensions::{Extension, Extensions, UnknownExtension};
use openmls::group::{MlsGroup, MlsGroupCreateConfig};

use crate::conversation::mls_extensions::{
    ConvoMetaInfo, GROUP_METADATA_EXTENSION_TYPE, capabilities_with_group_metadata,
};
use crate::conversation::{ConversationIdRef, Convo, GroupConvo, Identified};
use crate::service_context::ServiceContext;
use crate::utils::{blake2b_hex, hash_size};
use crate::{ChatError, DeliveryService, ExternalServices, SignerKey};

// Type Aliases
type Frame = payloads::GroupV3Frame;
type FrameId = String;

fn rand_string() -> String {
    let n = 22;
    let bytes: Vec<u8> = (0..n).map(|_| rand::random::<u8>()).collect();
    hex::encode(bytes)
}

fn group_create_config(name: &str, desc: &str) -> MlsGroupCreateConfig {
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

fn delivery_address_from_id(convo_id: &str) -> String {
    blake2b_hex::<hash_size::DeliveryAddr>(&["delivery_addr|", convo_id])
}

#[derive(Debug)]
pub struct GroupV3Convo {
    convo_id: String,
    mls_group: MlsGroup,
}

impl GroupV3Convo {
    pub fn new<S: ExternalServices>(
        cx: &mut ServiceContext<S>,
        name: &str,
        desc: &str,
        signers: &[SignerKey],
    ) -> Result<Self, ChatError> {
        let convo_id = rand_string();

        // Create MlsGroup
        let config = group_create_config(name, desc);
        let mls_group = MlsGroup::new(
            &cx.mls_provider,
            &cx.mls_identity,
            &config,
            cx.mls_identity.get_credential(),
        )
        .map_err(|e| ChatError::GroupCreate(e.to_string()))?;

        let mut convo = Self {
            convo_id,
            mls_group,
        };

        convo.init(cx)?;

        convo.add_signer(cx, signers)?;
        Ok(convo)
    }

    fn init<S: ExternalServices>(&self, cx: &mut ServiceContext<S>) -> Result<(), ChatError> {
        // Configure the delivery service to listen for the required delivery addresses.
        cx.ds
            .subscribe(&delivery_address_from_id(&self.convo_id))
            .map_err(ChatError::generic)?;
        Ok(())
    }

    /// Primary entry point to putting a Frame into the conversation.
    ///
    /// EncodeFrame -> MlsEncrypt -> Wrap in Envelope
    fn send_frame<S: ExternalServices>(
        &mut self,
        cx: &mut ServiceContext<S>,
        frame: Frame,
    ) -> Result<super::MessageId, ChatError> {
        todo!()
    }
}

impl Identified for GroupV3Convo {
    fn id(&self) -> ConversationIdRef<'_> {
        &self.convo_id
    }
}

impl<S> GroupConvo<S> for GroupV3Convo
where
    S: ExternalServices,
{
    fn add_signer(
        &mut self,
        cx: &mut ServiceContext<S>,
        signers: &[SignerKey],
    ) -> Result<(), ChatError> {
        todo!()
    }

    fn remove_signer(
        &mut self,
        cx: &mut ServiceContext<S>,
        signer: &[crate::SignerRef],
    ) -> Result<(), ChatError> {
        todo!()
    }

    fn pending_signers(&self) -> Result<Vec<crate::Signer>, ChatError> {
        todo!()
    }

    fn metadata(&self) -> Option<crate::ConvoMetadata> {
        todo!()
    }
}

impl<S> Convo<S> for GroupV3Convo
where
    S: ExternalServices,
{
    fn send_content(
        &mut self,
        cx: &mut ServiceContext<S>,
        content: &[u8],
    ) -> Result<super::MessageId, ChatError> {
        todo!()
    }

    fn handle_frame(
        &mut self,
        cx: &mut ServiceContext<S>,
        enc: chat_proto::logoschat::encryption::EncryptedPayload,
    ) -> Result<crate::ConvoOutcome, ChatError> {
        todo!()
    }

    fn wakeup(&mut self, cx: &mut ServiceContext<S>) -> Result<crate::ConvoOutcome, ChatError> {
        todo!()
    }

    fn signers(&self) -> Result<Vec<crate::Signer>, ChatError> {
        todo!()
    }

    fn can_send(&self) -> bool {
        todo!()
    }
}
