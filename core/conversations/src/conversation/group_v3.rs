// TESTING ONLY
// Group Conversation that uses a commit validator to ensure valid commit order.
//
// Invariants:
//  - Signers are not allowed change their SigningKey.
//  - Everyone is an "Admin"
//

mod payloads;

use openmls::extensions::{Extension, Extensions, UnknownExtension};
use openmls::framing::MlsMessageOut;
use openmls::group::{MlsGroup, MlsGroupCreateConfig, MlsGroupJoinConfig, StagedWelcome};
use openmls::key_packages::KeyPackage;
use openmls::messages::Welcome;
use openmls::prelude::SenderRatchetConfiguration;

use crate::conversation::{ConversationIdRef, Convo, ConvoBase, GroupConvo, Identified};
use crate::errors::{SendError, TypeConversionError};
use crate::service_context::ServiceContext;
use crate::utils::{blake2b_hex, hash_size};
use crate::{AddressedEnvelope, ChatError, DeliveryService, ExternalServices, Signer, SignerKey};

use super::mls_extensions::{
    ConvoMetaInfo, GROUP_METADATA_EXTENSION_TYPE, capabilities_with_group_metadata,
};
use super::mls_utils::{fetch_key_packages, member_diff, unique};

use self::payloads::frame_id;

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

const OUTBOUND_HASH_CACHE_SIZE: usize = 25;
// A message stays readable until one this many newer from its sender is
// decrypted. Covers logos-delivery's reconnect backfill: up to 20 missed
// messages, handed over after newer live ones.
const OUT_OF_ORDER_TOLERANCE: u32 = 32;

fn mls_join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .sender_ratchet_configuration(sender_ratchet_config())
        .build()
}

fn sender_ratchet_config() -> SenderRatchetConfiguration {
    let default = SenderRatchetConfiguration::default();
    SenderRatchetConfiguration::new(OUT_OF_ORDER_TOLERANCE, default.maximum_forward_distance())
}

fn create_group<S: ExternalServices>(
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
        let mls_group = create_group(cx, name, desc)?;

        let mut convo = Self {
            convo_id,
            mls_group,
        };

        convo.init(cx)?;
        convo.add_signer(cx, signers)?;
        Ok(convo)
    }

    pub fn new_from_welcome<S: ExternalServices>(
        cx: &mut ServiceContext<S>,
        welcome: Welcome,
    ) -> Result<Self, ChatError> {
        let mls_group =
            StagedWelcome::build_from_welcome(&cx.mls_provider, &mls_join_config(), welcome)
                .map_err(ChatError::generic)?
                .build()
                .map_err(ChatError::generic)?
                .into_group(&cx.mls_provider)
                .map_err(ChatError::generic)?;

        // let convo_id = hex::encode(mls_group.group_id().as_slice());
        let mut convo = Self {
            convo_id,
            mls_group,
        };

        convo.init(cx)?;
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
    ) -> Result<super::MessageId, SendError> {
        let frame = frame.encode();
        let frame_id = frame_id(frame.as_slice());

        let mls_msg =
            self.mls_group
                .create_message(&cx.mls_provider, &cx.mls_identity, frame.as_slice())?;

        self.send_mls_msg(cx, mls_msg)?;

        Ok(frame_id)
    }

    fn send_mls_msg<S: ExternalServices>(
        &mut self,
        cx: &mut ServiceContext<S>,
        msg: MlsMessageOut,
    ) -> Result<(), SendError> {
        cx.ds
            .publish(self.to_envelope(msg)?)
            .map_err(|e| SendError::Delivery(e.to_string()))?;

        Ok(())
    }

    // Handles pending_commit
    fn process_generated_commit<S: ExternalServices>(
        &mut self,
        cx: &mut ServiceContext<S>,
        commit: MlsMessageOut,
        dependent_msgs: Vec<AddressedEnvelope>,
    ) -> Result<(), SendError> {
        // Check if can commit
        // ????
        // Send Commit
        self.send_mls_msg(cx, commit)?;

        // Update State
        self.mls_group.merge_pending_commit(&cx.mls_provider)?;

        // Send Welcomes
        for env in dependent_msgs {
            cx.ds
                .publish(env)
                .map_err(|e| SendError::Delivery(e.to_string()))?;
        }
        Ok(())
    }
}

impl ConvoBase for GroupV3Convo {
    fn signers(&self) -> Result<Vec<crate::Signer>, ChatError> {
        let signers: Result<Vec<Signer>, TypeConversionError> = self
            .mls_group
            .members()
            .map(|m| Signer::from_member(&m))
            .collect();

        Ok(signers?)
    }

    fn pending_signers(&self) -> Result<Vec<Signer>, ChatError> {
        todo!()
    }

    fn can_send(&self) -> bool {
        todo!()
    }

    fn metadata(&self) -> Option<crate::ConvoMetadata> {
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
        // filter for duplicates and existing signers
        let existing = self.signers()?.into_iter();
        let signers = unique(member_diff(signers, existing));

        let key_packages: Vec<KeyPackage> = fetch_key_packages(cx, signers)?;
        let (commit, welcome, _) = self
            .mls_group
            .add_members(&cx.mls_provider, &cx.mls_identity, key_packages.as_slice())
            .map_err(ChatError::generic)?;

        let dependent_messages: Result<Vec<AddressedEnvelope>, SendError> = key_packages
            .iter()
            .map(|s| crate::inbox_v2::create_invite_v3(&SignerKey::from(s.leaf_node()), &welcome))
            .collect();

        self.process_generated_commit(cx, commit, dependent_messages?)?;

        Ok(())
    }

    fn remove_signer(
        &mut self,
        _cx: &mut ServiceContext<S>,
        _signer: &[crate::SignerRef],
    ) -> Result<(), ChatError> {
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
        let frame = Frame::from_content(content);
        self.send_frame(cx, frame).map_err(Into::into)
    }

    fn handle_frame(
        &mut self,
        _cx: &mut ServiceContext<S>,
        _enc: chat_proto::logoschat::encryption::EncryptedPayload,
    ) -> Result<crate::ConvoOutcome, ChatError> {
        todo!()
    }

    fn wakeup(&mut self, _cx: &mut ServiceContext<S>) -> Result<crate::ConvoOutcome, ChatError> {
        todo!()
    }
}
