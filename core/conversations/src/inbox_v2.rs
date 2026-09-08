mod identity;
mod mls_provider;

use crate::storage::{ConversationKind, ConversationMeta, ConversationStore};
use chat_proto::logoschat::envelope::EnvelopeV1;
use de_mls::protos::de_mls::messages::v1::MemberWelcome;
use openmls::prelude::tls_codec::Serialize;
use openmls::prelude::*;
use prost::{Message, Oneof};
use tracing::info;
use tracing::instrument;

pub use identity::MlsIdentityProvider;
pub(crate) use mls_provider::MlsEphemeralPqProvider;

use crate::ChatError;
use crate::DeliveryService;
use crate::RegistrationService;
use crate::conversation::GroupConvo;
use crate::conversation::GroupV1Convo;
use crate::conversation::GroupV2Convo;
use crate::conversation::Identified as _;
use crate::conversation::mls_extensions::GROUP_METADATA_EXTENSION_TYPE;
use crate::outcomes::ConversationClass;
use crate::service_context::{ExternalServices, ServiceContext};
use crate::utils::{blake2b_hex, hash_size};
use crate::{AddressedEnvelope, IdentId, IdentIdRef, IdentityProvider};

pub(crate) const CIPHER_SUITE: Ciphersuite =
    Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;

// Define unique Identifiers derivations used in InboxV2
fn delivery_address_for(ident_id: IdentIdRef) -> String {
    blake2b_hex::<hash_size::DeliveryAddr>(&["InboxV2|", "delivery_address|", ident_id.as_str()])
}

fn conversation_id_for(ident_id: IdentIdRef) -> String {
    blake2b_hex::<hash_size::ConvoId>(&["InboxV2|", "conversation_id|", ident_id.as_str()])
}

/// An Extension trait which extends OpenMlsProvider to add required functionality
/// All MLS based Conversation should use this trait for defining requirements.
pub trait MlsProvider: OpenMlsProvider {
    fn invite_user<DS: DeliveryService>(
        &self,
        ds: &mut DS,
        ident_id: IdentIdRef,
        welcome: &MlsMessageOut,
    ) -> Result<(), ChatError>;
}

/// Deliver a de-mls welcome to `signer_id` over its InboxV2 1-1 channel.
/// Function mirroring the GroupV1 `invite_user` path, but carrying a de-mls `MemberWelcome`.
pub fn invite_user_v2<DS: DeliveryService>(
    ds: &mut DS,
    signer_id: IdentIdRef,
    welcome: &MemberWelcome,
) -> Result<(), ChatError> {
    let frame = InboxV2Frame {
        payload: Some(InviteType::GroupV2(welcome.encode_to_vec())),
    };
    let envelope = EnvelopeV1 {
        conversation_hint: conversation_id_for(signer_id),
        salt: 0,
        payload: frame.encode_to_vec().into(),
    };
    ds.publish(AddressedEnvelope {
        delivery_address: delivery_address_for(signer_id),
        data: envelope.encode_to_vec(),
    })
    .map_err(ChatError::generic)
}

/// A convo built from an InboxV2 invite, paired with the display class its
/// invite type implies.
type ClassifiedConvo<S> = (Box<dyn GroupConvo<S>>, ConversationClass);

/// A PQ focused Conversation initializer.
/// InboxV2 is signer-scoped: it receives invites under this installation's
/// signer id (the hex of the signer's verifying key), supporting PQ based
/// conversation protocols such as MLS.
pub struct InboxV2 {
    // Owned so it can be returned via reference.
    ident_id: IdentId,
}

impl InboxV2 {
    pub fn new(ident_id: IdentId) -> Self {
        Self { ident_id }
    }

    pub fn ident_id(&self) -> IdentIdRef<'_> {
        &self.ident_id
    }

    /// Submit MlsKeypackage to registration service
    pub fn register<S: ExternalServices>(
        &mut self,
        cx: &mut ServiceContext<S>,
    ) -> Result<(), ChatError> {
        let keypackage_bytes = Self::create_keypackage(cx)?.tls_serialize_detached()?;

        // TODO: publishes a single key package per installation. The intended
        // design is a pool of one-time key packages (the registry pops one per
        // fetch, the client replenishes) with the last-resort key package as the
        // exhaustion fallback rather than the primary; that needs pop/claim
        // semantics in the registry service. Tracked in #169.
        cx.registry
            .register(&cx.mls_identity, keypackage_bytes)
            .map_err(ChatError::generic)?;

        Ok(())
    }

    pub fn delivery_address(&self) -> String {
        delivery_address_for(&self.ident_id)
    }

    pub fn id(&self) -> String {
        conversation_id_for(&self.ident_id)
    }

    /// The convo built from an invite, paired with the display class its invite
    /// type implies: `InviteType::GroupV1` carries the pairwise DirectV1 welcome,
    /// so it is `Dm`; `InviteType::GroupV2` is a real group.
    #[instrument(name = "inboxV2.handle_frame", skip_all, fields(user_id = %service_ctx.mls_identity.display_name()))]
    pub fn handle_frame<S: ExternalServices>(
        &self,
        service_ctx: &mut ServiceContext<S>,
        payload_bytes: &[u8],
    ) -> Result<Option<ClassifiedConvo<S>>, ChatError> {
        // On a broadcast transport the inbox address also receives traffic
        // that isn't an invite (or that prost decodes into an empty frame).
        // Treat anything we can't interpret as "not for us" and skip it,
        // rather than failing the whole poll cycle.
        let Ok(inbox_frame) = InboxV2Frame::decode(payload_bytes) else {
            return Ok(None);
        };
        let Some(payload) = inbox_frame.payload else {
            return Ok(None);
        };

        match payload {
            InviteType::GroupV1(inv) => {
                let convo = self.handle_heavy_invite(service_ctx, inv)?;
                Ok(Some((Box::new(convo), ConversationClass::Dm)))
            }
            InviteType::GroupV2(welcome_bytes) => {
                info!("Process WelcomeMessage");
                let mw =
                    MemberWelcome::decode(welcome_bytes.as_slice()).map_err(ChatError::generic)?;
                let convo = GroupV2Convo::new_from_welcome(service_ctx, &mw)?;
                Ok(Some((Box::new(convo), ConversationClass::Group)))
            }
        }
    }

    fn persist_convo<S: ExternalServices>(
        &self,
        convo: &GroupV1Convo,
        cx: &mut ServiceContext<S>,
    ) -> Result<(), ChatError> {
        // TODO: (P3) Implement From<Convo> for ConversationMeta
        let meta = ConversationMeta {
            local_convo_id: convo.id().to_string(),
            kind: ConversationKind::GroupV1,
        };
        cx.store.save_conversation(&meta)?;
        // TODO: (P1) Persist state
        Ok(())
    }

    fn handle_heavy_invite<S: ExternalServices>(
        &self,
        cx: &mut ServiceContext<S>,
        invite: GroupV1HeavyInvite,
    ) -> Result<GroupV1Convo, ChatError> {
        let (msg_in, _rest) = MlsMessageIn::tls_deserialize_bytes(invite.welcome_bytes.as_slice())?;

        let MlsMessageBodyIn::Welcome(welcome) = msg_in.extract() else {
            return Err(ChatError::ProtocolExpectation(
                "something else",
                "Welcome".into(),
            ));
        };

        let convo = GroupV1Convo::new_from_welcome(cx, welcome)?;
        self.persist_convo(&convo, cx)?;

        Ok(convo)
    }

    fn create_keypackage<S: ExternalServices>(
        cx: &ServiceContext<S>,
    ) -> Result<KeyPackage, ChatError> {
        // Last-resort key package. openmls consumes (deletes) a normal key
        // package's init key on the first welcome that uses it; since each
        // installation publishes just one, a second group inviting it would find
        // no matching key package and reject the welcome ("welcome not addressed
        // to this member"). Last-resort key packages are retained, so one admits
        // the installation to any number of groups. Every key-package extension
        // must be advertised in the leaf capabilities, hence LastResort there.
        let capabilities = Capabilities::builder()
            .ciphersuites(vec![CIPHER_SUITE])
            .extensions(vec![
                ExtensionType::ApplicationId,
                ExtensionType::LastResort,
                ExtensionType::Unknown(GROUP_METADATA_EXTENSION_TYPE),
            ])
            .build();
        let a = KeyPackage::builder()
            .mark_as_last_resort()
            .leaf_node_capabilities(capabilities)
            .build(
                CIPHER_SUITE,
                &cx.mls_provider,
                &cx.mls_identity,
                cx.mls_identity.get_credential(),
            )
            .expect("Failed to build KeyPackage");

        Ok(a.key_package().clone())
    }
}

#[derive(Clone, PartialEq, Message)]
pub struct InboxV2Frame {
    #[prost(oneof = "InviteType", tags = "1, 2, 3")]
    pub payload: Option<InviteType>,
}

#[derive(Clone, PartialEq, Oneof)]
pub enum InviteType {
    #[prost(message, tag = "1")]
    GroupV1(GroupV1HeavyInvite),
    #[prost(bytes, tag = "2")]
    GroupV2(Vec<u8>),
}

#[derive(Clone, PartialEq, Message)]
pub struct GroupV1HeavyInvite {
    #[prost(bytes, tag = "1")]
    pub welcome_bytes: Vec<u8>,
}
