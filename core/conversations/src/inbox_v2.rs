mod identity;

use crate::Protocol;
use crate::kv::KvTransaction;
use chat_proto::logoschat::envelope::EnvelopeV1;
use de_mls::protos::de_mls::messages::v1::MemberWelcome;
use openmls::prelude::tls_codec::Serialize;
use openmls::prelude::*;
use prost::{Message, Oneof};
use tracing::info;
use tracing::instrument;

pub use identity::MlsIdentityProvider;

use crate::ChatError;
use crate::conversation::ConvoTypeOwned;
use crate::conversation::DirectV1Convo;
use crate::conversation::GroupV1Convo;
use crate::conversation::GroupV2Convo;
use crate::conversation::mls_extensions::GROUP_METADATA_EXTENSION_TYPE;
use crate::mls::{KeyPackages, MlsAdapter, MlsProvider};
use crate::service_context::{ExternalServices, ServiceContext};
use crate::utils::{blake2b_hex, hash_size};
use crate::{AddressedEnvelope, DeliveryService, IdentId, IdentIdRef, IdentityProvider};

pub(crate) const CIPHER_SUITE: Ciphersuite =
    Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;

// Define unique Identifiers derivations used in InboxV2
fn delivery_address_for(ident_id: IdentIdRef) -> String {
    blake2b_hex::<hash_size::DeliveryAddr>(&["InboxV2|", "delivery_address|", ident_id.as_str()])
}

fn conversation_id_for(ident_id: IdentIdRef) -> String {
    blake2b_hex::<hash_size::ConvoId>(&["InboxV2|", "conversation_id|", ident_id.as_str()])
}

/// Deliver a GroupV1 welcome to `ident_id` over its InboxV2 1-1 channel.
pub fn invite_user<DS: DeliveryService>(
    ds: &mut DS,
    ident_id: IdentIdRef,
    welcome: &MlsMessageOut,
) -> Result<(), ChatError> {
    let invite = GroupV1HeavyInvite {
        welcome_bytes: welcome.to_bytes()?,
    };

    let frame = InboxV2Frame {
        payload: Some(InviteType::GroupV1(invite)),
    };

    let envelope = EnvelopeV1 {
        conversation_hint: conversation_id_for(ident_id),
        salt: 0,
        payload: frame.encode_to_vec().into(),
    };

    ds.publish(AddressedEnvelope {
        delivery_address: delivery_address_for(ident_id),
        data: envelope.encode_to_vec(),
    })
    .map_err(ChatError::generic)
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

/// A conversation an invite admitted this installation to.
pub(crate) struct Joined<S: ExternalServices> {
    pub(crate) convo: ConvoTypeOwned<S>,
    /// The protocol whose scope holds its state.
    pub(crate) protocol: Protocol,
}

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

    /// This installation's MLS KeyPackage, minted inside the transaction and returned serialized:
    /// the private init and encryption keys it commits to are only stored when that transaction
    /// lands, so the package may not be announced before it does.
    pub fn register<S: ExternalServices>(
        &mut self,
        cx: &mut ServiceContext<S>,
        tx: &KvTransaction<'_>,
    ) -> Result<Vec<u8>, ChatError> {
        // TODO: publishes a single key package per installation. The intended
        // design is a pool of one-time key packages (the registry pops one per
        // fetch, the client replenishes) with the last-resort key package as the
        // exhaustion fallback rather than the primary; that needs pop/claim
        // semantics in the registry service. Tracked in #169.
        Ok(self.create_keypackage(cx, tx)?.tls_serialize_detached()?)
    }

    pub fn delivery_address(&self) -> String {
        delivery_address_for(&self.ident_id)
    }

    pub fn id(&self) -> String {
        conversation_id_for(&self.ident_id)
    }

    /// The conversation an invite admits this installation to: `InviteType::GroupV1` carries the
    /// pairwise DirectV1 welcome, `InviteType::GroupV2` a real group.
    #[instrument(name = "inboxV2.handle_frame", skip_all, fields(user_id = %service_ctx.mls_identity.display_name()))]
    pub fn handle_frame<S: ExternalServices>(
        &self,
        service_ctx: &mut ServiceContext<S>,
        tx: &KvTransaction<'_>,
        payload_bytes: &[u8],
    ) -> Result<Option<Joined<S>>, ChatError> {
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
                let convo = self.handle_heavy_invite(service_ctx, tx, inv)?;
                Ok(Some(Joined {
                    convo: ConvoTypeOwned::Direct(Box::new(convo)),
                    protocol: Protocol::DirectV1,
                }))
            }
            InviteType::GroupV2(welcome_bytes) => {
                info!("Process WelcomeMessage");
                let mw =
                    MemberWelcome::decode(welcome_bytes.as_slice()).map_err(ChatError::generic)?;
                let key_packages = self.key_packages(tx);
                let convo_id =
                    GroupV2Convo::welcome_convo_id(service_ctx, key_packages, &mw.welcome_bytes)?;
                let convo = GroupV2Convo::new_from_welcome(
                    service_ctx,
                    tx.scope(Protocol::GroupV2, &convo_id),
                    key_packages,
                    &mw,
                )?;
                Ok(Some(Joined {
                    convo: ConvoTypeOwned::Group(Box::new(convo)),
                    protocol: Protocol::GroupV2,
                }))
            }
        }
    }

    /// The key packages this installation minted, in the scope InboxV2 binds for its signer: a
    /// welcome for a conversation of any protocol consumes one, so they belong to no conversation.
    fn key_packages<'a>(&'a self, tx: &'a KvTransaction<'_>) -> KeyPackages<'a> {
        KeyPackages::new(tx.scope(Protocol::InboxV2, self.ident_id.as_str()))
    }

    fn handle_heavy_invite<S: ExternalServices>(
        &self,
        cx: &mut ServiceContext<S>,
        tx: &KvTransaction<'_>,
        invite: GroupV1HeavyInvite,
    ) -> Result<DirectV1Convo, ChatError> {
        let (msg_in, _rest) = MlsMessageIn::tls_deserialize_bytes(invite.welcome_bytes.as_slice())?;

        let MlsMessageBodyIn::Welcome(welcome) = msg_in.extract() else {
            return Err(ChatError::ProtocolExpectation(
                "something else",
                "Welcome".into(),
            ));
        };

        // `GroupV1HeavyInvite` carries no shape discriminator, so every welcome on it is taken as
        // pairwise: a multi-party GroupV1 group joined here lands in DirectV1's namespace.
        let processed = GroupV1Convo::process_welcome(cx, self.key_packages(tx), welcome)?;
        let convo_id = GroupV1Convo::convo_id_for(processed.unverified_group_info().group_id());
        let kv = tx.scope(Protocol::DirectV1, &convo_id);

        DirectV1Convo::new_from_welcome(cx, kv, processed)
    }

    fn create_keypackage<S: ExternalServices>(
        &self,
        cx: &ServiceContext<S>,
        tx: &KvTransaction<'_>,
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
                &MlsProvider::new(
                    &cx.crypto,
                    MlsAdapter::for_key_packages(self.key_packages(tx)),
                ),
                &cx.mls_identity,
                cx.mls_identity.get_credential(),
            )
            .map_err(ChatError::generic)?;

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
