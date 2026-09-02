mod direct_v1;
pub mod group_v1;
mod group_v2;
pub mod mls_extensions;

pub use crate::errors::ChatError;
use crate::kv::ScopedKvStore;
use crate::outcomes::{ConversationClass, ConvoOutcome};
use crate::proto::EncryptedPayload;
use crate::service_context::{ExternalServices, ServiceContext};
use crate::types::ConvoMetadata;
pub use direct_v1::DirectV1Convo;
pub use group_v1::GroupV1Convo;
pub use group_v2::{GroupV2Clock, GroupV2Convo};
use shared_traits::IdentIdRef;
use std::fmt::Debug;

pub type ConversationId = String;
pub type ConversationIdRef<'a> = &'a str;

/// Identifies one message within a conversation, as carried by the
/// causal-history envelope. Handed back by a send so a caller can match later
/// observations — acknowledgements, gaps — to the message that produced them.
pub type MessageId = String;

/// Behaviour shared by every conversation kind.
///
/// An operation that reads or writes conversation state takes the `kv` its state lives in, bound
/// to this conversation's scope for that call alone.
pub(crate) trait Convo<S: ExternalServices>: Identified + Send {
    /// Encrypt and publish `content`, returning the id assigned to it.
    fn send_content(
        &mut self,
        cx: &mut ServiceContext<S>,
        kv: ScopedKvStore<'_>,
        content: &[u8],
    ) -> Result<MessageId, ChatError>;

    /// Decrypts and processes an incoming encrypted frame.
    ///
    /// Returns the [`ConvoOutcome`] describing what the frame produced; its
    /// `content` is `None` for protocol-only frames (placeholders, MLS
    /// commits). Errors only on decryption or frame-parsing failure.
    fn handle_frame(
        &mut self,
        cx: &mut ServiceContext<S>,
        kv: ScopedKvStore<'_>,
        enc: EncryptedPayload,
    ) -> Result<ConvoOutcome, ChatError>;

    /// Advances any time-driven protocol work (de-mls consensus deadlines) and
    /// reports what it observed, mirroring [`Self::handle_frame`].
    fn wakeup(
        &mut self,
        service_ctx: &mut ServiceContext<S>,
        kv: ScopedKvStore<'_>,
    ) -> Result<ConvoOutcome, ChatError>;

    /// Each current member's MLS leaf-credential content (hex-encoded), self
    /// included.
    fn members(&self) -> Result<Vec<Vec<u8>>, ChatError>;
}

/// Group-only operations.
pub(crate) trait GroupConvo<S: ExternalServices>: Convo<S> + std::fmt::Debug + Send {
    fn add_member(
        &mut self,
        cx: &mut ServiceContext<S>,
        kv: ScopedKvStore<'_>,
        members: &[IdentIdRef],
    ) -> Result<(), ChatError>;

    /// Each member this conversation invited and the group has not committed
    /// yet, in the same encoding as [`Self::members`]. Covers only invites
    /// [`Self::add_member`] made here, and is empty for a conversation kind
    /// whose add takes effect within that call.
    fn pending_members(&self) -> Result<Vec<Vec<u8>>, ChatError>;
    // All GroupConvos MUST return ConvoMetadata
    // the return type is Option<_> to support legacy ConvoTypes which
    // are being phased out.
    fn metadata(&self) -> Option<ConvoMetadata>;
}

pub(crate) trait Identified {
    fn id(&self) -> ConversationIdRef<'_>;
}

pub(crate) enum ConvoTypeOwned<S: ExternalServices> {
    Direct(Box<dyn Convo<S>>),
    Group(Box<dyn GroupConvo<S>>),
}

impl<S: ExternalServices> ConvoTypeOwned<S> {
    pub(crate) fn class(&self) -> ConversationClass {
        match self {
            Self::Direct(_) => ConversationClass::Dm,
            Self::Group(_) => ConversationClass::Group,
        }
    }
}

impl<S: ExternalServices> Debug for ConvoTypeOwned<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Direct(arg0) => f.debug_tuple("Pairwise").field(&arg0.id()).finish(),
            Self::Group(arg0) => f.debug_tuple("Group").field(&arg0.id()).finish(),
        }
    }
}

impl<S: ExternalServices> Identified for ConvoTypeOwned<S> {
    fn id(&self) -> ConversationIdRef<'_> {
        match self {
            ConvoTypeOwned::Direct(convo) => convo.id(),
            ConvoTypeOwned::Group(group_convo) => group_convo.id(),
        }
    }
}

impl<S: ExternalServices> Convo<S> for ConvoTypeOwned<S> {
    fn send_content(
        &mut self,
        cx: &mut ServiceContext<S>,
        kv: ScopedKvStore<'_>,
        content: &[u8],
    ) -> Result<MessageId, ChatError> {
        match self {
            ConvoTypeOwned::Group(group_convo) => group_convo.send_content(cx, kv, content),
            ConvoTypeOwned::Direct(convo) => convo.send_content(cx, kv, content),
        }
    }

    fn handle_frame(
        &mut self,
        cx: &mut ServiceContext<S>,
        kv: ScopedKvStore<'_>,
        enc: EncryptedPayload,
    ) -> Result<ConvoOutcome, ChatError> {
        match self {
            ConvoTypeOwned::Group(group_convo) => group_convo.handle_frame(cx, kv, enc),
            ConvoTypeOwned::Direct(convo) => convo.handle_frame(cx, kv, enc),
        }
    }

    fn wakeup(
        &mut self,
        service_ctx: &mut ServiceContext<S>,
        kv: ScopedKvStore<'_>,
    ) -> Result<ConvoOutcome, ChatError> {
        match self {
            ConvoTypeOwned::Group(group_convo) => group_convo.wakeup(service_ctx, kv),
            ConvoTypeOwned::Direct(convo) => convo.wakeup(service_ctx, kv),
        }
    }

    fn members(&self) -> Result<Vec<Vec<u8>>, ChatError> {
        match self {
            ConvoTypeOwned::Group(group_convo) => group_convo.members(),
            ConvoTypeOwned::Direct(convo) => convo.members(),
        }
    }
}
