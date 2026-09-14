mod direct_v1;
pub mod group_v1;
mod group_v2;
pub mod mls_extensions;

pub use crate::errors::ChatError;
use crate::outcomes::ConvoOutcome;
use crate::proto::EncryptedPayload;
use crate::service_context::{ExternalServices, ServiceContext};
use crate::types::ConvoMetadata;
pub use direct_v1::DirectV1Convo;
pub use group_v1::GroupV1Convo;
pub use group_v2::{GroupV2Clock, GroupV2Convo};
use shared_traits::IdentIdRef;

pub type ConversationId = String;
pub type ConversationIdRef<'a> = &'a str;

/// Identifies one message within a conversation, as carried by the
/// causal-history envelope. Handed back by a send so a caller can match later
/// observations — acknowledgements, gaps — to the message that produced them.
pub type MessageId = String;

/// Behaviour shared by every conversation kind.
pub(crate) trait Convo<S: ExternalServices>: Identified + Send {
    /// Encrypt and publish `content`, returning the id assigned to it.
    fn send_content(
        &mut self,
        cx: &mut ServiceContext<S>,
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
        enc: EncryptedPayload,
    ) -> Result<ConvoOutcome, ChatError>;

    /// Advances any time-driven protocol work (de-mls consensus deadlines) and
    /// reports what it observed, mirroring [`Self::handle_frame`].
    fn wakeup(&mut self, service_ctx: &mut ServiceContext<S>) -> Result<ConvoOutcome, ChatError>;

    /// Each current member's MLS leaf-credential content (hex-encoded), self
    /// included.
    fn members(&self) -> Result<Vec<Vec<u8>>, ChatError>;

    /// Whether the local identity may currently submit content: it is still a
    /// member of this (loaded) conversation with send rights.
    ///
    /// This is the "can submit new content" capability, kept deliberately
    /// separate from whether the conversation merely *exists* — see
    /// [`Core::can_send`](crate::Core::can_send) /
    /// [`Core::can_receive`](crate::Core::can_receive). Send permission
    /// (read-only / broadcast conversations) will refine this once roles carry
    /// that distinction; today it reflects live membership.
    fn can_send(&self) -> bool;
}

/// Group-only operations.
pub(crate) trait GroupConvo<S: ExternalServices>: Convo<S> + std::fmt::Debug + Send {
    fn add_member(
        &mut self,
        cx: &mut ServiceContext<S>,
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
