use crate::identity::SignerKey;
use chat_proto::logoschat::encryption::EncryptedPayload;

use crate::{
    ChatError, ConvoMetadata, ExternalServices, MessageId, Signer,
    conversation::{ConversationIdRef, Convo, ConvoBase, GroupConvo, GroupV1Convo, Identified},
    service_context::ServiceContext,
};

type DelegateGroup = GroupV1Convo;

/// A Conversation between two participants.
#[derive(Debug)]
pub struct DirectV1Convo {
    inner_group: DelegateGroup,
}

impl DirectV1Convo {
    // Constructor must accept multiple SignerKey's
    // While the conversation is limited to 2 participants, each participants may
    // have multiple Installations.
    pub fn new<S: ExternalServices>(
        cx: &mut ServiceContext<S>,
        members: &[SignerKey],
    ) -> Result<Self, ChatError> {
        let mut inner_group = DelegateGroup::new(cx)?;
        inner_group.add_signer(cx, members)?;
        Ok(Self { inner_group })
    }
}

impl Identified for DirectV1Convo {
    fn id(&self) -> ConversationIdRef<'_> {
        self.inner_group.id()
    }
}

impl<S> Convo<S> for DirectV1Convo
where
    S: ExternalServices,
{
    fn send_content(
        &mut self,
        cx: &mut ServiceContext<S>,
        content: &[u8],
    ) -> Result<MessageId, ChatError> {
        self.inner_group.send_content(cx, content)
    }

    fn handle_frame(
        &mut self,
        cx: &mut ServiceContext<S>,
        enc: EncryptedPayload,
    ) -> Result<crate::ConvoOutcome, ChatError> {
        self.inner_group.handle_frame(cx, enc)
    }

    fn wakeup(
        &mut self,
        service_ctx: &mut ServiceContext<S>,
    ) -> Result<crate::ConvoOutcome, ChatError> {
        self.inner_group.wakeup(service_ctx)
    }
}

impl ConvoBase for DirectV1Convo {
    fn signers(&self) -> Result<Vec<Signer>, ChatError> {
        self.inner_group.signers()
    }

    /// Always empty: a DM's membership is fixed at creation.
    fn pending_signers(&self) -> Result<Vec<Signer>, ChatError> {
        Ok(Vec::new())
    }

    fn can_send(&self) -> bool {
        // A DM is a pairwise GroupV1; defer to the inner group's membership.
        self.inner_group.can_send()
    }

    /// A DM carries no name or description.
    fn metadata(&self) -> Option<ConvoMetadata> {
        None
    }
}
