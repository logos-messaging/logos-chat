use chat_proto::logoschat::encryption::EncryptedPayload;
use shared_traits::IdentIdRef;

use crate::{
    ChatError, ExternalServices, MessageId,
    conversation::{ConversationIdRef, Convo, GroupConvo, GroupV1Convo, Identified},
    service_context::ServiceContext,
};

type DelegateGroup = GroupV1Convo;

/// A Conversation between two participants.
#[derive(Debug)]
pub struct DirectV1Convo {
    inner_group: DelegateGroup,
}

impl DirectV1Convo {
    // Constructor must accept multiple IdentId's
    // While the conversation is limited to 2 participants, each participants may
    // have multiple Installations.
    pub fn new<S: ExternalServices>(
        cx: &mut ServiceContext<S>,
        members: &[IdentIdRef],
    ) -> Result<Self, ChatError> {
        let mut inner_group = DelegateGroup::new(cx)?;
        inner_group.add_member(cx, members)?;
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

    fn members(&self) -> Result<Vec<Vec<u8>>, ChatError> {
        Convo::<S>::members(&self.inner_group)
    }

    fn can_send(&self) -> bool {
        // A DM is a pairwise GroupV1; defer to the inner group's membership.
        Convo::<S>::can_send(&self.inner_group)
    }
}
