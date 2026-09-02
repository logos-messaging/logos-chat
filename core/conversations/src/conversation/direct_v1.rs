use crate::kv::ScopedKvStore;
use chat_proto::logoschat::encryption::EncryptedPayload;
use openmls::prelude::ProcessedWelcome;
use openmls_traits::random::OpenMlsRand;
use shared_traits::IdentIdRef;

use crate::{
    ChatError, ExternalServices, MessageId,
    conversation::{
        ConversationId, ConversationIdRef, Convo, GroupConvo, GroupV1Convo, Identified,
    },
    service_context::ServiceContext,
};

type DelegateGroup = GroupV1Convo;

/// A Conversation between two participants.
#[derive(Debug)]
pub struct DirectV1Convo {
    inner_group: DelegateGroup,
}

impl DirectV1Convo {
    pub fn mint_id(rand: &impl OpenMlsRand) -> ConversationId {
        DelegateGroup::mint_id(rand)
    }

    // Constructor must accept multiple IdentId's
    // While the conversation is limited to 2 participants, each participants may
    // have multiple Installations.
    pub fn new<S: ExternalServices>(
        cx: &mut ServiceContext<S>,
        kv: ScopedKvStore<'_>,
        convo_id: ConversationId,
        members: &[IdentIdRef],
    ) -> Result<Self, ChatError> {
        let mut inner_group = DelegateGroup::new(cx, kv, convo_id)?;
        inner_group.add_member(cx, kv, members)?;
        Ok(Self { inner_group })
    }

    /// Joins the conversation a welcome admits this installation to.
    pub fn new_from_welcome<S: ExternalServices>(
        cx: &mut ServiceContext<S>,
        kv: ScopedKvStore<'_>,
        processed: ProcessedWelcome,
    ) -> Result<Self, ChatError> {
        Ok(Self {
            inner_group: DelegateGroup::new_from_welcome(cx, kv, processed)?,
        })
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
        kv: ScopedKvStore<'_>,
        content: &[u8],
    ) -> Result<MessageId, ChatError> {
        self.inner_group.send_content(cx, kv, content)
    }

    fn handle_frame(
        &mut self,
        cx: &mut ServiceContext<S>,
        kv: ScopedKvStore<'_>,
        enc: EncryptedPayload,
    ) -> Result<crate::ConvoOutcome, ChatError> {
        self.inner_group.handle_frame(cx, kv, enc)
    }

    fn wakeup(
        &mut self,
        service_ctx: &mut ServiceContext<S>,
        kv: ScopedKvStore<'_>,
    ) -> Result<crate::ConvoOutcome, ChatError> {
        self.inner_group.wakeup(service_ctx, kv)
    }

    fn members(&self) -> Result<Vec<Vec<u8>>, ChatError> {
        Convo::<S>::members(&self.inner_group)
    }
}
