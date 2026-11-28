/// A direct convo type which is based on GroupV3.
use crate::identity::SignerKey;

use crate::{
    ChatError, ConvoMetadata, DebugData, DeliveryInfo, ExternalServices, MessageId, Signer,
    conversation::{
        ConversationIdRef, Convo, ConvoBase, Debuggable, GroupV3Convo, Identified, Typed,
    },
    service_context::ServiceContext,
};

type DelegateGroup = GroupV3Convo;

/// A Conversation between two participants.
#[derive(Debug)]
pub struct DirectV2Convo {
    inner_group: DelegateGroup,
}

impl DirectV2Convo {
    /// Create a new DM
    pub fn create<S: ExternalServices>(
        cx: &mut ServiceContext<S>,
        signers: &[SignerKey],
    ) -> Result<Self, ChatError> {
        let mut inner_group = DelegateGroup::initialize_group(cx, "DM", "")?;

        inner_group.add_founding_signers(cx, signers)?;
        Ok(Self { inner_group })
    }
}

impl Identified for DirectV2Convo {
    fn id(&self) -> ConversationIdRef<'_> {
        self.inner_group.id()
    }
}

impl Typed for DirectV2Convo {
    fn type_name(&self) -> &'static str {
        "DirectV2"
    }
}

impl Debuggable for DirectV2Convo {
    fn debug_data(&self) -> DebugData {
        self.inner_group.debug_data()
    }
}

impl<S> Convo<S> for DirectV2Convo
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

    fn handle_payload(
        &mut self,
        cx: &mut ServiceContext<S>,
        payload: &[u8],
        delivery_info: Option<&DeliveryInfo>,
    ) -> Result<crate::ConvoOutcome, ChatError> {
        self.inner_group.handle_payload(cx, payload, delivery_info)
    }

    fn wakeup(
        &mut self,
        service_ctx: &mut ServiceContext<S>,
    ) -> Result<crate::ConvoOutcome, ChatError> {
        self.inner_group.wakeup(service_ctx)
    }

    fn handle_delivery_report(
        &mut self,
        message_id: &str,
        info: &DeliveryInfo,
    ) -> Result<(), ChatError> {
        Convo::<S>::handle_delivery_report(&mut self.inner_group, message_id, info)
    }
}

impl ConvoBase for DirectV2Convo {
    fn signers(&self) -> Result<Vec<Signer>, ChatError> {
        self.inner_group.signers()
    }

    /// Always empty: a DM's membership is fixed at creation.
    fn pending_signers(&self) -> Result<Vec<Signer>, ChatError> {
        self.inner_group.signers()
    }

    fn can_send(&self) -> bool {
        self.inner_group.can_send()
    }

    fn metadata(&self) -> Option<ConvoMetadata> {
        None
    }
}
