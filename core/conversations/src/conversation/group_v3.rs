// TESTING ONLY
// A stream Group Conversation that uses a commit validator to ensure valid commit order.
//
// Invariants:
//  - Signers are not allowed change their SigningKey.
//  - Everyone is an "Admin"
//

mod handlers;
mod payloads;

use chat_proto::logoschat::encryption::{EncryptedPayload, encrypted_payload};
use openmls::framing::MlsMessageOut;
use openmls::group::{MlsGroup, StagedWelcome};
use openmls::key_packages::KeyPackage;
use openmls::messages::Welcome;
use openmls::prelude::tls_codec::DeserializeBytes as _;
use openmls::prelude::{
    MlsMessageIn, ProcessMessageError, ProcessedMessageContent, Sender, ValidationError,
};
use openmls_traits::OpenMlsProvider;
use tracing::{debug, instrument, warn};

use crate::conversation::mls_groups::{HasMlsConvo, create_group, mls_join_config};
use crate::conversation::{ConversationIdRef, Convo, ConvoBase, GroupConvo, Identified};
use crate::errors::SendError;
use crate::service_context::ServiceContext;
use crate::utils::{blake2b_hex, hash_size};
use crate::{
    AddressedEnvelope, ChatError, ConvoOutcome, DeliveryService, ExternalServices,
    IdentityProvider, SignerKey,
};

use super::mls_utils::{fetch_key_packages, member_diff, unique};

use self::payloads::frame_id;

// Type Aliases
type Frame = payloads::GroupV3Frame;
type FrameId = String;

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
        // Create MlsGroup
        let mls_group = create_group(cx, name, desc)?;

        let mut convo = Self {
            convo_id: hex::encode(mls_group.group_id().as_slice()),
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
        let convo = Self {
            convo_id: hex::encode(mls_group.group_id().as_slice()),
            mls_group,
        };

        convo.init(cx)?;
        Ok(convo)
    }
}

impl GroupV3Convo {
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
    fn process_pending_commit<S: ExternalServices>(
        &mut self,
        cx: &mut ServiceContext<S>,
        commit_msg: MlsMessageOut,
        dependent_msgs: Vec<AddressedEnvelope>,
    ) -> Result<(), ChatError> {
        // TODO: Check if Can merge?

        // Send Commit
        if let Err(e) = self.send_mls_msg(cx, commit_msg) {
            // Discard the staged commit so the group isn't left wedged
            if let Err(clear_err) = self
                .mls_group
                .clear_pending_commit(cx.mls_provider.storage())
            {
                warn!(convo = %self.convo_id, error = %clear_err, "failed to clear pending commit");
            }
            return Err(e.into());
        }

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

        // TODO: Check if allowed to make commit;

        let key_packages: Vec<KeyPackage> = fetch_key_packages(cx, signers)?;
        if key_packages.is_empty() {
            warn!("no members to add to mls::group, ignoring");
            return Ok(());
        }

        let (commit_msg, welcome, _) = self
            .mls_group
            .add_members(&cx.mls_provider, &cx.mls_identity, key_packages.as_slice())
            .map_err(ChatError::generic)?;

        let dependent_messages: Result<Vec<AddressedEnvelope>, SendError> = key_packages
            .iter()
            .map(|s| crate::inbox_v2::create_invite_v3(&SignerKey::from(s.leaf_node()), &welcome))
            .collect();

        self.process_pending_commit(cx, commit_msg, dependent_messages?)?;

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

    #[instrument(name = "groupv3.handle_frame", skip_all, fields(user_id = %cx.mls_identity.display_name()))]
    fn handle_frame(
        &mut self,
        cx: &mut ServiceContext<S>,
        enc: EncryptedPayload,
    ) -> Result<ConvoOutcome, ChatError> {
        let empty = ConvoOutcome::empty(self.convo_id.clone());

        let Some(encrypted_payload::Encryption::Plaintext(pt)) = enc.encryption else {
            return Err(ChatError::ProtocolExpectation(
                "None",
                "Some(Encryption::Plaintext)".into(),
            ));
        };

        let protocol_message = MlsMessageIn::tls_deserialize_exact_bytes(&pt.payload)
            .map_err(ChatError::generic)?
            .try_into_protocol_message()
            .map_err(ChatError::generic)?;

        // Includes our own commits, which return here after we merged them.
        if protocol_message.epoch() < self.mls_group.epoch() {
            debug!(convo = %self.convo_id, epoch = protocol_message.epoch().as_u64(), "dropping message from past epoch");
            return Ok(empty);
        }

        let processed = match self
            .mls_group
            .process_message(&cx.mls_provider, protocol_message)
        {
            Ok(processed) => processed,
            Err(ProcessMessageError::ValidationError(ValidationError::CannotDecryptOwnMessage)) => {
                debug!(convo = %self.convo_id, "dropping own message");
                return Ok(empty);
            }
            Err(e) => return Err(ChatError::generic(e)),
        };

        // Resolved before `into_content` consumes the message.
        let sender = match processed.sender() {
            Sender::Member(index) => self.mls_group.member_at(*index),
            _ => None,
        };

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(msg) => {
                self.handle_content(cx, sender, &msg.into_bytes())
            }
            ProcessedMessageContent::StagedCommitMessage(commit) => {
                self.handle_mls_commit(cx, *commit)
            }
            other => {
                debug!(convo = %self.convo_id, ?other, "ignoring mls message");
                Ok(empty)
            }
        }
    }

    fn wakeup(&mut self, _cx: &mut ServiceContext<S>) -> Result<crate::ConvoOutcome, ChatError> {
        Ok(ConvoOutcome::empty(self.id().to_string()))
    }
}

impl Identified for GroupV3Convo {
    fn id(&self) -> ConversationIdRef<'_> {
        &self.convo_id
    }
}

impl HasMlsConvo for GroupV3Convo {
    fn mls_group(&self) -> &MlsGroup {
        &self.mls_group
    }
}
