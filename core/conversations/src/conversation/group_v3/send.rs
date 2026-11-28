use openmls::framing::MlsMessageOut;
use sds::StartPoint;
use tracing::warn;

use crate::errors::SendError;
use crate::service_context::ServiceContext;
use crate::{
    AddressedEnvelope, DeliveryService as _, ExternalServices, IdentityProvider as _, MessageId,
};

use super::payloads::{GroupV3External, GroupV3FrameType, GroupV3Header, GroupV3Packet};
use super::{Frame, GroupV3Convo, delivery_address_from_id, recovery_convo_id, trace};

impl GroupV3Convo {
    /// Primary entry point to putting a Frame into the conversation.
    ///
    /// EncodeFrame -> MlsEncrypt -> SDS -> Wrap in Envelope
    pub(super) fn send_frame<S: ExternalServices>(
        &mut self,
        cx: &mut ServiceContext<S>,
        frame: Frame,
    ) -> Result<MessageId, SendError> {
        let is_post = matches!(frame.payload, Some(GroupV3FrameType::Content(_)));
        let message_id = self.encrypt_and_send(cx, frame)?;

        if is_post {
            trace::sent(self, &message_id);
        }
        Ok(message_id)
    }

    fn encrypt_and_send<S: ExternalServices>(
        &mut self,
        cx: &mut ServiceContext<S>,
        frame: Frame,
    ) -> Result<MessageId, SendError> {
        let mls_message = self.mls_group.create_message(
            &cx.mls_provider,
            &cx.mls_identity,
            frame.encode().as_slice(),
        )?;

        self.send_mls_msg(cx, mls_message)
            .map(|start_point| start_point.message_id)
    }

    /// Sends the pending commit through SDS. Returns the commit's place in the SDS channel, where a
    /// member it adds starts. The commit stays pending until `defer_pending_commit`; on failure it
    /// is discarded.
    pub(super) fn send_pending_commit<S: ExternalServices>(
        &mut self,
        cx: &mut ServiceContext<S>,
        commit_msg: MlsMessageOut,
    ) -> Result<StartPoint, SendError> {
        self.send_mls_msg(cx, commit_msg)
            .inspect_err(|_| self.discard_pending_commit(cx))
    }

    fn send_mls_msg<S: ExternalServices>(
        &mut self,
        cx: &mut ServiceContext<S>,
        mls_msg: MlsMessageOut,
    ) -> Result<StartPoint, SendError> {
        let header = GroupV3Header::new(cx.mls_identity.signer_key(), &self.epoch_data);
        let packet = GroupV3Packet::from_mls_message(header, mls_msg)?;

        self.channel.send(cx, packet)
    }

    /// Send our beacon once it is due. A failure is retried on a later tick
    /// rather than failing the operation that changed the epoch.
    pub(super) fn send_beacon<S: ExternalServices>(&mut self, cx: &mut ServiceContext<S>) {
        let now = cx.clock.now();
        let Some(beacon) = self.beacons.due(now) else {
            return;
        };
        match self.publish_external(cx, GroupV3External::beacon(beacon.clone())) {
            Ok(()) => self.beacons.sent(),
            Err(e) => {
                warn!(convo = %self.convo_id, error = %e, "beacon not sent");
                self.beacons.failed(now);
            }
        }
    }

    /// Sends a frame outside SDS, under the recovery convo id: nothing orders or resends it, and a
    /// forked member must still be able to read it.
    pub(super) fn publish_external<S: ExternalServices>(
        &self,
        cx: &mut ServiceContext<S>,
        frame: GroupV3External,
    ) -> Result<(), SendError> {
        let env = AddressedEnvelope::new(
            delivery_address_from_id(&self.convo_id),
            recovery_convo_id(&self.convo_id),
            frame.encode(),
        );
        Self::publish_envelope(cx, env)
    }

    pub(super) fn publish_envelope<S: ExternalServices>(
        cx: &mut ServiceContext<S>,
        env: AddressedEnvelope,
    ) -> Result<(), SendError> {
        cx.ds
            .publish(env)
            .map_err(|e| SendError::Delivery(e.to_string()))
            .map(drop)
    }
}
