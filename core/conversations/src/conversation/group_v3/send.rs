use openmls::framing::MlsMessageOut;
use openmls_traits::OpenMlsProvider as _;
use sds::StartPoint;
use tracing::warn;

use crate::errors::SendError;
use crate::service_context::ServiceContext;
use crate::{
    AddressedEnvelope, ChatError, DeliveryService as _, ExternalServices, IdentityProvider as _,
    MessageId,
};

use super::payloads::{GroupV3External, GroupV3FrameType, GroupV3Header, GroupV3Packet};
use super::{Frame, GroupV3Convo, delivery_address_from_id, now_ms, recovery_convo_id, trace};

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
        let mls_message = self.mls_group.create_message(
            &cx.mls_provider,
            &cx.mls_identity,
            frame.encode().as_slice(),
        )?;

        let header = GroupV3Header::new(cx.mls_identity.signer_key(), &self.epoch_data);
        let message = GroupV3Packet::from_mls_message(header, mls_message)?.into_outgoing_message();
        let message_id = message.message_id.clone();

        let record = self.channel.send(message, now_ms(cx))?;
        // SDS resends a logged message, so it counts as sent even if the publish fails.
        if is_post {
            trace::sent(self, &message_id);
        }
        self.publish_record(cx, record)?;

        Ok(message_id)
    }

    /// Sends the pending commit through SDS. Returns the commit's place in the SDS channel, where a
    /// member it adds starts. The commit stays pending until `defer_pending_commit`.
    pub(super) fn send_pending_commit<S: ExternalServices>(
        &mut self,
        cx: &mut ServiceContext<S>,
        commit_msg: MlsMessageOut,
    ) -> Result<StartPoint, ChatError> {
        let header = GroupV3Header::new(cx.mls_identity.signer_key(), &self.epoch_data);
        // Send Commit
        let sent = GroupV3Packet::from_mls_message(header, commit_msg).and_then(|envelope| {
            Ok(self
                .channel
                .send(envelope.into_outgoing_message(), now_ms(cx))?)
        });
        let record = match sent {
            Ok(record) => record,
            Err(e) => {
                // Discard the staged commit so the group isn't left wedged
                if let Err(clear_err) = self
                    .mls_group
                    .clear_pending_commit(cx.mls_provider.storage())
                {
                    warn!(convo = %self.convo_id, error = %clear_err, "failed to clear pending commit");
                }
                return Err(e.into());
            }
        };

        let start = StartPoint {
            message_id: record.header.message_id.clone(),
            lamport_timestamp: record
                .header
                .lamport_timestamp
                .ok_or_else(|| ChatError::generic("sds sent the commit without a timestamp"))?,
        };
        // SDS keeps the commit and resends it, so a failed publish heals as a lost one does.
        if let Err(e) = self.publish_record(cx, record) {
            warn!(convo = %self.convo_id, error = %e, "failed to publish commit");
        }
        Ok(start)
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
