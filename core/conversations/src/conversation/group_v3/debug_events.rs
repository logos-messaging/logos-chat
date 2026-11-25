//! The debug events for a message's steps through SDS. Each is built here and
//! pushed where its step happens.

use openmls::framing::ProtocolMessage;
use openmls::prelude::ContentType;
use sds::{HistoryEntry, SDSRecord};

use crate::{ChatError, DebugEvent, DeliveryInfo, LossReason, MessageId, Observation, SignerKey};

/// `None` for a sync, which carries no message.
pub(super) fn sds_received(record: &SDSRecord, info: Option<&DeliveryInfo>) -> Option<Observation> {
    record.content.as_ref()?;
    Some(Observation::Debug(DebugEvent::SdsReceived {
        message_id: record.header.message_id.clone(),
        sender_hint: SignerKey::try_from(record.header.sender_id.as_str()).ok(),
        delivery_msg_id: info.map(|info| info.delivery_msg_id.clone()),
    }))
}

pub(super) fn sds_buffered(
    message_id: MessageId,
    missing: &[HistoryEntry],
    buffered: &[HistoryEntry],
) -> Observation {
    Observation::Debug(DebugEvent::SdsBuffered {
        message_id,
        missing_dependencies: message_ids(missing),
        buffered_dependencies: message_ids(buffered),
    })
}

/// `message` is the released content as decoded, a failure included.
pub(super) fn sds_released(
    message_id: &str,
    message: &Result<Option<ProtocolMessage>, ChatError>,
) -> Observation {
    Observation::Debug(DebugEvent::SdsReleased {
        message_id: message_id.to_owned(),
        kind: kind(message).to_owned(),
    })
}

pub(super) fn sds_lost(message_id: MessageId, reason: sds::LossReason) -> Observation {
    let reason = match reason {
        sds::LossReason::Expired => LossReason::Expired,
        sds::LossReason::BufferFull => LossReason::BufferFull,
    };
    Observation::Debug(DebugEvent::SdsLost { message_id, reason })
}

fn kind(message: &Result<Option<ProtocolMessage>, ChatError>) -> &'static str {
    match message {
        Ok(Some(message)) => match message.content_type() {
            ContentType::Application => "application",
            ContentType::Proposal => "proposal",
            ContentType::Commit => "commit",
        },
        Ok(None) => "external",
        Err(_) => "undecodable",
    }
}

fn message_ids(entries: &[HistoryEntry]) -> Vec<MessageId> {
    entries
        .iter()
        .map(|entry| entry.message_id.clone())
        .collect()
}
