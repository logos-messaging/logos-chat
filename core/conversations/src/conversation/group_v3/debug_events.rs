//! The debug events for a message's steps through SDS. Each is built here and
//! pushed where its step happens.

use openmls::framing::ProtocolMessage;
use openmls::prelude::ContentType;
use sds::{HistoryEntry, SDSRecord};

use crate::{
    ChatError, DebugEvent, DeliveryInfo, DeliveryMsgId, IgnoreReason, LossReason, MessageId,
    Observation, SdsDependency, SignerKey,
};

/// `None` for a sync, which carries no message.
pub(super) fn sds_received(record: &SDSRecord, info: Option<&DeliveryInfo>) -> Option<Observation> {
    record.content.as_ref()?;
    Some(Observation::Debug(DebugEvent::SdsReceived {
        message_id: record.header.message_id.clone(),
        sender_hint: SignerKey::try_from(record.header.sender_id.as_str()).ok(),
        delivery_msg_id: info.map(|info| info.delivery_msg_id.clone()),
    }))
}

pub(super) fn sds_ignored(message_id: MessageId, reason: sds::IgnoreReason) -> Observation {
    let reason = match reason {
        sds::IgnoreReason::Own => IgnoreReason::Own,
        sds::IgnoreReason::Duplicate => IgnoreReason::Duplicate,
        sds::IgnoreReason::BeforeStart => IgnoreReason::BeforeStart,
    };
    Observation::Debug(DebugEvent::SdsIgnored { message_id, reason })
}

/// `None` for an error `receive` never returns.
pub(super) fn sds_ignored_for_error(
    message_id: MessageId,
    error: &sds::Error,
) -> Option<Observation> {
    let reason = match error {
        sds::Error::WrongChannel { .. } => IgnoreReason::WrongChannel,
        sds::Error::ContentTooLarge { .. } => IgnoreReason::TooLarge,
        sds::Error::EmptyContent | sds::Error::InvalidConfig(_) | sds::Error::UnknownMessage(_) => {
            return None;
        }
    };
    Some(Observation::Debug(DebugEvent::SdsIgnored {
        message_id,
        reason,
    }))
}

pub(super) fn sds_buffered(
    message_id: MessageId,
    missing: &[HistoryEntry],
    buffered: &[HistoryEntry],
) -> Observation {
    Observation::Debug(DebugEvent::SdsBuffered {
        message_id,
        missing_dependencies: dependencies(missing),
        buffered_dependencies: dependencies(buffered),
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

pub(super) fn sds_fetch_failed(delivery_msg_ids: Vec<DeliveryMsgId>) -> Observation {
    Observation::Debug(DebugEvent::SdsFetchFailed { delivery_msg_ids })
}

pub(super) fn sds_resent(record: &SDSRecord) -> Observation {
    Observation::Debug(DebugEvent::SdsResent {
        message_id: record.header.message_id.clone(),
    })
}

pub(super) fn sds_send_failed(message_id: MessageId) -> Observation {
    Observation::Debug(DebugEvent::SdsSendFailed { message_id })
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

fn dependencies(entries: &[HistoryEntry]) -> Vec<SdsDependency> {
    entries
        .iter()
        .map(|entry| SdsDependency {
            message_id: entry.message_id.clone(),
            delivery_msg_id: entry.retrieval_hint.clone().map(DeliveryMsgId::from),
        })
        .collect()
}
