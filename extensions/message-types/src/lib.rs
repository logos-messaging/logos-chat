//! **Approach A — media-typed parts** (see `docs/content-types-rfc.md`), realised
//! with the **MIMI content format** ([`mimi-content`], the reference Rust
//! implementation of the IETF MIMI WG content draft).
//!
//! A message body is opaque bytes to the transport. This crate encodes a typed
//! body as MIMI content (CBOR) to place inside `ReliablePayload.content`, and
//! decodes it back on receive. A content type is an **IANA media type**
//! (`text/plain`, `text/markdown`, …). Approach A's signature is
//! **graceful degradation via alternatives**: a message MAY carry several
//! representations in a `chooseOne` multipart, and a receiver renders the richest
//! it understands, falling back to a plainer part.
//!
//! **Relationships** ride on MIMI's top-level fields, not a part type: a reply is
//! any message with `in_reply_to` set to the referenced message's id (see
//! [`encode_reply`] / [`Message::in_reply_to`]).
//!
//! This is the first of the RFC's three candidate approaches; it exists so a
//! draft PR can show what Approach A looks like in real code. Approaches B
//! (namespaced type-id envelope) and C (curated tagged union) are separate.
//!
//! [`mimi-content`]: https://github.com/nexun-foundation/mimi-rs

use mimi_content::{
    MessageId, MimiContent, MimiContentDeserialize, MimiContentSerialize, MultiPart, NestedPart,
    NestedPartContent, PartSemantics, SinglePart,
};

/// Media type of a plain-text message.
pub const TEXT: &str = "text/plain";
/// Media type of a Markdown message.
pub const MARKDOWN: &str = "text/markdown";

/// Errors from the encode/decode helpers.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to encode content: {0}")]
    Encode(String),
    #[error("failed to decode content: {0}")]
    Decode(String),
    #[error("bad message id: {0}")]
    BadMessageId(String),
}

/// A decoded message: its body, plus — for a reply — the id of the message it
/// references.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub content: MessageContent,
    /// Hex id of the message this one replies to, if any (MIMI `in_reply_to`).
    pub in_reply_to: Option<String>,
}

/// A decoded message body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageContent {
    Text(String),
    Markdown(String),
    /// A content type this build doesn't handle; carries its media type so the
    /// caller can show a placeholder.
    Unsupported {
        content_type: String,
    },
}

/// Encode a plain-text message (`text/plain`) as MIMI content bytes.
pub fn encode_text(body: &str) -> Result<Vec<u8>, Error> {
    encode(single_part(TEXT, body.as_bytes()), None)
}

/// Encode a Markdown message (`text/markdown`) as MIMI content bytes.
pub fn encode_markdown(body: &str) -> Result<Vec<u8>, Error> {
    encode(single_part(MARKDOWN, body.as_bytes()), None)
}

/// Encode a plain-text **reply** to the message whose hex id is `in_reply_to`.
/// The body is a normal `text/plain` part; the relationship is the top-level
/// `in_reply_to` field, so replies compose with any body type.
pub fn encode_reply(in_reply_to: &str, body: &str) -> Result<Vec<u8>, Error> {
    encode(
        single_part(TEXT, body.as_bytes()),
        Some(parse_id(in_reply_to)?),
    )
}

/// Encode several representations of one message as a `chooseOne` multipart — the
/// receiver renders the richest it understands, else a plainer alternative
/// (Approach A's built-in graceful degradation). List parts simplest-first.
pub fn encode_alternatives(parts: &[(&str, &[u8])]) -> Result<Vec<u8>, Error> {
    let children = parts
        .iter()
        .map(|(mt, body)| single_part(mt, body))
        .collect();
    let multi = NestedPart::builder()
        .part_content(NestedPartContent::MultiPart(MultiPart {
            part_semantics: PartSemantics::ChooseOne,
            parts: children,
        }))
        .build();
    encode(multi, None)
}

/// Decode MIMI content bytes into a [`Message`], resolving a multipart
/// `chooseOne` to the richest representation this build understands.
pub fn decode(bytes: &[u8]) -> Result<Message, Error> {
    let content = MimiContent::from_cbor_bytes(bytes).map_err(|e| Error::Decode(e.to_string()))?;
    let in_reply_to = content.in_reply_to.as_ref().map(format_id);
    Ok(Message {
        content: decode_part(&content.nested_part),
        in_reply_to,
    })
}

// --- internals ---

/// Wrap a body part into a `MimiContent` (optionally a reply) and serialize.
fn encode(part: NestedPart, in_reply_to: Option<MessageId>) -> Result<Vec<u8>, Error> {
    MimiContent::builder()
        .topic_id(Vec::new().into())
        .nested_part(part)
        .maybe_in_reply_to(in_reply_to)
        .build()
        .to_cbor_bytes()
        .map_err(|e| Error::Encode(e.to_string()))
}

fn single_part(content_type: &str, body: &[u8]) -> NestedPart {
    NestedPart::builder()
        .part_content(NestedPartContent::SinglePart(
            SinglePart::builder()
                .content_type(content_type.into())
                .content(body.to_vec().into())
                .build(),
        ))
        .build()
}

/// A libchat message id (32-byte hex) → MIMI's fixed-size `MessageId`.
fn parse_id(hex_id: &str) -> Result<MessageId, Error> {
    let bytes = hex::decode(hex_id).map_err(|e| Error::BadMessageId(e.to_string()))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Error::BadMessageId("message id must be 32 bytes".into()))?;
    Ok(MessageId::from_raw_unchecked(arr))
}

fn format_id(id: &MessageId) -> String {
    hex::encode(**id)
}

/// Classify a single part, or `None` if this build doesn't know the media type.
fn classify(part: &SinglePart) -> Option<MessageContent> {
    let body = || String::from_utf8_lossy(&part.content).into_owned();
    match &*part.content_type {
        TEXT => Some(MessageContent::Text(body())),
        MARKDOWN => Some(MessageContent::Markdown(body())),
        _ => None,
    }
}

fn decode_part(part: &NestedPart) -> MessageContent {
    match &part.part_content {
        NestedPartContent::SinglePart(sp) => {
            classify(sp).unwrap_or_else(|| MessageContent::Unsupported {
                content_type: sp.content_type.to_string(),
            })
        }
        // `chooseOne` = alternatives. Pick the richest representation we
        // understand (last-understood wins, per multipart/alternative ordering);
        // if we understand none, degrade to Unsupported carrying an unknown type.
        NestedPartContent::MultiPart(mp) => {
            let mut best = None;
            let mut unknown = None;
            for child in &mp.parts {
                if let NestedPartContent::SinglePart(sp) = &child.part_content {
                    match classify(sp) {
                        Some(c) => best = Some(c),
                        None => {
                            unknown.get_or_insert_with(|| sp.content_type.to_string());
                        }
                    }
                }
            }
            best.unwrap_or_else(|| MessageContent::Unsupported {
                content_type: unknown.unwrap_or_else(|| "<no known representation>".into()),
            })
        }
        _ => MessageContent::Unsupported {
            content_type: "<unsupported structure>".into(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_round_trips() {
        let msg = decode(&encode_text("hello").unwrap()).unwrap();
        assert_eq!(msg.content, MessageContent::Text("hello".into()));
        assert_eq!(msg.in_reply_to, None);
    }

    #[test]
    fn markdown_round_trips() {
        let msg = decode(&encode_markdown("# Title").unwrap()).unwrap();
        assert_eq!(msg.content, MessageContent::Markdown("# Title".into()));
    }

    #[test]
    fn reply_round_trips() {
        let target = "ab".repeat(32); // 64 hex chars = 32 bytes
        let msg = decode(&encode_reply(&target, "sure").unwrap()).unwrap();
        assert_eq!(msg.content, MessageContent::Text("sure".into()));
        assert_eq!(msg.in_reply_to.as_deref(), Some(target.as_str()));
    }

    #[test]
    fn reply_rejects_a_non_32_byte_id() {
        assert!(matches!(
            encode_reply("dead", "hi"),
            Err(Error::BadMessageId(_))
        ));
    }

    #[test]
    fn unknown_media_type_is_unsupported() {
        let msg =
            decode(&encode(single_part("application/x-thing", b"raw"), None).unwrap()).unwrap();
        assert_eq!(
            msg.content,
            MessageContent::Unsupported {
                content_type: "application/x-thing".into()
            }
        );
    }

    #[test]
    fn alternatives_pick_the_richest_understood() {
        let bytes =
            encode_alternatives(&[(TEXT, b"# Title (plain)"), (MARKDOWN, b"# Title")]).unwrap();
        assert_eq!(
            decode(&bytes).unwrap().content,
            MessageContent::Markdown("# Title".into())
        );
    }

    #[test]
    fn alternatives_fall_back_to_text() {
        let bytes =
            encode_alternatives(&[("application/x-poll", b"<poll>"), (TEXT, b"sent a poll")])
                .unwrap();
        assert_eq!(
            decode(&bytes).unwrap().content,
            MessageContent::Text("sent a poll".into())
        );
    }
}
