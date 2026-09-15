//! **Approach B — namespaced type-id envelope** (see `docs/content-types-rfc.md`).
//!
//! A message body is opaque bytes to the transport. This crate defines a typed
//! layer that lives **inside** `ReliablePayload.content`: [`encode`] produces the
//! bytes to send, [`decode`] turns received bytes back into a [`MessageContent`].
//! Nothing below (MLS, delivery, causal reliability) changes. It exists as a
//! real, reviewable example of what Approach B looks like; Approaches A
//! (media-typed parts / MIMI) and C (curated tagged union) are separate.
//!
//! ## The three guarantees
//!
//! - **Self-describing:** every message carries its `content_type`, so a receiver
//!   knows how to decode it without any prior agreement.
//! - **Graceful degradation:** an unrecognized type decodes to
//!   [`MessageContent::Unknown`] carrying a human-readable `fallback`, so a client
//!   shows *something* instead of nothing (Approach B's fallback is a string, not
//!   an alternative part).
//! - **Extensible without collision:** a type is named by an IANA media type
//!   (`text/plain`) or a namespaced `authority/type` (`logos/reaction`).
//!
//! ## Relationships
//!
//! Unlike Approach A (a top-level `in_reply_to` field), here a **reply is its own
//! content type** — [`Reply`] carries the referenced id inside its payload. Since
//! the envelope is ours, the id is a plain string with no fixed-size constraint.
//!
//! ## Add your own type
//!
//! Implement [`Content`] (see [`Text`] / [`Reply`] / [`Reaction`] for worked
//! examples) and add one arm to [`decode`]. Sending works immediately; peers that
//! don't know the type still render your `fallback`.

mod markdown;
mod reaction;
mod reply;
mod text;

pub use markdown::Markdown;
pub use reaction::Reaction;
pub use reply::Reply;
pub use text::Text;

use serde::{Deserialize, Serialize};

/// A libchat message id that a reply or reaction refers to (hex-encoded).
pub type MessageId = String;

/// Errors from [`encode`] / [`decode`].
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to encode content: {0}")]
    Encode(String),
    #[error("failed to decode content: {0}")]
    Decode(String),
}

/// A typed message body. Implement this to define a content type.
///
/// `CONTENT_TYPE` is the stable identifier — an IANA media type (`text/plain`)
/// or a namespaced `authority/type` (`logos/reaction`) you own. `fallback` is
/// the one-line text a client shows if it can't decode the type.
pub trait Content: Serialize + for<'de> Deserialize<'de> {
    const CONTENT_TYPE: &'static str;
    fn fallback(&self) -> String;
}

/// The wire envelope placed in `ReliablePayload.content` (CBOR-encoded). The
/// `fallback` rides alongside the payload so unknown types still degrade well.
#[derive(Serialize, Deserialize)]
struct Envelope {
    content_type: String,
    fallback: String,
    payload: Vec<u8>,
}

/// Encode a content value to the bytes that go in `ReliablePayload.content`.
pub fn encode<C: Content>(content: &C) -> Result<Vec<u8>, Error> {
    let mut payload = Vec::new();
    ciborium::into_writer(content, &mut payload).map_err(|e| Error::Encode(e.to_string()))?;
    let envelope = Envelope {
        content_type: C::CONTENT_TYPE.to_string(),
        fallback: content.fallback(),
        payload,
    };
    let mut bytes = Vec::new();
    ciborium::into_writer(&envelope, &mut bytes).map_err(|e| Error::Encode(e.to_string()))?;
    Ok(bytes)
}

/// A decoded message body: a type this build understands, or [`Self::Unknown`]
/// carrying the fallback so the client can still show a line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageContent {
    Text(Text),
    Markdown(Markdown),
    Reply(Reply),
    Reaction(Reaction),
    Unknown {
        content_type: String,
        fallback: String,
    },
}

impl MessageContent {
    /// A human-readable line for any content — the type's own rendering, or the
    /// fallback text for an unknown type.
    pub fn fallback(&self) -> String {
        match self {
            MessageContent::Text(t) => t.fallback(),
            MessageContent::Markdown(m) => m.fallback(),
            MessageContent::Reply(r) => r.fallback(),
            MessageContent::Reaction(r) => r.fallback(),
            MessageContent::Unknown { fallback, .. } => fallback.clone(),
        }
    }
}

/// Decode bytes from `ReliablePayload.content`. An unrecognized `content_type`
/// degrades to [`MessageContent::Unknown`] rather than erroring — only a
/// malformed envelope is an error.
pub fn decode(bytes: &[u8]) -> Result<MessageContent, Error> {
    let envelope: Envelope =
        ciborium::from_reader(bytes).map_err(|e| Error::Decode(e.to_string()))?;
    // The registry, POC-style: one arm per known type. An integrator adds their
    // type here (or we grow this into a dynamic registry later).
    match envelope.content_type.as_str() {
        Text::CONTENT_TYPE => Ok(MessageContent::Text(decode_payload(&envelope.payload)?)),
        Markdown::CONTENT_TYPE => Ok(MessageContent::Markdown(decode_payload(&envelope.payload)?)),
        Reply::CONTENT_TYPE => Ok(MessageContent::Reply(decode_payload(&envelope.payload)?)),
        Reaction::CONTENT_TYPE => Ok(MessageContent::Reaction(decode_payload(&envelope.payload)?)),
        _ => Ok(MessageContent::Unknown {
            content_type: envelope.content_type,
            fallback: envelope.fallback,
        }),
    }
}

fn decode_payload<C: Content>(payload: &[u8]) -> Result<C, Error> {
    ciborium::from_reader(payload).map_err(|e| Error::Decode(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_round_trips() {
        let bytes = encode(&Text::new("hello")).unwrap();
        assert_eq!(
            decode(&bytes).unwrap(),
            MessageContent::Text(Text::new("hello"))
        );
    }

    #[test]
    fn markdown_round_trips() {
        let bytes = encode(&Markdown::new("# Title")).unwrap();
        assert_eq!(
            decode(&bytes).unwrap(),
            MessageContent::Markdown(Markdown::new("# Title"))
        );
    }

    #[test]
    fn reply_round_trips() {
        let r = Reply::new("1a2b3c", "sure");
        let bytes = encode(&r).unwrap();
        assert_eq!(decode(&bytes).unwrap(), MessageContent::Reply(r));
    }

    #[test]
    fn reaction_round_trips() {
        let r = Reaction::new("1a2b3c", "👍");
        let bytes = encode(&r).unwrap();
        assert_eq!(decode(&bytes).unwrap(), MessageContent::Reaction(r));
    }

    #[test]
    fn unknown_type_degrades_to_its_fallback() {
        // A type this build has never heard of — exactly an integrator's custom
        // type reaching a client that hasn't been updated.
        #[derive(Serialize, Deserialize)]
        struct Poll {
            question: String,
        }
        impl Content for Poll {
            const CONTENT_TYPE: &'static str = "acme.example/poll";
            fn fallback(&self) -> String {
                "sent a poll".into()
            }
        }

        let bytes = encode(&Poll {
            question: "coffee?".into(),
        })
        .unwrap();
        let decoded = decode(&bytes).unwrap();
        assert_eq!(
            decoded,
            MessageContent::Unknown {
                content_type: "acme.example/poll".into(),
                fallback: "sent a poll".into(),
            }
        );
        assert_eq!(decoded.fallback(), "sent a poll");
    }
}
