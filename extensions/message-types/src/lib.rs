//! **Approach C — curated tagged union** (see `docs/content-types-rfc.md`).
//!
//! A message body is opaque bytes to the transport. This crate defines a typed
//! layer that lives **inside** `ReliablePayload.content`: [`encode`] produces the
//! bytes to send, [`decode`] turns received bytes back into a [`MessageContent`].
//! Nothing below (MLS, delivery, causal reliability) changes. It exists as a
//! real, reviewable example of what Approach C looks like; Approaches A
//! (media-typed parts / MIMI) and B (namespaced type-id envelope) are separate.
//!
//! ## What makes this "Approach C"
//!
//! There is **one enum**, [`MessageContent`], that *is* the content — you build
//! it to send and you get it back on receive. There is no per-type trait, no
//! `CONTENT_TYPE` string, and no codec registry (contrast Approach B). Adding a
//! type means adding a variant here, and the compiler's exhaustiveness checking
//! turns that into a single, centrally-reviewed change touching every match — the
//! whole point of a *curated* union.
//!
//! The known variants are serialized **directly** as an internally-tagged enum:
//! the fields sit inline next to a `kind` discriminator (`{ kind: "text", body:
//! "hi" }`), with no opaque nested payload blob.
//!
//! ## The three guarantees
//!
//! - **Self-describing:** every message carries its `kind`, so a receiver knows
//!   how to decode it without any prior agreement.
//! - **Graceful degradation:** a `kind` this build doesn't know decodes to
//!   [`MessageContent::Unknown`], carrying a human-readable `fallback` so a client
//!   shows *something* instead of nothing. Note the honest cost of a closed union:
//!   the receiver has *no code* for a future variant, so the **sender** must ship
//!   a `fallback` string alongside the typed fields for degradation to say
//!   anything useful — see [`encode`].
//! - **Curated, not open:** the set of types is owned in one place. This trades
//!   Approach B's third-party extensibility for maximal type-safety and the
//!   simplest possible model.
//!
//! ## Relationships
//!
//! A reply/reaction carries the referenced id inside its own variant
//! ([`MessageContent::Reply`] / [`MessageContent::Reaction`]). Because the wire
//! is ours, the id is a plain string with no fixed-size constraint.

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
    #[error("{0} cannot be encoded — it is only produced by decode")]
    NotEncodable(&'static str),
}

/// The curated, closed set of message bodies libchat understands.
///
/// This single enum *is* the content type system for Approach C. Construct a
/// variant to send it; [`decode`] hands one back on receive. [`Self::Unknown`]
/// is never constructed by a sender — it is the decode target for a `kind` this
/// build has never heard of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageContent {
    /// Plain UTF-8 text — the baseline type, today's implicit behavior made explicit.
    Text { body: String },
    /// A Markdown message.
    Markdown { body: String },
    /// A reply to another message; the relationship lives in the variant.
    Reply {
        in_reply_to: MessageId,
        body: String,
    },
    /// An emoji reaction keyed to the message it targets.
    Reaction {
        in_reply_to: MessageId,
        emoji: String,
    },
    /// A `kind` this build does not know. Carries the sender-supplied fallback so
    /// the client can still show a line. Never sent — only produced by [`decode`].
    Unknown { kind: String, fallback: String },
}

impl MessageContent {
    /// Plain text.
    pub fn text(body: impl Into<String>) -> Self {
        Self::Text { body: body.into() }
    }

    /// Markdown.
    pub fn markdown(body: impl Into<String>) -> Self {
        Self::Markdown { body: body.into() }
    }

    /// A reply to `in_reply_to`.
    pub fn reply(in_reply_to: impl Into<MessageId>, body: impl Into<String>) -> Self {
        Self::Reply {
            in_reply_to: in_reply_to.into(),
            body: body.into(),
        }
    }

    /// A reaction to `in_reply_to`.
    pub fn reaction(in_reply_to: impl Into<MessageId>, emoji: impl Into<String>) -> Self {
        Self::Reaction {
            in_reply_to: in_reply_to.into(),
            emoji: emoji.into(),
        }
    }

    /// A human-readable one-line rendering, used both as the wire `fallback`
    /// (so unknown-to-the-receiver types still degrade) and by clients directly.
    pub fn fallback(&self) -> String {
        match self {
            MessageContent::Text { body } => body.clone(),
            // The raw markdown source is a reasonable plain-text fallback.
            MessageContent::Markdown { body } => body.clone(),
            MessageContent::Reply { body, .. } => body.clone(),
            MessageContent::Reaction { emoji, .. } => format!("reacted {emoji}"),
            MessageContent::Unknown { fallback, .. } => fallback.clone(),
        }
    }
}

/// The known, curated set, serialized directly as an internally-tagged enum:
/// `{ kind: "text", body: "hi" }`. `Unknown` is deliberately absent — it has no
/// wire form; it only ever comes *out* of [`decode`].
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Known {
    Text {
        body: String,
    },
    Markdown {
        body: String,
    },
    Reply {
        in_reply_to: MessageId,
        body: String,
    },
    Reaction {
        in_reply_to: MessageId,
        emoji: String,
    },
}

impl From<Known> for MessageContent {
    fn from(k: Known) -> Self {
        match k {
            Known::Text { body } => MessageContent::Text { body },
            Known::Markdown { body } => MessageContent::Markdown { body },
            Known::Reply { in_reply_to, body } => MessageContent::Reply { in_reply_to, body },
            Known::Reaction { in_reply_to, emoji } => {
                MessageContent::Reaction { in_reply_to, emoji }
            }
        }
    }
}

impl TryFrom<&MessageContent> for Known {
    type Error = Error;

    fn try_from(m: &MessageContent) -> Result<Self, Error> {
        Ok(match m {
            MessageContent::Text { body } => Known::Text { body: body.clone() },
            MessageContent::Markdown { body } => Known::Markdown { body: body.clone() },
            MessageContent::Reply { in_reply_to, body } => Known::Reply {
                in_reply_to: in_reply_to.clone(),
                body: body.clone(),
            },
            MessageContent::Reaction { in_reply_to, emoji } => Known::Reaction {
                in_reply_to: in_reply_to.clone(),
                emoji: emoji.clone(),
            },
            MessageContent::Unknown { .. } => return Err(Error::NotEncodable("Unknown")),
        })
    }
}

/// The wire form: the tagged union, plus a `fallback` sibling so a receiver that
/// doesn't know the `kind` still has a line to show. Flattening keeps the fields
/// inline — `{ fallback, kind, ...variant fields }`.
#[derive(Serialize, Deserialize)]
struct Wire {
    fallback: String,
    #[serde(flatten)]
    known: Known,
}

/// Just the always-present header, tolerant of an unknown `kind`. Used to recover
/// a fallback when the full typed decode can't (because the `kind` is unknown).
#[derive(Deserialize)]
struct Header {
    kind: String,
    #[serde(default)]
    fallback: String,
}

/// Encode a [`MessageContent`] to the bytes that go in `ReliablePayload.content`.
///
/// [`MessageContent::Unknown`] cannot be encoded — it only ever comes out of
/// [`decode`] — so passing one is [`Error::NotEncodable`].
pub fn encode(content: &MessageContent) -> Result<Vec<u8>, Error> {
    let wire = Wire {
        fallback: content.fallback(),
        known: Known::try_from(content)?,
    };
    let mut bytes = Vec::new();
    ciborium::into_writer(&wire, &mut bytes).map_err(|e| Error::Encode(e.to_string()))?;
    Ok(bytes)
}

/// Decode bytes from `ReliablePayload.content`. A `kind` this build doesn't know
/// degrades to [`MessageContent::Unknown`] (carrying the sender's `fallback`)
/// rather than erroring — only a malformed frame is an error.
pub fn decode(bytes: &[u8]) -> Result<MessageContent, Error> {
    // Fast path: a kind we know, decoded straight into its typed variant.
    if let Ok(wire) = ciborium::from_reader::<Wire, _>(bytes) {
        return Ok(wire.known.into());
    }
    // Unknown kind (or a kind we know but whose fields changed shape): recover the
    // header so we can still show the fallback. A frame with no readable header is
    // the only genuine decode error.
    let header: Header = ciborium::from_reader(bytes).map_err(|e| Error::Decode(e.to_string()))?;
    Ok(MessageContent::Unknown {
        kind: header.kind,
        fallback: header.fallback,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_round_trips() {
        let bytes = encode(&MessageContent::text("hello")).unwrap();
        assert_eq!(decode(&bytes).unwrap(), MessageContent::text("hello"));
    }

    #[test]
    fn markdown_round_trips() {
        let bytes = encode(&MessageContent::markdown("# Title")).unwrap();
        assert_eq!(decode(&bytes).unwrap(), MessageContent::markdown("# Title"));
    }

    #[test]
    fn reply_round_trips() {
        let r = MessageContent::reply("1a2b3c", "sure");
        let bytes = encode(&r).unwrap();
        assert_eq!(decode(&bytes).unwrap(), r);
    }

    #[test]
    fn reaction_round_trips() {
        let r = MessageContent::reaction("1a2b3c", "👍");
        let bytes = encode(&r).unwrap();
        assert_eq!(decode(&bytes).unwrap(), r);
    }

    #[test]
    fn unknown_kind_degrades_to_its_fallback() {
        // A `kind` this build has never heard of — exactly a newer peer's type
        // reaching a client that hasn't been updated. We hand-roll the wire the
        // way a future build would emit it: a new `kind` plus a fallback sibling.
        #[derive(Serialize)]
        struct FutureWire {
            fallback: String,
            kind: String,
            question: String,
        }
        let mut bytes = Vec::new();
        ciborium::into_writer(
            &FutureWire {
                fallback: "sent a poll".into(),
                kind: "poll".into(),
                question: "coffee?".into(),
            },
            &mut bytes,
        )
        .unwrap();

        let decoded = decode(&bytes).unwrap();
        assert_eq!(
            decoded,
            MessageContent::Unknown {
                kind: "poll".into(),
                fallback: "sent a poll".into(),
            }
        );
        assert_eq!(decoded.fallback(), "sent a poll");
    }

    #[test]
    fn unknown_is_not_encodable() {
        let u = MessageContent::Unknown {
            kind: "poll".into(),
            fallback: "sent a poll".into(),
        };
        assert!(matches!(encode(&u), Err(Error::NotEncodable(_))));
    }
}
