//! Content types for libchat message bodies: a self-describing,
//! gracefully-degrading format inside `ReliablePayload.content`. MLS, delivery
//! and causal reliability are unaffected.
//!
//! This is an *application* concern, deliberately kept out of the client: the
//! client moves opaque bytes, an application encodes with [`encode_text`] /
//! [`encode_reply`] before `send_message` and reads with [`decode`] on
//! `MessageReceived`.
//!
//! ```ignore
//! let bytes = message_types::encode_text("LET's GO!")?;
//! let id = chat_client.send_message(&convo_id, &bytes)?;
//! ```
//!
//! Interim format; the standard track ([246/CONTENT-TYPES]) is expected to
//! replace it. The public surface ([`Message`], [`MessageContent`],
//! [`ContentId`], [`encode_text`], [`encode_reply`], [`decode`]) is the facade
//! meant to survive that swap.
//!
//! Wire: `[0xC7, 0x7E, version, CBOR envelope]`.
//!
//! # Determinism
//!
//! The envelope is a CBOR map and `ciborium` does not implement canonical CBOR
//! (RFC 8949 §4.2) for maps. Serde emits struct fields in declaration order, so
//! *this* encoder is byte-reproducible for a given input — pinned by
//! `encoded_bytes_are_stable` below — but another implementation of this format
//! may order the map differently. Until the standard-track format lands, do not
//! hash or sign these bytes expecting agreement across implementations; the
//! ids libchat derives are over the payload bytes it was handed, not over a
//! re-encoding of this structure.
//!
//! [246/CONTENT-TYPES]: https://github.com/logos-co/logos-lips/pull/453

use core::cmp::Ordering;
use core::fmt;

use serde::{Deserialize, Serialize};

/// Media type of a plain-text body.
pub const TEXT: &str = "text/plain";

/// Content-envelope marker. `[0xC7, 0x7E]` is guaranteed-invalid UTF-8, so a
/// legacy plain-text body can never be mistaken for one of ours.
const MAGIC: [u8; 2] = [0xC7, 0x7E];

/// Envelope-structure version, carried outside the CBOR. Bump only on a
/// structural change — never to add a content type or an optional field.
const VERSION: u8 = 1;

const HEADER_LEN: usize = 3;

/// Errors from the encode helpers; [`decode`] is infallible.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to encode content: {0}")]
    Encode(String),
}

/// Identifies one piece of content across peers: the id a send returns and an
/// inbound message carries. Opaque — this crate only ever echoes it back.
///
/// A newtype rather than a bare `String` so a conversation id or a body cannot
/// be passed where a reply target is meant.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ContentId(String);

impl ContentId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ContentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A decoded message: its body, and the content it references, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub content: MessageContent,
    /// Id of the replied-to content. A top-level field, not a distinct type,
    /// so it composes with any body.
    pub in_reply_to: Option<ContentId>,
}

/// A decoded message body. Every variant past [`Self::Text`] is still
/// something a receiver can render rather than an error to handle — nothing is
/// dropped, and no variant requires further parsing to display.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum MessageContent {
    Text(String),
    /// A content type this build does not know; `fallback` is the sender's
    /// one-line description, if any.
    Unsupported {
        content_type: String,
        fallback: Option<String>,
    },
    /// A newer envelope format — the remedy is a newer build, not a type handler.
    UnsupportedFormat {
        version: u8,
    },
    /// Carried our marker, but the envelope would not parse: a truncated or
    /// corrupted body, or a sender that framed something that is not ours.
    Malformed,
    /// Neither one of our envelopes nor UTF-8 text. Never lossy-decoded into
    /// replacement characters — the bytes are the caller's to interpret.
    Unrecognized,
}

/// One-line rendering for any content, for lists and placeholders.
impl fmt::Display for MessageContent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MessageContent::Text(body) => f.write_str(body),
            MessageContent::Unsupported {
                content_type,
                fallback,
            } => match fallback {
                Some(line) => f.write_str(line),
                None => write!(f, "[unsupported content: {content_type}]"),
            },
            MessageContent::UnsupportedFormat { version } => {
                write!(
                    f,
                    "[message needs a newer build: content format v{version}]"
                )
            }
            MessageContent::Malformed => f.write_str("[unreadable content]"),
            MessageContent::Unrecognized => f.write_str("[unrecognized content]"),
        }
    }
}

/// Encode a plain-text body.
pub fn encode_text(body: &str) -> Result<Vec<u8>, Error> {
    encode(&Envelope::text(body, None))
}

/// Encode a plain-text reply to `in_reply_to`. The target is not validated —
/// nothing here knows which ids a conversation has seen.
pub fn encode_reply(in_reply_to: &ContentId, body: &str) -> Result<Vec<u8>, Error> {
    encode(&Envelope::text(body, Some(in_reply_to.clone())))
}

/// Decode a message body. Infallible: every input yields something renderable,
/// so a receiver never has to choose between dropping content and guessing at
/// it. Unparseable input is a [`MessageContent`] variant, not an error.
pub fn decode(bytes: &[u8]) -> Message {
    let Some((version, body)) = split_header(bytes) else {
        return Message {
            content: decode_legacy(bytes),
            in_reply_to: None,
        };
    };

    match version.cmp(&VERSION) {
        Ordering::Equal => {}
        Ordering::Greater => {
            return Message {
                content: MessageContent::UnsupportedFormat { version },
                in_reply_to: None,
            };
        }
        // None below ours exist yet. When VERSION bumps, decode prior versions
        // here — a newer build must still read older bodies.
        Ordering::Less => {
            return Message {
                content: MessageContent::Malformed,
                in_reply_to: None,
            };
        }
    }

    let Ok(envelope) = ciborium::from_reader::<Envelope, _>(body) else {
        return Message {
            content: MessageContent::Malformed,
            in_reply_to: None,
        };
    };

    let Envelope {
        content_type,
        content,
        in_reply_to,
        fallback,
    } = envelope;

    let content = match content_type.as_str() {
        TEXT => MessageContent::Text(String::from_utf8_lossy(&content).into_owned()),
        _ => MessageContent::Unsupported {
            content_type,
            fallback,
        },
    };

    Message {
        content,
        in_reply_to,
    }
}

/// The CBOR body of a content envelope. Unknown fields are ignored and absent
/// ones default, so a sender ahead of this build does not break it.
///
/// Field order is the wire order; see the crate-level determinism note before
/// reordering.
#[derive(Debug, Serialize, Deserialize)]
struct Envelope {
    content_type: String,
    /// `serde_bytes` keeps this a CBOR byte string, not an int array.
    #[serde(with = "serde_bytes")]
    content: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    in_reply_to: Option<ContentId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fallback: Option<String>,
}

impl Envelope {
    fn text(body: &str, in_reply_to: Option<ContentId>) -> Self {
        Self {
            content_type: TEXT.to_owned(),
            content: body.as_bytes().to_vec(),
            in_reply_to,
            fallback: None,
        }
    }
}

fn encode(envelope: &Envelope) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::with_capacity(HEADER_LEN + envelope.content.len() + 32);
    bytes.extend_from_slice(&MAGIC);
    bytes.push(VERSION);
    ciborium::into_writer(envelope, &mut bytes).map_err(|e| Error::Encode(e.to_string()))?;
    Ok(bytes)
}

/// Split the fixed header, or `None` if `bytes` is not one of our envelopes.
fn split_header(bytes: &[u8]) -> Option<(u8, &[u8])> {
    let header = bytes.get(..HEADER_LEN)?;
    (header[..MAGIC.len()] == MAGIC).then(|| (header[MAGIC.len()], &bytes[HEADER_LEN..]))
}

fn decode_legacy(bytes: &[u8]) -> MessageContent {
    match str::from_utf8(bytes) {
        Ok(text) => MessageContent::Text(text.to_owned()),
        Err(_) => MessageContent::Unrecognized,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wrap an arbitrary body in our header, standing in for a sender this
    /// build cannot decode.
    fn enveloped<T: Serialize>(version: u8, body: &T) -> Vec<u8> {
        let mut bytes = Vec::from(MAGIC);
        bytes.push(version);
        ciborium::into_writer(body, &mut bytes).unwrap();
        bytes
    }

    #[test]
    fn text_round_trips() {
        let msg = decode(&encode_text("hello").unwrap());
        assert_eq!(msg.content, MessageContent::Text("hello".into()));
        assert_eq!(msg.in_reply_to, None);
    }

    #[test]
    fn reply_round_trips_and_keeps_its_target() {
        let target = ContentId::new("a1b2c3");
        let msg = decode(&encode_reply(&target, "sure").unwrap());
        assert_eq!(msg.content, MessageContent::Text("sure".into()));
        assert_eq!(msg.in_reply_to, Some(target));
    }

    #[test]
    fn a_body_from_a_build_predating_this_crate_is_text() {
        let msg = decode(b"hello raya");
        assert_eq!(msg.content, MessageContent::Text("hello raya".into()));
        assert_eq!(msg.in_reply_to, None);
    }

    #[test]
    fn an_unknown_type_degrades_to_its_fallback() {
        let bytes = enveloped(
            VERSION,
            &Envelope {
                content_type: "acme.example/poll".into(),
                content: b"<poll>".to_vec(),
                in_reply_to: None,
                fallback: Some("sent a poll".into()),
            },
        );
        let msg = decode(&bytes);
        assert_eq!(
            msg.content,
            MessageContent::Unsupported {
                content_type: "acme.example/poll".into(),
                fallback: Some("sent a poll".into()),
            }
        );
        assert_eq!(msg.content.to_string(), "sent a poll");
    }

    #[test]
    fn an_unknown_type_without_a_fallback_still_says_something() {
        let bytes = enveloped(
            VERSION,
            &Envelope {
                content_type: "acme.example/poll".into(),
                content: b"<poll>".to_vec(),
                in_reply_to: None,
                fallback: None,
            },
        );
        assert_eq!(
            decode(&bytes).content.to_string(),
            "[unsupported content: acme.example/poll]"
        );
    }

    #[test]
    fn a_newer_envelope_version_is_reported_as_such() {
        let bytes = enveloped(VERSION + 1, &("whatever shape v2 has", 42));
        assert_eq!(
            decode(&bytes).content,
            MessageContent::UnsupportedFormat { version: 2 }
        );
    }

    #[test]
    fn a_version_below_ours_is_malformed_not_unsupported_format() {
        let bytes = enveloped(VERSION - 1, &("no such older format", 0));
        assert_eq!(decode(&bytes).content, MessageContent::Malformed);
    }

    #[test]
    fn unframed_non_utf8_bytes_are_not_rendered_as_text() {
        let msg = decode(&[0xA5, 0x66, 0xFF, 0xFE]);
        assert_eq!(msg.content, MessageContent::Unrecognized);
    }

    #[test]
    fn a_broken_envelope_is_reported_as_malformed() {
        let mut bytes = Vec::from(MAGIC);
        bytes.push(VERSION);
        bytes.extend_from_slice(b"not cbor at all");
        assert_eq!(decode(&bytes).content, MessageContent::Malformed);
    }

    #[test]
    fn every_variant_renders_without_further_parsing() {
        for content in [
            MessageContent::Text("hi".into()),
            MessageContent::Unsupported {
                content_type: "acme.example/poll".into(),
                fallback: None,
            },
            MessageContent::UnsupportedFormat { version: 9 },
            MessageContent::Malformed,
            MessageContent::Unrecognized,
        ] {
            assert!(!content.to_string().is_empty(), "{content:?} renders empty");
        }
    }

    #[test]
    fn unknown_envelope_fields_are_ignored() {
        #[derive(Serialize)]
        struct Extended<'a> {
            content_type: &'a str,
            #[serde(with = "serde_bytes")]
            content: &'a [u8],
            expires: u64,
            language: &'a str,
        }

        let bytes = enveloped(
            VERSION,
            &Extended {
                content_type: TEXT,
                content: b"still readable",
                expires: 1_700_000_000,
                language: "en",
            },
        );
        assert_eq!(
            decode(&bytes).content,
            MessageContent::Text("still readable".into())
        );
    }

    #[test]
    fn buffers_shorter_than_the_header_are_treated_as_legacy() {
        assert_eq!(decode(b"hi").content, MessageContent::Text("hi".into()));
        assert_eq!(decode(b"").content, MessageContent::Text(String::new()));
    }

    #[test]
    fn the_body_is_encoded_as_a_byte_string() {
        let body = "x".repeat(64);
        let encoded = encode_text(&body).unwrap();
        assert!(
            encoded.len() < body.len() * 2,
            "body looks like it was encoded as an integer array: {} bytes for {}",
            encoded.len(),
            body.len()
        );
    }

    /// Pins the exact bytes this encoder produces. `ciborium` gives no
    /// canonical-CBOR guarantee for maps (see the crate-level note), so the
    /// stability we do have — declaration field order, definite-length map,
    /// omitted `None`s — is asserted rather than assumed.
    #[test]
    fn encoded_bytes_are_stable() {
        let expected = concat!(
            "c77e01",                     // magic + version
            "a2",                         // map(2): the two present fields
            "6c636f6e74656e745f74797065", // "content_type"
            "6a746578742f706c61696e",     // "text/plain"
            "67636f6e74656e74",           // "content"
            "426869",                     // h'6869' — a byte string, not an array
        );
        assert_eq!(hex_of(&encode_text("hi").unwrap()), expected);
    }

    fn hex_of(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
