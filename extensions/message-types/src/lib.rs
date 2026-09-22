//! Content types for libchat message bodies: a self-describing,
//! gracefully-degrading format inside `ReliablePayload.content`. MLS, delivery
//! and causal reliability are unaffected.
//!
//! Interim format; the standard track ([246/CONTENT-TYPES]) is expected to
//! replace it. The public surface ([`Message`], [`MessageContent`],
//! [`encode_text`], [`encode_reply`], [`decode`]) is the facade meant to
//! survive that swap.
//!
//! Wire: `[0xC7, 0x7E, version, CBOR envelope]`.
//!
//! [246/CONTENT-TYPES]: https://github.com/logos-co/logos-lips/pull/453

use core::cmp::Ordering;

use serde::{Deserialize, Serialize};

/// Media type of a plain-text body.
pub const TEXT: &str = "text/plain";

/// `content_type` reported for a frame whose envelope will not parse.
pub const MALFORMED: &str = "<malformed>";

/// `content_type` reported for bytes that are neither a frame nor UTF-8 text.
pub const UNRECOGNIZED: &str = "<unrecognized>";

/// Frame marker. `[0xC7, 0x7E]` is guaranteed-invalid UTF-8, so a legacy
/// plain-text body can never be mistaken for a frame.
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

/// A decoded message: its body, and the message it references, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub content: MessageContent,
    /// Cross-peer id of the replied-to message. A top-level field, not a
    /// distinct type, so it composes with any body.
    pub in_reply_to: Option<String>,
}

/// A decoded message body. Every variant past [`Self::Text`] carries something
/// renderable rather than signalling an error — receivers never drop content.
#[derive(Debug, Clone, PartialEq, Eq)]
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
}

impl MessageContent {
    /// One-line rendering for any content, for lists and placeholders.
    pub fn display_line(&self) -> String {
        match self {
            MessageContent::Text(body) => body.clone(),
            MessageContent::Unsupported {
                content_type,
                fallback,
            } => fallback
                .clone()
                .unwrap_or_else(|| format!("[unsupported content: {content_type}]")),
            MessageContent::UnsupportedFormat { version } => {
                format!("[message needs a newer build: content format v{version}]")
            }
        }
    }
}

/// Encode a plain-text body.
pub fn encode_text(body: &str) -> Result<Vec<u8>, Error> {
    encode(&Envelope::text(body, None))
}

/// Encode a plain-text reply to `in_reply_to`. The id is not validated.
pub fn encode_reply(in_reply_to: &str, body: &str) -> Result<Vec<u8>, Error> {
    encode(&Envelope::text(body, Some(in_reply_to.to_owned())))
}

/// Decode a message body. Infallible: every input yields something renderable.
/// Unframed non-UTF-8 bytes become [`UNRECOGNIZED`], never lossy-decoded text.
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
        // here — a newer build must still read older frames.
        Ordering::Less => {
            return Message {
                content: unsupported(MALFORMED),
                in_reply_to: None,
            };
        }
    }

    let Ok(envelope) = ciborium::from_reader::<Envelope, _>(body) else {
        return Message {
            content: unsupported(MALFORMED),
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

/// The CBOR body of a frame. Unknown fields are ignored and absent ones
/// default, so a sender ahead of this build does not break it.
#[derive(Debug, Serialize, Deserialize)]
struct Envelope {
    content_type: String,
    /// `serde_bytes` keeps this a CBOR byte string, not an int array.
    #[serde(with = "serde_bytes")]
    content: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    in_reply_to: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fallback: Option<String>,
}

impl Envelope {
    fn text(body: &str, in_reply_to: Option<String>) -> Self {
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

/// Split the fixed header, or `None` if `bytes` is not one of our frames.
fn split_header(bytes: &[u8]) -> Option<(u8, &[u8])> {
    let header = bytes.get(..HEADER_LEN)?;
    (header[..MAGIC.len()] == MAGIC).then(|| (header[MAGIC.len()], &bytes[HEADER_LEN..]))
}

fn decode_legacy(bytes: &[u8]) -> MessageContent {
    match str::from_utf8(bytes) {
        Ok(text) => MessageContent::Text(text.to_owned()),
        Err(_) => unsupported(UNRECOGNIZED),
    }
}

fn unsupported(content_type: &str) -> MessageContent {
    MessageContent::Unsupported {
        content_type: content_type.to_owned(),
        fallback: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Frame an arbitrary body, standing in for a sender this build can't decode.
    fn frame<T: Serialize>(version: u8, body: &T) -> Vec<u8> {
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
        let msg = decode(&encode_reply("a1b2c3", "sure").unwrap());
        assert_eq!(msg.content, MessageContent::Text("sure".into()));
        assert_eq!(msg.in_reply_to.as_deref(), Some("a1b2c3"));
    }

    #[test]
    fn a_body_from_a_build_predating_this_crate_is_text() {
        let msg = decode(b"hello raya");
        assert_eq!(msg.content, MessageContent::Text("hello raya".into()));
        assert_eq!(msg.in_reply_to, None);
    }

    #[test]
    fn an_unknown_type_degrades_to_its_fallback() {
        let bytes = frame(
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
        assert_eq!(msg.content.display_line(), "sent a poll");
    }

    #[test]
    fn an_unknown_type_without_a_fallback_still_says_something() {
        let bytes = frame(
            VERSION,
            &Envelope {
                content_type: "acme.example/poll".into(),
                content: b"<poll>".to_vec(),
                in_reply_to: None,
                fallback: None,
            },
        );
        assert_eq!(
            decode(&bytes).content.display_line(),
            "[unsupported content: acme.example/poll]"
        );
    }

    #[test]
    fn a_newer_envelope_version_is_reported_as_such() {
        let bytes = frame(VERSION + 1, &("whatever shape v2 has", 42));
        assert_eq!(
            decode(&bytes).content,
            MessageContent::UnsupportedFormat { version: 2 }
        );
    }

    #[test]
    fn a_version_below_ours_is_malformed_not_unsupported_format() {
        let bytes = frame(VERSION - 1, &("no such older format", 0));
        assert_eq!(decode(&bytes).content, unsupported(MALFORMED));
    }

    #[test]
    fn unframed_non_utf8_bytes_are_not_rendered_as_text() {
        let msg = decode(&[0xA5, 0x66, 0xFF, 0xFE]);
        assert_eq!(msg.content, unsupported(UNRECOGNIZED));
    }

    #[test]
    fn a_frame_with_a_broken_envelope_is_reported_as_malformed() {
        let mut bytes = Vec::from(MAGIC);
        bytes.push(VERSION);
        bytes.extend_from_slice(b"not cbor at all");
        assert_eq!(decode(&bytes).content, unsupported(MALFORMED));
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

        let bytes = frame(
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
}
