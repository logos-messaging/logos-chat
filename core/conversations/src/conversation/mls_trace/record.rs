//! Trace records: each epoch this signer enters, one log event per fact.
//!
//! Each is one `TRACE` event on [`TARGET`]: the record's name as the message,
//! what it says as fields. Names, fields and how a value is written are a
//! format, and no value holds whitespace, so a record renders as one line of
//! `key=value` words. The signer that writes a record and the
//! conversation it is about are `signer` and `convo` on the span of the op
//! that writes it, so a line reads
//! `op{signer=.. convo=..}: libchat::mls_trace: <record>`. `run`, which no op
//! writes, names its signer itself.

use std::fmt::{self, Write as _};

use tracing::{Level, trace};

use crate::identity::{ParticipantId, Signer, SignerKey};
use crate::utils::{blake2b_hex, hash_size};

const TARGET: &str = "libchat::mls_trace";

/// Whether the records are written, for a caller to skip gathering what one
/// says when they are not.
pub(crate) fn enabled() -> bool {
    tracing::enabled!(target: TARGET, Level::TRACE)
}

/// A core was built for `signer`, acting for `participant`.
pub(crate) fn run(signer: &SignerKey, participant: &ParticipantId) {
    trace!(
        target: TARGET,
        signer = %Short(signer.as_bytes()),
        participant = %Short(participant.as_bytes()),
        "run"
    );
}

/// The signer entered `epoch` of its conversation, with `signers` as its
/// members. Signers that hold the same group state write the same
/// `state`.
pub(crate) fn epoch(epoch: u64, authenticator: &[u8], signers: &[Signer]) {
    trace!(
        target: TARGET,
        epoch,
        state = %state(authenticator),
        members = signers.len(),
        signers = %Signers(signers),
        "epoch"
    );
}

/// The commit that made `epoch` removed the signer from its
/// conversation.
pub(crate) fn left(epoch: u64) {
    trace!(target: TARGET, epoch, "left");
}

/// The epoch authenticator is a secret the members hold, so a record carries
/// a hash of it.
fn state(authenticator: &[u8]) -> String {
    blake2b_hex::<hash_size::EpochState>(&[
        b"report|".as_slice(),
        b"state|".as_slice(),
        authenticator,
    ])
}

/// An id cut to its first four bytes, in hex.
pub(crate) struct Short<'a>(pub(crate) &'a [u8]);

impl fmt::Display for Short<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let head = &self.0[..self.0.len().min(4)];
        f.write_str(&hex::encode(head))
    }
}

/// A conversation id as one word: a byte outside `[0-9A-Za-z_-]` is written
/// `%xx`. Whoever creates a group picks its id.
pub(crate) struct ConvoId<'a>(pub(crate) &'a str);

impl fmt::Display for ConvoId<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0.bytes() {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-') {
                f.write_char(byte as char)?;
            } else {
                write!(f, "%{byte:02x}")?;
            }
        }
        Ok(())
    }
}

/// Members as `signer:participant`, comma-separated.
struct Signers<'a>(&'a [Signer]);

impl fmt::Display for Signers<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, member) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(",")?;
            }
            write!(
                f,
                "{}:{}",
                Short(member.signer.as_bytes()),
                Short(member.participant_id.as_bytes())
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Buffer(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Buffer {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// What `write` logs, as the default formatter renders it.
    fn rendered(write: impl FnOnce()) -> String {
        let buffer = Buffer::default();
        let writer = buffer.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(Level::TRACE)
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .without_time()
            .finish();
        tracing::subscriber::with_default(subscriber, write);
        let bytes = buffer.0.lock().unwrap().clone();
        String::from_utf8(bytes).unwrap().trim().to_string()
    }

    #[test]
    fn an_epoch_state_keeps_its_digest() {
        // Members on different versions compare it; readers take 16 hex digits.
        assert_eq!(state(b"an epoch authenticator"), "560ea97ab98fe22b");
    }

    #[test]
    fn a_conversation_id_stays_one_word() {
        let line = rendered(|| {
            let op = tracing::info_span!(
                "op",
                signer = %Short(b"\xe0\x9a\x3f\x52\x01\x02"),
                convo = %ConvoId("a b=c\nd%")
            );
            let _in_op = op.enter();
            left(8);
        });
        assert_eq!(
            line,
            "TRACE op{signer=e09a3f52 convo=a%20b%3dc%0ad%25}: libchat::mls_trace: left epoch=8"
        );
    }
}
