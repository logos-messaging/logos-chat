//! Trace records: what this installation holds and what became of the
//! frames it sent and was handed, one log event per fact.
//!
//! Each is one `TRACE` event on [`TARGET`]: the record's name as the message,
//! what it says as fields. Names, fields and how a value is written are a
//! format, and no value holds whitespace, so a record renders as one line of
//! `key=value` words.

use std::fmt::{self, Write as _};

use tracing::{Level, trace};

use crate::identity::{ParticipantId, Signer, SignerKey};
use crate::utils::{blake2b_hex, hash_size};

const TARGET: &str = "libchat::mls_trace";

/// Whether the records are written, for a caller to skip gathering what one
/// says when they are not.
pub(super) fn enabled() -> bool {
    tracing::enabled!(target: TARGET, Level::TRACE)
}

/// A core was built for `installation`, acting for `account`.
pub(crate) fn run(installation: &SignerKey, account: &ParticipantId) {
    trace!(
        target: TARGET,
        installation = %Short(installation.as_bytes()),
        account = %Short(account.as_bytes()),
        "run"
    );
}

/// `installation` holds `convo` at `epoch`, with `roster` as its members.
/// Installations that hold the same group state write the same `state`.
pub(super) fn epoch(
    installation: &SignerKey,
    convo: &str,
    epoch: u64,
    authenticator: &[u8],
    roster: &[Signer],
) {
    trace!(
        target: TARGET,
        installation = %Short(installation.as_bytes()),
        convo = %ConvoId(convo),
        epoch,
        state = %state(authenticator),
        members = roster.len(),
        roster = %Roster(roster),
        "epoch"
    );
}

/// The commit that made `epoch` removed `installation` from `convo`.
pub(super) fn left(installation: &SignerKey, convo: &str, epoch: u64) {
    trace!(
        target: TARGET,
        installation = %Short(installation.as_bytes()),
        convo = %ConvoId(convo),
        epoch,
        "left"
    );
}

/// `installation` published a post of its own to `convo` as `frame`, sent at
/// `epoch`.
pub(super) fn sent(installation: &SignerKey, convo: &str, frame: &[u8], epoch: u64) {
    trace!(
        target: TARGET,
        installation = %Short(installation.as_bytes()),
        convo = %ConvoId(convo),
        frame = %frame_id(frame),
        epoch,
        "sent"
    );
}

/// `installation` read the post `frame` carries, which `from` sent at
/// `epoch`.
pub(super) fn received(
    installation: &SignerKey,
    convo: &str,
    frame: &[u8],
    from: &SignerKey,
    epoch: u64,
) {
    trace!(
        target: TARGET,
        installation = %Short(installation.as_bytes()),
        convo = %ConvoId(convo),
        frame = %frame_id(frame),
        from = %Short(from.as_bytes()),
        epoch,
        "received"
    );
}

/// `frame`, sent at `epoch`, reached `installation` and could not be read.
pub(super) fn unreadable(
    installation: &SignerKey,
    convo: &str,
    frame: &[u8],
    epoch: u64,
    why: Why,
) {
    trace!(
        target: TARGET,
        installation = %Short(installation.as_bytes()),
        convo = %ConvoId(convo),
        frame = %frame_id(frame),
        epoch,
        why = %why,
        "unreadable"
    );
}

/// Why a frame could not be read.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Why {
    /// It is of another epoch than the installation holds.
    Epoch,
    /// It is of the epoch number the installation holds and did not decrypt.
    Decrypt,
    /// Its post decrypted and the sender's account could not be checked.
    Sender,
}

impl fmt::Display for Why {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Why::Epoch => "epoch",
            Why::Decrypt => "decrypt",
            Why::Sender => "sender",
        })
    }
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

/// An encoded frame reaches each receiver as its sender wrote it, so a hash
/// of the bytes names the frame at both ends.
fn frame_id(encoded: &[u8]) -> String {
    blake2b_hex::<hash_size::FrameId>(&[b"report|".as_slice(), b"frame|".as_slice(), encoded])
}

/// An id cut to its first four bytes, in hex.
struct Short<'a>(&'a [u8]);

impl fmt::Display for Short<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let head = &self.0[..self.0.len().min(4)];
        f.write_str(&hex::encode(head))
    }
}

/// A conversation id as one word: a byte outside `[0-9A-Za-z_-]` is written
/// `%xx`. Whoever creates a group picks its id.
struct ConvoId<'a>(&'a str);

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

/// Members as `installation:account`, comma-separated.
struct Roster<'a>(&'a [Signer]);

impl fmt::Display for Roster<'_> {
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

    fn installation(hex_id: &str) -> SignerKey {
        SignerKey::from(hex::decode(hex_id).unwrap().as_slice())
    }

    fn account(hex_id: &str) -> ParticipantId {
        ParticipantId::from(hex::decode(hex_id).unwrap().as_slice())
    }

    fn member(installation_hex: &str, account_hex: &str) -> Signer {
        Signer {
            signer: installation(installation_hex),
            participant_id: account(account_hex),
        }
    }

    #[test]
    fn run_line() {
        let line = rendered(|| run(&installation("e09a3f5201020304"), &account("5be2c0d1aabb")));
        assert_eq!(
            line,
            "TRACE libchat::mls_trace: run installation=e09a3f52 account=5be2c0d1"
        );
    }

    #[test]
    fn epoch_line() {
        let roster = [
            member("e09a3f5201020304", "5be2c0d1aabb"),
            member("a3f91c0705060708", "91c0e3a7ccdd"),
        ];
        let line = rendered(|| {
            epoch(
                &installation("e09a3f5201020304"),
                "2a30d6a2c1",
                7,
                b"an epoch authenticator",
                &roster,
            )
        });
        assert_eq!(
            line,
            "TRACE libchat::mls_trace: epoch installation=e09a3f52 convo=2a30d6a2c1 epoch=7 \
             state=560ea97ab98fe22b members=2 roster=e09a3f52:5be2c0d1,a3f91c07:91c0e3a7"
        );
    }

    #[test]
    fn a_conversation_id_stays_one_word() {
        let line = rendered(|| left(&installation("e09a3f5201020304"), "a b=c\nd%", 8));
        assert_eq!(
            line,
            "TRACE libchat::mls_trace: left installation=e09a3f52 convo=a%20b%3dc%0ad%25 epoch=8"
        );
    }

    #[test]
    fn left_line() {
        let line = rendered(|| left(&installation("e09a3f5201020304"), "2a30d6a2c1", 8));
        assert_eq!(
            line,
            "TRACE libchat::mls_trace: left installation=e09a3f52 convo=2a30d6a2c1 epoch=8"
        );
    }

    #[test]
    fn sent_line() {
        let line = rendered(|| {
            sent(
                &installation("e09a3f5201020304"),
                "2a30d6a2c1",
                b"an encoded frame",
                7,
            )
        });
        assert_eq!(
            line,
            "TRACE libchat::mls_trace: sent installation=e09a3f52 convo=2a30d6a2c1 \
             frame=7aca96962fbe257f epoch=7"
        );
    }

    #[test]
    fn received_line() {
        let line = rendered(|| {
            received(
                &installation("a3f91c0705060708"),
                "2a30d6a2c1",
                b"an encoded frame",
                &installation("e09a3f5201020304"),
                7,
            )
        });
        assert_eq!(
            line,
            "TRACE libchat::mls_trace: received installation=a3f91c07 convo=2a30d6a2c1 \
             frame=7aca96962fbe257f from=e09a3f52 epoch=7"
        );
    }

    #[test]
    fn unreadable_line() {
        let unreadable_for = |why| {
            rendered(|| {
                unreadable(
                    &installation("a3f91c0705060708"),
                    "2a30d6a2c1",
                    b"an encoded frame",
                    7,
                    why,
                )
            })
        };
        for (why, written) in [
            (Why::Epoch, "epoch"),
            (Why::Decrypt, "decrypt"),
            (Why::Sender, "sender"),
        ] {
            assert_eq!(
                unreadable_for(why),
                format!(
                    "TRACE libchat::mls_trace: unreadable installation=a3f91c07 \
                     convo=2a30d6a2c1 frame=7aca96962fbe257f epoch=7 why={written}"
                )
            );
        }
    }
}
