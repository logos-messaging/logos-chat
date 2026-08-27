//! Wire format for [`EncodedAccountLog`]: the canonical byte encoding of an
//! [`AccountLog`]. Encoding and decoding live together so they cannot drift
//! apart. The bytes are opaque to the server, which needs only to compare
//! them for the extension check.

use crate::account_log::{
    AccountEntry, AccountLog, EncodedAccountLog, EntryData, SignedAccountLog,
};
use crate::context::Context;
use crate::error::AccountLogError;

/// Domain-separation tag, prepended to every signed payload:
pub const ACCOUNT_LOG_DOMAIN: &[u8] = b"logos:accounts:1\0";

/// [`ACCOUNT_LOG_DOMAIN`] without the version segment.
const DOMAIN_STEM: &[u8] = b"logos:accounts:";

/// Largest payload that may be published or accepted.
pub const MAX_PAYLOAD_BYTES: usize = 128 * 1024;

/// Size of a  Ed25519 S=ignature
const SIGNATURE_LEN: usize = 64;

// Entry opcodes. The high nibble is reserved for per-entry flags and must be
// zero, so only 0x00-0x0f are opcodes at all.
const OP_ADD: u8 = 0x01;
const OP_REMOVE: u8 = 0x02;
const OPCODE_MASK: u8 = 0xf0;

// Data variants, read only after an OP_ADD. A separate space from the
// opcodes: a future data kind and a future operation are separate allocations.
const DATA_ED25519: u8 = 0x01;
const DATA_TEXT: u8 = 0x02;

/// Entry header: opcode (u8) plus body length (u16 LE).
const ENTRY_HEADER: usize = 3;

impl AccountLog {
    /// Canonical binary encoding — the bytes that are both signed and
    /// transmitted:
    ///
    /// ```text
    /// payload := domain || entry*
    ///
    /// domain : ACCOUNT_LOG_DOMAIN   (constant prefix incl. version, NUL-terminated)
    /// entry  : opcode || u16 LE len || body, filling the payload exactly
    ///
    ///   0x01 <len> <u8 ctx_len> <context> 0x01 <32 bytes>   Add(Ed25519Key)
    ///   0x01 <len> <u8 ctx_len> <context> 0x02 <value>      Add(Text), UTF-8
    ///   0x02 <len=0x0004> <u32 LE index>                    Remove
    /// ```
    ///
    /// There is no entry count and no stored index: entries are
    /// self-delimiting and an entry's index is its position, so neither can
    /// disagree with the bytes it describes. The account key is not embedded
    /// either — the account is identified by the address the caller already
    /// holds, and [`verify_log`] checks the signature under it.
    ///
    /// Fails only on [`MAX_PAYLOAD_BYTES`]: an owner must not publish a
    /// payload no consumer will accept.
    pub fn encode(&self) -> Result<EncodedAccountLog, AccountLogError> {
        encode_entries(self.entries())
    }
}

/// The encoder itself. Separate from [`Account::encode`] because it must also
/// serve entries no account can author — an opaque entry written by a newer
/// build, which this one can only carry through unchanged.
pub(crate) fn encode_entries(
    entries: &[AccountEntry],
) -> Result<EncodedAccountLog, AccountLogError> {
    let mut out = Vec::with_capacity(ACCOUNT_LOG_DOMAIN.len() + entries.len() * 51);
    out.extend_from_slice(ACCOUNT_LOG_DOMAIN);
    for entry in entries {
        let (opcode, body) = match entry {
            AccountEntry::Add { context, data } => (OP_ADD, encode_add(context, data)),
            AccountEntry::Remove { index } => (OP_REMOVE, index.to_le_bytes().to_vec()),
            AccountEntry::Unknown { opcode, body } => (*opcode, body.clone()),
        };
        out.push(opcode);
        out.extend_from_slice(&(body.len() as u16).to_le_bytes());
        out.extend_from_slice(&body);
    }
    check_size(&out)?;
    Ok(EncodedAccountLog(out))
}

/// An `Add` body: the context first, then the tagged data. Context precedes
/// the tag so it is parsed uniformly before dispatching on type.
fn encode_add(context: &Context, data: &EntryData) -> Vec<u8> {
    let mut body = Vec::with_capacity(2 + context.as_bytes().len() + 32);
    body.push(context.as_bytes().len() as u8);
    body.extend_from_slice(context.as_bytes());
    match data {
        EntryData::Ed25519Key(key) => {
            body.push(DATA_ED25519);
            body.extend_from_slice(key);
        }
        EntryData::Text(value) => {
            body.push(DATA_TEXT);
            body.extend_from_slice(value.as_bytes());
        }
        EntryData::Unknown { tag, body: raw } => {
            body.push(*tag);
            body.extend_from_slice(raw);
        }
    }
    body
}

impl EncodedAccountLog {
    /// Wrap received bytes as an account-log payload.
    ///
    /// Only the size is checked — enough to refuse a hostile length before
    /// allocating further. Holding one of these asserts nothing about whether
    /// the bytes decode; that is [`decode`](Self::decode)'s answer, and it is
    /// deliberately deferred so a store can hold and compare payloads without
    /// knowing the entry format.
    ///
    /// Bytes from an untrusted source should reach this only through
    /// [`verify_received`], which checks the signature first.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, AccountLogError> {
        check_size(&bytes)?;
        Ok(Self(bytes))
    }

    /// Decode the payload: domain prefix and version, entry framing to the
    /// exact end of the payload, and the log itself via
    /// [`AccountLog::from_entries`].
    pub fn decode(&self) -> Result<AccountLog, AccountLogError> {
        AccountLog::from_entries(decode_entries(&self.0)?)
    }

    /// The exact bytes that are signed and transmitted.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl SignedAccountLog {
    /// The transmitted artifact: `signature || payload`.
    ///
    /// The signature comes first because it is fixed-width, so the payload is
    /// whatever remains. No length is carried: one would sit outside the
    /// signature and could disagree with it.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SIGNATURE_LEN + self.payload.as_bytes().len());
        out.extend_from_slice(self.signature.as_ref());
        out.extend_from_slice(self.payload.as_bytes());
        out
    }

    /// Inverse of [`to_bytes`](Self::to_bytes). Splits and size-checks only —
    /// call [`verify`](Self::verify) before trusting the result.
    pub fn from_bytes(artifact: &[u8]) -> Result<Self, AccountLogError> {
        if artifact.len() < SIGNATURE_LEN + ACCOUNT_LOG_DOMAIN.len() {
            return Err(malformed(
                "artifact too short to hold a signature and a payload",
            ));
        }
        let (signature, payload) = artifact.split_at(SIGNATURE_LEN);
        let signature: [u8; SIGNATURE_LEN] = signature.try_into().expect("checked length");
        Ok(Self {
            payload: EncodedAccountLog::from_bytes(payload.to_vec())?,
            signature: signature.into(),
        })
    }
}

/// Shorthand for the reject-only decode failures.
fn malformed(detail: impl Into<String>) -> AccountLogError {
    AccountLogError::Malformed(detail.into())
}

fn check_size(payload: &[u8]) -> Result<(), AccountLogError> {
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(AccountLogError::TooLarge(MAX_PAYLOAD_BYTES));
    }
    Ok(())
}

/// Decoder behind [`EncodedAccountLog::decode`].
fn decode_entries(payload: &[u8]) -> Result<Vec<AccountEntry>, AccountLogError> {
    let Some(mut body) = payload.strip_prefix(ACCOUNT_LOG_DOMAIN) else {
        return Err(domain_error(payload));
    };
    let mut entries = Vec::new();
    while !body.is_empty() {
        let (entry, rest) = decode_entry(body)?;
        entries.push(entry);
        body = rest;
    }
    Ok(entries)
}

/// Parse one entry off the front of `body`, returning it and the rest.
///
/// The length prefix is read before the opcode is interpreted, so an entry
/// this version does not understand still yields its extent — which is what
/// lets it be kept as an opaque slot instead of rejecting the whole log.
fn decode_entry(input: &[u8]) -> Result<(AccountEntry, &[u8]), AccountLogError> {
    let (header, rest) = split_at_checked(input, ENTRY_HEADER)?;
    let opcode = header[0];
    if opcode & OPCODE_MASK != 0 {
        return Err(malformed(format!(
            "entry opcode {opcode:#04x} has reserved high bits set"
        )));
    }
    let len = u16::from_le_bytes(header[1..3].try_into().expect("2 bytes")) as usize;
    let (body, rest) = split_at_checked(rest, len)?;

    let entry = match opcode {
        OP_ADD => decode_add(body)?,
        OP_REMOVE => {
            let index = body
                .try_into()
                .map(u32::from_le_bytes)
                .map_err(|_| malformed(format!("remove body is {len} bytes, must be 4")))?;
            AccountEntry::Remove { index }
        }
        _ => AccountEntry::Unknown {
            opcode,
            body: body.to_vec(),
        },
    };
    Ok((entry, rest))
}

/// `ctx_len || context || data_tag || data_body`, filling the entry body
/// exactly. An unreadable `data_tag` is opaque, but the context is always
/// parsed: it is what selects the entry, known tag or not.
fn decode_add(body: &[u8]) -> Result<AccountEntry, AccountLogError> {
    let (&ctx_len, rest) = body
        .split_first()
        .ok_or_else(|| malformed("add body is empty"))?;
    if ctx_len == 0 {
        return Err(malformed("add context length is zero"));
    }
    let (context, rest) = split_at_checked(rest, ctx_len as usize)?;
    let context = Context::from_bytes(context)?;
    let (&tag, data) = rest
        .split_first()
        .ok_or_else(|| malformed("add context leaves no room for a data tag"))?;

    let data = match tag {
        DATA_ED25519 => {
            let key: [u8; 32] = data.try_into().map_err(|_| {
                malformed(format!("ed25519 key is {} bytes, must be 32", data.len()))
            })?;
            EntryData::Ed25519Key(key)
        }
        DATA_TEXT => EntryData::Text(
            String::from_utf8(data.to_vec()).map_err(|_| malformed("text record is not UTF-8"))?,
        ),
        tag => EntryData::Unknown {
            tag,
            body: data.to_vec(),
        },
    };
    Ok(AccountEntry::Add { context, data })
}

/// Classify a payload that failed the domain check: our stem with a different
/// version segment, or a foreign domain altogether. An operator can then tell
/// "newer than me" from "corrupt".
fn domain_error(payload: &[u8]) -> AccountLogError {
    let Some(rest) = payload.strip_prefix(DOMAIN_STEM) else {
        return malformed("payload is missing the account-log domain prefix");
    };
    match rest.iter().take(16).position(|&b| b == 0) {
        Some(end) => AccountLogError::Version(String::from_utf8_lossy(&rest[..end]).into_owned()),
        None => malformed("payload is missing the account-log domain prefix"),
    }
}

/// `split_at` that reports a truncated payload instead of panicking.
fn split_at_checked(body: &[u8], mid: usize) -> Result<(&[u8], &[u8]), AccountLogError> {
    if body.len() < mid {
        return Err(malformed("payload shorter than its declared layout"));
    }
    Ok(body.split_at(mid))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AccountAddr;
    use crate::context::SIGNER_CONTEXT;
    use crate::crypto::Ed25519SigningKey;

    fn key_bytes() -> [u8; 32] {
        Ed25519SigningKey::generate()
            .verifying_key()
            .as_ref()
            .try_into()
            .expect("32 bytes")
    }

    fn key() -> AccountEntry {
        AccountEntry::add(SIGNER_CONTEXT.clone(), EntryData::Ed25519Key(key_bytes()))
    }

    fn make_log(entries: Vec<AccountEntry>) -> AccountLog {
        AccountLog::from_entries(entries).unwrap()
    }

    fn encoded(entries: Vec<AccountEntry>) -> EncodedAccountLog {
        encode_entries(&entries).unwrap()
    }

    /// encode → decode round-trips every variant, and parse accepts encode's
    /// bytes. Opaque entries round-trip byte-for-byte too, or re-encoding a
    /// log a consumer only partly understands would rewrite it.
    #[test]
    fn payload_roundtrips() {
        let log = make_log(vec![
            key(),
            key(),
            AccountEntry::Remove { index: 0 },
            AccountEntry::add(
                Context::new("profile.displayname").unwrap(),
                EntryData::Text("alice".into()),
            ),
            AccountEntry::Unknown {
                opcode: 0x0f,
                body: vec![0xde, 0xad, 0xbe, 0xef],
            },
            AccountEntry::add(
                SIGNER_CONTEXT.clone(),
                EntryData::Unknown {
                    tag: 0x7f,
                    body: vec![1, 2, 3],
                },
            ),
        ]);
        let payload = encode_entries(log.entries()).unwrap();
        assert_eq!(payload.decode().unwrap(), log);
        assert_eq!(
            EncodedAccountLog::from_bytes(payload.as_bytes().to_vec()).unwrap(),
            payload
        );

        // Empty log is valid (an account with no entries yet).
        assert!(encoded(vec![]).decode().unwrap().entries().is_empty());
    }

    /// A `Text` with an empty value is a present-but-blank record, not an
    /// error: the entry length bounds it, so zero bytes is expressible.
    #[test]
    fn empty_text_roundtrips() {
        let log = make_log(vec![AccountEntry::add(
            SIGNER_CONTEXT.clone(),
            EntryData::Text(String::new()),
        )]);
        assert_eq!(
            encode_entries(log.entries()).unwrap().decode().unwrap(),
            log
        );
    }

    #[test]
    fn decode_rejects_truncated_entries() {
        // Drop a key byte: the last entry's declared length no longer fits.
        let mut bytes = encoded(vec![key()]).as_bytes().to_vec();
        bytes.pop();
        assert!(matches!(
            EncodedAccountLog::from_bytes(bytes).unwrap().decode(),
            Err(AccountLogError::Malformed(m)) if m.contains("shorter than")
        ));

        // A lone opcode with no length.
        let mut bytes = ACCOUNT_LOG_DOMAIN.to_vec();
        bytes.push(OP_ADD);
        assert!(matches!(
            EncodedAccountLog::from_bytes(bytes).unwrap().decode(),
            Err(AccountLogError::Malformed(_))
        ));
    }

    /// Bytes past the last entry are not a valid payload: entries fill it
    /// exactly.
    #[test]
    fn decode_rejects_trailing_bytes() {
        let mut bytes = encoded(vec![key()]).as_bytes().to_vec();
        bytes.extend_from_slice(&[0xff, 0xff]);
        assert!(matches!(
            EncodedAccountLog::from_bytes(bytes).unwrap().decode(),
            Err(AccountLogError::Malformed(_))
        ));
    }

    #[test]
    fn decode_rejects_missing_domain() {
        let payload = encoded(vec![]);
        let without_domain = payload.as_bytes()[ACCOUNT_LOG_DOMAIN.len()..].to_vec();
        assert!(matches!(
            EncodedAccountLog::from_bytes(without_domain).unwrap().decode(),
            Err(AccountLogError::Malformed(m)) if m.contains("domain")
        ));
    }

    #[test]
    fn decode_rejects_bad_version() {
        let mut bytes = encoded(vec![]).as_bytes().to_vec();
        bytes[ACCOUNT_LOG_DOMAIN.len() - 2] = b'9'; // the version character
        assert!(matches!(
            EncodedAccountLog::from_bytes(bytes).unwrap().decode(),
            Err(AccountLogError::Version(v)) if v == "9"
        ));
    }

    /// The high nibble is reserved for future per-entry flags, so an opcode
    /// that sets it is not an unknown opcode — it is a malformed entry.
    #[test]
    fn decode_rejects_reserved_opcode_bits() {
        let mut bytes = encoded(vec![key()]).as_bytes().to_vec();
        bytes[ACCOUNT_LOG_DOMAIN.len()] = 0x81;
        assert!(matches!(
            EncodedAccountLog::from_bytes(bytes).unwrap().decode(),
            Err(AccountLogError::Malformed(m)) if m.contains("reserved high bits")
        ));
    }

    /// A known opcode must match the body its operation requires: trailing
    /// bytes inside an entry are not permitted.
    #[test]
    fn decode_rejects_wrong_body_length_for_known_opcodes() {
        let mut bytes = ACCOUNT_LOG_DOMAIN.to_vec();
        bytes.push(OP_REMOVE);
        bytes.extend_from_slice(&5u16.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 5]);
        assert!(matches!(
            EncodedAccountLog::from_bytes(bytes).unwrap().decode(),
            Err(AccountLogError::Malformed(m)) if m.contains("must be 4")
        ));

        // An Add(Ed25519Key) with 31 key bytes.
        let mut body = vec![SIGNER_CONTEXT.as_bytes().len() as u8];
        body.extend_from_slice(SIGNER_CONTEXT.as_bytes());
        body.push(DATA_ED25519);
        body.extend_from_slice(&[7u8; 31]);
        let mut bytes = ACCOUNT_LOG_DOMAIN.to_vec();
        bytes.push(OP_ADD);
        bytes.extend_from_slice(&(body.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&body);
        assert!(matches!(
            EncodedAccountLog::from_bytes(bytes).unwrap().decode(),
            Err(AccountLogError::Malformed(m)) if m.contains("must be 32")
        ));
    }

    /// A context is always parsed and validated, even where the data under it
    /// is unreadable: the context is what selects the entry.
    #[test]
    fn decode_rejects_bad_contexts() {
        let add_with_context = |context: &[u8]| {
            let mut body = vec![context.len() as u8];
            body.extend_from_slice(context);
            body.push(DATA_ED25519);
            body.extend_from_slice(&[7u8; 32]);
            let mut bytes = ACCOUNT_LOG_DOMAIN.to_vec();
            bytes.push(OP_ADD);
            bytes.extend_from_slice(&(body.len() as u16).to_le_bytes());
            bytes.extend_from_slice(&body);
            EncodedAccountLog::from_bytes(bytes).unwrap().decode()
        };

        for context in [&b"chat.sign@r"[..], b"signer", b"1chat.signer"] {
            assert!(matches!(
                add_with_context(context),
                Err(AccountLogError::InvalidContext(_))
            ));
        }

        // ctx_len = 0, and a context that consumes the whole body.
        let mut bytes = ACCOUNT_LOG_DOMAIN.to_vec();
        bytes.push(OP_ADD);
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.push(0);
        assert!(matches!(
            EncodedAccountLog::from_bytes(bytes).unwrap().decode(),
            Err(AccountLogError::Malformed(m)) if m.contains("context length is zero")
        ));

        let context = SIGNER_CONTEXT.as_bytes();
        let mut bytes = ACCOUNT_LOG_DOMAIN.to_vec();
        bytes.push(OP_ADD);
        bytes.extend_from_slice(&((1 + context.len()) as u16).to_le_bytes());
        bytes.push(context.len() as u8);
        bytes.extend_from_slice(context);
        assert!(matches!(
            EncodedAccountLog::from_bytes(bytes).unwrap().decode(),
            Err(AccountLogError::Malformed(m)) if m.contains("no room for a data tag")
        ));
    }

    /// Well-formed bytes carrying an invalid log (a self-referencing remove)
    /// are rejected at parse: broken logs never get past the boundary. Such
    /// bytes cannot be produced through the API, so they are handcrafted.
    #[test]
    fn decode_rejects_invalid_log() {
        let mut bytes = ACCOUNT_LOG_DOMAIN.to_vec();
        bytes.push(OP_REMOVE);
        bytes.extend_from_slice(&4u16.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes()); // Remove{0} at position 0
        assert!(matches!(
            EncodedAccountLog::from_bytes(bytes).unwrap().decode(),
            Err(AccountLogError::Malformed(m)) if m.contains("remove at position")
        ));
    }

    /// The size cap binds on both sides: an owner cannot sign a payload no
    /// consumer would accept, and a consumer will not decode one.
    #[test]
    fn oversize_payloads_are_refused() {
        let mut bytes = ACCOUNT_LOG_DOMAIN.to_vec();
        bytes.resize(MAX_PAYLOAD_BYTES + 1, 0);
        // Size is the one thing `from_bytes` still checks, so it never reaches
        // the decoder.
        assert!(matches!(
            EncodedAccountLog::from_bytes(bytes),
            Err(AccountLogError::TooLarge(MAX_PAYLOAD_BYTES))
        ));

        let big = Context::new("chat.signer").unwrap();
        let filler = "x".repeat(60_000);
        let entries = vec![
            AccountEntry::add(big.clone(), EntryData::Text(filler.clone())),
            AccountEntry::add(big.clone(), EntryData::Text(filler.clone())),
            AccountEntry::add(big, EntryData::Text(filler)),
        ];
        assert!(matches!(
            encode_entries(&entries),
            Err(AccountLogError::TooLarge(_))
        ));
    }

    /// Full happy path: sign with the account key, verify under the account key.
    #[test]
    fn verify_accepts_well_formed_log() {
        let account_key = Ed25519SigningKey::generate();
        let addr = AccountAddr::from(&account_key.verifying_key());
        let log = make_log(vec![key(), key()]);

        let payload = encode_entries(log.entries()).unwrap();
        let signed = SignedAccountLog {
            signature: account_key.sign(payload.as_bytes()),
            payload,
        };

        assert_eq!(signed.verify(&addr).unwrap(), log);
        // The artifact round-trips, and still verifies once reassembled.
        let reassembled = SignedAccountLog::from_bytes(&signed.to_bytes()).unwrap();
        assert_eq!(reassembled, signed);
        assert_eq!(reassembled.verify(&addr).unwrap(), log);
    }

    /// A log validly signed by account A, served as the answer to a query for
    /// account B, fails: B's key does not verify A's signature. This is the
    /// anti-substitution guarantee.
    #[test]
    fn verify_rejects_wrong_account() {
        let account_key = Ed25519SigningKey::generate();
        let payload = encoded(vec![]);
        let signed = SignedAccountLog {
            signature: account_key.sign(payload.as_bytes()),
            payload,
        };

        let other = AccountAddr::from(&Ed25519SigningKey::generate().verifying_key());
        assert!(matches!(
            signed.verify(&other),
            Err(AccountLogError::SignatureInvalid)
        ));
    }

    /// A signature over one entry list does not verify another.
    #[test]
    fn verify_rejects_swapped_payload() {
        let account_key = Ed25519SigningKey::generate();
        let addr = AccountAddr::from(&account_key.verifying_key());

        let signature = account_key.sign(encoded(vec![key()]).as_bytes());
        let signed = SignedAccountLog {
            payload: encoded(vec![key()]),
            signature,
        };
        assert!(matches!(
            signed.verify(&addr),
            Err(AccountLogError::SignatureInvalid)
        ));
    }

    /// Received bytes are verified before they are decoded, so a bad signature
    /// is reported even when the payload is also garbage.
    #[test]
    fn received_bytes_are_verified_before_decoding() {
        let account_key = Ed25519SigningKey::generate();
        let addr = AccountAddr::from(&account_key.verifying_key());
        let junk = b"not a log at all".to_vec();

        let wrong_sig = SignedAccountLog {
            payload: EncodedAccountLog::from_bytes(junk.clone()).unwrap(),
            signature: account_key.sign(b"other"),
        };
        assert!(matches!(
            wrong_sig.verify(&addr),
            Err(AccountLogError::SignatureInvalid)
        ));

        // Correctly signed but malformed bytes are authentic, so the signature
        // check passes; decoding is deferred, and rejects them there.
        let signed = SignedAccountLog {
            payload: EncodedAccountLog::from_bytes(junk.clone()).unwrap(),
            signature: account_key.sign(&junk),
        };
        assert!(matches!(
            signed.verify(&addr),
            Err(AccountLogError::Malformed(_))
        ));

        // An artifact with no room for a payload never reaches either check.
        assert!(matches!(
            SignedAccountLog::from_bytes(&[0u8; 64]),
            Err(AccountLogError::Malformed(m)) if m.contains("too short")
        ));
    }

    /// Appending entries is the only thing that reads as newer; everything
    /// else is identical, behind, or a divergence.
    #[test]
    fn freshness_treats_appends_only_as_newer() {
        use crate::account_log::{LogFreshness, compare_log_freshness};
        let compare = |old: &EncodedAccountLog, new: &EncodedAccountLog| {
            compare_log_freshness(old.as_bytes(), new.as_bytes())
        };

        let first = key();
        let old = encoded(vec![first.clone()]);
        let new = encoded(vec![first.clone(), key()]);
        assert_eq!(compare(&old, &new), LogFreshness::Newer);

        // An extension has to add something.
        assert_eq!(compare(&old, &old), LogFreshness::Identical);

        // An older version of the same history is behind, not a divergence.
        assert_eq!(compare(&new, &old), LogFreshness::Behind);

        // Longer, but rewrites entry 0.
        let fork = encoded(vec![key(), key()]);
        assert_eq!(compare(&old, &fork), LogFreshness::Diverged);

        // Same length, different history: divergence, not staleness.
        let sibling = encoded(vec![key()]);
        assert_eq!(compare(&old, &sibling), LogFreshness::Diverged);
    }
}
