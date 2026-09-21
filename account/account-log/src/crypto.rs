//! The crate's only dependency on a concrete Ed25519 implementation.
//!
//! Dalek types are wrapped rather than re-exported so they never appear in this
//! crate's public API: the backend stays swappable, and every byte-level rule
//! about a key or a signature has one place to live.

use ed25519_dalek::Signer as _;

use crate::error::AccountLogError;

/// An Ed25519 signing key. Wrapped so the dalek type stays inside this module.
#[derive(Clone)]
pub struct Ed25519SigningKey(ed25519_dalek::SigningKey);

impl Ed25519SigningKey {
    pub fn generate() -> Self {
        Self(ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng))
    }

    pub fn verifying_key(&self) -> Ed25519VerifyingKey {
        Ed25519VerifyingKey(self.0.verifying_key())
    }

    pub fn sign(&self, msg: &[u8]) -> Ed25519Signature {
        Ed25519Signature(self.0.sign(msg).to_bytes())
    }
}

/// Never print key material.
impl std::fmt::Debug for Ed25519SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Ed25519SigningKey")
            .field(&"[redacted]")
            .finish()
    }
}

/// Raw key and signature widths, before any prefix.
pub const KEY_LEN: usize = 32;
pub const SIG_LEN: usize = 64;

/// An Ed25519 verifying key that is canonically encoded and not small-order.
///
/// Both checks happen here, at construction, so a key one implementation admits
/// and another rejects cannot exist.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ed25519VerifyingKey(ed25519_dalek::VerifyingKey);

/// An Ed25519 signature, held as its 64 canonical bytes. Nothing is checked
/// here: malleable and small-order-component signatures are rejected on verify
/// by `verify_strict`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ed25519Signature([u8; SIG_LEN]);

impl Ed25519VerifyingKey {
    /// Accept `bytes` only if they are the one valid encoding of a usable key:
    /// canonical `y`, a real curve point, and not small-order.
    pub fn from_canonical_bytes(bytes: &[u8; KEY_LEN]) -> Result<Self, AccountLogError> {
        if !is_canonical_y(bytes) {
            return Err(AccountLogError::Malformed(
                "key is not a canonical Ed25519 encoding".into(),
            ));
        }
        let key = ed25519_dalek::VerifyingKey::from_bytes(bytes)
            .map_err(|_| AccountLogError::Malformed("key is not an Ed25519 curve point".into()))?;
        if key.is_weak() {
            return Err(AccountLogError::Malformed(
                "key is a small-order Ed25519 point".into(),
            ));
        }
        Ok(Self(key))
    }

    pub fn to_bytes(&self) -> [u8; KEY_LEN] {
        self.0.to_bytes()
    }

    /// Strict verification: rejects malleable and small-order-component
    /// signatures that permissive verifiers accept.
    pub fn verify(&self, msg: &[u8], sig: &Ed25519Signature) -> Result<(), AccountLogError> {
        let sig = ed25519_dalek::Signature::from_bytes(&sig.0);
        self.0
            .verify_strict(msg, &sig)
            .map_err(|_| AccountLogError::SignatureInvalid)
    }
}

impl Ed25519Signature {
    pub fn from_bytes(bytes: &[u8; SIG_LEN]) -> Self {
        Self(*bytes)
    }

    pub fn to_bytes(&self) -> [u8; SIG_LEN] {
        self.0
    }
}

impl AsRef<[u8]> for Ed25519VerifyingKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl AsRef<[u8]> for Ed25519Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; SIG_LEN]> for Ed25519Signature {
    fn from(bytes: [u8; SIG_LEN]) -> Self {
        Self(bytes)
    }
}

/// `2^255 - 19`, little-endian — the field prime.
const FIELD_ORDER_LE: [u8; KEY_LEN] = {
    let mut p = [0xff; KEY_LEN];
    p[0] = 0xed;
    p[31] = 0x7f;
    p
};

/// Whether `y` (the low 255 bits) is less than the field prime.
///
/// Dalek's `from_bytes` reduces an out-of-range `y` instead of rejecting it, and
/// its `to_bytes` returns the bytes it was given, so a round-trip check cannot
/// detect this. Two encodings decoding to one key would let a log's live set
/// differ between implementations, so the comparison is done on the bytes.
fn is_canonical_y(bytes: &[u8; KEY_LEN]) -> bool {
    let mut y = *bytes;
    y[31] &= 0x7f; // drop the sign bit; it is not part of y
    for i in (0..KEY_LEN).rev() {
        if y[i] != FIELD_ORDER_LE[i] {
            return y[i] < FIELD_ORDER_LE[i];
        }
    }
    false // y == p exactly
}

#[cfg(test)]
mod tests {
    use super::*;

    /// All-zero is the identity point: canonically encoded, but small-order.
    #[test]
    fn rejects_small_order_keys() {
        assert!(Ed25519VerifyingKey::from_canonical_bytes(&[0u8; KEY_LEN]).is_err());
    }

    /// `y = 2^255 - 18` is one past the field prime — an encoding dalek would
    /// silently reduce to `y = 1`.
    #[test]
    fn rejects_non_canonical_y() {
        let mut unreduced = [0xffu8; KEY_LEN];
        unreduced[0] = 0xee;
        unreduced[31] = 0x7f;
        assert!(!is_canonical_y(&unreduced));
        assert!(Ed25519VerifyingKey::from_canonical_bytes(&unreduced).is_err());

        // p itself is likewise not a valid y.
        assert!(!is_canonical_y(&FIELD_ORDER_LE));
        // p - 1 is in range, and the sign bit is ignored when comparing.
        let mut max = FIELD_ORDER_LE;
        max[0] -= 1;
        assert!(is_canonical_y(&max));
        max[31] |= 0x80;
        assert!(is_canonical_y(&max));
    }

    #[test]
    fn signatures_roundtrip_and_verify() {
        let signing = Ed25519SigningKey::generate();
        let verifying = signing.verifying_key();
        let sig = signing.sign(b"payload");

        assert_eq!(Ed25519Signature::from_bytes(&sig.to_bytes()), sig);
        assert!(verifying.verify(b"payload", &sig).is_ok());
        assert!(verifying.verify(b"other", &sig).is_err());
    }
}
