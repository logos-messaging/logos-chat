use std::fmt;
use std::str::FromStr;

use crate::crypto::Ed25519VerifyingKey;
use crate::error::AccountAddrError;

/// A routable representation of an account
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AccountAddr {
    pubkey: Ed25519VerifyingKey,
}

impl AccountAddr {
    pub fn to_bytes(&self) -> &[u8] {
        self.pubkey.as_ref()
    }

    /// The verifying key this address wraps — what signatures are checked under.
    pub(crate) fn verifying_key(&self) -> &Ed25519VerifyingKey {
        &self.pubkey
    }
}

/// Displays as the hex of the account verifying key — the same form the
/// directory and keypackage registry use for ids.
impl fmt::Display for AccountAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.pubkey.as_ref()))
    }
}

impl From<&Ed25519VerifyingKey> for AccountAddr {
    fn from(value: &Ed25519VerifyingKey) -> Self {
        Self {
            pubkey: value.clone(),
        }
    }
}

/// The string form is exactly what [`Display`](fmt::Display) produces: 64
/// lowercase hex characters, unprefixed. Uppercase and prefixed variants are
/// rejected rather than accepted-and-normalized, so one address has one
/// spelling and two implementations cannot disagree on what they hold.
impl FromStr for AccountAddr {
    type Err = AccountAddrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 64
            || !s
                .bytes()
                .all(|b| b.is_ascii_digit() || b.is_ascii_lowercase())
        {
            return Err(AccountAddrError::InvalidAddress);
        }
        let bytes = hex::decode(s).map_err(|_| AccountAddrError::InvalidAddress)?;
        Self::try_from(bytes.as_slice())
    }
}

/// Not every byte string is an address: exactly 32 bytes forming a valid
/// Ed25519 key.
impl TryFrom<&[u8]> for AccountAddr {
    type Error = AccountAddrError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let bytes: [u8; 32] = value.try_into().map_err(|_| AccountAddrError::InvalidAddress)?;
        let pubkey =
            Ed25519VerifyingKey::from_canonical_bytes(&bytes)
                .map_err(|_| AccountAddrError::InvalidAddress)?;
        Ok(Self { pubkey })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Ed25519SigningKey;

    /// Display is the hex of the key; TryFrom round-trips the bytes.
    #[test]
    fn display_and_try_from_roundtrip() {
        let key = Ed25519SigningKey::generate().verifying_key();
        let addr = AccountAddr::from(&key);
        assert_eq!(addr.to_string(), hex::encode(key.as_ref()));
        assert_eq!(AccountAddr::try_from(addr.to_bytes()).unwrap(), addr);
    }

    #[test]
    fn try_from_rejects_wrong_length() {
        assert!(AccountAddr::try_from(&[0u8; 31][..]).is_err());
    }

    /// Only the canonical spelling parses: uppercase and prefixed forms are
    /// rejected, not normalized.
    #[test]
    fn from_str_accepts_only_lowercase_unprefixed_hex() {
        let key = Ed25519SigningKey::generate().verifying_key();
        let addr = AccountAddr::from(&key);
        let canonical = addr.to_string();

        assert_eq!(canonical.parse::<AccountAddr>().unwrap(), addr);
        for bad in [
            canonical.to_uppercase(),
            format!("0x{canonical}"),
            canonical[..63].to_string(),
            format!("{canonical}0"),
        ] {
            assert!(bad.parse::<AccountAddr>().is_err(), "accepted {bad}");
        }
    }
}
