use crypto::{Ed25519SigningKey, Ed25519VerifyingKey};
use libchat::{IdentityProvider, Signer, trunc};

use crate::ClientError;

type AccountAddr = String;

/// A local signing identity that holds an Ed25519 keypair — the per-device
/// (installation) signer. It knows nothing about accounts: the client composes
/// the account association into the wire credential ([`DelegateIdentity`]).
pub struct DelegateSigner {
    signing_key: Ed25519SigningKey,
    verifying_key: Ed25519VerifyingKey,
}

impl DelegateSigner {
    /// Create a new signer with a randomly generated keypair.
    pub fn random() -> Self {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    pub fn public_key(&self) -> &Ed25519VerifyingKey {
        &self.verifying_key
    }

    pub fn sign(&self, payload: &[u8]) -> crypto::Ed25519Signature {
        self.signing_key.sign(payload)
    }
}

/// The identity the core sees: a [`DelegateSigner`] plus the wire credential
/// the client composed from it and its account address. The account
/// association is client state; neither the signer nor the core knows it.
pub(crate) struct DelegateIdentity {
    signer: DelegateSigner,
    /// The delegate key, which is what this identity signs under.
    identity: Signer,
    /// The account claim, serialized — carried in the MLS leaf credential and
    /// opaque to the core.
    credential: Vec<u8>,
}

impl DelegateIdentity {
    pub(crate) fn new(signer: DelegateSigner, account: &str) -> Self {
        let credential = DelegateCredential::associated(signer.public_key(), account).serialize();
        Self {
            identity: Signer::from(signer.public_key().clone()),
            credential,
            signer,
        }
    }
}

impl IdentityProvider for DelegateIdentity {
    fn signer(&self) -> libchat::SignerRef<'_> {
        &self.identity
    }

    fn participant_id(&self) -> shared_traits::ParticipantId {
        shared_traits::ParticipantId::from(self.credential.as_slice())
    }

    fn display_name(&self) -> String {
        trunc(&self.identity.to_string())
    }

    fn sign(&self, payload: &[u8]) -> crypto::Ed25519Signature {
        self.signer.sign(payload)
    }
}

/// A credential issued to a delegate key, optionally bound to an account address.
///
/// Serialized as a TLV byte sequence prefixed with magic bytes `0x23 0x23`.
/// A credential without an `account_addr` is *unassociated* — it identifies the
/// delegate key but has not yet been linked to an account.
#[derive(Debug)]
pub struct DelegateCredential {
    delegate_id: Ed25519VerifyingKey,
    account_addr: Option<AccountAddr>,
}

impl DelegateCredential {
    const TAG_DELEGATE_ID: u8 = 0x01;
    const TAG_ACCOUNT_ADDR: u8 = 0x02;

    pub fn unassociated(delegate: &Ed25519VerifyingKey) -> Self {
        Self {
            delegate_id: delegate.clone(),
            account_addr: None,
        }
    }

    pub fn associated(delegate: &Ed25519VerifyingKey, account: &str) -> Self {
        Self {
            delegate_id: delegate.clone(),
            account_addr: Some(account.to_string()),
        }
    }

    /// The delegate (device / LocalIdentity) verifying key this credential names.
    pub fn delegate_id(&self) -> &Ed25519VerifyingKey {
        &self.delegate_id
    }

    /// The account this delegate claims to act for, if it is associated. The
    /// claim is unverified — confirm it against the account directory.
    pub fn account_addr(&self) -> Option<&str> {
        self.account_addr.as_deref()
    }

    pub fn serialize(self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&[0x23, 0x23]);
        let key_bytes = self.delegate_id.as_ref();
        debug_assert!(
            key_bytes.len() <= 255,
            "delegate_id too large for 1-byte TLV length"
        );
        data.extend_from_slice(&[Self::TAG_DELEGATE_ID, key_bytes.len() as u8]);
        data.extend_from_slice(key_bytes);
        if let Some(addr) = self.account_addr {
            let addr_bytes = addr.as_bytes();
            debug_assert!(
                addr_bytes.len() <= 255,
                "account_addr too large for 1-byte TLV length"
            );
            data.extend_from_slice(&[Self::TAG_ACCOUNT_ADDR, addr_bytes.len() as u8]);
            data.extend_from_slice(addr_bytes);
        }
        data
    }
}

impl From<DelegateCredential> for Vec<u8> {
    fn from(value: DelegateCredential) -> Self {
        value.serialize()
    }
}

impl TryFrom<Vec<u8>> for DelegateCredential {
    type Error = ClientError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.get(..2) != Some(&[0x23, 0x23]) {
            return Err(ClientError::BadlyFormedCredential);
        }
        let mut delegate_id = None;
        let mut account_addr = None;
        let mut i = 2;
        while i + 2 <= value.len() {
            let tag = value[i];
            let len = value[i + 1] as usize;
            i += 2;
            let v = value
                .get(i..i + len)
                .ok_or(ClientError::BadlyFormedCredential)?;
            i += len;
            match tag {
                DelegateCredential::TAG_DELEGATE_ID => {
                    let bytes: &[u8; 32] = v
                        .try_into()
                        .map_err(|_| ClientError::BadlyFormedCredential)?;
                    delegate_id = Some(
                        Ed25519VerifyingKey::from_bytes(bytes)
                            .map_err(|_| ClientError::BadlyFormedCredential)?,
                    );
                }
                DelegateCredential::TAG_ACCOUNT_ADDR => {
                    account_addr = Some(
                        String::from_utf8(v.to_vec())
                            .map_err(|_| ClientError::BadlyFormedCredential)?,
                    );
                }
                _ => {}
            }
        }
        Ok(Self {
            delegate_id: delegate_id.ok_or(ClientError::BadlyFormedCredential)?,
            account_addr,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::Ed25519SigningKey;

    fn test_key() -> Ed25519VerifyingKey {
        Ed25519SigningKey::generate().verifying_key()
    }

    #[test]
    fn roundtrip_unassociated() {
        let key = test_key();
        let bytes = DelegateCredential::unassociated(&key).serialize();
        let recovered: DelegateCredential = bytes.clone().try_into().unwrap();
        assert_eq!(recovered.serialize(), bytes);
    }

    #[test]
    fn roundtrip_associated() {
        let key = test_key();
        let bytes = DelegateCredential::associated(&key, "user@example.com").serialize();
        let recovered: DelegateCredential = bytes.clone().try_into().unwrap();
        assert_eq!(recovered.serialize(), bytes);
    }

    #[test]
    fn account_addr_preserved_across_roundtrip() {
        let key = test_key();
        let addr = "alice@libchat.example";
        let recovered: DelegateCredential = DelegateCredential::associated(&key, addr)
            .serialize()
            .try_into()
            .unwrap();
        assert_eq!(recovered.account_addr.as_deref(), Some(addr));
    }

    #[test]
    fn unassociated_has_no_account_after_roundtrip() {
        let key = test_key();
        let recovered: DelegateCredential = DelegateCredential::unassociated(&key)
            .serialize()
            .try_into()
            .unwrap();
        assert!(recovered.account_addr.is_none());
    }

    #[test]
    fn bad_magic_bytes_rejected() {
        let bytes = vec![0x00, 0x00, 0x01, 0x20];
        assert!(matches!(
            DelegateCredential::try_from(bytes),
            Err(ClientError::BadlyFormedCredential)
        ));
    }

    #[test]
    fn truncated_payload_rejected() {
        // Magic + TAG_DELEGATE_ID + len=32, but only 16 bytes of key data
        let mut bytes = vec![0x23, 0x23, 0x01, 32];
        bytes.extend_from_slice(&[0u8; 16]);
        assert!(matches!(
            DelegateCredential::try_from(bytes),
            Err(ClientError::BadlyFormedCredential)
        ));
    }

    #[test]
    fn missing_delegate_id_rejected() {
        // Valid magic but no TLV fields
        let bytes = vec![0x23, 0x23];
        assert!(matches!(
            DelegateCredential::try_from(bytes),
            Err(ClientError::BadlyFormedCredential)
        ));
    }

    #[test]
    fn invalid_utf8_account_addr_rejected() {
        let key = test_key();
        // Build a valid credential then corrupt the account_addr bytes
        let mut bytes = DelegateCredential::unassociated(&key).serialize();
        // Append a TAG_ACCOUNT_ADDR field with invalid UTF-8
        bytes.push(DelegateCredential::TAG_ACCOUNT_ADDR);
        bytes.push(3); // len
        bytes.extend_from_slice(&[0xFF, 0xFE, 0xFD]); // invalid UTF-8
        assert!(matches!(
            DelegateCredential::try_from(bytes),
            Err(ClientError::BadlyFormedCredential)
        ));
    }
}
