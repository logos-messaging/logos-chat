//! The spec's own vectors, run against this implementation.
//!
//! Every artifact is signed by the RFC 8032 §7.1 test key, so a rejection
//! vector that fails at the signature check has failed for the wrong reason
//! and is reported as such.

use account_log::*;
use std::str::FromStr;

include!("vectors.rs");

/// The account all vectors are signed by.
const ADDR: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex"))
        .collect()
}

/// A signed log is `signature || payload`, verified under the address alone.
fn verify(payload: &str, signature: &str) -> Result<AccountLog, AccountLogError> {
    let addr = AccountAddr::from_str(ADDR).expect("valid address");
    let mut artifact = unhex(signature);
    artifact.extend_from_slice(&unhex(payload));
    SignedAccountLog::from_bytes(&artifact)?.verify(&addr)
}

#[test]
fn accepts_every_test_vector() {
    for (name, payload, signature) in VECTORS.iter().filter(|(n, ..)| n.starts_with('V')) {
        assert!(verify(payload, signature).is_ok(), "{name} must verify");
    }
}

/// Each rejection vector must fail at its own check. Failing at the signature
/// would mean the payload never reached the rule under test.
#[test]
fn rejects_every_rejection_vector() {
    for (name, payload, signature) in VECTORS.iter().filter(|(n, ..)| n.starts_with('N')) {
        match verify(payload, signature) {
            Ok(_) => panic!("{name} must be rejected"),
            Err(AccountLogError::SignatureInvalid) => {
                panic!("{name} was rejected at the signature, not for its stated reason")
            }
            Err(_) => (),
        }
    }
}

/// The live sets the spec describes for each accepted vector, as
/// `(chat.messaging keys, profile.displayname records, storage.vault keys)`.
/// V5's unknown opcode and V8's unknown data_tag hold live slots without
/// appearing here — that is what makes the counts right.
#[test]
fn derives_the_live_set_the_spec_describes() {
    let chat = Context::new("chat.messaging").unwrap();
    let profile = Context::new("profile.displayname").unwrap();
    let vault = Context::new("storage.vault").unwrap();

    let expected: [(&str, usize, &[&str], usize); 8] = [
        ("V1", 0, &[], 0),
        ("V2", 1, &[], 0),
        ("V3", 2, &[], 0),
        ("V4", 1, &[], 0),
        ("V5", 0, &[], 0),
        ("V6", 1, &["alice", "alice j"], 0),
        ("V7", 1, &[], 1),
        ("V8", 1, &[], 0),
    ];

    for (tag, keys, records, vault_keys) in expected {
        let (name, payload, signature) = VECTORS
            .iter()
            .find(|(n, ..)| n.starts_with(tag))
            .expect("vector present");
        let log = verify(payload, signature).expect("verifies");
        assert_eq!(log.ed25519_keys_for(&chat).len(), keys, "{name}");
        assert_eq!(log.text_for(&profile), records.to_vec(), "{name}");
        assert_eq!(log.ed25519_keys_for(&vault).len(), vault_keys, "{name}");
    }
}
