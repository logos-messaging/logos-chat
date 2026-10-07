//! The crate's Ed25519 types, owned by `crypto` so there is one implementation
//! of them in the workspace rather than one per crate.
//!
//! Re-exported rather than wrapped: a second wrapper would be a second place
//! for the byte-level rules about a key to live, which is what having two
//! implementations cost in the first place.

pub use crypto::{Ed25519Error, Ed25519Signature, Ed25519SigningKey, Ed25519VerifyingKey};
