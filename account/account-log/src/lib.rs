//! Append-only signed account log — the record of keys and data an account has
//! endorsed, and the canonical bytes it signs.
//!
//! ```text
//! SignedAccountLog          payload + account signature over its exact bytes
//! └── EncodedAccountLog     the log as canonical bytes (wire form)
//!     └── AccountLog        the log as validated entries (working form)
//!         └── AccountEntry      Add { context, data } | Remove { index } | Unknown
//!             └── EntryData     Ed25519Key | Text | Unknown
//! ```
//!
//! The crate is protocol only: no identity type, no transport, no notion of
//! what any [`Context`] means.

mod account_log;
mod account_record;
mod addr;
mod codec;
mod draft;
mod context;
mod crypto;
mod error;

pub use account_log::{
    IndexedAccountEntry,AccountEntry, AccountLog, EncodedAccountLog, EntryData, SignedAccountLog};
pub use account_record::{AccountRecord, AccountRecordUpdate, Outcome};
pub use addr::AccountAddr;
pub use draft::AccountLogDraft;
pub use context::{Context, SIGNER_CONTEXT};
pub use crypto::{Ed25519SigningKey, Ed25519VerifyingKey};
pub use error::{AccountAddrError, AccountLogError};
