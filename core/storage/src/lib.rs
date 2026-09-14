//! Shared storage layer for libchat.
//!
//! This crate provides a common storage abstraction that can be used by
//! multiple crates in the libchat workspace (conversations, etc.).
//!
//! The storage implementation is handled by other crates.

mod errors;
mod store;

pub use errors::StorageError;
pub use store::{ConversationKind, ConversationMeta, ConversationStore};
