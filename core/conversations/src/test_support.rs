//! What a test against a store needs: an in-memory store, the suite that holds any store to the
//! contract, and the transaction a test reads a conversation's scope through.

pub use crate::kv::{KvTransaction, ScopedKvStore};
pub use crate::storage::{MemStore, assert_kv_contract};
