//! Test doubles for the store contract: an in-memory store, and the suite
//! that holds any store to it. Plus a way to read GroupV3 frames off the wire.

pub use crate::conversation::group_v3_wire;
pub use crate::storage::{MemStore, assert_identity_store_contract, assert_kv_contract};
