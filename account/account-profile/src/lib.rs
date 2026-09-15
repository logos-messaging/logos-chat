//! The `profile` namespace of an [`AccountLog`](account_log::AccountLog): the
//! metadata an account publishes to describe its owner.
//!
//! Interpretation only. This crate reads the live set and says what the
//! entries under a profile context mean. It never decides whether a log is
//! valid and cannot reject one — an entry that fails a rule here is ignored,
//! and the log stands.

mod profile;

pub use profile::{
    DISPLAYNAME, Profile, ProfileError, ProfileExt, endorse_display_name, is_valid_display_name,
};
