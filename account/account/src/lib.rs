mod account;
mod error;
mod namespaces;
mod resolver;

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

use std::fmt::{Debug, Display};

use account_log::SignedAccountLog;
pub use account_log::{AccountAddr, Ed25519VerifyingKey};

pub use crate::account::{Account, AccountUpdate};
pub use crate::error::AccountError;
pub use crate::resolver::AccountResolver;

// Blanket export of namespaces
pub use namespaces::prelude::*;

/// Read access to published account logs.
///
/// Separate from [`AccountPublisher`] so a consumer that only resolves other
/// accounts — a chat client looking up a peer's devices — can be handed this
/// and be structurally incapable of publishing.
///
/// The provider is untrusted: `fetch` returns the log as received, not a
/// verified one, and the caller checks the signature under the address it asked
/// for. `Ok(None)` means the account has never published.
pub trait AccountProvider {
    type Error: Display + Debug;

    fn fetch(&self, addr: &AccountAddr) -> Result<Option<SignedAccountLog>, Self::Error>;
}

/// Write access to published account logs.
pub trait AccountPublisher {
    type Error: Display + Debug;

    fn publish(&mut self, addr: &AccountAddr, log: &SignedAccountLog) -> Result<(), Self::Error>;
}
