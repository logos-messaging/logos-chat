use std::collections::HashMap;

use account_log::{AccountAddr, SignedAccountLog};

use crate::{AccountProvider, AccountPublisher};

type ErrorType = String;

/// A AccountProvide + AccountPublisher used for tests
/// It does not rely on network, and can be used safely within a single test.
/// Results are ephemeral
pub struct TestAccountProvider {
    state: HashMap<AccountAddr, SignedAccountLog>,
}

impl Default for TestAccountProvider {
    fn default() -> Self {
        Self {
            state: Default::default(),
        }
    }
}

impl TestAccountProvider {
    pub fn publish_without_verify(
        &mut self,
        addr: &AccountAddr,
        log: &SignedAccountLog,
    ) -> Result<(), ErrorType> {
        self.state.insert(addr.to_owned(), log.to_owned());
        Ok(())
    }
}

impl AccountProvider for TestAccountProvider {
    type Error = String;

    fn fetch(&self, addr: &AccountAddr) -> Result<Option<SignedAccountLog>, Self::Error> {
        Ok(self.state.get(addr).cloned())
    }
}

impl AccountPublisher for TestAccountProvider {
    type Error = String;

    fn publish(&mut self, addr: &AccountAddr, log: &SignedAccountLog) -> Result<(), Self::Error> {
        let _ = log.verify(addr).map_err(|e| e.to_string())?;

        self.publish_without_verify(addr, log)
    }
}
