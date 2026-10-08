use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use account_log::{AccountAddr, SignedAccountLog};

use crate::{AccountProvider, AccountPublisher};

type ErrorType = String;

/// A AccountProvide + AccountPublisher used for tests
/// It does not rely on network, and can be used safely within a single test.
/// Results are ephemeral. Clones share one registry.
#[derive(Clone, Default)]
pub struct TestAccountProvider {
    state: Arc<Mutex<HashMap<AccountAddr, SignedAccountLog>>>,
}

impl TestAccountProvider {
    pub fn publish_without_verify(
        &mut self,
        addr: &AccountAddr,
        log: &SignedAccountLog,
    ) -> Result<(), ErrorType> {
        self.state
            .lock()
            .unwrap()
            .insert(addr.to_owned(), log.to_owned());
        Ok(())
    }
}

impl AccountProvider for TestAccountProvider {
    type Error = String;

    fn fetch(&self, addr: &AccountAddr) -> Result<Option<SignedAccountLog>, Self::Error> {
        Ok(self.state.lock().unwrap().get(addr).cloned())
    }
}

impl AccountPublisher for TestAccountProvider {
    type Error = String;

    fn publish(&mut self, addr: &AccountAddr, log: &SignedAccountLog) -> Result<(), Self::Error> {
        let _ = log.verify(addr).map_err(|e| e.to_string())?;

        self.publish_without_verify(addr, log)
    }
}
