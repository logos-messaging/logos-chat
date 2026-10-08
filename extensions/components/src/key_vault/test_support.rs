use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use logos_account::test_support::TestAccountProvider;

use super::basic_file_key_vault::{FileKeyVault, InstallationKey, KeyVaultError};

pub struct EphemeralKeyVault {}

impl EphemeralKeyVault {}

/// A file vault that publishes to an in-memory registry, never the network.
pub struct TestFileKeyVault {
    vault: FileKeyVault<TestAccountProvider>,
    dir: PathBuf,
}

impl TestFileKeyVault {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "keyvault-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);

        Self {
            vault: FileKeyVault::new(dir.clone()),
            dir,
        }
    }

    pub fn install(&self, alias: &str) -> Result<InstallationKey, KeyVaultError> {
        self.vault.install(alias)
    }

    pub fn accounts(&self) -> Result<Vec<String>, KeyVaultError> {
        self.vault.accounts()
    }

    pub fn installations(&self, alias: &str) -> Result<Vec<u32>, KeyVaultError> {
        self.vault.installations(alias)
    }

    #[cfg(test)]
    pub(crate) fn inner(&self) -> &FileKeyVault<TestAccountProvider> {
        &self.vault
    }
}

impl Drop for TestFileKeyVault {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}
