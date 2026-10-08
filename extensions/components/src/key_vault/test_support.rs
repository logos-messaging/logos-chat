use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::TestAuthClient;

use super::basic_file_key_vault::{FileKeyVault, InstallationKey, KeyVaultError};

pub struct EphemeralKeyVault {}

impl EphemeralKeyVault {}

/// A [`FileKeyVault`] publishing through a [`TestAuthClient`], never the network.
pub struct TestFileKeyVault {
    vault: FileKeyVault<TestAuthClient>,
    dir: PathBuf,
}

impl TestFileKeyVault {
    /// A vault in a fresh temp directory, removed on drop. Vaults and clients
    /// given clones of one `client` see each other's publishes.
    pub fn new(client: TestAuthClient) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "keyvault-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);

        Self {
            vault: FileKeyVault::new(dir.clone(), client),
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
    pub(crate) fn inner(&self) -> &FileKeyVault<TestAuthClient> {
        &self.vault
    }
}

impl Drop for TestFileKeyVault {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}
