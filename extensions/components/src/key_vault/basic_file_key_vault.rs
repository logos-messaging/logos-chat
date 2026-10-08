//! Accounts and their installations as plain key files, one folder per account:
//!
//! ```text
//! <dir>/saro/account.key              the account's signing key
//! <dir>/saro/installations/1.key      installation `saro:1`
//! ```
//!
//! Each file holds a single raw 32-byte Ed25519 seed, **unencrypted**. Keys are
//! created on first use: a new account publishes its display name, and a new
//! installation is endorsed on the account's log before its key is written, so
//! any key on disk is one the log carries.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crypto::Ed25519SigningKey;
use logos_account::{
    Account, AccountAddr, AccountProvider, AccountPublisher, ChatWrite, ProfileWrite,
};

use crate::HttpAuthClient;

/// The account's key, in its folder.
const ACCOUNT_FILE: &str = "account.key";

/// The folder in an account's folder holding its installations, one `<n>.key` each.
const INSTALLATIONS_DIR: &str = "installations";

const KEY_EXT: &str = "key";

/// Every key file holds exactly one Ed25519 seed, and nothing else.
const SEED_LEN: usize = 32;

/// Identifies a stored secret. A newtype so ids and secrets can't be mixed up.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct KeyId(String);

impl KeyId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, thiserror::Error)]
pub enum KeyVaultError {
    #[error("key not found: {0:?}")]
    NotFound(KeyId),
    #[error("key already exists: {0:?}")]
    AlreadyExists(KeyId),
    #[error("vault is locked or the passphrase is wrong")]
    AccessDenied,
    #[error("invalid alias: {0}")]
    InvalidAlias(String),
    #[error("publish the endorsement")]
    Publish(#[source] logos_account::AccountError),
    #[error("storage error")]
    Storage(#[source] Box<dyn std::error::Error + Send + Sync>),
}

impl From<io::Error> for KeyVaultError {
    fn from(error: io::Error) -> Self {
        Self::Storage(Box::new(error))
    }
}

/// An installation's key, paired with the account that endorsed it.
#[derive(Debug)]
pub struct InstallationKey {
    pub account: AccountAddr,
    pub signing_key: Ed25519SigningKey,
}

impl InstallationKey {
    pub fn account(&self) -> &AccountAddr {
        &self.account
    }
}

/// A [`FileKeyVault`] publishing to the devnet registry.
pub struct BasicFileKeyVault(FileKeyVault<HttpAuthClient>);

impl BasicFileKeyVault {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self(FileKeyVault::new(dir, HttpAuthClient::default()))
    }

    /// The installation `alias` names, creating whatever part of it is missing.
    pub fn install(&self, alias: &str) -> Result<InstallationKey, KeyVaultError> {
        self.0.install(alias)
    }

    /// The account aliases held, in name order.
    pub fn accounts(&self) -> Result<Vec<String>, KeyVaultError> {
        self.0.accounts()
    }

    /// The installation numbers held for `alias`, in order.
    pub fn installations(&self, alias: &str) -> Result<Vec<u32>, KeyVaultError> {
        self.0.installations(alias)
    }
}

/// The vault itself, generic over how accounts publish.
///
/// `Account` owns its provider, so each account loaded gets a clone of
/// `provider`. Clones must share state, or an account can't see its own log.
pub(crate) struct FileKeyVault<AP> {
    dir: PathBuf,
    provider: AP,
}

impl<AP: AccountProvider + AccountPublisher + Clone> FileKeyVault<AP> {
    pub(crate) fn new(dir: impl Into<PathBuf>, provider: AP) -> Self {
        Self {
            dir: dir.into(),
            provider,
        }
    }

    pub(crate) fn install(&self, alias: &str) -> Result<InstallationKey, KeyVaultError> {
        let (alias, number) = parse_alias(alias)?;
        let mut account = self.account(&alias)?;
        let path = self.installation_path(&alias, number);

        let signing_key = match seed_at(&path)? {
            Some(seed) => Ed25519SigningKey::from_seed(&seed),
            None => {
                let key = Ed25519SigningKey::generate();
                // Endorsed before the key reaches disk, so a key on disk is
                // always one the log carries.
                account
                    .update()
                    .endorse_chat_signer(&key.verifying_key())
                    .publish()
                    .map_err(KeyVaultError::Publish)?;
                // Warning: secret bytes, written in the clear.
                write_new(&path, key.seed().as_slice())?;
                key
            }
        };

        Ok(InstallationKey {
            account: account.addr(),
            signing_key,
        })
    }

    /// The account `alias` names, generated and written on first use.
    fn account(&self, alias: &str) -> Result<Account<AP>, KeyVaultError> {
        let path = self.account_dir(alias).join(ACCOUNT_FILE);
        let auth = self.provider.clone();
        let account = match seed_at(&path)? {
            Some(seed) => Account::from_signing_key(Ed25519SigningKey::from_seed(&seed), auth),
            None => {
                let key = Ed25519SigningKey::generate();
                // Warning: secret bytes, written in the clear.
                write_new(&path, key.seed().as_slice())?;
                let mut account = Account::from_signing_key(key, auth);
                account
                    .update()
                    .set_display_name(alias)
                    .publish()
                    .map_err(KeyVaultError::Publish)?;
                account
            }
        };
        Ok(account)
    }

    pub(crate) fn accounts(&self) -> Result<Vec<String>, KeyVaultError> {
        names_in(&self.dir, |path| path.is_dir())
    }

    pub(crate) fn installations(&self, alias: &str) -> Result<Vec<u32>, KeyVaultError> {
        let dir = self.account_dir(alias).join(INSTALLATIONS_DIR);
        let mut numbers: Vec<u32> = names_in(&dir, |path| path.is_file())?
            .iter()
            .filter_map(|name| name.strip_suffix(KEY_EXT)?.strip_suffix('.')?.parse().ok())
            .collect();
        numbers.sort();
        Ok(numbers)
    }

    /// Everything belonging to one account: its key, and its installations.
    fn account_dir(&self, alias: &str) -> PathBuf {
        self.dir.join(alias)
    }

    /// Where installation `number` of `alias` is kept.
    fn installation_path(&self, alias: &str, number: u32) -> PathBuf {
        self.account_dir(alias)
            .join(INSTALLATIONS_DIR)
            .join(format!("{number}.{KEY_EXT}"))
    }
}

/// The entries directly in `dir` that `keep` accepts, by name, sorted. A
/// directory that does not exist yet holds nothing, which is not an error.
fn names_in(dir: &Path, keep: impl Fn(&Path) -> bool) -> Result<Vec<String>, KeyVaultError> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };

    let mut names: Vec<String> = entries
        .flatten()
        .filter(|entry| keep(&entry.path()))
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    Ok(names)
}

/// Write `bytes` to `path`, creating the directory it sits in.
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), KeyVaultError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(fs::write(path, bytes)?)
}

/// The seed `path` holds, or `None` if there is no file there yet.
fn seed_at(path: &Path) -> Result<Option<[u8; SEED_LEN]>, KeyVaultError> {
    match fs::read(path) {
        Ok(bytes) => bytes.as_slice().try_into().map(Some).map_err(|_| {
            KeyVaultError::Storage(
                format!("{} holds {} bytes, not a key", path.display(), bytes.len()).into(),
            )
        }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Splits `alice:2` into its account and installation number; a bare name is installation 1.
fn parse_alias(text: &str) -> Result<(String, u32), KeyVaultError> {
    let invalid = |reason: String| KeyVaultError::InvalidAlias(reason);
    let (account, number) = match text.split_once(':') {
        Some((account, number)) => (
            account,
            number
                .parse::<u32>()
                .map_err(|_| invalid(format!("'{number}' is not an installation number")))?,
        ),
        None => (text, 1),
    };

    if account.is_empty() {
        return Err(invalid("an alias needs an account name".into()));
    }
    if !account
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(invalid(format!(
            "'{account}' is not a name: use letters, digits, '-', '_' or '.'"
        )));
    }
    if number == 0 {
        return Err(invalid("installations are numbered from 1".into()));
    }

    Ok((account.to_string(), number))
}

#[cfg(test)]
mod tests {
    use crate::TestAuthClient;
    use logos_account::AccountProvider;

    use crate::key_vault::test_support::TestFileKeyVault;

    /// The key on disk is the account: reading it back must not mint a new one.
    #[test]
    fn an_account_key_is_written_once_and_read_back() {
        let vault = TestFileKeyVault::new(TestAuthClient::default());

        let first = vault.inner().account("saro").expect("create saro").addr();
        let again = vault.inner().account("saro").expect("reuse saro").addr();

        assert_eq!(first, again);
        assert_eq!(vault.accounts().expect("list accounts"), vec!["saro"]);
        assert!(
            vault.installations("saro").expect("list").is_empty(),
            "the key file is not an installation"
        );
    }

    #[test]
    fn a_new_installation_is_endorsed_once_and_then_reused() {
        let vault = TestFileKeyVault::new(TestAuthClient::default());

        let minted = vault.install("saro").expect("mint saro:1");
        // A second call finds the key on disk, so it must not publish again —
        // a log refuses to endorse the same signer twice.
        let reused = vault.install("saro").expect("reuse saro:1");

        assert_eq!(minted.account(), reused.account());
        assert_eq!(vault.accounts().expect("list"), vec!["saro"]);
        assert_eq!(vault.installations("saro").expect("list"), vec![1]);
    }

    #[test]
    fn vaults_sharing_a_provider_see_each_others_logs() {
        let provider = TestAuthClient::default();
        let alice = TestFileKeyVault::new(provider.clone());
        let bob = TestFileKeyVault::new(provider.clone());

        let alice_addr = alice.install("alice").expect("mint alice").account;
        let bob_addr = bob.install("bob").expect("mint bob").account;

        assert!(provider.fetch(&alice_addr).expect("fetch").is_some());
        assert!(provider.fetch(&bob_addr).expect("fetch").is_some());
    }
}
