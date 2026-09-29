//! Named identities on disk, so a test run can be the same person twice.
//!
//! `alice` is an account; `alice:2` is its second installation. Each account is
//! a folder named for it, holding its key beside its installations:
//!
//! ```text
//! keystore/saro/account   the account's signing key
//! keystore/saro/saro_1    its first installation
//! keystore/saro/saro_2    its second
//! ```
//!
//! So a test can inspect one, copy it between machines, or delete a folder to
//! start that identity over.
//!
//! Nothing here is encrypted. These are throwaway identities on a devnet, and
//! a test whose keys cannot be read is harder to debug than one whose keys do
//! not matter. Anything holding an identity worth protecting wants
//! [`StorageConfig::EncryptedWithKey`](logos_chat::StorageConfig) instead.

// `main` does not open through this yet, so nothing here has a caller.
#![allow(dead_code)]

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, anyhow, bail};
use components::HttpAuthClient;
use logos_account::AccountProvider;
use logos_account::AccountPublisher;
use logos_account::{
    Account, CHATSIGNER_CONTEXT, Ed25519SigningKey, Ed25519VerifyingKey, PROFILE_DISPLAYNAME,
};
use logos_chat::Installation;

/// The key file in an account's folder. Every other file there is an
/// installation, named for its number.
const ACCOUNT_FILE: &str = "account";

/// Every key file holds exactly one Ed25519 seed, and nothing else.
const SEED_LEN: usize = 32;

/// Accounts and their installations, one folder per account.
pub struct Keystore {
    dir: PathBuf,
}

impl Keystore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into().join("chat-cli-keystore"),
        }
    }

    pub fn temp() -> Self {
        let path = std::env::temp_dir().join(format!("chat-cli-keystore-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        Self { dir: path }
    }

    /// The installation `alias` names, creating whatever part of it is missing.
    ///
    /// Reusing an installation is the point: it is the identity peers already
    /// hold, and the conversations in a client's database belong to it.
    pub fn install(&self, alias: &str) -> Result<Installation> {
        let (alias, number) = parse_alias(alias)?;
        let mut account = self.account(&alias)?;
        let path = self.installation_path(&alias, number);

        let key = match seed_at(&path)? {
            Some(seed) => crypto::Ed25519SigningKey::from_seed(&seed),
            None => {
                let key = crypto::Ed25519SigningKey::generate();
                // Endorsed before the key reaches disk. A key the log does not
                // carry is an installation no peer will accept, and the next
                // run would load it rather than mint a fresh one.
                endorse(&mut account, &key.verifying_key())?;
                // Warning: secret bytes, written in the clear.
                write_new(&path, key.seed().as_slice())?;
                key
            }
        };

        Ok(Installation::make(key, account.addr()))
    }

    /// The account aliases held, in name order.
    pub fn accounts(&self) -> Result<Vec<String>> {
        names_in(&self.dir, |path| path.is_dir())
    }

    /// The installation numbers held for `alias`, in order.
    pub fn installations(&self, alias: &str) -> Result<Vec<String>> {
        let mut names = names_in(&self.account_dir(alias), |path| path.is_file())?;
        names.retain(|name| name != ACCOUNT_FILE);
        Ok(names)
    }

    /// Everything belonging to one account: its key, and its installations.
    fn account_dir(&self, alias: &str) -> PathBuf {
        self.dir.join(alias)
    }

    /// Where installation `number` of `alias` is kept.
    fn installation_path(&self, alias: &str, number: u32) -> PathBuf {
        self.account_dir(alias).join(format!("{alias}_{number}"))
    }

    /// The account `alias` names, generated and written on first use.
    fn account(&self, alias: &str) -> Result<Account<HttpAuthClient>> {
        let path = self.account_dir(alias).join(ACCOUNT_FILE);
        let auth = HttpAuthClient::default();
        let acc = match seed_at(&path)? {
            Some(seed) => Account::from_signing_key(Ed25519SigningKey::from_bytes(&seed), auth),
            None => {
                let key = Ed25519SigningKey::generate();
                // Warning: secret bytes, written in the clear.
                write_new(&path, key.as_bytes())?;
                let mut account = Account::from_signing_key(key, auth);
                register(&mut account, alias.to_string())?;

                account
            }
        };

        Ok(acc)
    }
}

fn register<AP: AccountProvider + AccountPublisher>(
    account: &mut Account<AP>,
    alias: String,
) -> Result<()> {
    account
        .update()
        .endorse_text(PROFILE_DISPLAYNAME.clone(), alias)
        // .endorse_text(TEST_EPHEMERAL, value)
        .publish()
        .map_err(|error| anyhow!("publish the endorsement: {error}"))?;

    Ok(())
}

/// Endorse `signer` on the account's log as a chat installation.
///
/// The publish reads the log it is extending, so this writes the first log for
/// an account that has never published, and appends for one that has — a
/// second installation joins the first rather than replacing it.
fn endorse(
    account: &mut Account<HttpAuthClient>,
    signer: &crypto::Ed25519VerifyingKey,
) -> Result<()> {
    let signer = Ed25519VerifyingKey::from_canonical_slice(signer.as_ref())
        .map_err(|error| anyhow!("a generated signer was not a key: {error}"))?;

    account
        .update()
        .endorse_ed25519_key(CHATSIGNER_CONTEXT.clone(), &signer)
        .publish()
        .map_err(|error| anyhow!("publish the endorsement: {error}"))?;
    Ok(())
}

/// The seed `path` holds, or `None` if there is no file there yet.
fn seed_at(path: &Path) -> Result<Option<[u8; SEED_LEN]>> {
    match fs::read(path) {
        Ok(bytes) => bytes
            .as_slice()
            .try_into()
            .map(Some)
            .map_err(|_| anyhow!("{} holds {} bytes, not a key", path.display(), bytes.len())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).context(format!("read {}", path.display())),
    }
}

fn parse_alias(text: &str) -> Result<(String, u32)> {
    let (account, number) = match text.split_once(':') {
        Some((account, number)) => (
            account,
            number
                .parse::<u32>()
                .map_err(|_| anyhow!("'{number}' is not an installation number"))?,
        ),
        None => (text, 1),
    };

    if account.is_empty() {
        bail!("an alias needs an account name");
    }
    if !account
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        bail!("'{account}' is not a name: use letters, digits, '-', '_' or '.'");
    }
    if number == 0 {
        bail!("installations are numbered from 1");
    }

    Ok((account.to_string(), number))
}

/// Write `bytes` to `path`, creating the directory it sits in.
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context(format!("create {}", parent.display()))?;
    }
    fs::write(path, bytes).context(format!("write {}", path.display()))
}

/// The entries directly in `dir` that `keep` accepts, by name, sorted. A
/// directory that does not exist yet holds nothing, which is not an error.
fn names_in(dir: &Path, keep: impl Fn(&Path) -> bool) -> Result<Vec<String>> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error).context(format!("read {}", dir.display())),
    };

    let mut names: Vec<String> = entries
        .flatten()
        .filter(|entry| keep(&entry.path()))
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The key on disk is the account: reading it back must not mint a new one.
    #[test]
    fn an_account_key_is_written_once_and_read_back() {
        let keystore = Keystore::temp();

        let first = keystore.account("saro").expect("create saro").addr();
        let again = keystore.account("saro").expect("reuse saro").addr();

        assert_eq!(first, again);
        assert_eq!(keystore.accounts().expect("list accounts"), vec!["saro"]);
        assert!(
            keystore.installations("saro").expect("list").is_empty(),
            "the key file is not an installation"
        );
    }

    /// Publishes to the devnet registry, so it is not part of a normal run:
    /// `cargo test -p chat-cli -- --ignored`.
    #[test]
    #[ignore = "publishes an account log to the devnet registry"]
    fn a_new_installation_is_endorsed_once_and_then_reused() {
        let dir = std::env::temp_dir().join(format!("chat-cli-endorse-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let keystore = Keystore::new(&dir);

        let minted = keystore.install("saro").expect("mint saro:1");
        // A second call finds the key on disk, so it must not publish again —
        // a log refuses to endorse the same signer twice.
        let reused = keystore.install("saro").expect("reuse saro:1");

        assert_eq!(minted.account(), reused.account());
        assert_eq!(keystore.accounts().expect("list"), vec!["saro"]);
        assert_eq!(
            keystore.installations("saro").expect("list"),
            vec!["saro_1"]
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn dev() {
        let keystore = Keystore::new("./keystore/");

        print!("{:?}", keystore.install("char:1").unwrap());
    }
}
