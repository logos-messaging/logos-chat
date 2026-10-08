use std::fs;

use super::basic_file_key_vault::BasicFileKeyVault;

pub struct EphemeralKeyVault {}

impl EphemeralKeyVault {}

impl BasicFileKeyVault {
    pub fn temp() -> Self {
        let path = std::env::temp_dir().join(format!("chat-cli-keystore-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        Self::new(path)
    }
}
