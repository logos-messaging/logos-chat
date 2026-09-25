//! The installation a store belongs to.

use super::StorageError;

/// The installation a client runs as, encoded by that client.
///
/// Opaque here, so a client can change what an installation is made of without any of it
/// reaching a store. **Secret:** a signing key is in these bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct StoredInstallation(Vec<u8>);

impl StoredInstallation {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for StoredInstallation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("StoredInstallation")
            .field(&"[redacted]")
            .finish()
    }
}

impl Drop for StoredInstallation {
    fn drop(&mut self) {
        self.0.iter_mut().for_each(|b| *b = 0);
    }
}

/// The one installation a store holds, as a typed record beside the conversation list.
///
/// One store, one installation: the conversations here were joined by it, and a second
/// installation reading them would hold groups whose leaves it cannot sign for.
///
/// Typed rather than a namespace in the substrate, because the substrate's namespaces are
/// conversation kinds and this record's shape is close to fixed while those arrive every few
/// weeks.
pub trait IdentityStore {
    /// `None` if this store has never held one, which is the signal to create one.
    fn load_installation(&self) -> Result<Option<StoredInstallation>, StorageError>;

    /// Records the installation this store belongs to, replacing any it already held.
    fn save_installation(&mut self, installation: &StoredInstallation) -> Result<(), StorageError>;
}
