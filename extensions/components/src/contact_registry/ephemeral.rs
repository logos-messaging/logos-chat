use std::{
    collections::HashMap,
    fmt::Debug,
    sync::{Arc, Mutex},
};

use libchat::{IdentityProvider, RegistrationService};

/// A Contact Registry used for Tests.
/// This implementation stores bundle bytes and then returns them when
/// retrieved.
///
/// A keypackage store ([`RegistrationService`]) keyed by `device_id`. The
/// account → device directory it also served was removed with the
/// device-bundle crate; account resolution returns with account-log.
#[derive(Clone, Default)]
pub struct EphemeralRegistry {
    key_packages: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl EphemeralRegistry {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Debug for EphemeralRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let registry = self.key_packages.lock().unwrap();
        let truncated: Vec<(&String, String)> = registry
            .iter()
            .map(|(k, v)| {
                let hex = if v.len() <= 8 {
                    hex::encode(v)
                } else {
                    format!(
                        "{}..{}",
                        hex::encode(&v[..4]),
                        hex::encode(&v[v.len() - 4..])
                    )
                };
                (k, hex)
            })
            .collect();
        f.debug_struct("EphemeralRegistry")
            .field("registry", &truncated)
            .finish()
    }
}

impl RegistrationService for EphemeralRegistry {
    type Error = String;

    fn register(
        &mut self,
        identity: &dyn IdentityProvider,
        key_bundle: Vec<u8>,
    ) -> Result<(), <Self as RegistrationService>::Error> {
        // Keyed by device id — the hex of the signer's verifying key — exactly
        // like the HTTP registry, so tests exercise the deployed keying.
        self.key_packages
            .lock()
            .unwrap()
            .insert(hex::encode(identity.signer_key().as_bytes()), key_bundle);
        Ok(())
    }

    fn retrieve(
        &self,
        device_id: &str,
    ) -> Result<Option<Vec<u8>>, <Self as RegistrationService>::Error> {
        Ok(self.key_packages.lock().unwrap().get(device_id).cloned())
    }
}
