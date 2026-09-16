use std::{
    collections::HashMap,
    fmt::Debug,
    sync::{Arc, Mutex},
};

use crypto::Ed25519VerifyingKey;
use libchat::{IdentityProvider, RegistrationService};
use logos_account_DELETE::{AccountDirectory, DeviceSet, SignedDeviceBundle, verify_bundle};

/// A Contact Registry used for Tests.
/// This implementation stores bundle bytes and then returns them when
/// retrieved.
///
/// Like the real `keypackage-registry`, one object serves both roles: a
/// keypackage store ([`RegistrationService`]) keyed by `device_id`, and an
/// account → device directory ([`AccountDirectory`]) keyed by the hex account key.
#[derive(Clone, Default)]
pub struct EphemeralRegistry {
    key_packages: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    installations: Arc<Mutex<HashMap<String, SignedDeviceBundle>>>,
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
            .insert(hex::encode(identity.signer().as_bytes()), key_bundle);
        Ok(())
    }

    fn retrieve(
        &self,
        device_id: &str,
    ) -> Result<Option<Vec<u8>>, <Self as RegistrationService>::Error> {
        Ok(self.key_packages.lock().unwrap().get(device_id).cloned())
    }
}

/// Account → device directory, verifying each bundle on `fetch` exactly as the
/// HTTP client does so callers exercise the same trust path without a server.
impl AccountDirectory for EphemeralRegistry {
    type Error = String;

    fn publish(
        &mut self,
        bundle: &SignedDeviceBundle,
    ) -> Result<(), <Self as AccountDirectory>::Error> {
        self.installations
            .lock()
            .unwrap()
            .insert(hex::encode(bundle.account_pub.as_ref()), bundle.clone());
        Ok(())
    }

    fn fetch(
        &self,
        account: &Ed25519VerifyingKey,
    ) -> Result<Option<DeviceSet>, <Self as AccountDirectory>::Error> {
        let Some(bundle) = self
            .installations
            .lock()
            .unwrap()
            .get(&hex::encode(account.as_ref()))
            .cloned()
        else {
            return Ok(None);
        };
        verify_bundle(account, &bundle)
            .map(Some)
            .map_err(|e| e.to_string())
    }
}
