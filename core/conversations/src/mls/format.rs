//! The shape MLS state takes in the substrate: `mls/<storage version>/<label>[/<sub-key>]` keys
//! holding JSON values.

use openmls_traits::storage::CURRENT_VERSION;
use serde::Serialize;
use serde::de::DeserializeOwned;

use super::MlsStorageError;

/// A key holding one value: `mls/<storage version>/<label>`.
pub(super) fn key(label: &str) -> Vec<u8> {
    format!("mls/{CURRENT_VERSION}/{label}").into_bytes()
}

/// A key holding one of the many values a label covers: `mls/<storage version>/<label>/<sub-key>`.
pub(super) fn sub_key(label: &str, sub: &impl Serialize) -> Result<Vec<u8>, MlsStorageError> {
    let mut out = sub_key_prefix(label);
    out.extend_from_slice(&encode(sub)?);
    Ok(out)
}

/// What every key under `label` starts with, so a scan or a purge reaches them all.
pub(super) fn sub_key_prefix(label: &str) -> Vec<u8> {
    let mut out = key(label);
    out.push(b'/');
    out
}

pub(super) fn encode(value: &impl Serialize) -> Result<Vec<u8>, MlsStorageError> {
    Ok(serde_json::to_vec(value)?)
}

pub(super) fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, MlsStorageError> {
    Ok(serde_json::from_slice(bytes)?)
}
