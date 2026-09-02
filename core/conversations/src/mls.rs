//! libchat's side of OpenMLS: the provider it runs against, its storage over the substrate, and
//! the key packages every protocol's welcome consumes.

// Complete, but no conversation type reaches this layer yet.
#![allow(dead_code, unused_imports)]

mod adapter;
mod error;
mod format;
mod key_packages;
mod provider;

#[cfg(test)]
mod tests;

pub(crate) use adapter::MlsAdapter;
pub(crate) use error::MlsStorageError;
pub(crate) use key_packages::KeyPackages;
pub(crate) use provider::MlsProvider;
