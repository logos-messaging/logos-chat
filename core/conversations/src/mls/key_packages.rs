use crate::kv::ScopedKvStore;
use openmls_traits::storage::{CURRENT_VERSION, Entity, Key};

use super::MlsStorageError;
use super::format::{decode, encode, sub_key};

const KEY_PACKAGE: &str = "key_package";

/// The key packages this installation has published, in the scope handed in.
///
/// A welcome for a conversation of any protocol consumes one, so they outlive every conversation
/// and belong to none.
#[derive(Clone, Copy)]
pub(crate) struct KeyPackages<'a> {
    kv: ScopedKvStore<'a>,
}

impl<'a> KeyPackages<'a> {
    pub(crate) fn new(kv: ScopedKvStore<'a>) -> Self {
        Self { kv }
    }

    pub(crate) fn write(
        &self,
        hash_ref: &impl Key<CURRENT_VERSION>,
        key_package: &impl Entity<CURRENT_VERSION>,
    ) -> Result<(), MlsStorageError> {
        Ok(self
            .kv
            .put(&sub_key(KEY_PACKAGE, hash_ref)?, &encode(key_package)?)?)
    }

    pub(crate) fn get<T: Entity<CURRENT_VERSION>>(
        &self,
        hash_ref: &impl Key<CURRENT_VERSION>,
    ) -> Result<Option<T>, MlsStorageError> {
        self.kv
            .get(&sub_key(KEY_PACKAGE, hash_ref)?)?
            .map(|bytes| decode(&bytes))
            .transpose()
    }

    pub(crate) fn delete(
        &self,
        hash_ref: &impl Key<CURRENT_VERSION>,
    ) -> Result<(), MlsStorageError> {
        Ok(self.kv.delete(&sub_key(KEY_PACKAGE, hash_ref)?)?)
    }
}
