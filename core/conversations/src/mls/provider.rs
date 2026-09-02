use openmls_libcrux_crypto::CryptoProvider as LibcruxCryptoProvider;
use openmls_traits::OpenMlsProvider;

use super::MlsAdapter;

/// The OpenMLS provider for one operation: the installation's crypto, and the MLS state reachable
/// while that operation's transaction is open.
pub(crate) struct MlsProvider<'a> {
    crypto: &'a LibcruxCryptoProvider,
    storage: MlsAdapter<'a>,
}

impl<'a> MlsProvider<'a> {
    pub(crate) fn new(crypto: &'a LibcruxCryptoProvider, storage: MlsAdapter<'a>) -> Self {
        Self { crypto, storage }
    }
}

impl<'a> OpenMlsProvider for MlsProvider<'a> {
    type CryptoProvider = LibcruxCryptoProvider;
    type RandProvider = LibcruxCryptoProvider;
    type StorageProvider = MlsAdapter<'a>;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        self.crypto
    }
}
