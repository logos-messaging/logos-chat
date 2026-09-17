//! Placeholder [`AuthService`](libchat::AuthService)s until the account log
//! can check endorsements.

use libchat::Signer;

/// Accepts every identifier without checking it.
///
/// A placeholder: the real check confirms in the account directory that the
/// external id's account endorses the signer. Until then the core's auth gate
/// asserts nothing.
#[derive(Debug, Clone, Copy, Default)]
pub struct UncheckedAuth;

impl libchat::AuthService for UncheckedAuth {
    type Error = std::convert::Infallible;

    fn validate_external_identifier(
        &self,
        _signer: Signer,
        _external_id: libchat::ExternalIdentifier,
    ) -> Result<libchat::AuthResult, Self::Error> {
        Ok(libchat::AuthResult::Valid)
    }

    fn signers_for_account(
        &self,
        ident: &libchat::ExternalIdentifier,
    ) -> Result<Vec<Signer>, Self::Error> {
        // TODO: resolving an account to its devices went with the device-bundle
        // directory and has no replacement yet.
        unimplemented!("account resolution for {ident}")
    }
}

/// Temp mock: panics so tests will not pass
#[derive(Debug, Clone, Copy, Default)]
pub struct PanicAuth;

impl libchat::AuthService for PanicAuth {
    type Error = std::convert::Infallible;

    fn validate_external_identifier(
        &self,
        _signer: Signer,
        _external_id: libchat::ExternalIdentifier,
    ) -> Result<libchat::AuthResult, Self::Error> {
        panic!("DANGER")
    }

    fn signers_for_account(
        &self,
        _ident: &libchat::ExternalIdentifier,
    ) -> Result<Vec<Signer>, Self::Error> {
        panic!("DANGER")
    }
}
