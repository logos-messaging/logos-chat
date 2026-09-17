//! A placeholder [`AuthService`](libchat::AuthService) until the account log
//! can check endorsements.

use libchat::Signer;

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
