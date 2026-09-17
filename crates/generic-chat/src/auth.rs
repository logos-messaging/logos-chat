//! A placeholder [`AuthService`](libchat::AuthService) until the account log
//! can check endorsements.

use libchat::SignerKey;

/// Temp mock: panics so tests will not pass
#[derive(Debug, Clone, Copy, Default)]
pub struct PanicAuth;

impl libchat::AuthService for PanicAuth {
    type Error = std::convert::Infallible;

    fn validate_signer(
        &self,
        _signer: SignerKey,
        _participant_id: libchat::ParticipantId,
    ) -> Result<libchat::AuthResult, Self::Error> {
        panic!("DANGER")
    }

    fn signers_for_participant(
        &self,
        _ident: &libchat::ParticipantId,
    ) -> Result<Vec<SignerKey>, Self::Error> {
        panic!("DANGER")
    }
}
