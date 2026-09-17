//! A placeholder [`AuthService`](libchat::AuthService) until the account log
//! can check endorsements.

use libchat::Signer;

/// Refuses to answer, loudly: every method panics.
///
/// A placeholder for a platform that has not wired an auth service yet. It is
/// deliberately not a permissive default — a client built with it fails on
/// first use rather than silently accepting every member.
#[derive(Debug, Clone, Copy, Default)]
pub struct PanicAuth;

impl libchat::AuthService for PanicAuth {
    type Error = std::convert::Infallible;

    fn validate_member(
        &self,
        _signer: Signer,
        _participant_id: libchat::ParticipantId,
    ) -> Result<libchat::AuthResult, Self::Error> {
        panic!("DANGER")
    }

    fn signers_for_participant(
        &self,
        _ident: &libchat::ParticipantId,
    ) -> Result<Vec<Signer>, Self::Error> {
        panic!("DANGER")
    }
}
