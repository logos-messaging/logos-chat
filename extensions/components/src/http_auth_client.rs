//! Account logs over HTTP, at `{base_url}/v1/account/<account_addr>`.
//!
//! ```text
//! GET   → 200 signature || payload    404 never published
//! POST  ← signature || payload
//! ```

use std::io::Read;
use std::time::Duration;

use account_log::{
    AccountLog, AccountLogError, CHATSIGNER_CONTEXT, Context, Ed25519VerifyingKey,
    MAX_PAYLOAD_BYTES, SignedAccountLog,
};
use libchat::{AuthResult, AuthService, SignerKey};
use logos_account::{AccountAddr, AccountProvider, AccountPublisher};
use reqwest::StatusCode;
use reqwest::blocking::{Client, Response};
use reqwest::header::CONTENT_TYPE;

const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// The largest valid response: a 64-byte Ed25519 signature, then the payload.
const MAX_ARTIFACT_BYTES: u64 = 64 + MAX_PAYLOAD_BYTES as u64;

#[derive(Debug, thiserror::Error)]
pub enum HttpAccountError {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("server returned status {0}: {1}")]
    Server(u16, String),
    #[error("reading response: {0}")]
    Io(#[from] std::io::Error),
    #[error("decode: {0}")]
    Decode(#[from] AccountLogError),
    #[error(transparent)]
    Addr(#[from] account_log::AccountAddrError),
    #[error("AccountLog contains zero endorsed keys")]
    NotChatEnabled,
    #[error("No account was found for address {0}")]
    AccountNotFound(String),
}

#[derive(Debug, Clone)]
struct Endpoint {
    base_url: String,
    http: Client,
}

impl Endpoint {
    fn new(base_url: impl Into<String>) -> Self {
        let http = Client::builder()
            .timeout(HTTP_TIMEOUT)
            .build()
            .expect("reqwest client builder is infallible with these options");
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http,
        }
    }

    fn url(&self, addr: &AccountAddr) -> String {
        format!("{}/v1/account/{addr}", self.base_url)
    }
}

/// A non-success status as [`HttpAccountError::Server`], with the server's message.
fn success(resp: Response) -> Result<Response, HttpAccountError> {
    let status = resp.status();
    if status.is_success() {
        return Ok(resp);
    }
    Err(HttpAccountError::Server(
        status.as_u16(),
        resp.text().unwrap_or_default(),
    ))
}

fn default_context() -> Context {
    CHATSIGNER_CONTEXT.clone()
}

#[derive(Debug, Clone)]
pub struct HttpAuthClient {
    endpoint: Endpoint,
    context: Context,
}

impl Default for HttpAuthClient {
    fn default() -> Self {
        Self::new("https://devnet.chat-kc.logos.co")
    }
}

impl HttpAuthClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            endpoint: Endpoint::new(base_url.into()),
            context: default_context(),
        }
    }

    fn get_account_log(&self, addr: &AccountAddr) -> Result<Option<AccountLog>, HttpAccountError> {
        let Some(signed_log) = self.fetch(addr)? else {
            return Ok(None);
        };
        signed_log
            .verify(addr)
            .map(Some)
            .map_err(HttpAccountError::from)
    }
}

impl AccountProvider for HttpAuthClient {
    type Error = HttpAccountError;

    fn fetch(&self, addr: &AccountAddr) -> Result<Option<SignedAccountLog>, Self::Error> {
        let resp = self.endpoint.http.get(self.endpoint.url(addr)).send()?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        // The server is untrusted: read one byte past the cap, never the whole body.
        let mut body = Vec::new();
        success(resp)?
            .take(MAX_ARTIFACT_BYTES + 1)
            .read_to_end(&mut body)?;

        if body.len() as u64 > MAX_ARTIFACT_BYTES {
            return Err(AccountLogError::TooLarge(MAX_PAYLOAD_BYTES).into());
        }
        Ok(Some(SignedAccountLog::from_bytes(&body)?))
    }
}

impl AccountPublisher for HttpAuthClient {
    type Error = HttpAccountError;

    fn publish(&mut self, addr: &AccountAddr, log: &SignedAccountLog) -> Result<(), Self::Error> {
        let resp = self
            .endpoint
            .http
            .post(self.endpoint.url(addr))
            .header(CONTENT_TYPE, "application/octet-stream")
            .body(log.to_bytes())
            .send()?;

        success(resp).map(drop)
    }
}

impl AuthService for HttpAuthClient {
    type Error = HttpAccountError;

    fn validate_signer(
        &self,
        signer_key: libchat::SignerKey,
        participant_id: libchat::ParticipantId,
    ) -> Result<libchat::AuthResult, Self::Error> {
        // A malformed claim is a definite no, not a failure to decide.
        let Ok(addr) = AccountAddr::try_from(participant_id.as_bytes()) else {
            return Ok(AuthResult::Invalid);
        };

        let Ok(signer) = Ed25519VerifyingKey::from_canonical_slice(signer_key.as_bytes()) else {
            return Ok(AuthResult::Invalid);
        };

        let Some(account_log) = self.get_account_log(&addr)? else {
            return Ok(libchat::AuthResult::Invalid);
        };

        Ok(
            if account_log
                .ed25519_keys_for(&self.context)
                .contains(&signer)
            {
                AuthResult::Valid
            } else if account_log
                .revoked_ed25519_keys_for(&self.context)
                .contains(&signer)
            {
                AuthResult::Revoked
            } else {
                AuthResult::Invalid
            },
        )
    }

    fn signers_for_participant(
        &self,
        participant_id: &libchat::ParticipantId,
    ) -> Result<Vec<SignerKey>, Self::Error> {
        // A malformed address is an resolution failure.
        let addr =
            AccountAddr::try_from(participant_id.as_bytes()).map_err(HttpAccountError::from)?;

        let Some(account_log) = self.get_account_log(&addr)? else {
            // The server has returned a success code but
            return Err(HttpAccountError::AccountNotFound(addr.to_string()));
        };

        let signers: Vec<SignerKey> = account_log
            .ed25519_keys_for(&self.context)
            .into_iter()
            .map(|k| SignerKey::from(k.as_ref()))
            .collect();

        if signers.is_empty() {
            return Err(HttpAccountError::NotChatEnabled);
        }
        Ok(signers)
    }
}
