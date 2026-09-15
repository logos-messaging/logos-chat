use std::fmt::{self, Debug};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use chat_proto::logoschat::store::{AccountSubmissionV1, KeyPackageSubmissionV1};
use crypto::{Ed25519Signature, Ed25519VerifyingKey};
use libchat::{AddressedEnvelope, DeliveryService, IdentityProvider, RegistrationService};
use logos_account_DELETE::{
    AccountDirectory, BundleError, DeviceSet, SignedDeviceBundle, verify_bundle,
};
use prost::Message;
use prost::bytes::Bytes;
use serde::{Deserialize, Serialize};

/// Delivery address the store listens on for keypackage submissions. The
/// transport maps it to its content topic (e.g.
/// `/logos-chat/1/store-keypackage-v0/proto` on logos-delivery); the store
/// subscribes to the same topic.
pub const KEYPACKAGE_SUBMIT_ADDRESS: &str = "store-keypackage-v0";

/// Delivery address the store listens on for account device-list bundles.
pub const ACCOUNT_SUBMIT_ADDRESS: &str = "store-account-v0";

/// Request timeout for the store's HTTP API (queries, and submissions in
/// [`RegistryPublishMode::Http`]).
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// How a [`ContactRegistry`] submits bundles to the store. Reads always use
/// the store's HTTP query API; only the write half switches.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RegistryPublishMode {
    /// Submit via the store's HTTP POST endpoints (synchronous, acknowledged).
    #[default]
    Http,
    /// Publish over the delivery network on the well-known store addresses;
    /// the store subscribes and persists what verifies. Fire-and-forget —
    /// there is no per-submission acknowledgement, which the registry can
    /// afford because consumers verify every bundle on retrieval anyway.
    Delivery,
}

/// The keypackage store and account → device directory.
///
/// Reads (keypackage retrieve, account fetch) always go over the store's HTTP
/// query API. Writes (register, publish) go over whichever wire
/// [`RegistryPublishMode`] selects: the store's HTTP POST endpoints (a JSON
/// body with hex + base64 fields) or a protobuf submission
/// ([`KeyPackageSubmissionV1`] / [`AccountSubmissionV1`]) published on the
/// well-known store addresses — matching the `/proto` content topics those
/// addresses map to, and carrying the keys, payload and signature as raw bytes.
///
/// A single registry serves both wires so it can be used behind one
/// `ChatClient` registry type; the delivery transport `D` is unused in
/// [`RegistryPublishMode::Http`].
#[derive(Clone)]
pub struct ContactRegistry<D> {
    base_url: String,
    http: reqwest::blocking::Client,
    delivery: D,
    publish_mode: RegistryPublishMode,
}

impl<D: Debug> Debug for ContactRegistry<D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContactRegistry")
            .field("base_url", &self.base_url)
            .field("publish_mode", &self.publish_mode)
            .field("delivery", &self.delivery)
            .finish()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ContactRegistryError {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("server returned status {0}: {1}")]
    Server(u16, String),
    #[error("decode: {0}")]
    Decode(String),
    #[error("clock before unix epoch")]
    Clock,
    #[error("signature verification failed")]
    SignatureInvalid,
    #[error("bundle: {0}")]
    Bundle(#[from] BundleError),
    #[error("publish over delivery: {0}")]
    Publish(String),
}

impl<D> ContactRegistry<D> {
    /// A registry that queries the store's HTTP API at `base_url` and submits
    /// per `publish_mode` — over `delivery` or over the same HTTP API.
    pub fn new(
        delivery: D,
        base_url: impl Into<String>,
        publish_mode: RegistryPublishMode,
    ) -> Self {
        let http = reqwest::blocking::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .build()
            .expect("reqwest client builder is infallible with these options");
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http,
            delivery,
            publish_mode,
        }
    }
}

impl<D> ContactRegistry<D> {
    /// POST `body` as JSON to `path` on the store, mapping a non-success status
    /// to [`ContactRegistryError::Server`] with the server's own message.
    fn http_post<S: Serialize>(&self, path: &str, body: &S) -> Result<(), ContactRegistryError> {
        let url = format!("{}{}", self.base_url, path);
        let resp = send_retrying(|| self.http.post(&url).json(body))?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            return Err(ContactRegistryError::Server(
                status,
                resp.text().unwrap_or_default(),
            ));
        }
        Ok(())
    }

    /// GET `url`, returning `None` on 404 (never published) and the decoded,
    /// still-unverified bundle on success. The caller verifies the signature.
    fn http_fetch(&self, url: &str) -> Result<Option<FetchedBundle>, ContactRegistryError> {
        let resp = send_retrying(|| self.http.get(url))?;
        if resp.status().as_u16() == 404 {
            return Ok(None);
        }
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            return Err(ContactRegistryError::Server(
                status,
                resp.text().unwrap_or_default(),
            ));
        }
        let body: FetchResponse = resp.json()?;
        let payload = BASE64
            .decode(&body.payload)
            .map_err(|e| ContactRegistryError::Decode(e.to_string()))?;
        let signature: [u8; 64] = BASE64
            .decode(&body.signature)
            .map_err(|e| ContactRegistryError::Decode(e.to_string()))?
            .as_slice()
            .try_into()
            .map_err(|_| ContactRegistryError::Decode("signature not 64 bytes".into()))?;
        Ok(Some(FetchedBundle { payload, signature }))
    }
}

impl<D: DeliveryService> ContactRegistry<D> {
    /// Encode `submission` as protobuf and publish it on `delivery_address`.
    /// Protobuf encoding into a `Vec` cannot fail, so the only error here is the
    /// transport's.
    fn publish_submission<M: Message>(
        &mut self,
        delivery_address: &str,
        submission: &M,
    ) -> Result<(), ContactRegistryError> {
        self.delivery
            .publish(AddressedEnvelope {
                delivery_address: delivery_address.to_string(),
                data: submission.encode_to_vec(),
            })
            .map_err(|e| ContactRegistryError::Publish(e.to_string()))
    }
}

impl<D: DeliveryService> RegistrationService for ContactRegistry<D> {
    type Error = ContactRegistryError;

    fn register(
        &mut self,
        identity: &dyn IdentityProvider,
        key_bundle: Vec<u8>,
    ) -> Result<(), Self::Error> {
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ContactRegistryError::Clock)?
            .as_millis() as u64;

        // The signed bytes are the same on both wires; only the encoding of the
        // submission around them differs. Sign once, then branch on transport.
        let payload = encode_payload(timestamp_ms, &key_bundle);
        let signature = identity.sign(&payload);
        let device_id = identity.public_key().as_ref();

        match self.publish_mode {
            RegistryPublishMode::Http => self.http_post(
                "/v0/keypackage",
                &SubmitRequest {
                    device_id: hex::encode(device_id),
                    payload: BASE64.encode(&payload),
                    signature: BASE64.encode(signature.as_ref()),
                },
            ),
            RegistryPublishMode::Delivery => {
                let req = KeyPackageSubmissionV1 {
                    device_id: Bytes::copy_from_slice(device_id),
                    payload: Bytes::from(payload),
                    signature: Bytes::copy_from_slice(signature.as_ref()),
                };
                self.publish_submission(KEYPACKAGE_SUBMIT_ADDRESS, &req)
            }
        }
    }

    fn retrieve(&self, device_id: &str) -> Result<Option<Vec<u8>>, Self::Error> {
        let url = format!("{}/v0/keypackage/{}", self.base_url, device_id);
        let Some(FetchedBundle { payload, signature }) = self.http_fetch(&url)? else {
            return Ok(None);
        };

        // Verify over the received payload bytes, using the key we asked for
        // (`device_id`). A bundle the requested device didn't sign won't verify.
        let device_pubkey: [u8; 32] = hex::decode(device_id)
            .map_err(|e| ContactRegistryError::Decode(e.to_string()))?
            .as_slice()
            .try_into()
            .map_err(|_| ContactRegistryError::Decode("device_id not a 32-byte key".into()))?;
        let verifying_key = Ed25519VerifyingKey::from_bytes(&device_pubkey)
            .map_err(|_| ContactRegistryError::Decode("device_id not a valid ed25519 vk".into()))?;
        verifying_key
            .verify(&payload, &Ed25519Signature::from(signature))
            .map_err(|_| ContactRegistryError::SignatureInvalid)?;

        let (_timestamp_ms, key_package) = decode_payload(&payload)
            .ok_or_else(|| ContactRegistryError::Decode("short payload".into()))?;
        Ok(Some(key_package.to_vec()))
    }
}

impl<D: DeliveryService> AccountDirectory for ContactRegistry<D> {
    type Error = ContactRegistryError;

    fn publish(&mut self, bundle: &SignedDeviceBundle) -> Result<(), Self::Error> {
        // The bundle is already signed; both wires carry its exact bytes.
        match self.publish_mode {
            RegistryPublishMode::Http => self.http_post(
                "/v0/account",
                &SubmitAccountRequest {
                    account_pub: hex::encode(bundle.account_pub.as_ref()),
                    payload: BASE64.encode(&bundle.payload),
                    signature: BASE64.encode(bundle.signature.as_ref()),
                },
            ),
            RegistryPublishMode::Delivery => {
                let req = AccountSubmissionV1 {
                    account_pub: Bytes::copy_from_slice(bundle.account_pub.as_ref()),
                    payload: Bytes::copy_from_slice(&bundle.payload),
                    signature: Bytes::copy_from_slice(bundle.signature.as_ref()),
                };
                self.publish_submission(ACCOUNT_SUBMIT_ADDRESS, &req)
            }
        }
    }

    fn fetch(&self, account: &Ed25519VerifyingKey) -> Result<Option<DeviceSet>, Self::Error> {
        let url = format!(
            "{}/v0/account/{}",
            self.base_url,
            hex::encode(account.as_ref())
        );
        let Some(FetchedBundle { payload, signature }) = self.http_fetch(&url)? else {
            return Ok(None);
        };

        // The directory service is untrusted: verify the account signature over
        // the exact received bytes, and that the bundle is bound to the account
        // we asked for, before handing back any device keys.
        let bundle = SignedDeviceBundle {
            account_pub: account.clone(),
            payload,
            signature: Ed25519Signature::from(signature),
        };
        let device_set = verify_bundle(account, &bundle)?;
        Ok(Some(device_set))
    }
}

/// Keypackage submission as the HTTP POST body. The delivery path carries the
/// same fields as protobuf; this JSON shape is the store's HTTP endpoint only.
#[derive(Debug, Serialize)]
struct SubmitRequest {
    /// hex of the 32-byte device verifying key — the verification + storage key.
    device_id: String,
    /// base64 of the canonical signed payload (see [`encode_payload`]).
    payload: String,
    /// base64 of the 64-byte Ed25519 signature over `payload`.
    signature: String,
}

/// Account device-list submission as the HTTP POST body, like [`SubmitRequest`].
#[derive(Debug, Serialize)]
struct SubmitAccountRequest {
    /// hex of the 32-byte account verifying key — verification + storage key.
    account_pub: String,
    /// base64 of the canonical signed device-list payload.
    payload: String,
    /// base64 of the 64-byte account signature over `payload`.
    signature: String,
}

/// The `payload` + `signature` of a store fetch response; both keypackage and
/// account queries return this shape.
#[derive(Debug, Deserialize)]
struct FetchResponse {
    payload: String,
    signature: String,
}

/// A fetch response with its base64 fields decoded but not yet verified.
struct FetchedBundle {
    payload: Vec<u8>,
    signature: [u8; 64],
}

/// Canonical binary payload — the bytes that are both signed and transmitted
/// verbatim. Opaque to the server; decoded only by consumers:
///
/// ```text
/// timestamp_ms : u64 little-endian (8 bytes)
/// key_package  : remaining bytes (variable, last → no length prefix needed)
/// ```
///
/// The fixed-width field first with the one variable field last makes every
/// byte string parse exactly one way — no delimiter, no ambiguity, even though
/// `key_package` is arbitrary bytes. The device verifying key is carried
/// alongside as `device_id`, not embedded here.
fn encode_payload(timestamp_ms: u64, key_package: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + key_package.len());
    out.extend_from_slice(&timestamp_ms.to_le_bytes());
    out.extend_from_slice(key_package);
    out
}

/// Inverse of [`encode_payload`]. Returns `None` if the payload is shorter than
/// the fixed header (`8`).
fn decode_payload(payload: &[u8]) -> Option<(u64, &[u8])> {
    if payload.len() < 8 {
        return None;
    }
    let timestamp_ms = u64::from_le_bytes(payload[..8].try_into().ok()?);
    Some((timestamp_ms, &payload[8..]))
}

/// Retry budget for the registry's transient, load-induced 5xx/429 responses.
/// The service is reliable request-by-request but sheds concurrent bursts, so a
/// few backed-off retries let a request land once the burst clears. On that path
/// each retry returns fast, so the added cost is the ~3s worst-case backoff sum,
/// well inside chat_module's ~20s init IPC budget. A fully unreachable registry
/// instead costs up to MAX_RETRIES times the reqwest timeout, which no retry
/// budget can rescue.
const MAX_RETRIES: u32 = 4;
const RETRY_BASE_MS: u64 = 200;
const RETRY_MAX_BACKOFF_MS: u64 = 2000;

/// Send a request built by `build`, retrying transient failures — network errors
/// and 5xx/429 responses — with exponential backoff and full jitter. The
/// registry is reliable request-by-request but sheds concurrent bursts with a
/// 5xx, so a backed-off retry lands once the burst clears; a 4xx (and any other
/// final response) is returned to the caller unchanged. `build` is re-invoked per
/// attempt because sending consumes the builder.
fn send_retrying(
    build: impl Fn() -> reqwest::blocking::RequestBuilder,
) -> Result<reqwest::blocking::Response, ContactRegistryError> {
    let mut attempt = 0;
    loop {
        let outcome = build().send();
        let transient = match &outcome {
            Err(_) => true, // network error / timeout: worth another try
            Ok(resp) => is_transient_status(resp.status()),
        };
        if !transient || attempt >= MAX_RETRIES {
            return Ok(outcome?);
        }
        std::thread::sleep(backoff_with_jitter(attempt));
        attempt += 1;
    }
}

/// Whether a response status is worth retrying: 5xx (the registry sheds
/// concurrent load with these) or 429 (explicit backpressure). A 4xx is the
/// caller's fault and won't change on retry.
fn is_transient_status(status: reqwest::StatusCode) -> bool {
    status.is_server_error() || status == reqwest::StatusCode::TOO_MANY_REQUESTS
}

/// Full-jitter exponential backoff: a random delay in
/// `[0, min(RETRY_MAX_BACKOFF_MS, RETRY_BASE_MS * 2^attempt)]`. The jitter
/// decorrelates concurrent publishers so their retries don't collide into the
/// same burst that failed them.
fn backoff_with_jitter(attempt: u32) -> Duration {
    let exp = RETRY_BASE_MS.saturating_mul(1u64 << attempt.min(16));
    Duration::from_millis(jitter_below(exp.min(RETRY_MAX_BACKOFF_MS)))
}

/// A value in `[0, max]`, seeded from the wall clock's sub-second nanos — enough
/// entropy to spread retries across processes without pulling in an RNG crate.
fn jitter_below(max: u64) -> u64 {
    if max == 0 {
        return 0;
    }
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0);
    nanos % (max + 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::Ed25519SigningKey;
    use libchat::{IdentId, IdentIdRef};

    #[derive(Debug, Default)]
    struct CapturingDelivery {
        published: Vec<AddressedEnvelope>,
    }

    impl DeliveryService for CapturingDelivery {
        type Error = std::convert::Infallible;
        fn publish(&mut self, envelope: AddressedEnvelope) -> Result<(), Self::Error> {
            self.published.push(envelope);
            Ok(())
        }
        fn subscribe(&mut self, _delivery_address: &str) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    struct TestIdent {
        id: IdentId,
        key: Ed25519SigningKey,
        verifying: Ed25519VerifyingKey,
    }

    impl TestIdent {
        fn new() -> Self {
            let key = Ed25519SigningKey::generate();
            let verifying = key.verifying_key();
            Self {
                id: IdentId::new("test"),
                key,
                verifying,
            }
        }
    }

    impl IdentityProvider for TestIdent {
        fn id(&self) -> IdentIdRef<'_> {
            &self.id
        }
        fn display_name(&self) -> String {
            self.id.to_string()
        }
        fn sign(&self, payload: &[u8]) -> Ed25519Signature {
            self.key.sign(payload)
        }
        fn public_key(&self) -> &Ed25519VerifyingKey {
            &self.verifying
        }
    }

    #[test]
    fn register_publishes_store_submission_on_keypackage_address() {
        let mut registry = ContactRegistry::new(
            CapturingDelivery::default(),
            "http://unused.invalid",
            RegistryPublishMode::Delivery,
        );
        let ident = TestIdent::new();
        let key_bundle = b"kp-bytes".to_vec();
        registry.register(&ident, key_bundle.clone()).unwrap();

        let [envelope] = &registry.delivery.published[..] else {
            panic!("expected exactly one published envelope");
        };
        assert_eq!(envelope.delivery_address, KEYPACKAGE_SUBMIT_ADDRESS);

        // Decode as the store does: the bytes on the wire are a protobuf
        // submission, so a field-number or type change here breaks ingestion.
        let wire = KeyPackageSubmissionV1::decode(&envelope.data[..]).unwrap();
        assert_eq!(wire.device_id.as_ref(), ident.verifying.as_ref());
        // The store verifies the signature over the payload bytes under the
        // device key before persisting — the submission must pass that check.
        assert!(wire.payload.ends_with(&key_bundle));
        let signature: [u8; 64] = wire.signature.as_ref().try_into().unwrap();
        ident
            .verifying
            .verify(&wire.payload, &Ed25519Signature::from(signature))
            .expect("store-side verification must succeed");
    }

    #[test]
    fn account_publish_targets_account_address_verbatim() {
        let mut registry = ContactRegistry::new(
            CapturingDelivery::default(),
            "http://unused.invalid",
            RegistryPublishMode::Delivery,
        );
        let account = Ed25519SigningKey::generate();
        let payload = b"signed-device-list".to_vec();
        let bundle = SignedDeviceBundle {
            account_pub: account.verifying_key(),
            signature: account.sign(&payload),
            payload: payload.clone(),
        };
        registry.publish(&bundle).unwrap();

        let [envelope] = &registry.delivery.published[..] else {
            panic!("expected exactly one published envelope");
        };
        assert_eq!(envelope.delivery_address, ACCOUNT_SUBMIT_ADDRESS);

        let wire = AccountSubmissionV1::decode(&envelope.data[..]).unwrap();
        assert_eq!(wire.account_pub.as_ref(), bundle.account_pub.as_ref());
        // Payload travels verbatim so the store and consumers verify the exact
        // signed bytes.
        assert_eq!(wire.payload.as_ref(), payload.as_slice());
        assert_eq!(wire.signature.as_ref(), bundle.signature.as_ref());
    }

    #[test]
    fn http_mode_never_touches_the_delivery_service() {
        // Port 9 (discard) refuses immediately; the point is only that the
        // submission goes down the HTTP path, not over delivery.
        let mut registry = ContactRegistry::new(
            CapturingDelivery::default(),
            "http://127.0.0.1:9",
            RegistryPublishMode::Http,
        );
        let err = registry.register(&TestIdent::new(), vec![1]).unwrap_err();
        assert!(matches!(err, ContactRegistryError::Http(_)));
        assert!(registry.delivery.published.is_empty());
    }

    /// `encode_payload` / `decode_payload` round-trip, including a key_package
    /// containing bytes that a delimiter scheme would choke on (`:`, `|`, NUL).
    #[test]
    fn payload_roundtrips_with_arbitrary_bytes() {
        let ts = 1_700_000_000_000u64;
        let key_package = b"mls:bytes|with\x00delimiters".to_vec();

        let payload = encode_payload(ts, &key_package);
        let (got_ts, got_kp) = decode_payload(&payload).unwrap();
        assert_eq!(got_ts, ts);
        assert_eq!(got_kp, key_package.as_slice());
    }

    #[test]
    fn decode_rejects_short_payload() {
        assert!(decode_payload(&[0u8; 7]).is_none());
    }

    /// Tampering with any byte of the payload breaks verification.
    #[test]
    fn signature_binds_payload() {
        let signing = Ed25519SigningKey::generate();
        let verifying = signing.verifying_key();

        let payload = encode_payload(1_700_000_000_000, b"original-keypackage");
        let signature = signing.sign(&payload);

        let tampered = encode_payload(1_700_000_000_000, b"tampered-keypackage");
        verifying
            .verify(&tampered, &signature)
            .expect_err("signature must not verify against a different payload");
    }

    /// End-to-end of the wire crypto: verify over the received payload bytes
    /// using the key recovered from device_id, exactly as `retrieve` does.
    #[test]
    fn sign_then_verify_over_payload() {
        let signing = Ed25519SigningKey::generate();
        let pubkey: [u8; 32] = signing.verifying_key().as_ref().try_into().unwrap();
        let payload = encode_payload(1_700_000_000_000, b"fake-mls-keypackage-bytes");
        let signature = signing.sign(&payload);

        // retrieve side: recover key from device_id (hex of pubkey), verify payload.
        let device_id = hex::encode(pubkey);
        let recovered: [u8; 32] = hex::decode(&device_id)
            .unwrap()
            .as_slice()
            .try_into()
            .unwrap();
        Ed25519VerifyingKey::from_bytes(&recovered)
            .unwrap()
            .verify(&payload, &signature)
            .expect("recovered key must verify the register-time signature");
    }

    /// Only 5xx and 429 are retried; 2xx/4xx are returned to the caller as-is.
    #[test]
    fn only_5xx_and_429_are_transient() {
        use reqwest::StatusCode;
        for s in [500u16, 502, 503, 504, 429] {
            assert!(
                is_transient_status(StatusCode::from_u16(s).unwrap()),
                "{s} should be retried"
            );
        }
        for s in [200u16, 201, 400, 401, 404, 409] {
            assert!(
                !is_transient_status(StatusCode::from_u16(s).unwrap()),
                "{s} should not be retried"
            );
        }
    }

    /// Backoff never exceeds the exponential ceiling for its attempt, nor the
    /// absolute cap — and the exponent shift can't overflow at high attempts.
    #[test]
    fn backoff_stays_within_the_cap() {
        for attempt in 0..40u32 {
            let ceiling = RETRY_BASE_MS
                .saturating_mul(1u64 << attempt.min(16))
                .min(RETRY_MAX_BACKOFF_MS);
            let delay = backoff_with_jitter(attempt).as_millis() as u64;
            assert!(delay <= ceiling, "attempt {attempt}: {delay} > {ceiling}");
        }
    }

    #[test]
    fn jitter_is_bounded() {
        assert_eq!(jitter_below(0), 0);
        for _ in 0..200 {
            assert!(jitter_below(50) <= 50);
        }
    }
}
