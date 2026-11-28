# AGENTS.md

Guidance for anyone changing code in this repository: people, and any coding
agent. It is tool-neutral on purpose. Tool-specific files (`CLAUDE.md`,
`.claude/`) only point back here.

## What this is

λChat (`logos-chat`) is an authenticated, end-to-end encrypted chat protocol library in Rust. It has:

- MLS (OpenMLS) for group encryption.
- SDS for causal history in GroupV3.
- de-mls consensus for GroupV2.
- Pluggable transport, registry, auth and storage.

It is pre-1.0. Every crate is `0.1.0`, the protocol is not frozen, and breaking changes are expected. Edition 2024, `resolver = "3"`, stable toolchain (`rust_toolchain.toml`).

## Build and test

`protoc` must be on PATH: `hashgraph-like-consensus` runs prost-build. On macOS: `brew install protobuf`.

`just check` runs what CI's fmt, clippy, build and test jobs run:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --workspace --exclude chat-cli -- -D warnings
cargo build --workspace --exclude chat-cli --exclude embedded-logos-delivery
cargo test  --workspace --exclude chat-cli --exclude embedded-logos-delivery
```

`just smoketest` builds `chat-cli` and runs `--smoketest` against `.github/scripts/mock-registry.py`. `just ci` runs both. Put personal recipes in `justfile.local`, which is gitignored and imported last. The README's `just test` / `just clippy` recipes don't exist.

`chat-cli`, `logos-chat` and `embedded-logos-delivery` link the native `liblogosdelivery`. They are outside `default-members`, so build them in the Nix shell, which exports `LOGOS_DELIVERY_LIB_DIR`:

```sh
nix develop
cargo build -p logos-chat
cargo build -p chat-cli
```

`.cargo/config.toml` points `LOGOS_DELIVERY_LIB_DIR` at `result/lib`. A prior `nix build .#logos-delivery` is then picked up by plain cargo and rust-analyzer.

Run a single test file or test:

```sh
cargo test -p libchat --lib
cargo test -p integration_tests_core --test test_group_v3
cargo test -p integration_tests_core --test test_direct_v1 happypath_roundtrip
cargo test -p logos-generic-chat --test saro_and_raya
```

`libchat` features:

- `test-support`: the in-memory store, store test assertions, and the hooks that inject bad input.
- `test-fast-commits`: shortens the GroupV3 finalize timeout to 100 ms.

When you touch either feature, also run clippy with it enabled.

GroupV2 scale test environment variables:

- `BUDGET=<seconds>`: the virtual-time settle budget. Default 30.
- `LOG=warn|info|debug`: turns on tracing. Off by default.

CI (`.github/workflows/ci.yml`) runs:

- fmt, clippy and build/test
- `cargo-deny`, configured in `deny.toml`
- the Nix `chat-cli --smoketest`
- `chat-sim.yml`, which posts a simulation comparison on every PR

## Workspace

| Path | Crate | Role |
|---|---|---|
| `core/conversations` | `libchat` | The synchronous protocol core |
| `core/crypto` | `crypto` | Ed25519 and shared primitives |
| `core/integration_tests_core` | | `TestHarness` and the protocol integration tests |
| `crates/generic-chat` | `logos-generic-chat` | `ChatClient`: threading and events, every service a type parameter |
| `crates/logos-chat` | `logos-chat` | The opinionated Logos stack; re-exports `logos_generic_chat` |
| `account/account`, `account/account-log` | `logos-account`, `account-log` | Accounts, namespaces, the account log |
| `extensions/components` | `components` | Swappable services, listed under "Extensions" below |
| `extensions/sqlite` | `chat-sqlite` | SQLCipher `SqliteStore` and the KV substrate |
| `extensions/message-store`, `extensions/message-types` | | App-side message persistence and content types |
| `extensions/embedded-logos-delivery` | | `liblogosdelivery` as a `Transport` |
| `bin/chat-cli` | | Example TUI client |

`logos-delivery` is a git dependency (`logos-delivery-rust-bindings`), not a workspace member.

`[profile.release] panic = "abort"` is set workspace-wide. Rust callbacks registered with `liblogosdelivery` must not unwind across the FFI boundary.

## Architecture

The code has three layers. Calls flow down, synchronous results come back as return values, and events flow up asynchronously.

```
app        bin/chat-cli: drains Receiver<Event>
client     crates/generic-chat, crates/logos-chat: owns the worker thread and services
core       core/conversations (libchat): synchronous, no threads, no callbacks
```

### The core is synchronous and caller-driven

`libchat::Core` (`core.rs`) starts no work of its own. It also holds no interior mutability or shared ownership.

Everything external is injected through `ExternalServices` (`service_context.rs`), which has six associated types:

- `IdentityProvider`
- `AuthService`
- `DeliveryService`
- `RegistrationService`
- `WakeupService`
- `ConversationStore`

A tuple impl of those six lets callers supply them separately. Constructors live on that tuple form, because `S` cannot be inferred backwards through `S::DS`.

`ServiceContext<S>` is the bundle every conversation operation receives as `&mut ServiceContext<S>`. It also carries the MLS identity and provider, causal history, the clock and the GroupV2 config. Keep conversation-specific state inside the conversation type, not here.

Inbound bytes have one entry point: `Core::handle_payload(&[u8], Option<&DeliveryInfo>) -> Result<PayloadOutcome>`. It decodes an `EnvelopeV1`, reads `conversation_hint`, and dispatches to one of:

- InboxV2
- a cached conversation
- a stored conversation

Anything else gets `PayloadOutcome::Empty`. Other entry points:

- `Core::wakeup(convo_id)` runs timer-driven work.
- `Core::handle_delivery_report` takes the delivery ids that the transport reports after a publish.

### Outcomes vs. events (ADR 0001)

The core and the client each have their own enum. The client maps between them explicitly, never through a blanket `From`, so the two can diverge.

- **Core** (`outcomes.rs`): `PayloadOutcome::{Empty, Convo, Inbox}`.
  - `ConvoOutcome` is an ordered `Vec<Observation>` on an existing conversation. `Observation` is one of `Content`, `SignersChanged` or `Delivered(MessageId)`.
  - `InboxOutcome` is a newly observed conversation (`NewConversation { convo_id, class }`), optionally with an initial `ConvoOutcome`. A `Convo` cannot manufacture a new conversation; its signature rules that out.
- **Client** (`crates/generic-chat/src/event.rs`): `Event` is `#[non_exhaustive]`. Its variants are `ConversationStarted`, `MessageReceived`, `MessageAcked`, `MessageDelivered`, `MessageMissing`, `ConversationMembersChanged` and `InboundError`.

Synchronous failures are never events. Publish, parse, store and MLS errors stay on the triggering call's `Result<_, ChatError>`. An event is something learned after that call returned, or with no synchronous trigger at all, such as wakeup-driven work.

The translation lives in `client.rs`: `events_from_inbound`, `convo_events`, `observation_event`, `inbox_events`, `delivery_ack_events` and `missing_events`.

### The client owns the threading

`ChatClient<T, R, A, S>` (transport, registry, auth, store) wraps `Core` in `Arc<parking_lot::Mutex<…>>`. It uses `parking_lot` for eventual fairness, so an inbound burst cannot starve callers.

One worker thread `select!`s over four inputs:

- inbound payloads
- delivery reports
- `WakeupEvent`s from `ThreadedWakeupService`
- shutdown

Outbound calls run on the caller's thread: lock briefly, invoke, return.

`Transport` is a `DeliveryService + Send + 'static` that also hands over its inbound and delivery-report receivers once, at construction. `ChatClientBuilder` is a typestate builder (`Unset`) over transport, registration, auth and storage.

Consumers have two entry points:

- **`logos-generic-chat`:** nothing Logos-specific is baked in.
- **`logos-chat`:** `open(LogosConfig)` commits to:
  - an embedded logos-delivery node
  - `ContactRegistry` (keypackages)
  - `CachedAuth<HttpAuthClient>`
  - an encrypted `SqliteStore`

### Identity model (ADR 0003, Proposed)

`identity.rs` keeps these concepts apart by type:

- **`SignerKey`:** an installation's public signature key. It identifies one installation.
- **`ParticipantId`:** the user an installation acts for. Opaque bytes to the core, which never learns what an account is.
- **`Signer { signer_key, participant_id }`:** one installation of one participant in a conversation.
- **`AuthenticatedSigner`:** a `Signer` that `AuthService::validate_signer` returned `Valid` for. `Content.sender` is always one, so the core only hands the app senders that passed an auth check.
- **`Installation`** (client): this app's signing key plus the `AccountAddr` that endorsed it. `logos-account` owns accounts.

The InboxV2 delivery address is derived from the signer key's hex form (`inbox_v2.rs`, `delivery_address_for`). That is the key registries list key packages under, so an inviter can derive it.

### Conversation kinds

All kinds live under `core/conversations/src/conversation/` and implement the crate-private traits in `conversation.rs`:

- **`Convo<S>`:** `send_content`, `handle_payload`, `wakeup`, `handle_delivery_report`.
- **`ConvoBase`:** `signers`, `pending_signers`, `can_send`, `metadata`.
- **`GroupConvo<S>`:** adds `add_signer`, `remove_signer`, `request_readd`, `force_readd`, `sync_state`, `debug_data`.

The kinds:

- **GroupV1:** a plain OpenMLS group, with ciphersuite `MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519` (X-Wing guards against harvest-now-decrypt-later). Adds commit within the call.
- **DirectV1:** a 1:1 conversation over an inner MLS group. A participant may have several installations. Not stored as its own kind.
- **GroupV2:** de-mls consensus, peer scoring and voting. Membership changes are put to the group and land in a later commit. `remove_signer` returns with the member still listed, and an add shows up in `pending_signers`. Labelled a spike.
- **GroupV3:** MLS with SDS causal history. `ChatClient::create_group_conversation` creates this kind (`Core::create_group_convo` still creates GroupV2). Its submodules:

  | Submodule | What it does |
  |---|---|
  | `payloads` | Framing |
  | `handlers` | Inbound frames |
  | `finality` | Deferred commits, finalized lowest fingerprint first |
  | `beacons` | Per-epoch signed beacons |
  | `external`, `sealed` | The private external-message channel |
  | `readd` | Fork repair by Remove + Add |
  | `sync_state` | `SyncState`, reported from beacons |
  | `trace`, `debug_data`, `inspect` | Diagnostics |

  The module header still says "TESTING ONLY".
- **InboxV2:** not a conversation. It is the 1:1 rendezvous channel that mints key packages and receives Welcomes. It creates conversations of any kind, including the rejoin after a requested re-add (`replaces`).

`Core::load_convo` is the only place that branches on `ConversationKind`. Adding a kind touches that match, `storage::ConversationKind` and `ConversationClass::from_kind`.

### Capability distinctions

These questions are kept separate on purpose:

- **Exists / known:** `list_all_conversations`, `can_receive`.
- **Content can be sent:** `can_send`, `list_sendable_conversations`. The conversation must be loaded this session, and the local identity must still be a member.

A conversation restored from an earlier session but not reloaded can receive but cannot send.

### Causal history

There are two implementations:

- **`causal_history.rs`:** the SDS causal-history subset for the older kinds. Lamport timestamps plus a bounded frontier of recently seen message ids.
- **GroupV3:** runs content through `sds-rs`. When SDS reports a member missing a message, it fetches that message through `DeliveryService::fetch_messages`.

On receive, the frontier produces gaps (`MessageMissing`) and passive acknowledgements (`MessageAcked`).

The `sender_id` on a frontier entry is a routing hint and is **not authenticated**. The same caveat applies to `MessageAcked.acked_by` and `MessageMissing.sender_hint`. A silent peer never acknowledges, so a missing ack means "not confirmed", not "not delivered".

### Storage (ADR 0002, Accepted, partly implemented)

What is wired in today: `ConversationStore` (`storage.rs`), a typed store of conversation metadata. `ConversationKind` currently has only `GroupV1` and `Unknown`. Implementations:

- `SqliteStore` (`chat-sqlite`; `StorageConfig::{InMemory, Encrypted}`)
- `MemStore`, behind `test-support`

MLS group state is in memory, so only stored GroupV1 conversations reload after a restart.

What is landing: the KV substrate.

- `KvStore` / `KvTx` address bytes by `Scope { ns, instance }` inside one transaction.
- `ScopedKvStore` (`kv.rs`) is the handle a conversation gets.
- `chat-sqlite` implements both.
- It is not yet carried by `ServiceContext`.

Read ADR 0002 before touching the store boundary. The guiding rule is that shipping a new conversation type must not move it.

### Extensions

`extensions/components` holds:

| Component | Purpose |
|---|---|
| `EphemeralRegistry` | In-memory registry |
| `ContactRegistry` | HTTP registry. `RegistryPublishMode` chooses HTTP POST or the delivery network; reads always use HTTP |
| `HttpAuthClient` + `CachedAuth` | Auth |
| `LocalBroadcaster` and the in-process delivery | Transports for tests |
| `key_vault` | Key storage |
| `ThreadedWakeupService` | Wakeups |

## Testing patterns

`integration_tests_core` provides `TestHarness<const N: usize>`: N in-process clients with a virtual clock. The clients are `saro()`, `raya()`, `pax()` and `mira()`, in index order. Tests drive, then settle:

```rust
let mut harness = TestHarness::<2>::new(|_, _| {});
let peer = harness.raya().addr();
let convo_id = harness.saro().create_direct_convo_v1(&[&peer]).unwrap();
harness.process_until(|h| h.raya().convo_count() == 1);
harness.saro().send_content(&convo_id, b"Marco").unwrap();
harness.process_until(|h| h.raya().check(&convo_id, b"Marco"));
```

- `process_until_label` names the settle, so a failure is readable.
- The harness panics on any rejected inbound payload. Call `tolerate_inbound_errors()` to collect rejections in `inbound_errors()` instead.
- GroupV2/V3 tests share a mock clock between the scheduler and the protocol timers.
- `crates/generic-chat` tests exercise the threaded client end to end over the in-process delivery.

## chat-cli

`bin/chat-cli` is an example TUI client.

- `--transport file` runs locally with no network. `--transport logos-delivery` uses the real network.
- `--group-commit auto|fast|default` sets GroupV2 timing:
  - `fast` commits membership changes in about 1 s instead of about 60 s.
  - `auto` picks `fast` for the file transport only.
- `--smoketest` initializes and exits.
- Slash commands are in `app.rs::handle_command`.

## Rules

These rules came out of review, and reviewers hold every PR to them, whoever
or whatever wrote it. **Read the guideline files that match your change before
writing code.** Agents: read them at the start of the task. They are not
optional background.

| Guideline | Covers |
|---|---|
| [mls-and-specs.md](docs/guidelines/mls-and-specs.md) | Logos LIPs first, then RFC 9420/9750 and the drafts; how MLS maps onto a network with no ordering server |
| [protocol-safety.md](docs/guidelines/protocol-safety.md) | Untrusted input, authentication, convergence, failure |
| [rust.md](docs/guidelines/rust.md) | Architecture, functions, errors, panics, types, naming, scope, lints |
| [testing.md](docs/guidelines/testing.md) | Proving tests, what to assert, the harness |
| [writing.md](docs/guidelines/writing.md) | Comments, doc comments, docs |
| [reviews-and-prs.md](docs/guidelines/reviews-and-prs.md) | Severity ladder, commits, shaping PRs |

Procedures, to follow step by step when asked:

- [Review](docs/procedures/review.md): review a diff or PR and report a
  severity-ladder table.
- [Prove a test](docs/procedures/prove-test.md): show that a test fails
  without its fix.

Housekeeping:

- Architecture decisions live in `docs/adr/`. Other `docs/` files are design
  notes and are not all implemented.
- `GroupV2Config` / `LogosConfig::set_group_v2_config` are a temporary,
  unsupported pathway. Don't build on them.
- Never read or print `chat-cli-keys`, `.env*`, or credentials.
- Personal agent preferences go in a local, uncommitted file
  (`CLAUDE.local.md` is gitignored), never in this one.
