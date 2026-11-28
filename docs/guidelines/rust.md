# Rust

## Architecture

- **Dependencies point down.** The app depends on the client, and the client
  depends on core. Core never depends on a client, transport, store or
  account system. It sees them only through the traits in
  `service_traits.rs` and `storage.rs`.
- **Core stays synchronous.** No threads, channels, async, callbacks or
  interior mutability in `libchat`. Concurrency belongs to the client.
- **One entry point per kind of input:** `handle_payload` for bytes,
  `wakeup` for timers, `handle_delivery_report` for receipts. Don't add a side
  door.
- **A new conversation type is a libchat-only change.** It must not change a
  service trait, the store boundary or the client's event enum (ADR 0002).
- **The client maps core outcomes to events explicitly**, with no blanket
  `From` (ADR 0001).
- **Each module answers one question.** For example, in GroupV3 `external` is
  what a beacon is and `beacons` is what a member does with one. When a file
  needs a section banner to be navigable, it needs a split instead.
- **Read the ADR before changing a boundary.** If a change needs a new
  boundary, write the ADR first.

## Functions

- **Short and single-purpose.** A function that needs comments to separate
  its steps wants to be several functions. Don't split one that reads fine as
  it is.
- **Validate at the edge, then trust the types.** Parse inbound data into a
  checked type once, and pass that type inward.
- **Prefer pure functions** for decisions: rank, classify, choose. They take
  state and return a verdict, and the caller applies it. They are easy to test
  and to reason about.
- **Borrow by default.** Take `&str`, `&[u8]` and `&T` unless the callee
  keeps the value. Don't `clone()` to satisfy the borrow checker without
  asking whether ownership is right.
- **Prefer iterators and `?`** to manual loops with flags and nested `match`.

## Errors

- **Libraries use `thiserror` enums** (`ChatError`, `ClientError`). `anyhow`
  is for binaries only (`chat-cli`).
- **An error variant says what went wrong for the caller**, not where in the
  code it happened. Carry the id or value that lets someone act on it.
- **Don't swallow errors.** If a failure is deliberately non-fatal, log it at
  the right level (`tracing`) and say why in one line.
- **No `println!`/`eprintln!` in library code.** Use `tracing`.

## Panics

- **No `unwrap` or `expect` on a path remote input can reach.** A removal once
  reached `.expect("is member")` in `From<&StagedCommit>`. The fix was a
  constructor that returns `Option`.
- **`expect` is fine for an invariant already proven upstream**, with that
  reason as its message. A fake error path for something that cannot happen is
  worse.
- **No `todo!()` or `unimplemented!()` on a reachable path.**

## Types

- **Encode invariants in types.**
  - Drop an `Option` that production never sees empty.
  - Return `Result` for data that is not optional.
  - Prefer constructors like `EpochData::from_group(&group)`.
- **Use typed identifiers, never strings**, for signers, participants and
  conversations (ADR 0003).
- **Public enums are `#[non_exhaustive]`.**
- **Use named structs instead of wide tuples.** `self.support[at].1` says
  nothing.
- **Pass structured data across layers, not `Vec<u8>`.**
- **Move rather than copy.** Take `impl Into<Bytes>` and owned values when the
  callee keeps them.
- **Use `From`/`TryFrom` for conversions.** Fallible conversion from wire or
  external data is always `TryFrom`.
- **Match your own enums exhaustively.** A `_ =>` arm hides the place a new
  variant needs handling.
- **Derive `Default` only when the default is meaningful.**
- **`Debug` never prints secrets.** Write a manual impl when a field is key
  material (see `SignerKey`, which prints hex of a public key only).
- **Don't return a closed enum from a public API that will grow.**

## Structure

- **Use the narrowest visibility.** A `pub` inside a private module tree
  defeats dead-code analysis.
- **No blanket `#![allow(dead_code)]`.** Use a scoped `#[expect(dead_code)]`
  and remove it in the PR that wires the code. A blanket allow once hid about
  200 dead lines.
- **One source of truth per value.** Ask MLS or de-mls whether something is
  true before keeping a list that mirrors it.
- **Logic lives in the layer that owns it.** Removing a member belongs in the
  group, which returns a proper error. It is not repeated in client and app.
- **Respect module boundaries.**
  - GroupV3 doesn't reuse GroupV2 internals.
  - Shared helpers move to a shared module (`mls_utils`) rather than being
    imported across siblings.
  - Conversation state stays in the conversation type, not in
    `ServiceContext`.
- **Prefer small traits** to growing an existing one.
- **Internal timers and tuning are not client knobs.** Expose them behind
  `test-support` if tests need them.
- **Keep nesting shallow.** Use early returns. Five levels deep is a refactor.
- **Argument order:** `self`, then the service context, then the rest.

## Naming

- **`handle_*` takes inbound, `send_*` is an outbound action, `publish_*`
  formats and hands to the delivery service.**
- **A function that creates is not `get_*`.**
- **Predicates read as predicates**, for example `is_active` rather than
  `reject_beacons`.
- **No invented verbs or vague nouns.** `hear()` became `record_epoch_data`.
- **Names follow the spec and ADR terms**: `Content`, `Signer`, `ParticipantId`,
  `SignersChanged`.
- **If a doc comment is needed to explain a name, rename instead.**

## Scope

- **Make the smallest diff that solves the problem.** No drive-by refactors,
  and don't move code between functions without a change in behaviour.
- **Don't add for later:** no speculative traits, feature flags, placeholders,
  or abstract clocks before they are needed.
- **If something isn't needed, delete it and its dependency.**
- **No back-compat paths for an undeployed protocol.** Delete unused wire
  fields and retire their tags.
- **A separate crate means a separate crate**, not a module.

## Lints

`[workspace.lints]` in the root `Cargo.toml` applies to every member. Today it
denies `unsafe_code`, `dbg_macro`, `todo` and `unimplemented`. `clippy.toml`
lets tests unwrap and expect.

Next, in one PR per crate, starting with `core/conversations`:

1. `unwrap_used` and `expect_used`
2. `cast_possible_truncation` and `as_conversions`
3. `allow_attributes_without_reason`

Each PR fixes that crate's sites, then adds `#![deny(clippy::…)]` to the
crate root. Cargo doesn't allow mixing `workspace = true` with per-crate
entries in `[lints]`. Once every crate has the lint, it moves to the
workspace table and the attributes go.

## Dependencies

- **Dependencies in every `Cargo.toml` are grouped (workspace / external) and
  sorted.** Workspace members use `{ workspace = true }`.
- **Fix an advisory by upgrading.** An ignore in `deny.toml` needs the reason
  and the condition for removing it.
