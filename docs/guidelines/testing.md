# Testing

- **Prove a new test can fail.** Put the bug back, watch the test fail, then
  restore the fix. Say in the PR that you did. The steps are in
  [prove-test.md](../procedures/prove-test.md).
- **Assert the real outcome, not a proxy.** "The requester got the Welcome and
  can exchange messages" beats "one repair commit was sent".
- **Assert counts where a duplicate is a bug.** A happy-path test once passed
  while a member was repaired twice.
- **A test named "every X" covers every variant.** One `every_outcome_*` test
  once covered 7 of 8.
- **Every documented guarantee has a test, or the claim goes.**
- **Pin wire and signed encodings** before a refactor that could change them.
- **A test's name says what it asserts.** Delete tests that only exercise std.
- **Don't add unit tests for trivial code.** Fold the check into an existing
  integration test.
- **Inject bad input through `test-support` hooks** such as `group_v3_wire` and
  `unsigned_readd`, not by exposing internals to integration tests.
- **Test the feature-off path too.**
- **Cover the negative cases** as well as the happy path: removing someone from
  a DM, overlapping retries, a far-behind member, a forged frame.

## The harness

`integration_tests_core::TestHarness<N>` runs N clients over an in-process
broadcaster with a virtual clock. Drive the clients, then settle:

```rust
harness.saro().send_content(&convo_id, b"Marco").unwrap();
harness.process_until_label("raya receives", |h| h.raya().check(&convo_id, b"Marco"));
```

The harness panics on a rejected inbound payload. Tests that feed it bad input
call `tolerate_inbound_errors()` and then assert on `inbound_errors()`.

## Before calling it done

```sh
just check
cargo clippy -p libchat --all-targets --features test-support -- -D warnings
```

Run the second command whenever you touch `test-support`.
