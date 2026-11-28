# Protocol safety

Every inbound byte is adversarial. Every rule here came out of a real review
finding. For each new receive path, the PR or its design doc should say what an
attacker can do with it.

## Untrusted input

- **Check the size before decoding or allocating.** A repeated protobuf field
  once let a 64 KB key past the per-field checks, so frames are bounded by
  `MAX_FRAME_LEN` / `MAX_BEACON_LEN` before they are decoded.
- **Gate external keys before any crypto call that can panic.** A short X-Wing
  key panics libcrux-kem (RUSTSEC-2026-0331). Every key from outside goes
  through `check_hpke_public_key` (`mls_utils.rs`) first. Keep the advisory id
  next to each guard, so grep finds them all.
- **Convert wire integers with `try_from`.** An `as u16` once aliased an
  out-of-range ciphersuite onto a real one.
- **Bound every store and every piece of work an anonymous sender can
  trigger.** That covers trial verification, HPKE opens and caches. Eviction
  must only push out the sender's own entries: forged far-future epochs once
  pinned a shared bucket.
- **Inbound traffic never drives retries or timers.** Each timer has one owner.

## Authentication decides

- **Only authenticated data reaches a conclusion.** Unverified data is a hint,
  is named as one (`sender_hint`, `unverified_*`), and never overrides
  verified state. A junk "commit at epoch N" once flipped every member to
  `Forked`.
- **Never break a tie on a value an attacker chose.** A fallback to
  `claimed < ours` once let an old epoch with a low fingerprint make a healthy
  member yield.
- **A signer that equivocates counts for neither side.**
- **Signatures cover canonical bytes**, not a re-encoding.
- **Use a type to enforce admission.** The beacon store's `receive_frame` takes
  `Admitted`, so no receive path can skip the check.

## Members must converge

- **A decision members must agree on comes from shared group state**, not from
  what one member happened to receive. Choosing an answerer from locally
  verified signers once produced two answerers, which forked the group again.
- **Messages sealed to an old state must stop being answerable.** Replaying
  public sealed bytes once removed a member who had already been repaired.
- **Expect duplicates.** Retries, replays and two members acting at once all
  happen, so test for the action happening exactly once.

## Failure and side effects

- **A failure leaves the old state intact.** Don't drop the held group until
  the replacement from the Welcome is installed.
- **Record "done" only after success.**
- **Don't return `Err` after a side effect already happened.** Report what was
  done instead, for example the count sent.
- **A secondary feature never fails the primary operation.** A beacon failure
  once skipped the Welcomes and lost the join. Log it, mark it pending and
  retry.
- **Every failure needs a way forward.** A failure that misleads the user is
  worse than one that leaves them stuck.
- **Synchronous failures stay on `Result`** and are never events (ADR 0001).

## Specs and claims

- **Follow the RFC and drafts.** Where we diverge on purpose, say so in the doc
  and pin the divergence with a test. Ciphersuite values in a private range
  are ours, not a draft's.
- **Never claim a security property the code doesn't have.** A hash of a
  public key is not "not a decryption oracle", and a cache is not a rate
  limit.
- **Ask whether key material needs to be kept at all** before storing it.
- **Don't add an optimization with security impact** until there is a
  measurement that calls for it.
