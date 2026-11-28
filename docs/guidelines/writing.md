# Writing: comments, doc comments, docs

Reviewers here push back on generated-sounding text by name, so write like a
person explaining the code to a colleague.

## In source

- **One-line comments by default.** Add a "why" only where a reader would get
  it wrong without it.
- **Doc comments state the contract and its caveats**: what is authenticated,
  what is only a hint, and what is not implemented yet. Don't narrate the
  implementation.
- **Describe the intended contract, not a temporary state that contradicts
  it.** If the current state is a temporary detour, say so in one line.
- **No section banners** (`// ── Identity ────`).
- **No design history in source.** Alternatives considered and earlier
  attempts go in `docs/`.
- **If a comment explains a name, rename instead.**
- **Delete comments left over from earlier drafts.**
- **A doc that contradicts its code blocks the PR.**
- **A TODO for a design question is one line** that points to an issue.

## Short and clear

A good comment is short because it says one thing a reader can't get from
the code.

```rust
// Bad: restates the code and narrates history.
// Here we check the length of the key. We added this after the review
// because previously the code would call into the KEM directly.
check_hpke_public_key(&key)?;

// Good: the one fact a reader would miss.
// A short X-Wing key panics libcrux-kem (RUSTSEC-2026-0331).
check_hpke_public_key(&key)?;
```

```rust
// Bad: a doc comment covering for a name.
/// Takes a frame and records the epoch data in the history.
fn hear(&mut self, frame: &Frame)

// Good: the name does the work, and the doc adds the caveat.
/// `frame` is unverified: the epoch is a claim until a signer vouches for it.
fn record_epoch_data(&mut self, frame: &Frame)
```

## Style

- Plain, specific words. Avoid generic filler and stacked prepositions
  ("in order to", "with respect to the handling of").
- Don't cross-reference the same context several times in one paragraph.
- If a paragraph reads like a generated summary, cut it in half.
- Numbers come from a measurement. Say how they were measured.

## Docs

- **Architecture decisions go in `docs/adr/`** using the existing format.
  Other `docs/` files are design notes.
- **A design doc reasons about our options and picks one.** Other projects
  (XMTP, MIMI, …) are references, not the argument.
- **Land the design doc first, as a docs-only PR**, before a large feature.
