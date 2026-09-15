# message-types — Approach C (curated tagged union)

Reference implementation of **Approach C** from
[`docs/content-types-rfc.md`](../../docs/content-types-rfc.md): message content
modeled as **one curated enum** that is serialized directly, no per-type trait
and no codec registry. It lives inside `ReliablePayload.content`.

It exists as a real, reviewable example of what Approach C looks like in the
codebase. Approaches **A** (media-typed parts / MIMI) and **B** (namespaced
type-id envelope) live in their own branches/PRs.

## What it shows

- **One enum is the content** — `MessageContent` is what you build to send and
  what you get back on receive. No `Content` trait, no `CONTENT_TYPE` strings, no
  registry dispatch (contrast Approach B). Adding a type is a new variant, and
  exhaustiveness checking makes every `match` a compile error until updated — a
  deliberate, centrally-reviewed change. That is the "curated" in curated union.
- **Serialized directly** — known variants encode as an internally-tagged enum
  with fields inline (`{ kind: "text", body: "hi" }`), not as a type string over
  an opaque payload blob.
- **Graceful degradation, with an honest cost** — an unknown `kind` decodes to
  `MessageContent::Unknown { kind, fallback }`. Because a closed union has no code
  for a future variant, the **sender** must ship a `fallback` string for
  degradation to say anything — so the wire carries `fallback` alongside the
  typed fields.
- **Relationships in the variant** — a reply is `Reply { in_reply_to, body }`, a
  reaction is `Reaction { in_reply_to, emoji }`. Because the wire is ours, the
  referenced id is a plain string (no fixed-size constraint).

Variants: `Text`, `Markdown`, `Reply`, `Reaction`, `Unknown`.

## Wiring

Used by `chat-cli`: a normal message sends `Text`, `/md <text>` sends `Markdown`,
`/reply <text>` sends `Reply` referencing the latest message (rendered with a
`↩ preview`). Inbound unknown kinds show their fallback.
