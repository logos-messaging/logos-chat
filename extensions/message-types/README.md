# message-types — Approach B (namespaced type-id envelope)

Reference implementation of **Approach B** from
[`docs/content-types-rfc.md`](../../docs/content-types-rfc.md): message content
wrapped in a small **native CBOR envelope** that names the type and carries a
fallback string, decoded through a codec **registry**. It lives inside
`ReliablePayload.content`.

It exists as a real, reviewable example of what Approach B looks like in the
codebase. Approaches **A** (media-typed parts / MIMI) and **C** (curated tagged
union) live in their own branches/PRs.

## What it shows

- **A thin envelope** — `Envelope { content_type, fallback, payload }` (CBOR).
  The `content_type` is an IANA media type (`text/plain`, `text/markdown`) or a
  namespaced `authority/type` (`logos/reply`, `logos/reaction`).
- **The `Content` trait + registry** — a type declares its `CONTENT_TYPE` and a
  `fallback()`; `decode` dispatches on the wire `content_type`. Adding a type is
  one impl + one arm.
- **Graceful degradation via the fallback string** — an unknown type decodes to
  `MessageContent::Unknown { content_type, fallback }`, so old clients still show
  a line (contrast Approach A, which degrades via an alternative *part*).
- **Relationships inside the payload** — a reply is its own content type
  (`Reply { in_reply_to, body }`), not a top-level field. Because the envelope is
  ours, the referenced id is a plain string (no fixed-size constraint).

Types: `Text`, `Markdown`, `Reply`, `Reaction`.

## Wiring

Used by `chat-cli`: a normal message sends `text/plain`, `/md <text>` sends
`text/markdown`, `/reply <text>` sends `logos/reply` referencing the latest
message (rendered with a `↩ preview`). Inbound unknown types show their fallback.
