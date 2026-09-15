# message-types — Approach A (media-typed parts)

Reference implementation of **Approach A** from
[`docs/content-types-rfc.md`](../../docs/content-types-rfc.md): message content
typed as **IANA media-typed parts**, encoded with the MIMI content format
([`mimi-content`](https://github.com/nexun-foundation/mimi-rs)) and carried inside
`ReliablePayload.content`.

It exists as a real, reviewable example of what Approach A looks like in the
codebase. Approaches **B** (namespaced type-id envelope) and **C** (curated tagged
union) from the same RFC live in their own branches/PRs.

## What it shows

- **Media-type identifiers** — `text/plain`, `text/markdown`.
- **Graceful degradation via alternatives** (Approach A's signature): a message
  MAY carry several representations in a `chooseOne` multipart.
  `encode_alternatives` ships them; `decode` renders the richest representation it
  understands, else a plainer fallback — so an unknown type never blanks the
  timeline (see the `alternatives_*` tests).
- **A thin, backing-agnostic facade** — `encode_text` / `encode_markdown` /
  `encode_alternatives` / `decode` → `MessageContent`. The `mimi-content` types
  never leak to callers, so the backing could be swapped without touching them.

## Wiring

Used by `chat-cli`: a normal message sends `text/plain`, `/md <text>` sends
`text/markdown`, and inbound bytes are decoded back to text. The content value
occupies `ReliablePayload.content`; MLS, delivery, and the causal-reliability
envelope are untouched.
