# MLS and the specs

The code implements specs. Read the relevant spec before changing a protocol
path, and say in the PR which section a change follows or departs from.

## Logos LIPs come first

Logos protocols are specified as LIPs in
[logos-co/logos-lips](https://github.com/logos-co/logos-lips), published at
<https://lip.logos.co>. They are the source of truth for chat behaviour,
terminology and wire formats.

| LIP | What it covers |
|---|---|
| [164/CHAT-DEFINITIONS](https://github.com/logos-co/logos-lips/blob/master/docs/messaging/informational/raw/chatdefs.md) | Shared terms: what a conversation, content, participant are |
| [239/CHAT-FRAMEWORK](https://github.com/logos-co/logos-lips/blob/master/docs/messaging/application/raw/chat-framework.md) | The modular framework chat protocols are built in |
| [236/CONVERSATIONTYPES](https://github.com/logos-co/logos-lips/blob/master/docs/messaging/application/raw/conversationtypes.md) | Conversation types and their properties |
| [240/CONTENTFRAME](https://github.com/logos-co/logos-lips/blob/master/docs/messaging/application/raw/contentframe.md) | Framing of application content |
| Content types ([logos-lips#453](https://github.com/logos-co/logos-lips/pull/453), open) | The content type registry |
| [109/SDS](https://github.com/logos-co/logos-lips/blob/master/docs/anoncomms/raw/sds.md) | Scalable Data Sync: causal history, used by GroupV3 |
| [104/DECENTRALIZED-MLS-OFFCHAIN-CONSENSUS](https://github.com/logos-co/logos-lips/blob/master/docs/anoncomms/raw/decentralized-mls-offchain-consensus.md) | de-mls, used by GroupV2 |
| [AccountLog](https://github.com/logos-co/logos-lips/blob/master/docs/identity/raw/accountlog.md), [Profile](https://lip.logos.co/identity/raw/profile.html) | Accounts and the installations they endorse |

All of these are `raw`: they change. Check the current version, not a copy you
read last month.

- **Use LIP terms in code and docs.** Write `Content`, not "message", as
  CHAT-DEFINITIONS defines it.
- **If the code and a LIP disagree, one of them is wrong.** Fix the code, or
  open a LIP PR. Don't let the difference stand unrecorded.
- **A new wire format or conversation type starts as a LIP**, or as a change
  to one, before or alongside the code.

## IETF

| Spec | Use |
|---|---|
| [RFC 9420](https://datatracker.ietf.org/doc/rfc9420/) | MLS protocol: groups, epochs, commits, Welcomes, key packages, the exporter |
| [RFC 9750](https://datatracker.ietf.org/doc/rfc9750/) | MLS architecture: the roles of the delivery and authentication services, and the security goals |
| [draft-mahy-mls-private-external](https://datatracker.ietf.org/doc/html/draft-mahy-mls-private-external-01) | Private external messages: GroupV3's sealed channel |
| [draft-kohbrok-mls-decentralized-mls](https://www.ietf.org/archive/id/draft-kohbrok-mls-decentralized-mls-00.html), [draft-xue-mls-decentralized](https://datatracker.ietf.org/doc/draft-xue-mls-decentralized/) | MLS without a central delivery service |
| [draft-connolly-cfrg-xwing-kem](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/) | The X-Wing hybrid KEM behind our ciphersuite |
| [draft-ietf-mimi-content](https://datatracker.ietf.org/doc/draft-ietf-mimi-content/) | Reference for content-type design |
| [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119) | MUST / SHOULD / MAY, as used in our docs |

Our own fork-recovery drafts (`draft-chenani-mls-epoch-fingerprint`,
`draft-chenani-mls-private-resync`) are in progress. Treat them as design
notes until they are published.

## How RFC 9420 maps onto this codebase

RFC 9420 assumes a delivery service that orders commits. Ours is a broadcast
network with no central server. Most of the hard bugs come from that gap.

- **No one orders commits.** Two members can commit at the same epoch, which
  forks the group. GroupV2 answers this with consensus (de-mls). GroupV3
  answers it with deferred commits finalized in a fixed order, plus fork
  detection and repair. Any change that creates a commit must say how it
  behaves when a rival commit arrives at the same epoch.
- **MLS carries credentials but never checks them.** RFC 9750 leaves
  authentication to the application. Here that is `AuthService`. Every signer
  that enters a group, by Add or by Welcome, must be validated by it.
- **Decide which Welcomes to accept.** Check that the Welcome is one we asked
  for or expect, from a signer we trust, for a group and epoch that make
  sense. Don't adopt whatever arrives.
- **Key packages:** validate the ciphersuite and the init key (length check,
  `check_hpke_public_key`) before use. InboxV2 publishes a last-resort key
  package that many inviters reuse. Its init key therefore does not get the
  forward secrecy a single-use key package would, so nothing should rely on
  that.
- **Authenticated data is authenticated, not encrypted.** Anything in AAD or
  framing headers is visible to the network. Keep unencrypted metadata
  minimal, and don't put large or sensitive values there.
- **Derive from the exporter with a distinct label per purpose.** Never reuse
  a label across features. Name the label and context in the code.
- **Keep forward secrecy.** Don't hold old epoch secrets, private keys or
  decrypted material longer than the feature needs. Ask whether each kept key
  is necessary. Wrap secrets in `Zeroizing`.
- **Epoch numbers in unauthenticated headers are claims.** They may route or
  order work. They must not change group state or a member's view of it.
- **Own commits are not final when sent.** Until the group accepts a commit,
  be ready to discard it, and don't report the change to the app as done.

## Crypto hygiene

- Don't write cryptographic primitives. Use OpenMLS and the `crypto` crate.
- Compare secrets in constant time.
- Keep the RUSTSEC id next to each workaround (see `deny.toml`), and remove the
  workaround when the advisory is fixed upstream.
- Pin a derivation's output with a test vector so a refactor cannot silently
  change it.
