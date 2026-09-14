# chat-cli

A terminal chat application built on top of logos-chat. End-to-end encrypted messaging in your terminal.

## Building

`chat-cli` links the native [logos-delivery](https://github.com/logos-messaging/logos-delivery)
library. The dev shell builds it and sets `LOGOS_DELIVERY_LIB_DIR` for you:

```bash
nix develop
cargo build --release -p chat-cli
```

Or build the library yourself and point `LOGOS_DELIVERY_LIB_DIR` at it:

```bash
nix build .#logos-delivery
LOGOS_DELIVERY_LIB_DIR=./result/lib cargo build --release -p chat-cli
```

The binary lands at `target/release/chat-cli`.

## Transports

Both transports are compiled into the binary and selected at runtime via `--transport`:

| Value (`--transport`) | Description |
|-----------------------|-------------|
| `logos-delivery` (default) | Embedded Waku node on the logos.test network |
| `file` | Shared directory; no network needed — great for local testing |

## Quick start

Run two instances in separate terminals:

```bash
# Terminal 1
cargo run -p chat-cli -- --name saro --port 60001

# Terminal 2
cargo run -p chat-cli -- --name raya --port 60002
```

For local-only testing without any network dependency, use the file transport:

```bash
# Terminal 1
cargo run -p chat-cli -- --name saro --transport file

# Terminal 2
cargo run -p chat-cli -- --name raya --transport file
```

### Starting a conversation

Every conversation is an MLS group. A **DM** is a 1:1; a **group** is a named
conversation. First share your address: type `/account` — it prints your address
and copies it to the clipboard.

**Direct message (1:1):**

1. Raya runs `/account` and shares her address.
2. Saro types `/dm <paste raya's address>`.
3. The chat opens on both sides; either can message.

**Group:**

1. Saro types `/new weekend` to create a group named "weekend". A name is
   required; addresses can follow (e.g. Pax's) to invite people at creation.
2. Saro types `/add <raya's address>` to invite Raya; the invite stays pending
   until the group commits it.
3. `/members` lists the roster — Raya shows `(pending)` until the commit lands,
   then appears without it. Once committed, both can chat.

### Optional: KeyPackage registry

When `--registry-url <url>` is set, the client publishes its MLS KeyPackage
to the [keypackage-registry](https://github.com/logos-messaging/chat-store)
service on startup so other clients can later fetch it by `account_id`. Without
the flag, an in-memory registry is used and is only visible inside the local
process.

```bash
# Terminal 1 — registry server (from a chat-store checkout)
cargo run -- --bind 127.0.0.1:18080

# Terminal 2 / 3 — chat clients pointing at it
cargo run -p chat-cli -- --name saro --transport file \
  --registry-url http://127.0.0.1:18080
cargo run -p chat-cli -- --name raya --transport file \
  --registry-url http://127.0.0.1:18080
```

The registry is a throwaway testnet helper; v0.3 replaces it with a
λLEZ-based discovery service.

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `--transport <kind>` | `logos-delivery` | Transport to use (`logos-delivery` or `file`) |
| `--data <dir>` | `tmp/chat-cli-data` | Data directory (UI state and default SQLite path) |
| `--db <path>` | `<data>/<name>.db` | SQLite file for persistent identity |
| `--preset <name>` | `logos.test` | logos-delivery network preset |
| `--port <n>` | `60000` | TCP port for the embedded logos-delivery node |
| `--registry-url <url>` | *(unset)* | Use the HTTP-backed [keypackage-registry](https://github.com/logos-messaging/chat-store) at this URL instead of the in-memory registry |
| `--log-file <path>` | *(stderr, off)* | Write logs to a file instead of stderr |

## Commands

| Command | Description |
|---------|-------------|
| `/help` | Show available commands |
| `/account` | Show your account address (copies to clipboard) |
| `/dm <address>` | Start a direct (1:1) chat |
| `/new <name> [address...]` | Create a named group chat (optionally inviting members) |
| `/add <address>` | Add someone to the active group |
| `/members` | List members of the active conversation |
| `/chats` | List all established chats |
| `/switch <user>` | Switch active chat |
| `/delete <user>` | Delete a chat session |
| `/status` | Show identity and connection info |
| `/clear` | Clear current chat's message history |
| `/quit` · `Esc` · `Ctrl+C` | Exit |

## Storage

All data lives under `tmp/chat-cli-data/` by default (override with `--data`):

| Path | Contents |
|------|----------|
| `<name>.db` | SQLite — identity keys, ratchet state, chat metadata (encrypted) |
| `<name>_state.json` | UI state — message history, active chat |
| `transport/<name>/` | Inbox directory watched for incoming messages (file transport only) |

The SQLite database can be inspected with *DB Browser for SQLite*: password `chat-cli`, cipher `SQLCipher 4 defaults`.

## Architecture

```
bin/chat-cli/
├── src/
│   ├── main.rs           entry point, CLI arg parsing, runtime transport dispatch
│   ├── app.rs            application state and command handling
│   ├── ui.rs             ratatui terminal UI
│   ├── utils.rs          shared helpers
│   ├── transport.rs      module declarations
│   └── transport/
│       ├── file.rs       file-based transport
│       └── logos_delivery.rs   logos-delivery (Waku) transport + FFI
└── build.rs              links liblogosdelivery (LOGOS_DELIVERY_LIB_DIR required)
```
