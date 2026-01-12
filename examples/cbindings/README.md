# C Bindings Example - Chat TUI

A simple terminal user interface that demonstrates how to use libchat from C.

## Build

1. First, build libchat from the root folder:

   ```bash
   make libchat
   ```

2. Then build the C example:

   ```bash
   cd examples/cbindings
   make
   ```

## Run

Terminal 1:

```bash
make run_alice 
# Runs as Alice on port 60001
```

Terminal 2:

```bash
make run_bob
# Runs as Bob on port 60002
```

## Workflow

1. Start the application - it automatically uses your inbox conversation
2. Type `/bundle` to get your IntroBundle JSON (will be copied to clipboard)
3. In the other terminal type `/join <your_bundle_json>` to start a conversation
4. You can send messages from one termnial to the other

## Command Line Options

```text
--name=<name>      Identity name (default: user)
--port=<port>      Waku port (default: random 50000-50200)
--cluster=<id>     Waku cluster ID (default: 42)
--shard=<id>       Waku shard ID (default: 2)
--peer=<addr>      Static peer multiaddr to connect to
--help             Show help
```

## Waku Configuration

- **Cluster ID**: 42
- **Shard ID**: 2
- **PubSub Topic**: `/waku/2/rs/42/2`
- **Port**: Random between 50000-50200 (or specify with --port)
