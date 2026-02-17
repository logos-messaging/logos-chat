# Logos Chat

This is the technical proof of a modular e2ee chat protocol using Waku. You can find discussion and details [here](https://github.com/waku-org/specs/pull/73)

See [EchoBot](./examples/bot_echo.nim) for a minimal client side usage example.
See [Client](./src/chat/client.nim) for the main entry point to the SDK

## Quick Start

```
# Build Dependencies and link libraries
make update

# Build executables
make all

# Run tests
make tests

# Run an example of two clients communicating
./build/pingpong
```

## API

### Client

#### `new_client(WakuClient, Identity) -> Client`
Constructs a new Client instance 

#### `create_intro_bundle(Client) -> IntroBundle`
Creates a package of keys required by initiators to initialize a conversation.

#### `new_private_conversation(Client, IntroBundle, Seq<u8>)`
Used by a client to initialize a conversation. Requires the `IntroBundle` of the other participant, as well as an initial message. 

#### `list_conversations(Client) ->  Seq<Conversation>`
Returns a list of conversations known to this client.

#### `get_conversation(Client, String) -> Conversation`
Returns a conversation given the conversation ID.

#### `on_new_message (Client, Callback(Conversation, ReceivedMessage)) -> Void`<br> `on_new_conversation(Client, Callback(Conversation)) -> Void` <br> `on_new_delivery_ack(Client, Callback(Conversation, String)) -> Void`
Registers callback to receive updates for events.

#### `start(Client) -> Void` <br> `stop(Client) -> Void`
Start MUST be called in order to receive messages. Stop should be called to finalize remaining tasks.

### Conversation

#### `id(Conversation) -> String`
Returns the Conversation Identifier (ConvoId).

#### `send_message(Conversation, Seq<u8>) -> String`
Sends content bytes to the conversation and returns a message_id.


### WakuClient

#### `default_config() -> DefaultConfig`
Creates a safe waku configuration to initialize a WakuClient.

#### `init_waku_client(WakuConfig) -> WakuClient`
Create a wakuClient from a configuration. 

### Identity

#### `create_identity*(name: string)-> Identity`
Creates a new random identity


## Details


### Features

Current state of the [ChatSDK FURPS](https://github.com/waku-org/pm/blob/master/FURPS/application/chat_sdk.md)

| ID  | Feature                    | Status | Notes                                                   |
|-----|----------------------------|--------|---------------------------------------------------------|
| F1  | Permissionless Accounts    | ✅     |                                                         |
| F2  | 1:1 Messaging              | ✅     |                                                         |
| F3  | FS + PCS                   | 🟡     | PCS in place — needs noise implementation               |
| F4  | Delivery Receipts          | ✅     |                                                         |
| F5  | Basic Content Types        | ✅     | Types need formal definition; plugin system prototyped  |
| F6  | Default Message Store      | 🚫     | Wont do - api changed, apps handle message storage       |
| F7  | Default Secrets Store      | ➡️     | Deferred - Not required for dev api preview             |
| U1  | Non-interactive Initiation | ✅     |                                                         |
| U2  | Invite Links               | ✅     |                                                         |
| U3  | 25 Lines of Code           | ✅     |                                                         |
| R1  | Dropped Message Detection  | 🚫     | Wont do - uses reliable channels                        |
| P1  | 10K Active Clients         | ⚪     |                                                         |
| S1  | RLN Compatible             | 🟡     | RLN supported, but not implemented yet                  |
| S2  | Future Proof               | 🟡     |                                                         |
| S3  | Go Bindings                | 🚫     | Wont do - Refocus on Logos-core                         |
| S4  | Rust Bindings              | 🚫     | Wont do - Refocus on Logos-core                         |
| +1  | Sender Privacy             | ✅     | Needs verification                                      |
| +2  | Membership Privacy         | 🟡     | Needs verification                                      |
| +3  | User Activity Privacy      | 🟡     | Needs verification                                      |
| +4  | Nimble Compatible          | ⛔     | Blocked — upstream dependency conflicts     





### Message Flow

To establish a secure conversation, Saro and Raya need to:
1. Find each others identityKeys
2. Agree on a secret key, and location to communicate

For this technical proof, recipient identity keys are exchanged out of bound via an invite link. More complex identity systems will be explored in the future. ..


 ```mermaid
sequenceDiagram
    participant S as Saro
    participant R as Raya

    Note over R,S: Discovery
    R -->> S: Send Invite Link via established channel

    Note over R,S: Initialization
    S ->> R: PrivateV1 Invite

    Note over R,S: Operation
    loop
        par
            R->> S: Send Message
        and
            S->> R: Send Message
        end
    end
 ```


## Limitations

1. `.proto` files are included in this repo due to complications in importing nested packages using `?subdir=`. Once resolved there will be a single definition of protocol types.
1. Messages are sent using waku, however wakunode discovery has not been implemented. As a stopgap a manual discovery process based on staticpeers is used.


## License

[MIT](https://choosealicense.com/licenses/mit/)