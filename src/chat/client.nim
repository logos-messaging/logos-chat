## Main Entry point to the ChatSDK.
## Clients are the primary manager of sending and receiving 
## messages, and managing conversations.


import # Foreign
  chronicles,
  chronos,
  libchat,
  std/options,
  strformat,
  types

import #local
  delivery/waku_client,
  errors,
  identity,
  types,
  utils


logScope:
  topics = "chat client"
 
#################################################
# Definitions
#################################################

type
  MessageCallback* = proc(conversation: Conversation, msg: ReceivedMessage): Future[void] {.async.}
  NewConvoCallback* = proc(conversation: Conversation): Future[void] {.async.}
  DeliveryAckCallback* = proc(conversation: Conversation,
      msgId: MessageId): Future[void] {.async.}


type KeyEntry* = object
  keyType: string
  privateKey: PrivateKey
  timestamp: int64

type ChatClient* = ref object
  libchatCtx: LibChat 
  ident: Identity
  ds*: WakuClient
  keyStore: Table[string, KeyEntry]          # Keyed by HexEncoded Public Key
  conversations: Table[string, Conversation] # Keyed by conversation ID
  inboundQueue: QueueRef
  isRunning: bool
  inbox: Inbox

  newMessageCallbacks: seq[MessageCallback]
  newConvoCallbacks: seq[NewConvoCallback]
  deliveryAckCallbacks: seq[DeliveryAckCallback]

#################################################
# Constructors
#################################################

proc newClient*(ds: WakuClient, ident: Identity): ChatClient {.raises: [IOError,
    ValueError, SerializationError].} =
  ## Creates new instance of a `ChatClient` with a given `WakuConfig`
  try:
    let rm = newReliabilityManager().valueOr:
      raise newException(ValueError, fmt"SDS InitializationError")

    let defaultInbox = initInbox(ident)

    var q = QueueRef(queue: newAsyncQueue[ChatPayload](10))
    var c = ChatClient(ident: ident,
    var c = ChatClient(
                  libchatCtx: newConversationsContext(),
                  ident: ident,
                  ds: ds,
                  keyStore: initTable[string, KeyEntry](),
                  conversations: initTable[string, Conversation](),
                  inboundQueue: q,
                  isRunning: false,
                  inbox: defaultInbox,
                  newMessageCallbacks: @[],
                  newConvoCallbacks: @[])

    c.conversations[defaultInbox.id()] = defaultInbox

    notice "Client started", client = c.ident.getName(),
        defaultInbox = defaultInbox, inTopic= topic_inbox(c.ident.get_addr())

    # Set LibChatBufferSize
    c.libchatCtx.setBufferSize(256);
    result = c
  except Exception as e:
    error "newCLient", err = e.msg

#################################################
# Parameter Access
#################################################

proc getId*(client: ChatClient): string =
  result = client.ident.getName()

proc identity*(client: ChatClient): Identity =
  result = client.ident

proc defaultInboxConversationId*(self: ChatClient): string =
  ## Returns the default inbox address for the client.
  result = conversationIdFor(self.ident.getPubkey())

proc getConversationFromHint(self: ChatClient,
    conversationHint: string): Result[Option[Conversation], string] =

  # TODO: Implementing Hinting
  if not self.conversations.hasKey(conversationHint):
    ok(none(Conversation))
  else:
    ok(some(self.conversations[conversationHint]))


proc listConversations*(client: ChatClient): seq[Conversation] =
  result = toSeq(client.conversations.values())

#################################################
# Callback Handling
#################################################

proc onNewMessage*(client: ChatClient, callback: MessageCallback) =
  client.newMessageCallbacks.add(callback)

proc notifyNewMessage*(client: ChatClient,  convo: Conversation, msg: ReceivedMessage) =
  for cb in client.newMessageCallbacks:
    discard cb(convo, msg)

proc onNewConversation*(client: ChatClient, callback: NewConvoCallback) =
  client.newConvoCallbacks.add(callback)

proc notifyNewConversation(client: ChatClient, convo: Conversation) =
  for cb in client.newConvoCallbacks:
    discard cb(convo)

proc onDeliveryAck*(client: ChatClient, callback: DeliveryAckCallback) =
  client.deliveryAckCallbacks.add(callback)

proc notifyDeliveryAck(client: ChatClient, convo: Conversation,
    messageId: MessageId) =
  for cb in client.deliveryAckCallbacks:
    discard cb(convo, messageId)

#################################################
# Functional
#################################################

proc createIntroBundle*(self: var ChatClient): IntroBundle =
  ## Generates an IntroBundle for the client, which includes
  ## the required information to send a message.

  # Create Ephemeral keypair, save it in the key store
  let ephemeralKey = generateKey()

  self.keyStore[ephemeralKey.getPublicKey().bytes().bytesToHex()] = KeyEntry(
    keyType: "ephemeral",
    privateKey: ephemeralKey,
    timestamp: getCurrentTimestamp()
  )

  result = IntroBundle(
    ident: @(self.ident.getPubkey().bytes()),
    ephemeral: @(ephemeralKey.getPublicKey().bytes()),
  )

  notice "IntroBundleCreated", client = self.getId(),
      pubBytes = result.ident


#################################################
# Conversation Initiation
#################################################

proc addConversation*(client: ChatClient, convo: Conversation) =
  notice "Creating conversation", client = client.getId(), convoId = convo.id()
  client.conversations[convo.id()] = convo
  client.notifyNewConversation(convo)

proc getConversation*(client: ChatClient, convoId: string): Conversation =
  notice "Get conversation", client = client.getId(), convoId = convoId
  result = client.conversations[convoId]

proc newPrivateConversation*(client: ChatClient,
    introBundle: IntroBundle, content: Content): Future[Option[ChatError]] {.async.} =
  ## Creates a private conversation with the given `IntroBundle`.
  ## `IntroBundles` are provided out-of-band.
  let remote_pubkey = loadPublicKeyFromBytes(introBundle.ident).get()
  let remote_ephemeralkey = loadPublicKeyFromBytes(introBundle.ephemeral).get()

  let convo = await client.inbox.inviteToPrivateConversation(client.ds,remote_pubkey, remote_ephemeralkey, content )
  client.addConversation(convo)     # TODO: Fix re-entrantancy bug. Convo needs to be saved before payload is sent.

  return none(ChatError)


#################################################
# Payload Handling
# Receives a incoming payload, decodes it, and processes it.
#################################################

proc parseMessage(client: ChatClient, msg: ChatPayload) {.raises: [ValueError,
    SerializationError].} =
  let envelopeRes = decode(msg.bytes, WapEnvelopeV1)
  if envelopeRes.isErr:
    debug "Failed to decode WapEnvelopeV1", client = client.getId(), err = envelopeRes.error
    return
  let envelope = envelopeRes.get()

  let convo = block:
    let opt = client.getConversationFromHint(envelope.conversationHint).valueOr:
      raise newException(ValueError, "Failed to get conversation: " & error)

    if opt.isSome():
      opt.get()
    else:
      let k = toSeq(client.conversations.keys()).join(", ")
      warn "No conversation found", client = client.getId(),
        hint = envelope.conversationHint, knownIds = k
      return

  try:
    convo.handleFrame(client, envelope.payload)
  except Exception as e:
    error "HandleFrame Failed", error = e.msg

#################################################
# Async Tasks
#################################################

proc messageQueueConsumer(client: ChatClient) {.async.} =
  ## Main message processing loop
  info "Message listener started"

  while client.isRunning:
    let message = await client.inboundQueue.queue.get()

    let topicRes = inbox.parseTopic(message.contentTopic).or(private_v1.parseTopic(message.contentTopic))
    if topicRes.isErr:
      debug "Invalid content topic", client = client.getId(), err = topicRes.error, contentTopic = message.contentTopic
      continue

    notice "Inbound Message Received", client = client.getId(),
        contentTopic = message.contentTopic, len = message.bytes.len()
    try:
      client.parseMessage(message)

    except CatchableError as e:
      error "Error in message listener", err = e.msg,
          pubsub = message.pubsubTopic, contentTopic = message.contentTopic


#################################################
# Control Functions
#################################################

proc start*(client: ChatClient) {.async.} =
  ## Start `ChatClient` and listens for incoming messages.
  client.ds.addDispatchQueue(client.inboundQueue)
  asyncSpawn client.ds.start()

  client.isRunning = true

  asyncSpawn client.messageQueueConsumer()

  notice "Client start complete", client = client.getId()

proc stop*(client: ChatClient) {.async.} =
  ## Stop the client.
  await client.ds.stop()
  client.isRunning = false
  notice "Client stopped", client = client.getId()
