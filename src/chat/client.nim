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
  types,
  utils


logScope:
  topics = "chat client"
 
#################################################
# Definitions
#################################################

# Type used to return message data via callback
type ReceivedMessage* = ref object of RootObj
  sender*: PublicKey
  timestamp*: int64
  content*: seq[byte]


type ConvoType = enum 
  PrivateV1

type Conversation* = object
  ctx: LibChat
  convoId: string
  ds: WakuClient
  convo_type: ConvoType


proc id*(self: Conversation): string =
  return self.convoId


type
  MessageCallback* = proc(conversation: Conversation, msg: ReceivedMessage): Future[void] {.async.}
  NewConvoCallback* = proc(conversation: Conversation): Future[void] {.async.}
  DeliveryAckCallback* = proc(conversation: Conversation,
      msgId: MessageId): Future[void] {.async.}

type ChatClient* = ref object
  libchatCtx: LibChat 
  ds*: WakuClient
  inboundQueue: QueueRef
  isRunning: bool

  newMessageCallbacks: seq[MessageCallback]
  newConvoCallbacks: seq[NewConvoCallback]
  deliveryAckCallbacks: seq[DeliveryAckCallback]

#################################################
# Constructors
#################################################

proc newClient*(ds: WakuClient, ephemeral: bool = true, installation_name: string = "default"): Result[ChatClient, ErrorType] =
  ## Creates new instance of a `ChatClient` with a given `WakuConfig`.
  ## A new installation is created if no saved installation with `installation_name` is found

  if not ephemeral:
    return err("persistence is not currently supported")

  try:

    var q = QueueRef(queue: newAsyncQueue[ChatPayload](10))
    var c = ChatClient(
                  libchatCtx: newConversationsContext(installation_name),
                  ds: ds,
                  inboundQueue: q,
                  isRunning: false,
                  newMessageCallbacks: @[],
                  newConvoCallbacks: @[])


    notice "Client started"

    result = ok(c)
  except Exception as e:
    error "newCLient", err = e.msg
    result = err(e.msg)

#################################################
# Parameter Access
#################################################

proc getId*(client: ChatClient): string =
  result = client.libchatCtx.getInstallationName()


proc listConversations*(client: ChatClient): seq[Conversation] =
  # TODO: (P1) Implement list conversations
  result = @[]

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
    debug "calling OnConvo CB",  client=client.getId(), len = client.newConvoCallbacks.len()
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

proc createIntroBundle*(self: ChatClient): seq[byte] =
  ## Generates an IntroBundle for the client, which includes
  ## the required information to send a message.
  result = self.libchatCtx.createIntroductionBundle().valueOr:
      error "could not create bundle",error=error, client = self.getId() 
      return
 
  notice "IntroBundleCreated", client = self.getId(),
      bundle = result

proc sendPayloads(ds: WakuClient, payloads: seq[PayloadResult]) =
  for payload in payloads:
   # TODO: (P2) surface errors
    discard ds.sendBytes(payload.address, payload.data)


#################################################
# Conversation Initiation
#################################################


proc getConversation*(client: ChatClient, convoId: string): Conversation =
  result = Conversation(ctx:client.libchatCtx, convoId:convoId, ds: client.ds, convo_type: PrivateV1)

proc newPrivateConversation*(client: ChatClient,
    introBundle: seq[byte], content: Content): Future[Option[ChatError]] {.async.} =

  let res = client.libchatCtx.createNewPrivateConvo(introBundle, content)
  let (convoId, payloads) = res.valueOr:
    error "could not create bundle",error=error, client = client.getId()  
    return some(ChatError(code: errLibChat, context:fmt"got: {error}" ))
  

  client.ds.sendPayloads(payloads);


  client.notifyNewConversation(Conversation(ctx: client.libchatCtx,
    convoId : convoId, ds: client.ds, convo_type: ConvoType.PrivateV1
  ))

  notice "CREATED",  client=client.getId(), convoId=convoId
  return none(ChatError)


#################################################
# Payload Handling
# Receives a incoming payload, decodes it, and processes it.
#################################################

proc parseMessage(client: ChatClient, msg: ChatPayload) {.raises: [ValueError].} =

  try:
    let opt_content = client.libchatCtx.handlePayload(msg.bytes).valueOr:
      error "handlePayload" , error=error, client=client.getId() 
      return 

    if opt_content.isSome():
      let content = opt_content.get()
      let convo = client.getConversation(content.conversationId)

      if content.isNewConvo:
        client.notifyNewConversation(convo)

      # TODO: (P1) Add sender information from LibChat.
      let msg = ReceivedMessage(timestamp:getCurrentTimestamp(),content: content.data  )
      client.notifyNewMessage(convo, msg)
    else:
      debug "Parsed message generated no content", client=client.getId()

  except Exception as e:
    error "HandleFrame Failed", error = e.msg

proc sendMessage*(convo: Conversation, content: Content) : Future[MessageId] {.async, gcsafe.} =
  let payloads = convo.ctx.sendContent(convo.convoId, content).valueOr:
    error "SendMessage", e=error
    return "error"

  convo.ds.sendPayloads(payloads);


#################################################
# Async Tasks
#################################################

proc messageQueueConsumer(client: ChatClient) {.async.} =
  ## Main message processing loop
  info "Message listener started"

  while client.isRunning:
    let message = await client.inboundQueue.queue.get()
    debug "Got WakuMessage", client = client.getId() , topic= message.content_topic, len=message.bytes.len() 

    client.parseMessage(message)


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
  client.libchatCtx.destroy()
  client.isRunning = false
  notice "Client stopped", client = client.getId()
