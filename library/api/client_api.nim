## Client API - FFI bindings for Client lifecycle and operations
## Uses the {.ffi.} pragma for async request handling

import std/json
import chronicles
import chronos
import ffi

import src/chat
import src/chat/proto_types
import src/chat/delivery/waku_client
import src/chat/identity
import library/utils

logScope:
  topics = "chat ffi client"

#################################################
# Client Creation Request (for chat_new)
#################################################

type ChatCallbacks* = object
  onNewMessage*: MessageCallback
  onNewConversation*: NewConvoCallback
  onDeliveryAck*: DeliveryAckCallback

proc createChatClient(
    configJson: cstring, chatCallbacks: ChatCallbacks
): Future[Result[ChatClient, string]] {.async.} =
  try:
    let config = parseJson($configJson)
    
    # Parse identity name
    let name = config.getOrDefault("name").getStr("anonymous")
    
    # Parse Waku configuration or use defaults
    var wakuCfg = DefaultConfig()
    
    if config.hasKey("port"):
      wakuCfg.port = config["port"].getInt().uint16
    
    if config.hasKey("clusterId"):
      wakuCfg.clusterId = config["clusterId"].getInt().uint16
    
    if config.hasKey("shardId"):
      wakuCfg.shardId = @[config["shardId"].getInt().uint16]
    
    if config.hasKey("staticPeers"):
      wakuCfg.staticPeers = @[]
      for peer in config["staticPeers"]:
        wakuCfg.staticPeers.add(peer.getStr())
    
    # Create identity
    let identity = createIdentity(name)
    
    # Create Waku client
    let wakuClient = initWakuClient(wakuCfg)
    
    # Create Chat client
    let client = newClient(wakuClient, identity)
    
    # Register event handlers
    client.onNewMessage(chatCallbacks.onNewMessage)
    client.onNewConversation(chatCallbacks.onNewConversation)
    client.onDeliveryAck(chatCallbacks.onDeliveryAck)
    
    notice "Chat client created", name = name
    return ok(client)
  except CatchableError as e:
    return err("failed to create client: " & e.msg)

registerReqFFI(CreateClientRequest, ctx: ptr FFIContext[ChatClient]):
  proc(
      configJson: cstring, chatCallbacks: ChatCallbacks
  ): Future[Result[string, string]] {.async.} =
    ctx.myLib[] = (await createChatClient(configJson, chatCallbacks)).valueOr:
      error "CreateClientRequest failed", error = error
      return err($error)
    return ok("")

#################################################
# ChatClient Lifecycle Operations
#################################################

proc chat_start(
    ctx: ptr FFIContext[ChatClient],
    callback: FFICallBack,
    userData: pointer
) {.ffi.} =
  try:
    await ctx.myLib[].start()
    return ok("")
  except CatchableError as e:
    error "chat_start failed", error = e.msg
    return err("failed to start client: " & e.msg)

proc chat_stop(
    ctx: ptr FFIContext[ChatClient],
    callback: FFICallBack,
    userData: pointer
) {.ffi.} =
  try:
    await ctx.myLib[].stop()
    return ok("")
  except CatchableError as e:
    error "chat_stop failed", error = e.msg
    return err("failed to stop client: " & e.msg)

#################################################
# ChatClient Info Operations
#################################################

proc chat_get_id(
    ctx: ptr FFIContext[ChatClient],
    callback: FFICallBack,
    userData: pointer
) {.ffi.} =
  ## Get the client's identifier
  let clientId = ctx.myLib[].getId()
  return ok(clientId)

proc chat_get_default_inbox_id(
    ctx: ptr FFIContext[ChatClient],
    callback: FFICallBack,
    userData: pointer
) {.ffi.} =
  ## Get the default inbox conversation ID
  let inboxId = ctx.myLib[].defaultInboxConversationId()
  return ok(inboxId)

#################################################
# Conversation List Operations
#################################################

proc chat_list_conversations(
    ctx: ptr FFIContext[ChatClient],
    callback: FFICallBack,
    userData: pointer
) {.ffi.} =
  ## List all conversations as JSON array
  let convos = ctx.myLib[].listConversations()
  var convoList = newJArray()
  for convo in convos:
    convoList.add(%*{"id": convo.id()})
  return ok($convoList)

proc chat_get_conversation(
    ctx: ptr FFIContext[ChatClient],
    callback: FFICallBack,
    userData: pointer,
    convoId: cstring
) {.ffi.} =
  ## Get a specific conversation by ID
  let convo = ctx.myLib[].getConversation($convoId)
  return ok($(%*{"id": convo.id()}))

