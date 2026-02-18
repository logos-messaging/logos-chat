## Conversation API - FFI bindings for conversation operations
## Uses the {.ffi.} pragma for async request handling

import std/options
import chronicles
import chronos
import ffi
import stew/byteutils

import src/chat
import library/utils

logScope:
  topics = "chat ffi conversation"

#################################################
# Private Conversation Operations
#################################################

proc chat_new_private_conversation(
    ctx: ptr FFIContext[ChatClient],
    callback: FFICallBack,
    userData: pointer,
    introBundleStr: cstring,
    contentHex: cstring
) {.ffi.} =
  ## Create a new private conversation with the given IntroBundle
  ## introBundleStr: Intro bundle ASCII string as returned by chat_create_intro_bundle
  ## contentHex: Initial message content as hex-encoded string
  try:
    # Convert bundle string to seq[byte]
    let bundle = toBytes($introBundleStr)

    # Convert hex content to bytes
    let content = hexToSeqByte($contentHex)

    # Create the conversation
    let errOpt = await ctx.myLib[].newPrivateConversation(bundle, content)
    if errOpt.isSome():
      return err("failed to create conversation: " & $errOpt.get())

    return ok("")
  except CatchableError as e:
    error "chat_new_private_conversation failed", error = e.msg
    return err("failed to create private conversation: " & e.msg)

#################################################
# Message Operations
#################################################

proc chat_send_message(
    ctx: ptr FFIContext[ChatClient],
    callback: FFICallBack,
    userData: pointer,
    convoId: cstring,
    contentHex: cstring
) {.ffi.} =
  ## Send a message to a conversation
  ## convoId: Conversation ID string
  ## contentHex: Message content as hex-encoded string
  try:
    let convo = ctx.myLib[].getConversation($convoId)
    let content = hexToSeqByte($contentHex)
    
    let msgId = await convo.sendMessage(content)
    return ok(msgId)
  except CatchableError as e:
    error "chat_send_message failed", error = e.msg
    return err("failed to send message: " & e.msg)
