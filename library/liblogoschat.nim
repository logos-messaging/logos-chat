## liblogoschat - C bindings for Logos-Chat
## Main entry point for the shared library
##
## This library exposes the chat functionality through a C-compatible FFI interface.
## It uses nim-ffi for thread-safe async request handling.

import std/[json, options]
import chronicles, chronos, ffi
import stew/byteutils

import
  src/chat/client,
  src/chat/delivery/waku_client,
  library/declare_lib,
  library/utils

logScope:
  topics = "chat ffi"

################################################################################
## Include different APIs, i.e. all procs with {.ffi.} pragma
include
  ./api/client_api,
  ./api/conversation_api,
  ./api/identity_api

################################################################################

proc chat_new(
    configJson: cstring, callback: FFICallBack, userData: pointer
): pointer {.dynlib, exportc, cdecl.} =
  initializeLibrary()

  ## Creates a new instance of the ChatClient.
  if isNil(callback):
    echo "error: missing callback in chat_new"
    return nil

  ## Create the Chat thread that will keep waiting for req from the main thread.
  var ctx = ffi.createFFIContext[ChatClient]().valueOr:
    let msg = "Error in createFFIContext: " & $error
    callback(RET_ERR, unsafeAddr msg[0], cast[csize_t](len(msg)), userData)
    return nil

  ctx.userData = userData

  proc onNewMessage(ctx: ptr FFIContext[ChatClient]): MessageCallback =
    return proc(conversation: Conversation, msg: ReceivedMessage): Future[void] {.async.} =
      callEventCallback(ctx, "onNewMessage"):
        $newJsonMessageEvent(
          conversation.id(),
          "",
          msg.content.toHex(),
          msg.timestamp
        )

  proc onNewConversation(ctx: ptr FFIContext[ChatClient]): NewConvoCallback =
    return proc(conversation: Conversation): Future[void] {.async.} =
      callEventCallback(ctx, "onNewConversation"):
        $newJsonConversationEvent(conversation.id(), "private")

  proc onDeliveryAck(ctx: ptr FFIContext[ChatClient]): DeliveryAckCallback =
    return proc(conversation: Conversation, msgId: MessageId): Future[void] {.async.} =
      callEventCallback(ctx, "onDeliveryAck"):
        $newJsonDeliveryAckEvent(conversation.id(), msgId)

  let chatCallbacks = ChatCallbacks(
    onNewMessage: onNewMessage(ctx),
    onNewConversation: onNewConversation(ctx),
    onDeliveryAck: onDeliveryAck(ctx),
  )

  ffi.sendRequestToFFIThread(
    ctx, CreateClientRequest.ffiNewReq(callback, userData, configJson, chatCallbacks)
  ).isOkOr:
    let msg = "error in sendRequestToFFIThread: " & $error
    callback(RET_ERR, unsafeAddr msg[0], cast[csize_t](len(msg)), userData)
    return nil

  return ctx

proc chat_destroy(
    ctx: ptr FFIContext[ChatClient], callback: FFICallBack, userData: pointer
): cint {.dynlib, exportc, cdecl.} =
  initializeLibrary()
  checkParams(ctx, callback, userData)

  ffi.destroyFFIContext(ctx).isOkOr:
    let msg = "liblogoschat error: " & $error
    callback(RET_ERR, unsafeAddr msg[0], cast[csize_t](len(msg)), userData)
    return RET_ERR

  callback(RET_OK, nil, 0, userData)

  return RET_OK
