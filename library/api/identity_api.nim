## Identity API - FFI bindings for identity operations
## Uses the {.ffi.} pragma for async request handling

import std/json
import chronicles
import chronos
import ffi
import stew/byteutils

import src/chat
import library/utils

logScope:
  topics = "chat ffi identity"

#################################################
# Identity Operations
#################################################

proc chat_get_identity(
    ctx: ptr FFIContext[ChatClient],
    callback: FFICallBack,
    userData: pointer
) {.ffi.} =
  ## Get the client identity
  ## Returns JSON string: {"name": "..."}
  let identJson = %*{
    "name": ctx.myLib[].getId()
  }
  return ok($identJson)

#################################################
# IntroBundle Operations
#################################################

proc chat_create_intro_bundle(
    ctx: ptr FFIContext[ChatClient],
    callback: FFICallBack,
    userData: pointer
) {.ffi.} =
  ## Create an IntroBundle for initiating private conversations
  ## Returns the intro bundle as an ASCII string (format: logos_chatintro_<version>_<base64url payload>)
  let bundle = ctx.myLib[].createIntroBundle()
  return ok(string.fromBytes(bundle))

