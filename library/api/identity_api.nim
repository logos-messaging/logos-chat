## Identity API - FFI bindings for identity operations
## Uses the {.ffi.} pragma for async request handling

import std/json
import chronicles
import chronos
import ffi
import stew/byteutils

import src/chat
import src/chat/crypto
import src/chat/proto_types
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
  ## Returns JSON string: {"name": "...", "address": "...", "pubkey": "hex..."}
  let ident = ctx.myLib[].identity()
  let identJson = %*{
    "name": ident.getName(),
    "address": ident.getAddr(),
    "pubkey": ident.getPubkey().toHex()
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
  ## Returns JSON string: {"ident": "hex...", "ephemeral": "hex..."}
  let bundle = ctx.myLib[].createIntroBundle()
  let bundleJson = %*{
    "ident": bundle.ident.toHex(),
    "ephemeral": bundle.ephemeral.toHex()
  }
  return ok($bundleJson)

