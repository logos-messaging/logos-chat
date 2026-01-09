import ffi
import src/chat/client

declareLibrary("chat")

proc set_event_callback(
    ctx: ptr FFIContext[Client],
    callback: FFICallBack,
    userData: pointer
) {.dynlib, exportc, cdecl.} =
  ctx[].eventCallback = cast[pointer](callback)
  ctx[].eventUserData = userData

