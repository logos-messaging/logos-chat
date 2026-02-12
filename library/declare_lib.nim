import ffi
import src/chat/client

declareLibrary("logoschat")

proc set_event_callback(
    ctx: ptr FFIContext[ChatClient],
    callback: FFICallBack,
    userData: pointer
) {.dynlib, exportc, cdecl.} =
  ctx[].eventCallback = cast[pointer](callback)
  ctx[].eventUserData = userData

