# Package

version = "0.1.0"
author = "jazzz"
description = "An example of the chat sdk in Nim"
license = "MIT"
srcDir = "src"
bin = @["nim_chat_poc"]

# Dependencies

requires "nim >= 2.2.4",
  "protobuf_serialization",
  "secp256k1",
  "blake2",
  "chronicles",
  "libp2p",
  "nimchacha20poly1305", # TODO: remove
  "confutils",
  "eth",
  "regex",
  "web3",
  "https://github.com/jazzz/nim-sds#exports",
  "waku",
  "ffi"

proc buildBinary(name: string, srcDir = "./", params = "", lang = "c") =
  if not dirExists "build":
    mkDir "build"
  # allow something like "nim nimbus --verbosity:0 --hints:off nimbus.nims"
  var extra_params = params
  for i in 2 ..< paramCount():
    extra_params &= " " & paramStr(i)

  exec "nim " & lang & " --out:build/" & name & " --mm:refc " & extra_params & " " &
    srcDir & name & ".nim"

proc buildLibrary(name: string, srcDir = "library/", params = "", lang = "c") =
  ## Build a shared library (.so on Linux, .dylib on macOS, .dll on Windows)
  if not dirExists "build":
    mkDir "build"
  
  # Determine library extension based on OS
  let libExt = when defined(macosx): "dylib"
               elif defined(windows): "dll"
               else: "so"
  
  var extra_params = params
  for i in 2 ..< paramCount():
    extra_params &= " " & paramStr(i)
  
  exec "nim " & lang & " --app:lib --out:build/lib" & name & "." & libExt & 
       " --mm:refc --nimMainPrefix:lib" & name & " " & extra_params & " " &
       srcDir & "lib" & name & ".nim"

proc test(name: string, params = "-d:chronicles_log_level=DEBUG", lang = "c") =
  buildBinary name, "tests/", params
  exec "build/" & name

task tests, "Build & run tests":
  test "all_tests", "-d:chronicles_log_level=ERROR -d:chronosStrictException"

task waku_example, "Build Waku based simple example":
  let name = "waku_example"
  buildBinary name, "examples/", " -d:chronicles_log_level='TRACE' "

task tui, "Build Waku based simple example":
  let name = "tui"
  buildBinary name, "examples/", " -d:chronicles_enabled=on -d:chronicles_log_level='INFO' -d:chronicles_sinks=textlines[file]"

task bot_echo, "Build the EchoBot example":
  let name = "bot_echo"
  buildBinary name, "examples/", "-d:chronicles_log_level='INFO' -d:chronicles_disabled_topics='waku node' "

task pingpong, "Build the Pingpong example":
  let name = "pingpong"
  buildBinary name, "examples/", "-d:chronicles_log_level='INFO' -d:chronicles_disabled_topics='waku node' "

task libchat, "Build the Chat SDK shared library (C bindings)":
  buildLibrary "chat", "library/", 
    "-d:chronicles_log_level='INFO' -d:chronicles_enabled=on --path:src --path:vendor/nim-ffi"
