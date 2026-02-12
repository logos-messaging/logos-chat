# Smoke test: validates that the binary links all dependencies at runtime.
# No networking, no start(), no message exchange — just instantiation.

import ../src/chat

proc main() =
  try:
    let waku = initWakuClient(DefaultConfig())
    let ident = createIdentity("SmokeTest")
    var client = newClient(waku, ident)
    if client.isNil:
      raise newException(CatchableError, "newClient returned nil")
    let id = client.getId()
    echo "smoke_test: OK (client id: " & id & ")"
    quit(QuitSuccess)
  except CatchableError as e:
    echo "smoke_test: FAILED — " & e.msg
    quit(QuitFailure)

when isMainModule:
  main()
