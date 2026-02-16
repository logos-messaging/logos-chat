# run with `./build/bot_echo`

import chronicles
import chronos

import chat
import content_types

proc main() {.async.} =
  let waku = initWakuClient(DefaultConfig())
  let ident = createIdentity("EchoBot")
  var chatClient = newClient(waku, ident)

  chatClient.onNewMessage(proc(convo: Conversation, msg: ReceivedMessage) {.async.} =
    info "New Message: ", convoId = convo.id(), msg= msg
    discard await convo.sendMessage(msg.content)
  )

  chatClient.onNewConversation(proc(convo: Conversation) {.async.} =
    info "New Conversation Initiated: ", convoId = convo.id()
    discard await convo.sendMessage(initTextFrame("Hello!").toContentFrame().encode())
  )

  await chatClient.start()
  
  info "EchoBot started"
  info "Invite", link=chatClient.createIntroBundle()

when isMainModule:
  waitFor main()
  runForever()