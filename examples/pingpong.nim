import chronicles
import chronos
import strformat

import chat
import content_types



proc getContent(content: ContentFrame): string =
  # Skip type checks and assume its a TextFrame
  let m = decode(content.bytes, TextFrame).valueOr:
    raise newException(ValueError, fmt"Badly formed ContentType")
  return fmt"{m}"

proc toBytes(content: ContentFrame): seq[byte] =
  encode(content)

proc fromBytes(bytes: seq[byte]): ContentFrame =
  decode(bytes, ContentFrame).valueOr:
      raise newException(ValueError, fmt"Badly formed Content")

proc main() {.async.} =

  # Create Configurations
  var waku_saro = initWakuClient(DefaultConfig())
  var waku_raya = initWakuClient(DefaultConfig())

  let sKey = loadPrivateKeyFromBytes(@[45u8, 216, 160, 24, 19, 207, 193, 214, 98, 92, 153, 145, 222, 247, 101, 99, 96, 131, 149, 185, 33, 187, 229, 251, 100, 158, 20, 131, 111, 97, 181, 210]).get()
  let rKey = loadPrivateKeyFromBytes(@[43u8, 12, 160, 51, 212, 90, 199, 160, 154, 164, 129, 229, 147, 69, 151, 17, 239, 51, 190, 33, 86, 164, 50, 105, 39, 250, 182, 116, 138, 132, 114, 234]).get()

  # Create Clients
  var saro = newClient(waku_saro, Identity(name: "saro", privateKey: sKey))
  var raya = newClient(waku_raya, Identity(name: "raya", privateKey: rKey))

  # Wire Saro Callbacks
  saro.onNewMessage(proc(convo: Conversation, msg: ReceivedMessage) {.async, closure.} =
    let contentFrame = msg.content.fromBytes()
    notice "    Saro  <------  ", content = getContent(contentFrame)
    await sleepAsync(1000.milliseconds)
    discard await convo.sendMessage(initTextFrame("Ping").toContentFrame().toBytes())
  )

  saro.onDeliveryAck(proc(convo: Conversation, msgId: string) {.async.} =
    notice "    Saro -- Read Receipt for ", msgId= msgId
  )


  # Wire Raya Callbacks
  var i = 0
  raya.onNewConversation(proc(convo: Conversation) {.async.} =
    notice "           ------>  Raya :: New Conversation: ", id = convo.id()
    discard await convo.sendMessage(initTextFrame("Hello").toContentFrame().toBytes())
  )


  raya.onNewMessage(proc(convo: Conversation,msg: ReceivedMessage) {.async.} =
    let contentFrame = msg.content.fromBytes()
    notice "           ------>  Raya :: from: ", content=  getContent(contentFrame)
    await sleepAsync(500.milliseconds)
    discard  await convo.sendMessage(initTextFrame("Pong" & $i).toContentFrame().toBytes())
    await sleepAsync(800.milliseconds)
    discard  await convo.sendMessage(initTextFrame("Pang" & $i).toContentFrame().toBytes())
    inc i
  )

 
  raya.onDeliveryAck(proc(convo: Conversation, msgId: string) {.async.} =
    echo "    raya -- Read Receipt for " & msgId
  )


  await saro.start()
  await raya.start()

  await sleepAsync(10.seconds)

  # Perform OOB Introduction: Raya -> Saro
  let raya_bundle = raya.createIntroBundle()
  discard await saro.newPrivateConversation(raya_bundle, initTextFrame("Init").toContentFrame().toBytes())

  await sleepAsync(20.seconds) # Run for some time 

  await saro.stop()
  await raya.stop()


when isMainModule:
  waitFor main()
  notice "Shutdown"
