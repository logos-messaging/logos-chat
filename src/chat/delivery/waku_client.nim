import
  chronicles,
  chronos,
  confutils,
  eth/p2p/discoveryv5/enr,
  libp2p/crypto/crypto,
  libp2p/peerid,
  std/random,
  stew/byteutils,
  strformat,
  waku/[
    common/logging,
    node/peer_manager,
    waku_core,
    waku_node,
    waku_enr,
    discovery/waku_discv5,
    discovery/waku_dnsdisc,
    factory/builder,
    waku_filter_v2/client,
  ]


logScope:
  topics = "chat waku"

type ChatPayload* = object
  pubsubTopic*: PubsubTopic
  contentTopic*: string
  timestamp*: Timestamp
  bytes*: seq[byte]

proc toChatPayload*(msg: WakuMessage, pubsubTopic: PubsubTopic): ChatPayload =
  result = ChatPayload(pubsubTopic: pubsubTopic, contentTopic: msg.contentTopic,
      timestamp: msg.timestamp, bytes: msg.payload)



const
  # Placeholder
  FilterContentTopic = ContentTopic("/chatsdk/test/proto")


type QueueRef* = ref object
  queue*: AsyncQueue[ChatPayload]


type WakuConfig* = object
  nodekey*: crypto.PrivateKey  # TODO: protect key exposure 
  port*: uint16
  clusterId*: uint16
  shardId*: seq[uint16]
  pubsubTopic*: string
  staticPeers*: seq[string]

type
  WakuClient* = ref object
    cfg*: WakuConfig
    node*: WakuNode
    dispatchQueues: seq[QueueRef]
    staticPeerList: seq[string]


proc DefaultConfig*(): WakuConfig =
  let nodeKey = crypto.PrivateKey.random(Secp256k1, crypto.newRng()[])[]
  let clusterId = 42'u16
  let shardId = 2'u16
  var port: uint16 = 50000'u16 + uint16(rand(200))

  result = WakuConfig(nodeKey: nodeKey, port: port, clusterId: clusterId,
      shardId: @[shardId], pubsubTopic: &"/waku/2/rs/{clusterId}/{shardId}",
          staticPeers: @[])


proc sendBytes*(client: WakuClient, contentTopic: string,
    bytes: seq[byte]) {.async.} =

  let msg = WakuMessage(contentTopic: contentTopic, payload: bytes)
  let res = await client.node.publish(some(PubsubTopic(client.cfg.pubsubTopic)), msg)
  if res.isErr:
    error "Failed to Publish", err = res.error,
        pubsubTopic = client.cfg.pubsubTopic

proc buildWakuNode(cfg: WakuConfig): WakuNode =
  let
    ip = parseIpAddress("0.0.0.0")
    flags = CapabilitiesBitfield.init(relay = true)

  let relayShards = RelayShards.init(cfg.clusterId, cfg.shardId).valueOr:
    error "Relay shards initialization failed", error = error
    quit(QuitFailure)

  var enrBuilder = EnrBuilder.init(cfg.nodeKey)
  enrBuilder.withWakuRelaySharding(relayShards).expect(
    "Building ENR with relay sharding failed"
  )

  let recordRes = enrBuilder.build()
  let record =
    if recordRes.isErr():
      error "failed to create enr record", error = recordRes.error
      quit(QuitFailure)
    else:
      recordRes.get()

  var builder = WakuNodeBuilder.init()
  builder.withNodeKey(cfg.nodeKey)
  builder.withRecord(record)
  builder.withNetworkConfigurationDetails(ip, Port(cfg.port)).tryGet()
  let node = builder.build().tryGet()

  node.mountMetadata(cfg.clusterId, cfg.shardId).expect("failed to mount waku metadata protocol")

  result = node


proc taskKeepAlive(client: WakuClient) {.async.} =
  while true:
    for peerStr in client.staticPeerList:
      let peer = parsePeerInfo(peerStr).get()

      debug "maintaining subscription", peer = peerStr
      # First use filter-ping to check if we have an active subscription
      let pingRes = await client.node.wakuFilterClient.ping(peer)
      if pingRes.isErr():
        # No subscription found. Let's subscribe.
        warn "no subscription found. Sending subscribe request"

        # TODO: Use filter. Removing this stops relay from working so keeping for now
        let subscribeRes = await client.node.wakuFilterClient.subscribe(
          peer, client.cfg.pubsubTopic, @[FilterContentTopic]
        )

        if subscribeRes.isErr():
          error "subscribe request failed. Skipping.", err = subscribeRes.error
          continue
        else:
          debug "subscribe request successful."
      else:
        debug "subscription found."

    await sleepAsync(60.seconds) # Subscription maintenance interval

proc start*(client: WakuClient) {.async.} =
  setupLog(logging.LogLevel.NOTICE, logging.LogFormat.TEXT)
  await client.node.mountFilter()
  await client.node.mountFilterClient()

  await client.node.start()
  (await client.node.mountRelay()).isOkOr:
    error "failed to mount relay", error = error
    quit(1)

  client.node.peerManager.start()

  let dnsDiscoveryUrl = "enrtree://AKHMR2NCDFW5GI7TQIET3Y4SOKAZPDOMIHQACRKNILMGUBER4XW6K@logos-chat.nodes.status.im"
  let nameServer = parseIpAddress("1.1.1.1")
  let discoveredPeers = await retrieveDynamicBootstrapNodes(dnsDiscoveryUrl, @[nameServer])
  if discoveredPeers.isOk:
    info "Connecting to discovered peers"
    let remotePeers = discoveredPeers.get()
    info "Discovered and connecting to peers", peerCount = remotePeers.len
    asyncSpawn client.node.connectToNodes(remotePeers)
  else:
    warn "Failed to find peers via DNS discovery", error = discoveredPeers.error

  let subscription: SubscriptionEvent = (kind: PubsubSub, topic:
    client.cfg.pubsubTopic)

  proc handler(topic: PubsubTopic, msg: WakuMessage): Future[void] {.async, gcsafe.} =
    let payloadStr = string.fromBytes(msg.payload)
    debug "message received",
      pubsubTopic = topic,
      contentTopic = msg.contentTopic

    let payload = msg.toChatPayload(topic)

    for queueRef in client.dispatchQueues:
      await queueRef.queue.put(payload)

  let res = subscribe(client.node, subscription, handler)
  if res.isErr:
    error "Subscribe failed", err = res.error

  await allFutures(taskKeepAlive(client))

proc initWakuClient*(cfg: WakuConfig): WakuClient =
  result = WakuClient(cfg: cfg, node: buildWakuNode(cfg), dispatchQueues: @[],
      staticPeerList: cfg.staticPeers)

proc addDispatchQueue*(client: var WakuClient, queue: QueueRef) =
  client.dispatchQueues.add(queue)

proc getConnectedPeerCount*(client: WakuClient): int =
  var count = 0
  for peerId, peerInfo in client.node.peerManager.switch.peerStore.peers:
    if peerInfo.connectedness == Connected:
      inc count
  return count

proc stop*(client: WakuClient) {.async.} =
  await client.node.stop()
