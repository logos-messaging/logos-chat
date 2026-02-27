import
  chronicles,
  chronos,
  confutils,
  eth/p2p/discoveryv5/enr as eth_enr,
  libp2p/crypto/crypto,
  libp2p/peerid,
  std/random,
  stew/byteutils,
  strformat,
  waku/[
    common/logging,
    common/enr as common_enr,
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

  ## Logos.dev Fleet ENRs

  # delivery-01.do-ams3.logos.dev.status.im - 16Uiu2HAmTUbnxLGT9JvV6mu9oPyDjqHK4Phs1VDJNUgESgNSkuby
  LogosDevDelivery01DoAms3 = "enr:-MG4QNjpXNETi50MXYSQNZyzd7YVi5UDmy53GjC7i9y1rmuRWd_rGhizRXV4YKLrb8G_ezIrE1gVkiuY_GzFGk6lfikBgmlkgnY0gmlwhIpEeomKbXVsdGlhZGRyc4wACgSKRHqJBh9A3gOCcnOTAAIIAAAAAQACAAMABAAFAAYAB4lzZWNwMjU2azGhA9w1_W3QN9zZw8FcFQT5XWJ7I_qBGXFCxeO5iOBgeWXkg3RjcIJ2X4N1ZHCCIyiFd2FrdTIv"

  # delivery-02.do-ams3.logos.dev.status.im - 16Uiu2HAmMK7PYygBtKUQ8EHp7EfaD3bCEsJrkFooK8RQ2PVpJprH
  LogosDevDelivery02DoAms3 = "enr:-MG4QO7X4HJ8BfAkbSbtG4uDvX1t4HIjEMTbdh4aYR4EV00cMrpa1NYejjVIGD0SXJGqbrRs2YYf59Me9K92iyyi_X4BgmlkgnY0gmlwhK6KavSKbXVsdGlhZGRyc4wACgSuimr0Bh9A3gOCcnOTAAIIAAAAAQACAAMABAAFAAYAB4lzZWNwMjU2azGhA4ChhnJvGLCZgYfCAn6zGi0_lump80dOnTXuwEdMqnveg3RjcIJ2X4N1ZHCCIyiFd2FrdTIv"

  # delivery-01.gc-us-central1-a.logos.dev.status.im - 16Uiu2HAm4S1JYkuzDKLKQvwgAhZKs9otxXqt8SCGtB4hoJP1S397
  LogosDevDelivery01GcUsCentral1a = "enr:-MG4QIiRL2QYsAMJuofnJ2ketbMf_vq448kZxa0DGzu_Wj8PW7YdeIFEJbEJapA2K-b_UMC-TdEaQ2LukC9ynyegRQ4BgmlkgnY0gmlwhIh3nFeKbXVsdGlhZGRyc4wACgSId5xXBh9A3gOCcnOTAAIIAAAAAQACAAMABAAFAAYAB4lzZWNwMjU2azGhAoXPCAUveBrCoOScJxl_jdLrPu4xyzbCmwP_ovGsqNkGg3RjcIJ2X4N1ZHCCIyiFd2FrdTIv"

  # delivery-02.gc-us-central1-a.logos.dev.status.im - 16Uiu2HAm8Y9kgBNtjxvCnf1X6gnZJW5EGE4UwwCL3CCm55TwqBiH
  LogosDevDelivery02GcUsCentral1a = "enr:-MG4QJ2n_Hkl0_ZaGxK4ye_lmXPCHi8qXISESIucQyrPd0oCOFXZf9ws5gjN3hovMw08GTJSAptX2q0GrrjQS9wOpb8BgmlkgnY0gmlwhCJ7yRmKbXVsdGlhZGRyc4wACgQie8kZBh9A3gOCcnOTAAIIAAAAAQACAAMABAAFAAYAB4lzZWNwMjU2azGhAsLQ0aIXN3XPEkZiqfPGU8aQp-Q8Vx8GoEipJx-uf4Dig3RjcIJ2X4N1ZHCCIyiFd2FrdTIv"

  # delivery-01.ac-cn-hongkong-c.logos.dev.status.im - 16Uiu2HAm8YokiNun9BkeA1ZRmhLbtNUvcwRr64F69tYj9fkGyuEP
  LogosDevDelivery01AcCnHongkongC = "enr:-MG4QFQc9ULfGsloUceZk2i1XiFDuZ4zDoMWIkfOrQQ2rlW_ZLIN7CAzw67W7oGSQ4-sJ3Ehat6-tKxJ3Vj428TlWyABgmlkgnY0gmlwhC_ygr2KbXVsdGlhZGRyc4wACgQv8oK9Bh9A3gOCcnOTAAIIAAAAAQACAAMABAAFAAYAB4lzZWNwMjU2azGhAsL7yU6Z4_I47DAMN8zTlJxl1DF0GVeBtFXj8uQM5vpog3RjcIJ2X4N1ZHCCIyiFd2FrdTIv"

  # delivery-02.ac-cn-hongkong-c.logos.dev.status.im - 16Uiu2HAkvwhGHKNry6LACrB8TmEFoCJKEX29XR5dDUzk3UT3UNSE
  LogosDevDelivery02AcCnHongkongC = "enr:-MG4QDnRm93660fPMd0MAwhYIYS1I6YzNI8lYGZP-IoDy6NYSsmgE-m4aIThWuiveMquo8uZz7f4-jpxjYM48kuZONgBgmlkgnY0gmlwhCtjZwqKbXVsdGlhZGRyc4wACgQrY2cKBh9A3gOCcnOTAAIIAAAAAQACAAMABAAFAAYAB4lzZWNwMjU2azGhAhaMkDdziqKJqwaxdMWwq9A21gF7Wp5eCfDA6VmJkccDg3RjcIJ2X4N1ZHCCIyiFd2FrdTIv"

  # Logos.dev fleet static peers
  LogosDevStaticPeers* = @[
    LogosDevDelivery01DoAms3,
    LogosDevDelivery02DoAms3,
    LogosDevDelivery01GcUsCentral1a,
    LogosDevDelivery02GcUsCentral1a,
    LogosDevDelivery01AcCnHongkongC,
    LogosDevDelivery02AcCnHongkongC,
  ]


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
    staticPeerList: seq[RemotePeerInfo]


proc DefaultConfig*(): WakuConfig =
  let nodeKey = crypto.PrivateKey.random(Secp256k1, crypto.newRng()[])[]
  let clusterId = 2'u16
  let shardId = 1'u16
  var port: uint16 = 50000'u16 + uint16(rand(200))

  result = WakuConfig(nodeKey: nodeKey, port: port, clusterId: clusterId,
      shardId: @[shardId], pubsubTopic: &"/waku/2/rs/{clusterId}/{shardId}",
          staticPeers: LogosDevStaticPeers)


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
    for peerInfo in client.staticPeerList:
      debug "maintaining subscription", peerId = $peerInfo.peerId
      # First use filter-ping to check if we have an active subscription
      let pingRes = await client.node.wakuFilterClient.ping(peerInfo)
      if pingRes.isErr():
        # No subscription found. Let's subscribe.
        warn "no subscription found. Sending subscribe request"

        # TODO: Use filter. Removing this stops relay from working so keeping for now
        let subscribeRes = await client.node.wakuFilterClient.subscribe(
          peerInfo, client.cfg.pubsubTopic, @[FilterContentTopic]
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

  # Connect to all configured static peers
  if client.staticPeerList.len > 0:
    info "Connecting to static peers", peerCount = client.staticPeerList.len
    asyncSpawn client.node.connectToNodes(client.staticPeerList)
  else:
    warn "No valid static peers configured"

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
  # Parse ENRs from static peers configuration
  var peerInfos: seq[RemotePeerInfo] = @[]
  for enrStr in cfg.staticPeers:
    let enrRecord = eth_enr.Record.fromURI(enrStr).valueOr:
      error "Failed to parse ENR in initWakuClient", enr = enrStr, err = error
      continue

    let peerInfo = enrRecord.toRemotePeerInfo().valueOr:
      error "Failed to convert ENR to PeerInfo in initWakuClient", enr = enrStr, err = error
      continue

    peerInfos.add(peerInfo)

  result = WakuClient(cfg: cfg, node: buildWakuNode(cfg), dispatchQueues: @[],
      staticPeerList: peerInfos)

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
