## Utility functions for C-bindings
## Provides JSON event serialization helpers

import std/json

#################################################
# JSON Event Types
#################################################

type
  JsonEventType* = enum
    EventNewMessage = "new_message"
    EventNewConversation = "new_conversation"
    EventDeliveryAck = "delivery_ack"
    EventError = "error"

type
  JsonMessageEvent* = object
    eventType*: string
    conversationId*: string
    messageId*: string
    content*: string
    timestamp*: int64

  JsonConversationEvent* = object
    eventType*: string
    conversationId*: string
    conversationType*: string

  JsonDeliveryAckEvent* = object
    eventType*: string
    conversationId*: string
    messageId*: string

  JsonErrorEvent* = object
    eventType*: string
    error*: string

#################################################
# JSON Event Constructors
#################################################

proc newJsonMessageEvent*(convoId, msgId, content: string, timestamp: int64): JsonMessageEvent =
  result = JsonMessageEvent(
    eventType: $EventNewMessage,
    conversationId: convoId,
    messageId: msgId,
    content: content,
    timestamp: timestamp
  )

proc newJsonConversationEvent*(convoId, convoType: string): JsonConversationEvent =
  result = JsonConversationEvent(
    eventType: $EventNewConversation,
    conversationId: convoId,
    conversationType: convoType
  )

proc newJsonDeliveryAckEvent*(convoId, msgId: string): JsonDeliveryAckEvent =
  result = JsonDeliveryAckEvent(
    eventType: $EventDeliveryAck,
    conversationId: convoId,
    messageId: msgId
  )

proc newJsonErrorEvent*(error: string): JsonErrorEvent =
  result = JsonErrorEvent(
    eventType: $EventError,
    error: error
  )

#################################################
# JSON Serialization
#################################################

proc `$`*(event: JsonMessageEvent): string =
  $(%*event)

proc `$`*(event: JsonConversationEvent): string =
  $(%*event)

proc `$`*(event: JsonDeliveryAckEvent): string =
  $(%*event)

proc `$`*(event: JsonErrorEvent): string =
  $(%*event)

