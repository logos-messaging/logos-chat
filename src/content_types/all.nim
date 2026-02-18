# Can this be an external package? It would be preferable to have these types
# easy to import and use.

import protobuf_serialization # This import is needed or th macro will not work
import protobuf_serialization/proto_parser
import results
import strformat


export protobuf_serialization

import_proto3 "protos/text_frame.proto"
import_proto3 "protos/common_frames.proto"

export ContentFrame, TextFrame

type ContentTypes = TextFrame


const DOMAIN_OWNED = 0
const TAG_TEXT = 0

# protobuf_serialization does not support enums, so it needs to be manually implemented
type
  TextEncoding* = enum
    Utf8 = 0


  ContentType* = enum
    text, unknown


proc encode*(frame: object): seq[byte] =
  ## Encodes the frame into a byte sequence using Protobuf serialization.
  result = Protobuf.encode(frame)


proc decode*[T: object] (bytes: seq[byte], proto: typedesc[
    T]): Result[T, string] =
  ## Encodes the frame into a byte sequence using Protobuf serialization.

  try:
    result = ok(Protobuf.decode(bytes, proto))
  except ProtobufError as e:
    result = err("Failed to decode payload: " & e.msg)


proc toContentFrame*(frame: TextFrame): ContentFrame =
  result = ContentFrame(domain: 0, tag: 0, bytes: encode(frame))


proc initTextFrame*(text: string): TextFrame =
  result = TextFrame(encoding: ord(Utf8), text: text)


proc `$`*(frame: TextFrame): string =

  result = fmt"TextFrame(encoding:{TextEncoding(frame.encoding)} text:{frame.text})"

proc contentType*(frame: ContentFrame): ContentType =
  if DOMAIN_OWNED != frame.domain:
    return unknown

  if TAG_TEXT == frame.tag:
    return text 