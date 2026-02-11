import waku/waku_core
import std/[macros, times]
import blake2
import strutils

proc getCurrentTimestamp*(): Timestamp =
    result = waku_core.getNanosecondTime(getTime().toUnix())

proc hash_func*(s: string | seq[byte]): string =
    # This should be Blake2s but it does not exist so substituting with Blake2b
    result = getBlake2b(s, 4, "")

proc bytesToHex*[T](bytes: openarray[T], lowercase: bool = false): string =
    ## Convert bytes to hex string with case option
    result = ""
    for b in bytes:
        let hex = b.toHex(2)
        result.add(if lowercase: hex.toLower() else: hex)
