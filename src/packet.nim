## Simple parsing support for 802.11 packets.
##
## https://technet.microsoft.com/en-us/library/cc757419(v=ws.10).aspx
##
## (See the 802.11 MAC Frame Format diagram).
##
## Also this: https://en.wikipedia.org/wiki/IEEE_802.11#Layer_2_%E2%80%93_Datagrams
import strformat, strutils

import crc32

type
  FrameControl* = distinct uint16

  MACAddress* = distinct array[6, uint8]

  MACHeader* = object
    frameControl*: FrameControl
    durationID*: uint16
    address1*, address2*, address3*: MACAddress
    sequenceControl*: uint16

  Packet* = object
    header*: MacHeader
    body*: string
    calculatedFCS*: Crc32

proc parsePacket*(data: string): Packet =
  var data = data
  assert data.len > sizeof MacHeader, "Got packet of size " & $data.len
  var macHeader: MacHeader
  copyMem(addr macHeader, addr data[0], sizeof MacHeader)
  var body = newString(data.len - sizeof MacHeader)
  copyMem(addr body[0],
          addr data[sizeof MacHeader],
          body.len)
  return Packet(
    header: macHeader,
    body: body,
    calculatedFCS: crc32(data[0 ..< ^4])
  )

proc `$`*(mac: MACAddress): string =
  let m = array[6, uint8](mac)
  return fmt"{m[0]:X}:{m[1]:X}:{m[2]:X}:{m[3]:X}:{m[4]:X}:{m[5]:X}"

proc toBin(x: uint16, len: Positive): string = toBin(x.BiggestInt, len)
proc `$`*(fc: FrameControl): string =
  let f = uint16(fc)
  # VV TT SSSS TF M R P M P O
  let version = (f and 0b1100_0000_0000_0000) shr 14
  let typ = (f and 0b0011_0000_0000_0000) shr 12
  let st = (f and 0b0000_1111_0000_0000) shr 8
  return fmt("(version: {version.toBin(2)}, type: {typ.toBin(2)}, " &
             "subtype: {st.toBin(4)}, ... {f:b})")

proc getFCS*(packet: Packet): Crc32 =
  if packet.body.len < 4: return 0.Crc32

  var fcs = packet.body[^4 .. ^1]
  result = cast[ptr uint32](addr fcs[0])[]
