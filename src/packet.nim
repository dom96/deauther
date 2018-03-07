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

  FrameType* = enum
    Management, Control, Data, Reserved

  ManagementSubtype* {.pure.} = enum
    AssociationRequest, AssociationResponse, ReassociationRequest,
    ReassociationResponse, ProbeRequest, ProbeResponse,
    Reserved6, Reserved7, Beacon, ATIM, Disassociation, Authentication,
    Deauthentication, Reserved13, Reserved14, Reserved15

  ControlSubtype* {.pure.} = enum
    Reserved0, Reserved1, Reserved2, Reserved3, Reserved4, Reserved5,
    Reserved6, Reserved7, Reserved8, Reserved9, PSPoll, RTS, CTS, ACK,
    CFEnd, CFEndCFAck

  DataSubtype* {.pure.} = enum
    Data, DataCFAck, DataCFPoll, DataCFAckCFPoll, Null,
    CFAck, CFPoll, CFAckCFPoll, Reserved8, Reserved9, Reserved10, Reserved11,
    Reserved12, Reserved13, Reserved14, Reserved15

proc parsePacket*(data: string): Packet =
  var data = data
  if data.len < sizeof MacHeader:
    raise newException(ValueError, "Got packet of size " & $data.len)

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

# http://www.sss-mag.com/pdf/802_11tut.pdf
proc getType*(fc: FrameControl): FrameType =
  let typ = (fc.uint16 and 0b0011_0000_0000_0000) shr 12
  case typ
  of 0: return Management
  of 1: return Control
  of 2: return Data
  of 3: return Reserved
  else: assert false

proc getManagementSubtype*(fc: FrameControl): ManagementSubtype =
  let st = (fc.uint16 and 0b0000_1111_0000_0000) shr 8
  return ManagementSubtype(st)

proc getControlSubtype*(fc: FrameControl): ControlSubtype =
  let st = (fc.uint16 and 0b0000_1111_0000_0000) shr 8
  return ControlSubtype(st)

proc getDataSubtype*(fc: FrameControl): DataSubtype =
  let st = (fc.uint16 and 0b0000_1111_0000_0000) shr 8
  return DataSubtype(st)

proc toBin(x: uint16, len: Positive): string = toBin(x.BiggestInt, len)
proc `$`*(fc: FrameControl): string =
  let f = uint16(fc)
  # VV TT SSSS TF M R P M P O
  let version = (f and 0b1100_0000_0000_0000) shr 14
  let typ = getType(fc)
  var subtype = ""
  case typ
  of Management:
    subtype = $getManagementSubtype(fc)
  of Control:
    subtype = $getControlSubtype(fc)
  of Data:
    subtype = $getDataSubtype(fc)
  of Reserved:
    assert false

  return fmt("(version: {version.toBin(2)}, type: {typ}, " &
             "subtype: {subtype}, ... {f:b})")

proc getFCS*(packet: Packet): Crc32 =
  if packet.body.len < 4: return 0.Crc32

  var fcs = packet.body[^4 .. ^1]
  result = cast[ptr uint32](addr fcs[0])[]
