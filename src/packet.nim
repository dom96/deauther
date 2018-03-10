## Simple parsing support for 802.11 packets.
##
## https://technet.microsoft.com/en-us/library/cc757419(v=ws.10).aspx
##
## (See the 802.11 MAC Frame Format diagram).
##
## Also this: https://en.wikipedia.org/wiki/IEEE_802.11#Layer_2_%E2%80%93_Datagrams
##
## For the formal standard, see section 8 in the IEEE 802.11 2012 document:
## https://legal.vvv.enseirb-matmeca.fr/download/amichel/%5BStandard%20LDPC%5D%20802.11-2012.pdf
import strformat, strutils, endians

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
    TimingAdvertisement, Reserved7, Beacon, ATIM, Disassociation, Authentication,
    Deauthentication, Action, ActionNoAck, Reserved15

  ControlSubtype* {.pure.} = enum
    Reserved0, Reserved1, Reserved2, Reserved3, Reserved4, Reserved5,
    Reserved6, ControlWrapper, BlockAckReq, BlockAck, PSPoll, RTS, CTS, ACK,
    CFEnd, CFEndCFAck

  DataSubtype* {.pure.} = enum
    Data, DataCFAck, DataCFPoll, DataCFAckCFPoll, Null,
    CFAck, CFPoll, CFAckCFPoll, QoSData, QoSDataCFAck, QoSDataCFPoll,
    QoSDataCFAckCFPoll, QoSNull,
    Reserved13, QoSCFPoll, QoSCFAckCFPoll

proc parsePacket*(data: string): Packet =
  # Required fields in header:
  #  * Frame control
  #  * Duration
  #  * Address1
  #
  # The rest is optional (and I think it depends on the frame type).
  var data = data
  if data.len < 10:
    raise newException(ValueError, "Got packet size: " & $data.len)
  var offset = 0

  # Frame control
  littleEndian16(addr result.header.frameControl, addr data[offset])
  offset.inc(2)

  # Duration
  littleEndian16(addr result.header.durationID, addr data[offset])
  offset.inc(2)

  # Address1
  copyMem(addr result.header.address1, addr data[offset], 6)
  offset.inc(6)

  result.calculatedFCS = crc32(data[0 ..< ^4])

proc `$`*(mac: MACAddress): string =
  let m = array[6, uint8](mac)
  return fmt"{m[0]:X}:{m[1]:X}:{m[2]:X}:{m[3]:X}:{m[4]:X}:{m[5]:X}"

# http://www.sss-mag.com/pdf/802_11tut.pdf
proc getType*(fc: FrameControl): FrameType =
  let typ = (fc.uint16 and 0b0000_0000_0000_1100) shr 2
  case typ
  of 0: return Management
  of 1: return Control
  of 2: return Data
  of 3: return Reserved
  else: assert false

proc getManagementSubtype*(fc: FrameControl): ManagementSubtype =
  let st = (fc.uint16 and 0b0000_0000_1111_0000) shr 4
  return ManagementSubtype(st)

proc getControlSubtype*(fc: FrameControl): ControlSubtype =
  let st = (fc.uint16 and 0b0000_0000_1111_0000) shr 4
  return ControlSubtype(st)

proc getDataSubtype*(fc: FrameControl): DataSubtype =
  let st = (fc.uint16 and 0b0000_0000_1111_0000) shr 4
  return DataSubtype(st)

proc toBin(x: uint16, len: Positive): string = toBin(x.BiggestInt, len)
proc `$`*(fc: FrameControl): string =
  let f = uint16(fc)
  # VV TT SSSS TF M R P M P O
  let version = (f and 0b0000_0000_0000_0011)
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

when isMainModule:
  import radiotap
  block test1:
    const data = "\x00\x008\x00k\x084\x00\x01\xE6\xF4\xE3\x00\x00\x00\x00\x10\x00\xB8\x15@\x01\xBE\xA3\x01\x00\x00\x00@\x01\x04\x00\xB8\x15p\"\x9B\x07\x00\x00\x00\x00\x00\x00\xFF\x01W\x01\x91\x00\x00\x00\x01\x00\x00\x00\x88\x02,\x00\\\x96V+]\x1D4\x8F\'\x1E\x1C<\x00\xFE\xED\xC0\xFF\xEE\xB0y\x06\x00\xAA\xAA\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x00\xFE\xED\xC0\xFF\xEE\x0A\xF8\x80\x01\x00\x00\x00\x00\x00\x00\x0A\xF8\x899\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xC8\x02\xA1z"
    let radiotap = parseRadiotap(data)

    let p = parsePacket(radiotap.data)
    doAssert p.header.frameControl.getType() == Data