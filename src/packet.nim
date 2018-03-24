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
import strformat, strutils, endians, options

import crc32

type
  FrameControl* = distinct uint16

  MACAddress* = distinct array[6, uint8]

  MACHeader* = object
    frameControl*: FrameControl
    durationID*: uint16
    address1*, address2*, address3*: MACAddress
    sequenceControl*: uint16
    htControl*: uint16

  Packet* = object
    header*: MacHeader
    body*: string
    calculatedFCS*: Crc32
    receivedFCS*: Crc32

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

proc getOrder*(fc: FrameControl): bool =
  ## For QoS data or a management frame, this determines whether the frame
  ## contains an HT Control Field.
  let order = (fc.uint16 and 0b1000_0000_0000_0000) shr 15
  return bool(order)

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

  # Take care of address 1,2 and seq control.
  let frameType = result.header.frameControl.getType()
  case frameType
  of Data, Management:
    # All data and management frames have address2/3, and sequence control.
    if data.len < offset + 14:
      raise newException(ValueError, "Expected 14 more bytes")

    copyMem(addr result.header.address2, addr data[offset], 6)
    offset.inc(6)

    copyMem(addr result.header.address3, addr data[offset], 6)
    offset.inc(6)

    littleEndian16(addr result.header.sequenceControl, addr data[offset])
    offset.inc(2)
  of Control:
    let subtype = result.header.frameControl.getControlSubtype()

    # Read the second address for all subtypes which possess it.
    if subtype in{RTS, PSPoll, CFEnd, CFEndCFAck, BlockAckReq, BlockAck}:
      copyMem(addr result.header.address2, addr data[offset], 6)
      offset.inc(6)
  of Reserved:
    discard

  # Other fields for data frames include: Address 4, QoS control, HT control.
  # TODO ^

  # Parse HT Control Field for management frames.
  if frameType == Management: #or is QoS frame, TODO
    littleEndian32(addr result.header.htControl, addr data[offset])
    offset.inc(2)

  # Handle frame body
  case frameType
  of Management:
    result.body = data[offset ..< ^4]
  else:
    result.body = "" # TODO

  # Calculate FCS for the data we received.
  result.calculatedFCS = crc32(data[0 ..< ^4])
  # Get recieved FCS
  var fcs = data[^4 .. ^1]
  result.receivedFCS = cast[ptr uint32](addr fcs[0])[]

proc `$`*(mac: MACAddress): string =
  let m = array[6, uint8](mac)
  return fmt"{m[0]:X}:{m[1]:X}:{m[2]:X}:{m[3]:X}:{m[4]:X}:{m[5]:X}"

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
    subtype = $f

  return fmt("(version: {version.toBin(2)}, type: {typ}, " &
             "subtype: {subtype}, ... {f:b})")

proc getSSID*(packet: Packet): Option[string] =
  ## Attempts to extract an SSID from a packet. Only some packets will contain
  ## an SSID. This currently focuses on a Beacon management frame.
  if packet.header.frameControl.getType() != Management:
    return none(string)

  # According to: https://mrncciew.com/2014/10/08/802-11-mgmt-beacon-frame/
  # Timestamp (8 bytes)
  # Beacon interval (2 bytes)
  # Capability info (2 bytes)
  # SSID (variable size, max 32 bytes)
  result = some("")
  # The IEEE spec doesn't explain how large the fields above are, but it
  # does explain that there is a byte containing the length before the SSID...
  let length = packet.body[11].int
  if length <= 0: return none(string)
  result = some[string](packet.body[12 ..< 12+length])

when isMainModule:
  import radiotap
  block test1:
    const data = "\x00\x008\x00k\x084\x00\x01\xE6\xF4\xE3\x00\x00\x00\x00\x10\x00\xB8\x15@\x01\xBE\xA3\x01\x00\x00\x00@\x01\x04\x00\xB8\x15p\"\x9B\x07\x00\x00\x00\x00\x00\x00\xFF\x01W\x01\x91\x00\x00\x00\x01\x00\x00\x00\x88\x02,\x00\\\x96V+]\x1D4\x8F\'\x1E\x1C<\x00\xFE\xED\xC0\xFF\xEE\xB0y\x06\x00\xAA\xAA\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x00\xFE\xED\xC0\xFF\xEE\x0A\xF8\x80\x01\x00\x00\x00\x00\x00\x00\x0A\xF8\x899\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xC8\x02\xA1z"
    let radiotap = parseRadiotap(data)

    let p = parsePacket(radiotap.data)
    doAssert p.header.frameControl.getType() == Data
    doAssert $p.header.address1 == "5C:96:56:2B:5D:1D"
    doAssert $p.header.address2 == "34:8F:27:1E:1C:3C"

  block test2:
    const data = "\x00\x00\x19\x00o\x08\x00\x00\xB8@\xA3\x0A\x00\x00\x00\x00\x120\xB8\x15@\x01\xAB\xA4\x01\x94\x00\x00\x004\x8F\'\x1E\x1C<\xA0\xD3zeci\x04\x00\x10\x96\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFFNh`\xEB"
    let radiotap = parseRadiotap(data)

    let p = parsePacket(radiotap.data)
    doAssert p.header.frameControl.getType() == Control
    doAssert p.header.frameControl.getControlSubtype() == BlockAck
    doAssert $p.header.address1 == "34:8F:27:1E:1C:3C"
    doAssert $p.header.address2 == "A0:D3:7A:65:63:69"

  block test3:
    const data = "\x00\x00\x19\x00o\x08\x00\x00p\xE0\xA5\x0A\x00\x00\x00\x00\x12\x0C\xB8\x15@\x01\xC8\xA4\x01\x80\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF4\x8F\'^\x1C<4\x8F\'^\x1C<@:\x9C\xB1\xF5t\xBF\x08\x00\x00d\x00\x11\x11\x00\x16ASK4 Wireless (802.1x)\x01\x08\x8C\x12\x98$\xB0H`l\x03\x01p\x05\x04\x00\x01\x00\x00\x07\x0AGB d\x05\x1E\x84\x02\x1E\x00\xDD\x18\x00P\xF2\x02\x01\x01\x82\x00\x03\xA4\x00\x00\'\xA4\x00\x00BC^\x00b2/\x000\x14\x01\x00\x00\x0F\xAC\x04\x01\x00\x00\x0F\xAC\x04\x01\x00\x00\x0F\xAC\x01\x00\x00F\x05\x02\x00\x00\x00\x00-\x1A\xEF\x19\x1B\xFF\xFF\xFF\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00=\x16p\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0B\x05\x00\x00\x03\x00\x00\x7F\x08\x00\x00\x08\x00\x00\x00\x00@\xBF\x0C\x92\x01\x80#\xEA\xFF\x00\x00\xEA\xFF\x00\x00\xC0\x05\x00\x00\x00\xFC\xFF\xC3\x05\x03<<<\x05\xDD\x08\x00\x13\x92\x01\x00\x01\x05\x00\xF5\x0A\\\xDE"
    let radiotap = parseRadiotap(data)

    let p = parsePacket(radiotap.data)
    doAssert $p.header.address1 == "FF:FF:FF:FF:FF:FF"
    doAssert $p.header.address2 == "34:8F:27:5E:1C:3C"
    doAssert $p.header.address3 == "34:8F:27:5E:1C:3C"
    doAssert p.header.frameControl.getType() == Management
    doAssert p.getSSID().get() == "ASK4 Wireless (802.1x)"

  block test4:
    const data = "\x00\x00\x19\x00o\x08\x00\x00\x13\x8C\x1E\x00\x00\x00\x00\x00Z0\x90\x15@\x01\xAD\xA7\x01\x12\x8C\xA1l\xFE\xAD\x1B{\xD3\x9B\x0AT~\xD6"
    let radiotap = parseRadiotap(data)

    doAssertRaises(ValueError):
      let p = parsePacket(radiotap.data)
