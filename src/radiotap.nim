## Simple parsing support for radiotap.
##
## http://www.radiotap.org/
## https://github.com/radiotap/python-radiotap/blob/master/radiotap/radiotap.py
import endians, logging

type
  RadiotapHeader* = object
    version*, pad*: uint8
    len*: uint16 ## the entire length of the radio tap data (including header).
    present*: uint32

  Radiotap* = object
    header*: RadiotapHeader
    tsft*: uint64 ## microseconds
    flags*: uint8
    rate*: uint8
    channel*: tuple[freq, flags: uint16]
    fhss*: tuple[hopSet, hopPattern: uint8]
    antennaSignal*: int8
    antennaNoise*: int8
    antenna*: uint8
    xchannel*: tuple[flags: uint32, freq: uint16, channel, maxPower: uint8]
    mpdu*: tuple[refNumber: uint32, flags: uint16, crc, reserver: uint8]
    vht*: VHT
    data*: string ## The non-radiotap data.

  VHT* = object
    known*: uint16
    flags*, bandwidth*: uint8
    mcsNss*: array[4, uint8]
    coding*: uint8
    groupId*: uint8
    partialAid*: uint16

proc parseRadiotapHeader*(packet: string): RadiotapHeader {.inline.} =
  var p = packet
  littleEndian64(addr result, addr p[0])

proc align(value: var int, align: int) =
  value = (value + align-1) and not (align-1)

proc parseRadiotap*(packet: string): Radiotap =
  var p = packet
  result.header = parseRadiotapHeader(p)

  var offset = 8 # Start at end of RadiotapHeader.
  var present = result.header.present
  # Skip all `it_present` "words".
  while (present and (1 shl 31)) != 0:
    littleEndian32(addr present, addr p[offset])
    offset.inc(4)

  # TODO: Support for namespaces.

  for i in 0..<32:
    if (present and uint32(1 shl i)) != 0:
      case i
      of 0:
        # TSFT aka MAC timestamp
        # http://www.radiotap.org/fields/TSFT.html
        align(offset, 8)
        littleEndian64(addr result.tsft, addr p[offset])
        offset.inc(8)
      of 1:
        # Flags
        # http://www.radiotap.org/fields/Flags.html
        copyMem(addr result.flags, addr p[offset], 1)
        offset.inc(1)
      of 2:
        # Rate
        # http://www.radiotap.org/fields/Rate.html
        copyMem(addr result.rate, addr p[offset], 1)
        offset.inc(1)
      of 3:
        # Channel
        align(offset, 2)
        littleEndian32(addr result.channel, addr p[offset])
        offset.inc(4)
      of 4:
        # FHSS
        littleEndian16(addr result.fhss, addr p[offset])
        offset.inc(2)
      of 5:
        # Antenna signal
        copyMem(addr result.antennaSignal, addr p[offset], 1)
        offset.inc(1)
      of 6:
        # Antenna noise
        copyMem(addr result.antennaNoise, addr p[offset], 1)
        offset.inc(1)
      of 11:
        # Antenna index
        copyMem(addr result.antenna, addr p[offset], 1)
        offset.inc(1)
      of 18:
        # XChannel
        # http://www.radiotap.org/fields/XChannel.html
        littleEndian64(addr result.xchannel, addr p[offset])
        offset.inc(8)
      of 20:
        # A-MPDU
        # http://www.radiotap.org/fields/A-MPDU%20status.html
        littleEndian64(addr result.mpdu, addr p[offset])
        offset.inc(8)
      of 21:
        # VHT
        # http://www.radiotap.org/fields/VHT.html
        littleEndian16(addr result.vht.known, addr p[offset])
        offset.inc(2)
        littleEndian16(addr result.vht.flags, addr p[offset])
        offset.inc(2)
        littleEndian32(addr result.vht.mcsNss, addr p[offset])
        offset.inc(4)
        littleEndian16(addr result.vht.coding, addr p[offset])
        offset.inc(2)
        littleEndian16(addr result.vht.partialAid, addr p[offset])
        offset.inc(2)
      else:
        warn("Radiotap unknown field ", i)

  # Store the rest as data.
  result.data = p[result.header.len .. ^1]

when isMainModule:
  block test1:
    const data = "\x00\x00\x19\x00o\x08\x00\x00}L4\xF1\x00\x00\x00\x00\x12\x0C\xCC\x15@\x01\xAA\xA3\x01\xA4\x10\x05\xC04\x8F\'\x1E\x1F\x8C\xD0\x13\xFD&o\xFF\x1C\xA7#\xCC"
    let radiotap = parseRadiotap(data)
    echo radiotap

  block test2:
    const data = "\x00\x00\x19\x00o\x08\x00\x00P\x11\xF1\xEF\x00\x00\x00\x00\x12\x0C\xCC\x15@\x01\xC8\xA3\x01\x80\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF4\x8F\'\x1E\x1C<4\x8F\'\x1E\x1C<\xB0W;\xB0\x7F\xD7K\x08\x00\x00d\x00\x01\x11\x00\x0DASK4 Wireless\x01\x08\x8C\x12\x98$\xB0H`l\x03\x01t\x05\x04\x00\x01\x00@\x07\x0AGB d\x05\x1E\x84\x02\x1E\x00\xDD\x18\x00P\xF2\x02\x01\x01\x82\x00\x03\xA4\x00\x00\'\xA4\x00\x00BC^\x00b2/\x00F\x05\x02\x00\x00\x00\x00-\x1A\xEF\x19\x1B\xFF\xFF\xFF\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00=\x16t\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0B\x05\x08\x00\x0F\x00\x00\x7F\x08\x00\x00\x08\x00\x00\x00\x00@\xBF\x0C\x92\x01\x80#\xEA\xFF\x00\x00\xEA\xFF\x00\x00\xC0\x05\x00\x00\x00\xFC\xFF\xC3\x05\x03<<<\x05\xDD\x08\x00\x13\x92\x01\x00\x01\x05\x00\\h;\x0B"
    let radiotap = parseRadiotap(data)
    echo radiotap

  block test3:
    const data = "\x00\x00\x19\x00o\x08\x00\x00\xA8\x01\x92\xEE\x00\x00\x00\x00\x12\x0C\xCC\x15@\x01\xB1\xA3\x01\x80\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF4\x8F\'\x1E\x1F\x8C4\x8F\'\x1E\x1F\x8C\x10\x0B;\xD0\x04\xD7K\x08\x00\x00d\x00\x01\x11\x00\x0DASK4 Wireless\x01\x08\x8C\x12\x98$\xB0H`l\x03\x01t\x05\x04\x00\x01\x00(\x07\x0AGB d\x05\x1E\x84\x02\x1E\x00\xDD\x18\x00P\xF2\x02\x01\x01\x8C\x00\x03\xA4\x00\x00\'\xA4\x00\x00BC^\x00b2/\x00F\x05\x02\x00\x00\x00\x00-\x1A\xEF\x19\x1B\xFF\xFF\xFF\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00=\x16t\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0B\x05\x02\x00\x03\x00\x00\x7F\x08\x00\x00\x08\x00\x00\x00\x00@\xBF\x0C\x92\x01\x80#\xEA\xFF\x00\x00\xEA\xFF\x00\x00\xC0\x05\x00\x00\x00\xFC\xFF\xC3\x05\x03<<<\x05\xDD\x08\x00\x13\x92\x01\x00\x01\x05\x00\x9D6\x00\x91"
    let radiotap = parseRadiotap(data)
    echo radiotap

  block test4:
    const data = "\x00\x00\x19\x00\x6f\x08\x00\x00\xbe\x2a\x2d\x00\x00\x00\x00\x00\x10\x04\x9e\x09\x80\x04\xc8\xad\x00"
    let radiotap = parseRadiotap(data)
    doAssert radiotap.header.version == 0
    doAssert radiotap.header.present == 2159
    doAssert radiotap.tsft == 2960062
    doAssert radiotap.antennaSignal == 200
    doAssert radiotap.antennaNoise == 173
    echo radiotap