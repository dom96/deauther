import strutils, os

import pcap/wrapper

import radiotap, packet

proc getPacket(pcap: pcap_t) =
  var packet: ptr pcap_pkthdr
  var buffer: cstring
  let ret = pcap_next_ex(pcap, addr packet, addr buffer)
  case ret
  of 0:
    echo("Timed out")
  of 1:
    assert buffer != nil
    # Copy data buffer.
    var data = newString(packet.caplen)
    copyMem(addr data[0], buffer, data.len)

    let radiotap = parseRadiotap(data)
    if radiotap.header.len >= packet.caplen:
      return

    let ieee802packet = parsePacket(radiotap.data)
    echo(ieee802packet.header)
    if ieee802packet.calculatedFCS != ieee802packet.getFCS:
      echo("  Packet CRC doesn't match")
  else:
    pcap.checkError(ret)

when isMainModule:
  var err = newString(PCAP_ERRBUF_SIZE)
  var p = pcap_open_live(defaultIfName, 65536.cint, 1.cint, 1.cint, addr(err))

  if not p.isNil():
    p.checkError p.pcap_set_datalink(DLT_IEEE802_11_RADIO)
    while true:
      try:
        getPacket(p)
      except ValueError as exc:
        echo("Failed ", exc.msg)

      sleep(500)
  else:
    echo "Could not open pcap"