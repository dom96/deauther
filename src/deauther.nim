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
    echo("Data received")
    let header = parseRadiotapHeader(buffer)
    echo(header.version, " ", header.len, " ", header.present)
    if header.len >= packet.caplen:
      return

    # Copy data buffer.
    var data = newString(packet.caplen)
    copyMem(addr data[0], addr buffer, data.len)
    data = data[header.len .. ^1] # Skip the radiotap header.
    echo data.len
    let ieee802packet = parsePacket(data)
    echo(ieee802packet)
    echo "ecas"
  else:
    pcap.checkError(ret)

when isMainModule:
  var err = newString(PCAP_ERRBUF_SIZE)
  var p = pcap_open_live(defaultIfName, 65536.cint, 1.cint, 1.cint, addr(err))

  if not p.isNil():
    p.checkError p.pcap_set_datalink(DLT_IEEE802_11_RADIO)
    getPacket(p)

  else:
    echo "Could not open pcap"