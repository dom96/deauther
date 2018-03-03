import pcap/wrapper

proc getPacket(pcap: pcap_t) =
  var packet: ptr pcap_pkthdr
  var data: cstring
  let ret = pcap_next_ex(pcap, addr packet, addr data)
  case ret
  of 0:
    echo("Timed out")
  of 1:
    assert data != nil
    echo("Data received")
    echo(packet.len, ", ", packet.caplen, " ", $packet.ts)

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