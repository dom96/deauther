import strutils, os, options, tables

import pcap/wrapper
import corewlan

import radiotap, packet

proc getPacket(pcap: pcap_t): Packet =
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

    let packet = parsePacket(radiotap.data)
    if packet.calculatedFCS != packet.receivedFCS:
      echo("Skipping packet due to CRC check failure")
      return getPacket(pcap)
    return packet
  else:
    pcap.checkError(ret)

when isMainModule:
  let wfc = sharedWiFiClient()
  let wif = wfc.getInterface()
  echo("Current SSID: ", toCString(wif.ssid()))

  echo("Disassociating...")
  wif.disassociate()

  # Set up PCAP.
  var err = newString(PCAP_ERRBUF_SIZE)
  var p = pcap_open_live(defaultIfName, 65536.cint, 1.cint, 1.cint, addr(err))

  # Set up storage for MAC addresses.
  var macs = initCountTable[string]()

  if not p.isNil():
    p.checkError p.pcap_set_datalink(DLT_IEEE802_11_RADIO)
    while true:
      try:
        let packet = getPacket(p)
        macs.inc($packet.header.address1)
        macs.inc($packet.header.address2)
        macs.inc($packet.header.address3)

      except ValueError as exc:
        echo("Failed ", exc.msg)

      echo(macs)
      sleep(500)
  else:
    echo "Could not open pcap"