import strutils, os, options, tables, times, strformat

import pcap/wrapper
import corewlan

import radiotap, packet

proc getPacket(pcap: pcap_t): Option[Packet] =
  var packet: ptr pcap_pkthdr
  var buffer: cstring
  let ret = pcap_next_ex(pcap, addr packet, addr buffer)
  case ret
  of 0:
    return none(Packet)
  of 1:
    assert buffer != nil
    # Copy data buffer.
    var data = newString(packet.caplen)
    copyMem(addr data[0], buffer, data.len)

    let radiotap = parseRadiotap(data)
    if radiotap.header.len >= packet.caplen:
      return none(Packet)

    let packet = parsePacket(radiotap.data)
    if packet.calculatedFCS != packet.receivedFCS:
      echo("Skipping packet due to CRC check failure")
      return getPacket(pcap)
    return some(packet)
  else:
    pcap.checkError(ret)

proc monitor(): pcap_t =
  # Set up PCAP.
  var err = newString(PCAP_ERRBUF_SIZE)
  var p = pcap_open_live(defaultIfName, 65536.cint, 1.cint, 1.cint, addr(err))

  if p.isNil():
    raise newException(OSError, "Could not open pcap")

  p.checkError p.pcap_set_datalink(DLT_IEEE802_11_RADIO)

  return p

proc findChannels(ssid: string=""): seq[CWChannel] =
  ## Finds a list of channels on which the specified SSID operates on.
  ##
  ## If the ``ssid`` is not specified, then the currently connected to
  ## SSID is used.
  result = @[]

  let wfc = sharedWiFiClient()
  let wif = wfc.getInterface()
  var ssid = ssid
  if ssid.len == 0:
    ssid = $toCString(wif.ssid())
    echo("Using current SSID: ", ssid)

  echo("Disassociating...")
  wif.disassociate()

  let pcap = monitor()

  let channels = wif.supportedWLANChannels
  for channel in items(CWChannel, channels.allObjects):
    wif.setWLANChannel(channel)
    echo("\nTesting ", channel.channelNumber)
    # Wait for beacon on this channel.
    let startTime = epochTime()
    # Grab packets for 4s.
    while epochTime() - startTime < 4:
      try:
        let packetOpt = getPacket(pcap)
        if packetOpt.isSome:
          let packet = packetOpt.get()
          let packetType = packet.header.frameControl.getType()
          if packetType == Management:
            let subtype = packet.header.frameControl.getManagementSubtype()
            if subtype == Beacon:
              echo("\nBeacon with SSID: ", packet.getSSID().get("None"))
              if packet.getSSID().get("") == ssid:
                echo("Added ", channel.channelNumber)
                result.add(channel)
                break
      except Exception as exc:
        echo("Failed ", exc.msg)


proc gatherMacs() =
  let wfc = sharedWiFiClient()
  let wif = wfc.getInterface()
  echo("Current SSID: ", toCString(wif.ssid()))

  echo("Disassociating...")
  wif.disassociate()

  # Set up PCAP.
  var p = monitor()

  # Set up storage for MAC addresses.
  var macs = initCountTable[string]()
  while true:
    try:
      let packet = getPacket(p).get()
      macs.inc($packet.header.address1)
      macs.inc($packet.header.address2)
      macs.inc($packet.header.address3)

    except ValueError as exc:
      echo("Failed ", exc.msg)

    echo(macs)
    sleep(500)

when isMainModule:
  let command = paramStr(1)

  case command.normalize()
  of "findchannels":
    let channels = findChannels()
    for channel in channels:
      echo(fmt"Channel(number: {channel.channelNumber()}, ",
           fmt"band: {channel.channelBand()}, ",
           fmt"width: {channel.channelWidth()})")
  of "gathermacs":
    gatherMacs()
  else:
    assert false