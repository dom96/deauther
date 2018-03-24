import strutils, os, options, tables, times, strformat, asyncdispatch, logging
import algorithm, future

import pcap/[wrapper, async]
import corewlan
import nimbox

import radiotap, packet, tui, listboxlogger

type
  Stage = enum
    Menu, SelectSSID, Macs

  Deauther = ref object
    nb: NimBox
    current: Stage
    currentSSID: string
    crcFails: int
    macsBox, ssidBox: ListBox
    messagesOverlay: bool
    logger: ListBoxLogger

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

when false:
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
      accessPoints[$network.bssid.toCString()] = network

  # Set up storage for MAC addresses.
  var macs = initOrderedTable[string, tuple[tx, rx: int, ch: CWChannel, rssi: int]]()
  while deauther.current == Macs:
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
          if bssid.toUpperAscii() notin [
              $packet.header.address1, $packet.header.address2
            ]:
            info("Skipping ", $packet.header.address1, "<-", $packet.header.address2)
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

    # Update UI
    macs.sort((x, y) => -cmp(x[1].tx + x[1].rx, y[1].tx + y[1].rx))
    deauther.macsBox.data.values = @[]
    for key, value in macs:
      deauther.macsBox.data.values.add(@[
        key, $value.tx, $value.rx, $value.ch.channelNumber, $value.rssi
      ])



    await sleepAsync(200)

proc selectSSID(deauther: Deauther) {.async.} =
  let wfc = sharedWiFiClient()
  let wif = wfc.getInterface()

  while deauther.current == SelectSSID:
    deauther.ssidBox.data.values = @[]

    # In case we ever want to probe manually. This explains how the OS does it
    # https://networkengineering.stackexchange.com/a/17225/46039

    let networks = wif.cachedScanResults()
    for network in items(CWNetwork, networks.allObjects()):
      deauther.ssidBox.data.values.add(@[
        $network.ssid.toCString(), $network.bssid.toCString(),
        $network.wlanChannel.channelNumber,
        $network.rssiValue
      ])

    deauther.ssidBox.data.values.sort((x, y) => cmp(x[3], y[3]))

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
    ("Q", "Quit")
  ]
  case deauther.current
  of Menu:
    controls =
      @({ "1": "SSID", "2": "Scan"}) & controls
  of SelectSSID:
    deauther.nb.drawStats(
      {
        "SSID": deauther.currentSSID
      }
    )

    deauther.nb.draw(deauther.ssidBox, 3)
  of Macs:
    deauther.nb.drawStats(
      {
        "SSID": deauther.currentSSID,
        "CRC check fails": $deauther.crcFails
      }
    )

    # Draw list box.
    deauther.nb.draw(deauther.macsBox, 3)

  deauther.nb.drawControls(controls)

  if deauther.messagesOverlay:
    deauther.nb.draw(deauther.logger.lb, 3)

  deauther.nb.present()

when isMainModule:
  let deauther = newDeauther()
  defer: deauther.nb.shutdown()

  # Set up UI elements.
  deauther.logger = newListBoxLogger()
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
              deauther.current = Macs
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