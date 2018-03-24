import strutils, os, options, tables, times, strformat, asyncdispatch, logging

import pcap/[wrapper, async]
import corewlan
import nimbox

import radiotap, packet, tui, listboxlogger

type
  Stage = enum
    Menu, Macs

  Deauther = ref object
    nb: NimBox
    current: Stage
    currentSSID: string
    crcFails: int
    macsBox: ListBox
    messagesOverlay: bool
    logger: ListBoxLogger

proc getPacket(pcap: AsyncPcap,
               deauther: Deauther): Future[Option[Packet]] {.async.} =
  let data = await pcap.readPacket()

  let radiotap = parseRadiotap(data)
  if radiotap.header.len.int >= data.len:
    return none(Packet)

  let packet = parsePacket(radiotap.data)
  if packet.calculatedFCS != packet.receivedFCS:
    deauther.crcFails.inc()
    return await getPacket(pcap, deauther)
  return some(packet)

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
  deauther.currentSSID = $toCString(wif.ssid())

  info("Disassociating...")
  wif.disassociate()

  # Set up PCAP.
  var p = monitor()

  # Set up storage for MAC addresses.
  var macs = initCountTable[string]()
  while true:
    let packetFut = getPacket(p, deauther)
    yield packetFut
    if packetFut.failed:
      error("Failed ", packetFut.error.msg)
    else:
      let packet = packetFut.read.get()
      macs.inc($packet.header.address1)
      macs.inc($packet.header.address2)
      macs.inc($packet.header.address3)

    # Update UI
    deauther.macsBox.data.values = @[]
    for key, value in macs:
      deauther.macsBox.data.values.add(@[key, $value])

proc newDeauther(): Deauther =
  result = Deauther(
    nb: newNimbox(),
    current: Menu,
    currentSSID: "",
    macsBox: newListBox(
      50, 20,
      initListBoxData(@["MAC", "Packets"])
    )

  )

proc draw(deauther: Deauther) =
  deauther.nb.clear()

  # Draw title header
  deauther.nb.drawTitle("Deauther")

  case deauther.current
  of Menu:
    deauther.nb.drawControls(
      {
        "1": "Scan radio waves for packets",
        "Q": "Quit"
      }
    )
  of Macs:
    deauther.nb.drawStats(
      {
        "SSID": deauther.currentSSID,
        "CRC check fails": $deauther.crcFails
      }
    )

    # Draw list box.
    deauther.nb.draw(deauther.macsBox, 3)

    deauther.nb.drawControls(
      {
        "Q": "Quit"
      }
    )

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
        of Symbol.Character:
          case evt.ch
          of 'q': break
          of 'm':
            deauther.messagesOverlay = not deauther.messagesOverlay
          of '1':
            if deauther.current == Menu:
              deauther.current = Macs
              asyncCheck gatherMacs(deauther)
          else:
            info("Key pressed: ", evt.ch)
        of Symbol.Down:
          deauther.logger.lb.onDown()
          deauther.macsBox.onDown()
        of Symbol.Up:
          deauther.logger.lb.onUp()
          deauther.macsBox.onUp()
        else: discard
      else: discard