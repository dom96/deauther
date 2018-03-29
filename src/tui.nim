import strutils, os, sequtils, math, unicode, future, algorithm, future, options

import nimbox

proc drawText(nb: NimBox, y: int, text: string, fg, bg: Color) =
  let middle = nb.width div 2 - (text.len div 2)
  nb.print(middle, y, text, fg=fg, bg=bg)

proc drawTitle*(nb: NimBox, title: string) =
  nb.print(2, 0, " ".repeat(nb.width() - 3), bg=clrBlue)
  nb.drawText(0, title, clrWhite, clrBlue)

proc drawStats*(nb: NimBox, stats: openarray[tuple[label, value: string]]) =
  nb.print(2, 1, " ".repeat(nb.width() - 3), bg=clrWhite)

  var x = 2
  for stat in stats:
    nb.print(x, 1, stat.label & ":", fg=clrBlack, bg=clrWhite, style=styBold)
    x.inc(stat.label.runeLen + 2)

    nb.print(x, 1, stat.value, fg=clrBlack, bg=clrWhite)
    x.inc(stat.value.runeLen)

    x.inc(2) # Spacing between stats.

proc drawControls*(nb: NimBox, controls: openarray[tuple[key, desc: string]]) =
  nb.print(2, nb.height()-1, " ".repeat(nb.width() - 3), bg=clrCyan)

  var maxDescSize = controls.map(x => x.desc.len).max()

  var x = 2
  for control in controls:
    # TODO: All this padding can be refactored into a nice drawing function.
    let paddedKey = " ".repeat(max(0, 2-control.key.len)) & control.key
    nb.print(x, nb.height()-1, paddedKey, fg=clrDefault, bg=clrDefault)
    x.inc(paddedKey.runeLen)

    let paddedDesc = control.desc & " ".repeat(
      max(0, maxDescSize-control.desc.len)
    )
    nb.print(x, nb.height()-1, paddedDesc, fg=clrBlack, bg=clrCyan)
    x.inc(paddedDesc.runeLen)

type
  ListBoxValue* = object
    text: string
    fg: Color
    bg: Color
    style: Style

  ListBoxData* = object
    columnCount: int
    columnLabels: seq[string]
    values: seq[seq[ListBoxValue]]

  ListBoxStyle* = object
    border*: array[6, string]
    fg*: Color
    bg*: Color
    selectionBg*: Color
    selectionFg*: Color

  ListBox* = ref object
    width, height: int
    style*: ListBoxStyle
    data: ListBoxData
    selectedIndex: int
    firstItemInView: int ## Used for scrolling

proc initListBoxData*(columnLabels: seq[string]): ListBoxData =
  ListBoxData(
    columnCount: columnLabels.len,
    columnLabels: columnLabels,
    values: @[]
  )

proc add*(lb: ListBox, data: seq[string], fg, bg: Color, style = styNone) =
  var value: seq[ListBoxValue] = @[]
  for t in data:
    value.add(
      ListBoxValue(
        text: t, fg: fg, bg: bg, style: style
      )
    )
  lb.data.values.add(value)

proc add*(lb: ListBox, data: seq[string], fg: Color) =
  lb.add(data, fg, lb.style.bg)

proc add*(lb: ListBox, data: seq[string]) =
  lb.add(data, lb.style.fg, lb.style.bg)

proc clear*(lb: ListBox) =
  lb.data.values = @[]

proc sort*(lb: ListBox, cmp: proc (x, y: seq[string]): int) =
  lb.data.values.sort((x, y) => (
    cmp(x.map(a => a.text), y.map(b => b.text))
  ))

proc initListBoxStyle*(): ListBoxStyle =
  result.border = ["┌", "┐", "┘", "└", "─", "│"]
  result.fg = clrWhite
  result.bg = clrDefault
  result.selectionBg = clrCyan
  result.selectionFg = clrBlack

proc newListBox*(width, height: int, data: ListBoxData): ListBox =
  ListBox(
    width: width,
    height: height,
    style: initListBoxStyle(),
    data: data,
    selectedIndex: 0,
    firstItemInView: 0
  )

proc distanceFromVisibility(lb: ListBox, index: int): int =
  ## Returns the number of positions this item is away from being visible.
  let drawableHeight = lb.height - 3 # Borders (2) + Column (1)
  return max(0, index - drawableHeight - lb.firstItemInView)

proc scroll(lb: ListBox) =
  # Check if selected index is off the screen.
  if lb.selectedIndex < lb.firstItemInView:
    lb.firstItemInView = lb.selectedIndex
  else:
    let dist = lb.distanceFromVisibility(lb.selectedIndex)
    if dist != 0:
      lb.firstItemInView.inc(dist)

proc onDown*(lb: ListBox) =
  lb.selectedIndex.inc

  if lb.selectedIndex >= lb.data.values.len:
    lb.selectedIndex = 0

  scroll(lb)

proc onUp*(lb: ListBox) =
  lb.selectedIndex.dec

  if lb.selectedIndex < 0:
    lb.selectedIndex = lb.data.values.len-1

  scroll(lb)

proc select*(lb: ListBox, index: int) =
  assert index >= 0 and index < lb.data.values.len
  lb.selectedIndex = index

  scroll(lb)

proc select*(lb: ListBox, val: string, col: int) =
  ## Searches for the specified value in the specified column. If it is found
  ## then it selects it.
  for i in 0..< lb.data.values.len:
    if lb.data.values[i][col].text == val:
      lb.selectedIndex = i
      break

  scroll(lb)

proc getSelectedRow*(lb: ListBox): Option[seq[string]] =
  if lb.data.values.len == 0:
    # Return none when there are no values. If selectedIndex points to an
    # incorrect index then that should still raise.
    return none(seq[string])
  return some(lb.data.values[lb.selectedIndex].map(x => x.text))

proc calcSizes(lb: ListBox): seq[int] =
  result = @[]

  let data = # Use the first row, or the columns if there are no rows.
    if lb.data.values.len > 0:
      map(lb.data.values[0], x => x.text)
    else: lb.data.columnLabels
  for i, val in pairs(data):
    result.add(max(val.len, lb.data.columnLabels[i].len+2))

  let sum = foldl(result, a + b + 1)
  let diff = sum - lb.width+2
  if diff > 0:
    # Just resize the first column for now and hope for the best.
    result[0] = max(0, result[0] - diff)
  elif diff < 0:
    # Increase the size so that the full list box is filled.
    result[0] = result[0] + -diff

proc pad(label: string, len: int, centre: bool): string =
  let diff = len-label.len
  if diff > 0:
    if centre:
      result = " ".repeat(ceil(diff / 2).int) & label &
               " ".repeat(floor(diff / 2).int)
    else:
      result = label & " ".repeat(diff)
  else:
    result = label[0 ..< ^(-diff)] # TODO: Ellipsis?

proc draw*(nb: NimBox, lb: ListBox, y: int) =
  ## Draws a list box in the middle of the screen starting at location y on
  ## the y-axis.

  let x = nb.width div 2 - lb.width div 2

  # Top line
  for curX in x..x+lb.width:
    nb.print(curX, y, lb.style.border[4], fg=clrWhite)

  # Bottom line
  for curX in x..x+lb.width:
    nb.print(curX, y+lb.height, lb.style.border[4], fg=clrWhite)

  # Left line
  for curY in y..y+lb.height:
    nb.print(x, curY, lb.style.border[5], fg=clrWhite)

  # Right line
  for curY in y..y+lb.height:
    nb.print(x+lb.width, curY, lb.style.border[5], fg=clrWhite)

  # Corners
  nb.print(x, y, lb.style.border[0], fg=clrWhite)
  nb.print(x+lb.width, y, lb.style.border[1], fg=clrWhite)
  nb.print(x, y+lb.height, lb.style.border[3], fg=clrWhite)
  nb.print(x+lb.width, y+lb.height, lb.style.border[2], fg=clrWhite)

  var curY = y+1
  let columnSizes = calcSizes(lb)
  # Draw columns
  block:
    var curX = x+1
    for i, size in pairs(columnSizes):
      var label = lb.data.columnLabels[i]

      # Pad or shorten the string
      label = pad(label, size, true)

      # Draw the column label.
      nb.print(curX, curY, label, fg=clrYellow)
      curX.inc label.len

      # Draw the separator
      if i != len(columnSizes)-1:
        nb.print(curX, curY, lb.style.border[5], fg=clrWhite)
        curX.inc
    curY.inc

  # Draw the values.
  for rowI, row in pairs(lb.data.values):
    # Skip for scrolling.
    if rowI < lb.firstItemInView: continue

    var curX = x+1
    for colI, size in pairs(columnSizes):
      let label = row[colI].text.pad(size, false)

      let fgColor =
        if rowI == lb.selectedIndex:
          lb.style.selectionFg
        else:
          row[colI].fg
      let bgColor =
        if rowI == lb.selectedIndex:
          lb.style.selectionBg
        else:
          row[colI].bg
      nb.print(curX, curY, label, fg=fgColor, bg=bgColor)
      curX.inc label.len

      # Draw the separator
      if colI != len(columnSizes)-1:
        nb.print(curX, curY, lb.style.border[5], fg=fgColor, bg=bgColor)
        curX.inc
    curY.inc

    # Don't draw past height of box.
    if curY > y + lb.height - 1: break

when isMainModule:
  var nb = newNimbox()
  defer: nb.shutdown()

  let lb = newListBox(
    50, 20,
    ListBoxData(
      columnCount: 2,
      columnLabels: @["MAC", "Packets"],
      values: @[
        @["2D:F3:1D:23:2E", "123"],
        @["8E:F3:1E:2A:1E", "12"]
      ]
    )
  )

  for i in 0..50:
    lb.data.values.add(@["8E:F3:1E:2A:1E", $i])

  var evt: Event
  while true:
    nb.clear()
    # Draw title header
    nb.drawTitle("Deauther")
    nb.drawStats(
      {
        "CRC fails": "54",
        "Errors": "12"
      }
    )

    # Draw list box.
    nb.draw(lb, 3)

    # Draw controls.
    nb.drawControls(
      {
        "Enter": "Select",
        "Q": "Quit"
      }
    )
    nb.present()

    evt = nb.peekEvent(1000)
    case evt.kind:
      of EventType.Key:
        case evt.sym
        of Symbol.Escape:
          break
        of Symbol.Character:
          if evt.ch == 'q': break
        of Symbol.Down:
          lb.onDown()
        of Symbol.Up:
          lb.onUp()
        else: discard
      else: discard

