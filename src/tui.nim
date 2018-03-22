import strutils, os, sequtils, math

import nimbox

proc drawText(nb: NimBox, y: int, text: string, fg, bg: Color) =
  let middle = nb.width div 2 - (text.len div 2)
  nb.print(middle, y, text, fg=fg, bg=bg)

proc drawTitle(nb: NimBox) =
  nb.print(2, 0, " ".repeat(nb.width() - 3), bg=clrBlue)
  nb.drawText(0, "Deauther", clrWhite, clrBlue)

type
  ListBoxData* = object
    columnCount: int
    columnLabels: seq[string]
    values: seq[seq[string]]

  ListBox* = ref object
    width, height: int
    style*: array[6, string]
    data: ListBoxData

proc newListBox(width, height: int, data: ListBoxData): ListBox =
  ListBox(
    width: width,
    height: height,
    style: ["┌", "┐", "┘", "└", "─", "│"],
    data: data
  )

proc calcSizes(lb: ListBox): seq[int] =
  result = @[]
  for i, val in pairs(lb.data.values[0]):
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
    result = label[0 ..^ -diff] # TODO: Ellipsis?

proc draw(nb: NimBox, lb: ListBox, y: int) =
  ## Draws a list box in the middle of the screen starting at location y on
  ## the y-axis.

  let x = nb.width div 2 - lb.width div 2

  # Top line
  for curX in x..x+lb.width:
    nb.print(curX, y, lb.style[4], fg=clrWhite)

  # Bottom line
  for curX in x..x+lb.width:
    nb.print(curX, y+lb.height, lb.style[4], fg=clrWhite)

  # Left line
  for curY in y..y+lb.height:
    nb.print(x, curY, lb.style[5], fg=clrWhite)

  # Right line
  for curY in y..y+lb.height:
    nb.print(x+lb.width, curY, lb.style[5], fg=clrWhite)

  # Corners
  nb.print(x, y, lb.style[0], fg=clrWhite)
  nb.print(x+lb.width, y, lb.style[1], fg=clrWhite)
  nb.print(x, y+lb.height, lb.style[3], fg=clrWhite)
  nb.print(x+lb.width, y+lb.height, lb.style[2], fg=clrWhite)

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
        nb.print(curX, curY, lb.style[5], fg=clrWhite)
        curX.inc
    curY.inc

  # Draw the values.
  for row in lb.data.values:
    var curX = x+1
    for i, size in pairs(columnSizes):
      let label = row[i].pad(size, false)

      nb.print(curX, curY, label, fg=clrWhite)
      curX.inc label.len

      # Draw the separator
      if i != len(columnSizes)-1:
        nb.print(curX, curY, lb.style[5], fg=clrWhite)
        curX.inc
    curY.inc


when isMainModule:
  var nb = newNimbox()
  defer: nb.shutdown()

  # Draw title header
  nb.drawTitle()

  # Draw list box.
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
  nb.draw(lb, 3)

  for i in 1..5:
    nb.cursor = (i, 2)
    nb.present()
    sleep(2000)

