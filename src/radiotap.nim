## Simple parsing support for radiotap.
##
## http://www.radiotap.org/

type
  RadiotapHeader* = object
    version*, pad*: uint8
    len*: uint16 ## the entire length of the radio tap data (including header).
    present*: uint32

proc parseRadiotapHeader*(packet: cstring): ptr RadiotapHeader =
  return cast[ptr RadiotapHeader](packet)
