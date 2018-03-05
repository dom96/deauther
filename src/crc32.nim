import strutils

type Crc32* = uint32
const InitCrc32* = Crc32(-1)

proc createCrcTable(): array[0..255, Crc32] =
  for i in 0..255:
    var rem = Crc32(i)
    for j in 0..7:
      if (rem and 1) > 0'u32: rem = (rem shr 1) xor Crc32(0xedb88320)
      else: rem = rem shr 1
    result[i] = rem

# Table created at compile time
const crc32table = createCrcTable()

proc updateCrc32(c: char, crc: var Crc32) =
  crc = (crc shr 8) xor crc32table[(crc and 0xff) xor ord(c).uint32]

proc crc32*(s: string): Crc32 =
  result = InitCrc32
  for c in s:
    updateCrc32(c, result)
  result = not result

when isMainModule:
  echo crc32("The quick brown fox jumps over the lazy dog").int64.toHex(8)