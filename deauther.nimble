# Package

version       = "0.1.0"
author        = "Dominik Picheta"
description   = "WiFi deauthor PoC"
license       = "MIT"
srcDir        = "src"
bin           = @["deauther"]
backend = "objc"

skipExt = @["nim"]

# Dependencies

requires "nim >= 0.18.0"
requires "https://github.com/dom96/oui#head"
requires "https://github.com/dom96/nimbox"
requires "https://github.com/dom96/corewlan"
requires "https://github.com/dom96/pcap"