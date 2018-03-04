# Package

version       = "0.1.0"
author        = "Dominik Picheta"
description   = "WiFi deauthor PoC"
license       = "MIT"
srcDir        = "src"
bin           = @["deauther"]

skipExt = @["nim"]

# Dependencies

requires "nim >= 0.18.0"
