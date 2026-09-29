# Package

version       = "0.1.0"
author        = "George Lemon"
description   = "Fast WebDAV, CalDAV and CardDAV server and client on top of powpow"
license       = "MIT"
srcDir        = "src"
bin           = @["ndav"]
binDir        = "bin"
installExt    = @["ndav"]
installDirs   = @["ndav"]


# Dependencies

requires "nim >= 2.2.0"
requires "powpow >= 0.2.0"
requires "voodoo >= 0.2.0"
requires "openparser >= 0.3.3"
requires "flysystem >= 0.2.0"
requires "mimedb >= 0.1.1"
requires "nimcypher >= 0.2.4"
