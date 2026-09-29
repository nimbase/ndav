# Package

version       = "0.1.0"
author        = "George Lemon"
description   = "WebDAV, CalDAV/CardDAV server and client. Powered by PowPow"
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
requires "blackpaper >= 0.2.0"
