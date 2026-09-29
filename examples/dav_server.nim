## WebDAV Class 1 server on top of powpow, disk-backed via flysystem.
##
## Run:
##   clue build examples/dav_server.nim --out:bin/dav_server
##   ./bin/dav_server [root] [port]   # defaults: ./davroot 9001
##
## Test:
##   curl -X OPTIONS http://localhost:9001/ -i
##   curl -X PUT http://localhost:9001/hello.txt -d 'hi' -i
##   curl -X PROPFIND http://localhost:9001/ -H 'Depth: 1' -i
##
## IMPORTANT: `import ndav` must come before any direct `import powpow`
## so the DAV verbs are staged before powpow compiles.

import ndav
import std/[os, strutils]

let root = if paramCount() >= 1: paramStr(1) else: getCurrentDir() / "davroot"
let port = if paramCount() >= 2: parseInt(paramStr(2)) else: 9001

let srv = newDavServer(newLocalDriver(root))

echo "webdav Class 1 serving " & root & " on http://localhost:" & $port
echo "  Press Ctrl+C to stop"
newHttpServer().start(srv.davHandler(), Port(port))
