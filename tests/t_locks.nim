## Class 2 locking: manager units + loopback LOCK/UNLOCK/423 flows.
import std/unittest
import std/strutils
import std/times
import std/httpcore except HttpMethod

import ndav

suite "lock manager units":
  test "exclusive conflicts, shared-shared passes":
    let m = newLockManager()
    discard m.acquire("/f", lsExclusive, 0, "", 3600)
    expect DavLockConflict:
      discard m.acquire("/f", lsExclusive, 0, "", 3600)
    let s = newLockManager()
    discard s.acquire("/f", lsShared, 0, "", 3600)
    discard s.acquire("/f", lsShared, 0, "", 3600)
    expect DavLockConflict:
      discard s.acquire("/f", lsExclusive, 0, "", 3600)

  test "depth infinity covers members both ways":
    let m = newLockManager()
    discard m.acquire("/col", lsExclusive, 2, "", 3600)
    expect DavLockConflict:
      discard m.acquire("/col/x", lsExclusive, 0, "", 3600)
    let m2 = newLockManager()
    discard m2.acquire("/col/x", lsExclusive, 0, "", 3600)
    expect DavLockConflict:
      discard m2.acquire("/col", lsExclusive, 2, "", 3600)
    # ...but a depth-0 collection lock leaves members alone.
    let m3 = newLockManager()
    discard m3.acquire("/col", lsExclusive, 0, "", 3600)
    check m3.findCovering("/col/x").len == 0
    check m3.findCovering("/col").len == 1

  test "refresh/release/expiry":
    let m = newLockManager()
    let l = m.acquire("/f", lsExclusive, 0, "", 3600)
    check m.refresh(l.token, 60) == true
    check m.getToken(l.token).timeout == 60
    check m.refresh("opaquelocktoken:nope", 60) == false
    check m.release(l.token, "/other") == false
    check m.release(l.token, "/f") == true
    check m.getToken(l.token) == nil
    let e = m.acquire("/g", lsExclusive, 0, "", 5)
    e.created = getTime() - initDuration(seconds = 30)
    check m.findCovering("/g").len == 0
    check m.getToken(e.token) == nil

  test "timeout parsing":
    check parseTimeout("Second-60") == 60
    check parseTimeout("Infinite") == -1
    check parseTimeout("Infinite, Second-30") == -1
    check parseTimeout("garbage") == DefaultLockTimeout
    check parseTimeout("Second-999999999") == MaxLockTimeout

  test "if parsing subset":
    let g = parseIf("(<opaquelocktoken:a> <opaquelocktoken:b>)")
    check g.len == 1
    check g[0].tokens.len == 2
    check g[0].tokens[0].negated == false
    let n = parseIf("(Not <opaquelocktoken:a>)")
    check n[0].tokens[0].negated == true
    let t = parseIf("<http://x/y> (<opaquelocktoken:c>)")
    check t[0].resource == "http://x/y"
    check parseIf("([\"etag1\"])").len == 0

  test "ifSatisfied gate":
    let m = newLockManager()
    check m.ifSatisfied("/f", "", @[]) == true
    let l = m.acquire("/f", lsExclusive, 0, "", 3600)
    check m.ifSatisfied("/f", "", @[]) == false
    check m.ifSatisfied("/f", "(<" & l.token & ">)") == true
    check m.ifSatisfied("/f", "(Not <" & l.token & ">)") == false
    check m.ifSatisfied("/f", "", @[l.token]) == true
    check m.ifSatisfied("/f", "", @["opaquelocktoken:no"]) == false

proc lockTokenOf(res: auto): string =
  let v: string = res.getHeaders()["Lock-Token"]
  v.strip(chars = {'<', '>'})

suite "lock/unlock loopback":
  test "exclusive lock, conflict, unlock, relock":
    let client = newHttpClient()
    let srv = newDavServer(newMemoryDriver())
    let server = newHttpServer(client.getLoop())
    server.handler = srv.davHandler()
    server.listen("127.0.0.1", 20952)
    let base = "http://127.0.0.1:20952"
    try:
      discard client.request(HttpPut, base & "/f.txt", "v")
      let info = """<D:lockinfo xmlns:D="DAV:"><D:lockscope>""" &
        """<D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype>""" &
        """<D:owner>me</D:owner></D:lockinfo>"""
      let l1 = client.request(HttpLock, base & "/f.txt", info,
        [("Depth", "0"), ("Timeout", "Second-600"),
         ("Content-Type", "application/xml")])
      check l1.getStatusCode() == Http200
      let tok = lockTokenOf(l1)
      check tok.startsWith("opaquelocktoken:")
      check "Second-600" in l1.getBodyString()
      let l2 = client.request(HttpLock, base & "/f.txt", info,
        [("Depth", "0")])
      check l2.getStatusCode() == Http423
      check client.request(HttpPut, base & "/f.txt", "w",
        [("If", "(<" & tok & ">)")]).getStatusCode() == Http204
      check client.request(HttpUnlock, base & "/f.txt").getStatusCode() == Http400
      check client.request(HttpUnlock, base & "/f.txt", "",
        [("Lock-Token", "<opaquelocktoken:wrong>")]).getStatusCode() == Http409
      check client.request(HttpUnlock, base & "/f.txt", "",
        [("Lock-Token", "<" & tok & ">")]).getStatusCode() == Http204
      let l3 = client.request(HttpLock, base & "/f.txt", info,
        [("Depth", "0")])
      check l3.getStatusCode() == Http200
    finally:
      server.close()
      client.close()

  test "locked put without token is 423, lockdiscovery shows":
    let client = newHttpClient()
    let srv = newDavServer(newMemoryDriver())
    let server = newHttpServer(client.getLoop())
    server.handler = srv.davHandler()
    server.listen("127.0.0.1", 20953)
    let base = "http://127.0.0.1:20953"
    try:
      discard client.request(HttpPut, base & "/g.txt", "v")
      let info = """<D:lockinfo xmlns:D="DAV:"><D:lockscope>""" &
        """<D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype>""" &
        """</D:lockinfo>"""
      let l = client.request(HttpLock, base & "/g.txt", info,
        [("Depth", "0")])
      check l.getStatusCode() == Http200
      # Extract eagerly: the client's pooled parser is recycled by later
      # requests on the same client.
      let tok = lockTokenOf(l)
      check client.request(HttpPut, base & "/g.txt", "w").getStatusCode() == Http423
      check client.request(HttpDelete, base & "/g.txt").getStatusCode() == Http423
      let f = client.request(HttpPropfind, base & "/g.txt",
        """<D:propfind xmlns:D="DAV:"><D:prop><D:lockdiscovery/>""" &
        """</D:prop></D:propfind>""", [("Depth", "0")])
      check tok in f.getBodyString()
    finally:
      server.close()
      client.close()

  test "depth-0 collection lock leaves members writable":
    let client = newHttpClient()
    let srv = newDavServer(newMemoryDriver())
    let server = newHttpServer(client.getLoop())
    server.handler = srv.davHandler()
    server.listen("127.0.0.1", 20954)
    let base = "http://127.0.0.1:20954"
    try:
      discard client.request(HttpMkcol, base & "/col")
      discard client.request(HttpPut, base & "/col/m.txt", "m")
      let info = """<D:lockinfo xmlns:D="DAV:"><D:lockscope>""" &
        """<D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype>""" &
        """</D:lockinfo>"""
      check client.request(HttpLock, base & "/col", info,
        [("Depth", "0")]).getStatusCode() == Http200
      check client.request(HttpPut, base & "/col/m.txt", "m2").getStatusCode() == Http204
      check client.request(HttpLock, base & "/col", info,
        [("Depth", "infinity")]).getStatusCode() == Http423
    finally:
      server.close()
      client.close()

  test "lock creates missing resource, shared-shared passes":
    let client = newHttpClient()
    let srv = newDavServer(newMemoryDriver())
    let server = newHttpServer(client.getLoop())
    server.handler = srv.davHandler()
    server.listen("127.0.0.1", 20955)
    let base = "http://127.0.0.1:20955"
    try:
      let info = """<D:lockinfo xmlns:D="DAV:"><D:lockscope>""" &
        """<D:shared/></D:lockscope><D:locktype><D:write/></D:locktype>""" &
        """</D:lockinfo>"""
      check client.request(HttpLock, base & "/fresh.txt", info,
        [("Depth", "0")]).getStatusCode() == Http200
      check client.get(base & "/fresh.txt").getStatusCode() == Http200
      check client.request(HttpLock, base & "/fresh.txt", info,
        [("Depth", "0")]).getStatusCode() == Http200
    finally:
      server.close()
      client.close()
