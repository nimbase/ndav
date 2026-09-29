## HTTP Basic auth: unit parsing/verification + loopback gate, identity,
## principals tree, client setAuth and config [users] round-trips.
import std/unittest
import std/strutils
import std/tables
import std/os
import std/httpcore except HttpMethod

import ndav
import ndav/config

let AliceHash = hashPassword("alicepw")

proc aliceUsers(): Table[string, string] =
  {"alice": AliceHash}.toTable

proc basic(user, pass: string): tuple[name, value: string] =
  ("Authorization", encodeBasic(user, pass))

template withAuthSrv(port: int, users: Table[string, string], body: untyped) =
  block:
    let client {.inject.} = newHttpClient()
    let srv {.inject.} = newDavServer(newMemoryDriver(), users)
    let authServer = newHttpServer(client.getLoop())
    authServer.handler = srv.davHandler()
    authServer.listen("127.0.0.1", port)
    let base {.inject.} = "http://127.0.0.1:" & $port
    try:
      body
    finally:
      authServer.close()
      client.close()

template withAuthDav(port: int, users: Table[string, string], body: untyped) =
  block:
    let http {.inject.} = newHttpClient()
    let srv {.inject.} = newDavServer(newMemoryDriver(), users)
    let authServer = newHttpServer(http.getLoop())
    authServer.handler = srv.davHandler()
    authServer.listen("127.0.0.1", port)
    let dav {.inject.} = wrapDavClient(http,
      "http://127.0.0.1:" & $port)
    try:
      body
    finally:
      authServer.close()
      dav.closeClient()

suite "basic parsing units":
  test "valid credentials split on the first colon":
    let c = parseBasic(encodeBasic("alice", "p:a:s:s"))
    check c.user == "alice"
    check c.pass == "p:a:s:s"
    let ci = parseBasic("bAsIc " & encodeBasic("bob", "x").split(' ')[1])
    check ci.user == "bob"

  test "malformed input raises DavAuthError":
    expect DavAuthError:
      discard parseBasic("")
    expect DavAuthError:
      discard parseBasic("Bearer abc")
    expect DavAuthError:
      discard parseBasic("Basic !!!not-base64!!!")
    expect DavAuthError:
      discard parseBasic(encodeBasic("", "nopass"))
    expect DavAuthError:
      discard parseBasic("Basic " & "bm9jb2xvbg==") # "nocolon", no colon
    expect DavAuthError:
      discard parseBasic(encodeBasic("a/b", "x"))

  test "usernames and verification":
    check validUserName("alice") == true
    check validUserName("a.b_c-d@e+f") == true
    check validUserName("") == false
    check validUserName("a/b") == false
    check validUserName("a:b") == false
    check validUserName("a b") == false
    check "realm=\"nDAV\"" in challengeHeader()
    let users = aliceUsers()
    check verifyUser(users, "alice", "alicepw") == true
    check verifyUser(users, "alice", "wrong") == false
    check verifyUser(users, "mallory", "alicepw") == false
    check verifyUser(users, "mallory", "wrong") == false

suite "open mode":
  test "no users means no challenge and no identity props":
    withAuthSrv(20991, initTable[string, string]()):
      check client.request(HttpPut, base & "/f.txt", "hi").getStatusCode() == Http201
      let g = client.request(HttpGet, base & "/f.txt")
      check g.getStatusCode() == Http200
      check "WWW-Authenticate" notin ($g.getHeaders())
      let f = client.request(HttpPropfind, base & "/",
        buildPropfindProp(@["current-user-principal"]), [("Depth", "0")])
      check f.getStatusCode() == Http207
      check "404 Not Found" in f.getBodyString()

suite "401 gate loopback":
  test "missing, wrong and malformed credentials are 401 with a challenge":
    withAuthSrv(20992, aliceUsers()):
      let meths: seq[HttpMethod] = @[HttpGet, HttpPut, HttpPropfind,
        HttpReport, HttpProppatch, HttpLock, HttpOptions]
      for meth in meths:
        let r = client.request(meth, base & "/", "")
        check r.getStatusCode() == Http401
        check "Basic" in ($r.getHeaders()["WWW-Authenticate"])
      check client.request(HttpPut, base & "/f.txt", "x",
        [basic("alice", "wrong")]).getStatusCode() == Http401
      check client.request(HttpPut, base & "/f.txt", "x",
        [basic("mallory", "alicepw")]).getStatusCode() == Http401
      check client.request(HttpPut, base & "/f.txt", "x",
        [("Authorization", "Bearer abc")]).getStatusCode() == Http401

  test "valid credentials pass the gate everywhere":
    withAuthSrv(20993, aliceUsers()):
      let good = basic("alice", "alicepw")
      check client.request(HttpPut, base & "/f.txt", "hi",
        [good]).getStatusCode() == Http201
      check client.request(HttpGet, base & "/f.txt",
        "", [good]).getBodyString() == "hi"
      check client.request(HttpMkcol, base & "/col",
        "", [good]).getStatusCode() == Http201
      check client.request(HttpPropfind, base & "/",
        "", @[good, ("Depth", "0")]).getStatusCode() == Http207
      let f = client.request(HttpPropfind, base & "/",
        buildPropfindProp(@["current-user-principal",
          "principal-collection-set"]), @[("Depth", "0"), good])
      check f.getStatusCode() == Http207
      check "/principals/alice" in f.getBodyString()
      check "/principals/" in f.getBodyString()

suite "principals tree loopback":
  test "collection lists users, resources carry home sets":
    withAuthSrv(20994, aliceUsers()):
      let good = basic("alice", "alicepw")
      let l = client.request(HttpPropfind, base & "/principals",
        "", @[("Depth", "1"), good])
      check l.getStatusCode() == Http207
      check "/principals/alice" in l.getBodyString()
      let p = client.request(HttpPropfind, base & "/principals/alice",
        "", @[("Depth", "0"), good])
      check p.getStatusCode() == Http207
      let pb = p.getBodyString()
      check "principal" in pb
      check "calendar-home-set" in pb
      check "addressbook-home-set" in pb
      check "principal-URL" in pb
      check client.request(HttpPropfind, base & "/principals/mallory",
        "", @[("Depth", "0"), good]).getStatusCode() == Http404

  test "principals tree is read-only":
    withAuthSrv(20995, aliceUsers()):
      let good = basic("alice", "alicepw")
      check client.request(HttpPut, base & "/principals/alice", "x",
        [good]).getStatusCode() == Http403
      check client.request(HttpDelete, base & "/principals",
        "", [good]).getStatusCode() == Http403
      check client.request(HttpMkcol, base & "/principals/x",
        "", [good]).getStatusCode() == Http403
      check client.request(HttpGet, base & "/principals",
        "", [good]).getStatusCode() == Http403
      check client.request(HttpGet, base & "/principals/alice",
        "", [good]).getStatusCode() == Http404
      check client.request(HttpReport, base & "/principals",
        buildSyncCollection(), @[("Depth", "1"), good]).getStatusCode() == Http403
      let pp = client.request(HttpProppatch, base & "/",
        buildPropertyupdate(
          @[DavProp(ns: DavNs, name: "current-user-principal",
            value: "x")], @[]), [good])
      check "403 Forbidden" in pp.getBodyString()

suite "client setAuth loopback":
  test "setAuth passes, clearAuth and wrong creds fail":
    withAuthDav(20996, aliceUsers()):
      check dav.put("/f.txt", "x").getStatusCode() == Http401
      dav.setAuth("alice", "wrong")
      check dav.put("/f.txt", "x").getStatusCode() == Http401
      dav.setAuth("alice", "alicepw")
      check dav.put("/f.txt", "x").getStatusCode() == Http201
      check dav.get("/f.txt").getBodyString() == "x"
      dav.clearAuth()
      check dav.get("/f.txt").getStatusCode() == Http401

suite "config users":
  test "setUserHash creates, appends and replaces":
    let cfg = getTempDir() / "t_auth_users.toml"
    try:
      removeFile(cfg)
      setUserHash(cfg, "alice", "h1")
      var c = loadConfig(cfg)
      check c.users.getOrDefault("alice") == "h1"
      check c.root.len > 0 # defaults still apply
      setUserHash(cfg, "bob", "h2")
      c = loadConfig(cfg)
      check c.users.getOrDefault("alice") == "h1"
      check c.users.getOrDefault("bob") == "h2"
      setUserHash(cfg, "alice", "h3")
      c = loadConfig(cfg)
      check c.users.getOrDefault("alice") == "h3"
      check c.users.getOrDefault("bob") == "h2"
      expect ValueError:
        setUserHash(cfg, "a/b", "h")
    finally:
      removeFile(cfg)

  test "loadConfig rejects bad users tables":
    let cfg = getTempDir() / "t_auth_bad.toml"
    try:
      writeFile(cfg, "port = 9001\n[users]\nalice = 42\n")
      expect ValueError:
        discard loadConfig(cfg)
      writeFile(cfg, "users = \"nope\"\n")
      expect ValueError:
        discard loadConfig(cfg)
    finally:
      removeFile(cfg)
