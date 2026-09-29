## Discovery (RFC 6764) + principal search (RFC 3744 section 9.4):
## parser units and loopback redirects, REPORT matching and identity props.
## Ports 21101+.
import std/unittest
import std/strutils
import std/tables
import std/os
import std/httpcore except HttpMethod

import ndav
import ndav/config

let
  AliceHash = hashPassword("alicepw")
  BobHash = hashPassword("bobpw")

proc twoUsers(): Table[string, string] =
  {"alice": AliceHash, "bob": BobHash}.toTable

proc basic(user, pass: string): tuple[name, value: string] =
  ("Authorization", encodeBasic(user, pass))

template withDiscoverySrv(port: int, users: Table[string, string],
    body: untyped) =
  block:
    let client {.inject.} = newHttpClient()
    let srv {.inject.} = newDavServer(newMemoryDriver(), users)
    let discoveryServer = newHttpServer(client.getLoop())
    discoveryServer.handler = srv.davHandler()
    discoveryServer.listen("127.0.0.1", port)
    let base {.inject.} = "http://127.0.0.1:" & $port
    try:
      body
    finally:
      discoveryServer.close()
      client.close()

suite "principal-property-search parsing units":
  test "valid bodies parse with scope, test mode and clauses":
    let r = parsePrincipalPropertySearch(
      buildPrincipalPropertySearch(@["displayname"], @[("displayname", "ali")]))
    check r.testAnyOf == true
    check r.scope == "apply-to-principal-collection-set"
    check r.wanted == @["displayname"]
    check r.searches.len == 1
    check r.searches[0].propName == "displayname"
    check r.searches[0].matchText == "ali"
    let a = parsePrincipalPropertySearch(
      buildPrincipalPropertySearch(@[], @[("displayname", "a"),
        ("principal-URL", "bob")], testAnyOf = false))
    check a.testAnyOf == false
    check a.wanted.len == 0
    check a.searches.len == 2

  test "malformed bodies raise DavXmlError":
    expect DavXmlError:
      discard parsePrincipalPropertySearch("")
    expect DavXmlError:
      discard parsePrincipalPropertySearch(
        "<D:principal-property-search xmlns:D=\"DAV:\"/>")
    expect DavXmlError:
      discard parsePrincipalPropertySearch(
        "<D:principal-property-search xmlns:D=\"DAV:\" test=\"sometimes\">" &
        "<D:prop/><D:apply-to-principal-collection-set/>" &
        "<D:property-search><D:prop><D:displayname/></D:prop>" &
        "<D:match>x</D:match></D:property-search>" &
        "</D:principal-property-search>")
    expect DavXmlError: # no scope
      discard parsePrincipalPropertySearch(
        "<D:principal-property-search xmlns:D=\"DAV:\"><D:prop/>" &
        "<D:property-search><D:prop><D:displayname/></D:prop>" &
        "<D:match>x</D:match></D:property-search>" &
        "</D:principal-property-search>")
    expect DavXmlError: # no search clause
      discard parsePrincipalPropertySearch(
        "<D:principal-property-search xmlns:D=\"DAV:\"><D:prop/>" &
        "<D:apply-to-principal-collection-set/>" &
        "</D:principal-property-search>")
    expect DavXmlError: # unknown search property
      discard parsePrincipalPropertySearch(
        "<D:principal-property-search xmlns:D=\"DAV:\"><D:prop/>" &
        "<D:apply-to-principal-collection-set/>" &
        "<D:property-search><D:prop><D:getetag/></D:prop>" &
        "<D:match>x</D:match></D:property-search>" &
        "</D:principal-property-search>")
    expect DavXmlError: # missing match
      discard parsePrincipalPropertySearch(
        "<D:principal-property-search xmlns:D=\"DAV:\"><D:prop/>" &
        "<D:apply-to-principal-collection-set/>" &
        "<D:property-search><D:prop><D:displayname/></D:prop>" &
        "</D:property-search></D:principal-property-search>")
    expect DavClientError:
      discard buildPrincipalPropertySearch(@[], @[])

suite "well-known loopback":
  test "open server redirects discovery paths without credentials":
    withDiscoverySrv(21101, initTable[string, string]()):
      for p in ["/.well-known/caldav", "/.well-known/carddav"]:
        let g = client.request(HttpGet, base & p, "")
        check g.getStatusCode() == Http307
        check ($g.getHeaders()["Location"]) == "/"
        let f = client.request(HttpPropfind, base & p,
          buildPropfindAllprop(), [("Depth", "0")])
        check f.getStatusCode() == Http307
        check ($f.getHeaders()["Location"]) == "/"
      check client.request(HttpDelete, base & "/.well-known/caldav", "",
        ).getStatusCode() == Http404
      check client.request(HttpGet, base & "/.well-known/other",
        "").getStatusCode() == Http404

  test "auth server exempts discovery but still gates everything else":
    withDiscoverySrv(21102, twoUsers()):
      let g = client.request(HttpGet, base & "/.well-known/caldav", "")
      check g.getStatusCode() == Http307
      check ($g.getHeaders()["Location"]) == "/"
      check client.request(HttpGet, base & "/",
        "").getStatusCode() == Http401
      check client.request(HttpPropfind, base & "/principals",
        "", [("Depth", "0")]).getStatusCode() == Http401

suite "principal-property-search loopback":
  test "anyof/allof matching with prop selection":
    withDiscoverySrv(21103, twoUsers()):
      let good = basic("alice", "alicepw")
      let any = client.request(HttpReport, base & "/principals",
        buildPrincipalPropertySearch(@["displayname"],
          @[("displayname", "ali")]), [good])
      check any.getStatusCode() == Http207
      check "/principals/alice" in any.getBodyString()
      check "/principals/bob" notin any.getBodyString()
      let all = client.request(HttpReport, base & "/principals",
        buildPrincipalPropertySearch(@["displayname"],
          @[("displayname", "a"), ("principal-URL", "principals")],
          testAnyOf = false), [good])
      check all.getStatusCode() == Http207
      check "/principals/alice" in all.getBodyString()
      check "/principals/bob" notin all.getBodyString()
      let none = client.request(HttpReport, base & "/principals",
        buildPrincipalPropertySearch(@["displayname"],
          @[("displayname", "mallory")]), [good])
      check none.getStatusCode() == Http207
      check "/principals/" notin none.getBodyString()
      let full = client.request(HttpReport, base & "/principals",
        buildPrincipalPropertySearch(@[], @[("displayname", "bob")]),
        [good])
      check full.getStatusCode() == Http207
      check "calendar-home-set" in full.getBodyString()
      check "principal-URL" in full.getBodyString()

  test "scope, target and auth guards":
    withDiscoverySrv(21104, twoUsers()):
      let good = basic("alice", "alicepw")
      let search = buildPrincipalPropertySearch(@["displayname"],
        @[("displayname", "a")])
      check client.request(HttpReport, base & "/principals", search,
        ).getStatusCode() == Http401
      check client.request(HttpReport, base & "/principals/alice", search,
        [good]).getStatusCode() == Http403
      check client.request(HttpReport, base & "/principals/nobody", search,
        [good]).getStatusCode() == Http404
      check client.request(HttpReport, base & "/principals",
        "<D:principal-property-search xmlns:D=\"DAV:\"><D:prop/>" &
        "<D:apply-to-home-set/>" &
        "<D:property-search><D:prop><D:displayname/></D:prop>" &
        "<D:match>a</D:match></D:property-search>" &
        "</D:principal-property-search>",
        [good]).getStatusCode() == Http403
      check client.request(HttpReport, base & "/principals",
        "<D:principal-property-search xmlns:D=\"DAV:\"><D:prop/>" &
        "</D:principal-property-search>",
        [good]).getStatusCode() == Http422
      check client.request(HttpReport, base & "/principals",
        buildSyncCollection(), @[("Depth", "1"), good]
        ).getStatusCode() == Http403

  test "search props are advertised on the principals collection":
    withDiscoverySrv(21105, twoUsers()):
      let good = basic("alice", "alicepw")
      let f = client.request(HttpPropfind, base & "/principals",
        buildPropfindAllprop(), @[("Depth", "0"), good])
      check f.getStatusCode() == Http207
      check "principal-search-property-set" in f.getBodyString()
      check "supported-report-set" in f.getBodyString()
      check "principal-property-search" in f.getBodyString()

suite "regular tree identity loopback":
  test "authenticated responses carry home sets, open mode omits them":
    withDiscoverySrv(21106, twoUsers()):
      let good = basic("alice", "alicepw")
      let f = client.request(HttpPropfind, base & "/",
        buildPropfindProp(@["current-user-principal",
          "principal-collection-set", "principal-URL", "calendar-home-set",
          "addressbook-home-set", "nosuchprop"]), @[("Depth", "0"), good])
      check f.getStatusCode() == Http207
      let b = f.getBodyString()
      check "/principals/alice" in b
      check "/principals/" in b
      check "calendar-home-set" in b
      check "addressbook-home-set" in b
      check "404 Not Found" in b
    withDiscoverySrv(21107, initTable[string, string]()):
      let f = client.request(HttpPropfind, base & "/",
        buildPropfindAllprop(), [("Depth", "0")])
      check f.getStatusCode() == Http207
      check "home-set" notin f.getBodyString()
      check "principal-URL" notin f.getBodyString()
      check "current-user-principal" notin f.getBodyString()
