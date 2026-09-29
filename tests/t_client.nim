## WebDAV client: builder units + loopback against DavServer (ports 20963+).
import std/unittest
import std/strutils
import std/httpcore except HttpMethod

import ndav

const
  Ev1 = """BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Test//Cal//EN
BEGIN:VEVENT
UID:cev1@test
DTSTAMP:20260101T000000Z
DTSTART:20260105T100000Z
DTEND:20260105T110000Z
SUMMARY:Client event
END:VEVENT
END:VCALENDAR
"""
  AdaVcf = """BEGIN:VCARD
VERSION:4.0
FN:Ada Client
N:Client;Ada;;;
UID:ada-client-1
END:VCARD
"""
  MultiVcf = """BEGIN:VCARD
VERSION:4.0
FN:One
UID:one-client-1
END:VCARD
BEGIN:VCARD
VERSION:4.0
FN:Two
UID:two-client-1
END:VCARD
"""

template withClient(port: int, body: untyped) =
  block:
    let http {.inject.} = newHttpClient()
    let srv {.inject.} = newDavServer(newMemoryDriver())
    let testServer = newHttpServer(http.getLoop())
    testServer.handler = srv.davHandler()
    testServer.listen("127.0.0.1", port)
    let dav {.inject.} = wrapDavClient(http,
      "http://127.0.0.1:" & $port)
    try:
      body
    finally:
      testServer.close()
      dav.closeClient()

suite "client setup and builders":
  test "base normalization and url joining":
    check newDavClient("http://x:1/").base == "http://x:1"
    check newDavClient("http://x:1/prefix").urlFor("/a") == "http://x:1/prefix/a"
    check newDavClient("http://x:1").urlFor("a") == "http://x:1/a"

  test "builders round-trip through the server parsers":
    let q = buildCalendarQuery("VEVENT", "20260105T000000Z",
      "20260106T000000Z")
    let rep = parseCalReport(q)
    check rep.kind == rkQuery
    check rep.compName == "VEVENT"
    check rep.wantEtag and rep.wantCalData
    check rep.hasTimeRange == true
    let mg = buildCalendarMultiget(@["/cal/a.ics", "/cal/b.ics"])
    let mrep = parseCalReport(mg)
    check mrep.kind == rkMultiget
    check mrep.hrefs == @["/cal/a.ics", "/cal/b.ics"]
    let cs = parseSyncCollection(buildCalSyncCollection("t", true, true,
      @["displayname"], 3))
    check cs.wantCalData == true
    check cs.token == "t"
    check cs.extraProps == @["displayname"]
    check cs.hasLimit and cs.limit == 3
    let asy = parseSyncCollection(buildSyncCollection("t2"))
    check asy.wantAddressData == true
    check asy.token == "t2"
    let pf = parsePropfind(buildPropfindProp(@["displayname", "getetag"]))
    check pf.kind == pfProp
    check pf.props == @["displayname", "getetag"]
    let li = parseLockinfo(buildLockinfo("shared", "me"))
    check li.scope == "shared"
    check li.owner == "me"

  test "builder validation errors":
    expect DavClientError:
      discard buildPropertyupdate(@[], @[])
    expect DavClientError:
      discard buildLockinfo("bogus")
    expect DavClientError:
      discard buildCalendarMultiget(@[])

suite "client basics loopback":
  test "options/mkcol/put/get/delete round trip":
    withClient(20963):
      let o = dav.options().ensure(Http200)
      check "PROPFIND" in ($o.getHeaders()["Allow"])
      check "calendar-access" in ($o.getHeaders()["DAV"])
      check dav.mkcol("/col").getStatusCode() == Http201
      check dav.put("/col/f.txt", "hi").getStatusCode() == Http201
      check dav.put("/col/f.txt", "hi!").getStatusCode() == Http204
      let g = dav.get("/col/f.txt").ensure(Http200)
      check g.getBodyString() == "hi!"
      check dav.delete("/col/f.txt").getStatusCode() == Http204
      check dav.get("/col/f.txt").getStatusCode() == Http404
      expect DavClientError:
        dav.get("/col/f.txt").ensure(Http200)

suite "client props loopback":
  test "proppatch set/remove and propfind parse":
    withClient(20964):
      dav.put("/f.txt", "data").ensure(Http201)
      let setBody = buildPropertyupdate(
        @[DavProp(ns: "http://example.com/", name: "rating", value: "5")], @[])
      check dav.raw(HttpProppatch, "/f.txt", setBody).getStatusCode() == Http207
      let all = dav.propfind("/f.txt", "0").multistatus()
      let fi = all.findResponse("/f.txt")
      check fi >= 0
      var names: seq[string]
      for p in all[fi].okProps():
        names.add(p.name)
      check "displayname" in names
      check "rating" in names
      let q = dav.propfind("/f.txt", "0",
        buildPropfindProp(@["getcontentlength", "bogus-prop"])).multistatus()
      check q.len == 1
      var codes: seq[int]
      for ps in q[0].propstats:
        codes.add(propstatCode(ps.status))
      check 200 in codes
      check 404 in codes
      let rmBody = buildPropertyupdate(@[],
        @[DavProp(ns: "http://example.com/", name: "rating")])
      check dav.raw(HttpProppatch, "/f.txt", rmBody).getStatusCode() == Http207
      let protBody = buildPropertyupdate(
        @[DavProp(ns: DavNs, name: "getetag", value: "x")], @[])
      let prot = dav.raw(HttpProppatch, "/f.txt", protBody).multistatus()
      var pcodes: seq[int]
      for ps in prot[0].propstats:
        pcodes.add(propstatCode(ps.status))
      check 403 in pcodes

suite "client copy/move/lock loopback":
  test "copy and move with path and absolute destinations":
    withClient(20965):
      dav.put("/a.txt", "A").ensure(Http201)
      check dav.copy("/a.txt", "/b.txt").getStatusCode() == Http201
      check dav.get("/b.txt").getBodyString() == "A"
      check dav.move("/b.txt", dav.urlFor("/c.txt")).getStatusCode() == Http201
      check dav.get("/c.txt").getBodyString() == "A"
      check dav.get("/b.txt").getStatusCode() == Http404

  test "lock/unlock flow with If enforcement":
    withClient(20966):
      dav.put("/l.txt", "v").ensure(Http201)
      let l = dav.lock("/l.txt", "exclusive", "0",
        "Second-600", "me").ensure(Http200)
      let tok = l.lockTokenOf()
      check tok.startsWith("opaquelocktoken:")
      check dav.put("/l.txt", "w").getStatusCode() == Http423
      check dav.put("/l.txt", "w2",
        [("If", "(<" & tok & ">)")]).getStatusCode() == Http204
      check dav.unlock("/l.txt", tok).getStatusCode() == Http204
      check dav.put("/l.txt", "w3").getStatusCode() == Http204

suite "client caldav loopback":
  test "query and multiget through builders":
    withClient(20967):
      check dav.mkcalendar("/cal").getStatusCode() == Http201
      check dav.put("/cal/ev.ics", Ev1).getStatusCode() == Http201
      let q = dav.report("/cal", buildCalendarQuery("VEVENT",
        "20260105T000000Z", "20260106T000000Z")).multistatus()
      check q.len == 1
      check q[0].href == "/cal/ev.ics"
      var gotData = ""
      for p in q[0].okProps():
        if p.ns == CalNs and p.name == "calendar-data":
          gotData = p.value
      check "BEGIN:VCALENDAR" in gotData
      let qf = dav.report("/cal", buildCalendarQuery("VEVENT",
        "20260201T000000Z", "20260202T000000Z")).multistatus()
      check qf.len == 0
      let m = dav.report("/cal", buildCalendarMultiget(
        @["/cal/ev.ics", "/cal/gone.ics"])).multistatus()
      check m.findResponse("/cal/ev.ics") >= 0
      check m.findResponse("/nope") == -1
      var mcodes: seq[int]
      for r in m:
        for ps in r.propstats:
          mcodes.add(propstatCode(ps.status))
      check 200 in mcodes
      check 404 in mcodes

  test "calendar sync through builder with tombstone":
    withClient(20989):
      check dav.mkcalendar("/cal").getStatusCode() == Http201
      check dav.put("/cal/ev.ics", Ev1).getStatusCode() == Http201
      let s = dav.report("/cal", buildCalSyncCollection()).ensure(Http207)
      let tok = syncTokenOf(s.getBodyString())
      check tok.len > 0
      let steady = dav.report("/cal",
        buildCalSyncCollection(tok)).multistatus()
      check steady.len == 0
      check dav.delete("/cal/ev.ics").getStatusCode() == Http204
      let s2 = dav.report("/cal",
        buildCalSyncCollection(tok)).ensure(Http207)
      let b2 = s2.getBodyString()
      check "ev.ics" in b2
      check "404 Not Found" in b2
      check syncTokenOf(b2) != tok

suite "client carddav loopback":
  test "mkcol addressbook, versioned query and sync through builders":
    withClient(20969):
      check dav.mkcolAddressbook("/cab", "Contacts").getStatusCode() == Http201
      check dav.put("/cab/ada.vcf", AdaVcf).getStatusCode() == Http201
      check dav.put("/cab/multi.vcf", MultiVcf).getStatusCode() == Http400
      let q = dav.report("/cab", buildAddressbookQuery(@["FN"], "ada",
        true, true, @[], false, -1, "3.0")).multistatus()
      check q.len == 1
      check q[0].href == "/cab/ada.vcf"
      var gotData = ""
      for p in q[0].okProps():
        if p.ns == CardNs and p.name == "address-data":
          gotData = p.value
      check "VERSION:3.0" in gotData
      let s = dav.report("/cab", buildSyncCollection()).ensure(Http207)
      let tok = syncTokenOf(s.getBodyString())
      check tok.len > 0
      let steady = dav.report("/cab", buildSyncCollection(tok)).multistatus()
      check steady.len == 0

suite "client error helpers":
  test "multistatus and lockTokenOf reject wrong shapes":
    withClient(20968):
      dav.put("/e.txt", "x").ensure(Http201)
      expect DavClientError:
        discard dav.get("/e.txt").multistatus()
      expect DavClientError:
        discard dav.get("/e.txt").lockTokenOf()
      check propstatCode("garbage") == 0
      check propstatCode("HTTP/1.1 404 Not Found") == 404
