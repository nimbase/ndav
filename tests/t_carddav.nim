## CardDAV core: REPORT parsing, filter matching units +
## loopback extended-MKCOL / PUT gate / addressbook-query / multiget.
import std/unittest
import std/strutils
import std/options
import std/httpcore except HttpMethod

import webdav

const
  Ada = """BEGIN:VCARD
VERSION:4.0
FN:Ada Lovelace
N:Lovelace;Ada;;;
ORG:OpenPeeps
TITLE:Dev
TEL;PREF=1;TYPE=cell:+1555000111
EMAIL:ada@example.org
NOTE:Analytical engines
END:VCARD
"""
  Bob = """BEGIN:VCARD
VERSION:3.0
FN:Bob Builder
N:Builder;Bob;;;
TEL;TYPE=HOME,VOICE:+1555000222
EMAIL;TYPE=WORK:bob@work.example
CATEGORIES:builder,friend
END:VCARD
"""
  AdaUid = """BEGIN:VCARD
VERSION:4.0
FN:Ada Lovelace
N:Lovelace;Ada;;;
UID:ada-1
TEL;PREF=1;TYPE=cell:+1555000111
END:VCARD
"""
  BobUid = """BEGIN:VCARD
VERSION:4.0
FN:Bob Builder
N:Builder;Bob;;;
UID:bob-1
TEL;TYPE=HOME:+1555000222
END:VCARD
"""
  Multi = """BEGIN:VCARD
VERSION:4.0
FN:One
UID:one-1
END:VCARD
BEGIN:VCARD
VERSION:4.0
FN:Two
UID:two-1
END:VCARD
"""

  QueryFnAda = """<CR:addressbook-query xmlns:D="DAV:" xmlns:CR="urn:ietf:params:xml:ns:carddav">""" &
    """<D:prop><D:getetag/><CR:address-data/></D:prop>""" &
    """<CR:filter><CR:prop-filter name="FN">""" &
    """<CR:text-match collation="i;unicode-casemap" match-type="contains">ada</CR:text-match>""" &
    """</CR:prop-filter></CR:filter></CR:addressbook-query>"""

template withAb(port: int, body: untyped) =
  block:
    let client {.inject.} = newHttpClient()
    let srv {.inject.} = newDavServer(newMemoryDriver())
    let abServer = newHttpServer(client.getLoop())
    abServer.handler = srv.davHandler()
    abServer.listen("127.0.0.1", port)
    let base {.inject.} = "http://127.0.0.1:" & $port
    try:
      body
    finally:
      abServer.close()
      client.close()

suite "mkcol addressbook parsing":
  test "empty body is plain mkcol":
    let (isAb, props) = parseMkcolAddressbook("")
    check isAb == false
    check props.len == 0

  test "addressbook body detected, defaults kept":
    let body = buildMkcolAddressbook("Contacts", "My contacts")
    let (isAb, props) = parseMkcolAddressbook(body)
    check isAb == true
    var names: seq[string]
    for p in props: names.add(p.name)
    check "displayname" in names
    check "addressbook-description" in names

  test "plain resourcetype is not addressbook":
    let body = """<D:mkcol xmlns:D="DAV:"><D:set><D:prop>""" &
      """<D:resourcetype><D:collection/></D:resourcetype>""" &
      """</D:prop></D:set></D:mkcol>"""
    let (isAb, _) = parseMkcolAddressbook(body)
    check isAb == false

  test "malformed mkcol raises":
    expect DavXmlError:
      discard parseMkcolAddressbook("""<D:mkcol xmlns:D="DAV:">""")
    expect DavXmlError:
      discard parseMkcolAddressbook("""<D:propfind xmlns:D="DAV:"/>""")

suite "report parsing":
  test "query prop-filter and text-match":
    let r = parseCardReport(QueryFnAda)
    check r.kind == rkAddressQuery
    check r.wantEtag == true
    check r.wantAddressData == true
    check r.filters.len == 1
    check r.filters[0].name == "FN"
    check r.filters[0].textMatches.len == 1
    check r.filters[0].textMatches[0].value == "ada"

  test "query without filter matches all":
    let r = parseCardReport(
      """<CR:addressbook-query xmlns:D="DAV:" xmlns:CR="urn:ietf:params:xml:ns:carddav">""" &
      """<D:prop><D:getetag/></D:prop></CR:addressbook-query>""")
    check r.filters.len == 0

  test "multiget hrefs and limit":
    let r = parseCardReport(
      """<CR:addressbook-multiget xmlns:D="DAV:" xmlns:CR="urn:ietf:params:xml:ns:carddav">""" &
      """<D:prop><D:getetag/><CR:address-data/></D:prop>""" &
      """<D:href>/ab/a.vcf</D:href><D:href>/ab/b.vcf</D:href>""" &
      """<CR:limit><CR:nresults>1</CR:nresults></CR:limit>""" &
      """</CR:addressbook-multiget>""")
    check r.kind == rkAddressMultiget
    check r.hrefs == @["/ab/a.vcf", "/ab/b.vcf"]
    check r.hasLimit == true
    check r.limit == 1

  test "is-not-defined and param-filter":
    let r = parseCardReport(
      """<CR:addressbook-query xmlns:D="DAV:" xmlns:CR="urn:ietf:params:xml:ns:carddav">""" &
      """<D:prop><D:getetag/></D:prop>""" &
      """<CR:filter test="anyof">""" &
      """<CR:prop-filter name="X-CUSTOM"><CR:is-not-defined/></CR:prop-filter>""" &
      """<CR:prop-filter name="TEL"><CR:param-filter name="TYPE">""" &
      """<CR:text-match match-type="equals">voice</CR:text-match>""" &
      """</CR:param-filter></CR:prop-filter>""" &
      """</CR:filter></CR:addressbook-query>""")
    check r.testAnyOf == true
    check r.filters.len == 2
    check r.filters[0].isNotDefined == true
    check r.filters[1].paramFilters.len == 1
    check r.filters[1].paramFilters[0].name == "TYPE"

  test "report errors are DavXmlError":
    expect DavXmlError:
      discard parseCardReport("")
    expect DavXmlError:
      discard parseCardReport("""<D:propfind xmlns:D="DAV:"/>""")
    expect DavXmlError:
      discard parseCardReport(
        """<CR:addressbook-multiget xmlns:CR="urn:ietf:params:xml:ns:carddav">""" &
        """<D:prop xmlns:D="DAV:"><D:getetag/></D:prop>""" &
        """</CR:addressbook-multiget>""")
    expect DavXmlError:
      discard parseCardReport(
        """<CR:addressbook-query xmlns:D="DAV:" xmlns:CR="urn:ietf:params:xml:ns:carddav">""" &
        """<D:prop><D:getetag/></D:prop>""" &
        """<CR:filter><CR:prop-filter>""" &
        """<CR:text-match>hi</CR:text-match>""" &
        """</CR:prop-filter></CR:filter></CR:addressbook-query>""")
    expect DavXmlError:
      discard parseCardReport(
        """<CR:addressbook-query xmlns:D="DAV:" xmlns:CR="urn:ietf:params:xml:ns:carddav">""" &
        """<D:prop><D:getetag/></D:prop>""" &
        """<CR:filter><CR:prop-filter name="FN">""" &
        """<CR:text-match collation="bogus">x</CR:text-match>""" &
        """</CR:prop-filter></CR:filter></CR:addressbook-query>""")

suite "matching":
  test "fn contains case-insensitive":
    let r = parseCardReport(QueryFnAda)
    check carddav.resourceMatches(Ada, r.filters, r.testAnyOf) == true
    check carddav.resourceMatches(Bob, r.filters, r.testAnyOf) == false

  test "bare prop-filter is presence":
    let filt = @[CardPropFilter(name: "CATEGORIES")]
    check carddav.resourceMatches(Bob, filt, false) == true
    check carddav.resourceMatches(Ada, filt, false) == false

  test "is-not-defined inverts presence":
    let filt = @[CardPropFilter(name: "CATEGORIES", isNotDefined: true)]
    check carddav.resourceMatches(Ada, filt, false) == true
    check carddav.resourceMatches(Bob, filt, false) == false

  test "param-filter type voice":
    let filt = @[CardPropFilter(name: "TEL", paramFilters: @[
      CardParamFilter(name: "TYPE",
        hasTextMatch: true,
        textMatch: CardTextMatch(value: "voice",
          collation: "i;unicode-casemap", matchType: "equals"))])]
    check carddav.resourceMatches(Bob, filt, false) == true
    check carddav.resourceMatches(Ada, filt, false) == false

  test "negated text-match matches absence":
    let filt = @[CardPropFilter(name: "CATEGORIES", textMatches: @[
      CardTextMatch(value: "zzz", collation: "i;unicode-casemap",
        matchType: "contains", negate: true)])]
    check carddav.resourceMatches(Ada, filt, false) == true

  test "anyof across props":
    let f = @[
      CardPropFilter(name: "FN", textMatches: @[
        CardTextMatch(value: "ada", collation: "i;unicode-casemap",
          matchType: "contains")]),
      CardPropFilter(name: "FN", textMatches: @[
        CardTextMatch(value: "bob", collation: "i;unicode-casemap",
          matchType: "contains")])]
    check carddav.resourceMatches(Ada, f, true) == true
    check carddav.resourceMatches(Bob, f, true) == true
    check carddav.resourceMatches(Ada, f, false) == false

  test "garbage never matches, content gate":
    let nofilt: seq[CardPropFilter] = @[]
    check carddav.resourceMatches("not vcard", nofilt, false) == false
    check isAddressContent(Ada) == true
    check isAddressContent(Bob) == true
    check isAddressContent("junk") == false
    check isAddressContent(
      "BEGIN:VCARD\r\nVERSION:4.0\r\nFN: \r\nEND:VCARD\r\n") == false

  test "client builders round-trip":
    let q = buildAddressbookQuery(@["FN"], "ada")
    let rep = parseCardReport(q)
    check rep.kind == rkAddressQuery
    check rep.filters.len == 1
    check rep.wantAddressData == true
    let mg = buildAddressbookMultiget(@["/ab/a.vcf"])
    let mrep = parseCardReport(mg)
    check mrep.kind == rkAddressMultiget
    check mrep.hrefs == @["/ab/a.vcf"]
    expect DavClientError:
      discard buildAddressbookMultiget(@[])

suite "extended mkcol loopback":
  test "create, duplicate, parent missing, propfind shows addressbook":
    withAb(20970):
      check client.request(HttpMkcol, base & "/ab",
        buildMkcolAddressbook("Contacts")).getStatusCode() == Http201
      check client.request(HttpMkcol, base & "/ab",
        buildMkcolAddressbook()).getStatusCode() == Http405
      check client.request(HttpMkcol, base & "/no/such",
        buildMkcolAddressbook()).getStatusCode() == Http409
      let f = client.request(HttpPropfind, base & "/ab", "",
        [("Depth", "0")])
      check f.getStatusCode() == Http207
      let fb = f.getBodyString()
      check "addressbook" in fb
      check "getctag" in fb
      check "addressbook-multiget" in fb
      check "supported-address-data" in fb

  test "non-addressbook body stays 415, calendar hint is 403":
    withAb(20971):
      check client.request(HttpMkcol, base & "/plain",
        """<D:mkcol xmlns:D="DAV:"><D:set><D:prop>""" &
        """<D:displayname>x</D:displayname>""" &
        """</D:prop></D:set></D:mkcol>""").getStatusCode() == Http415
      check client.request(HttpMkcol, base & "/cal",
        """<D:mkcol xmlns:D="DAV:"><D:set><D:prop>""" &
        """<D:resourcetype><D:collection/>""" &
        """<C:calendar xmlns:C="urn:ietf:params:xml:ns:caldav"/>""" &
        """</D:resourcetype></D:prop></D:set></D:mkcol>""").getStatusCode() == Http403

  test "protected body prop is 403, description sticks":
    withAb(20972):
      let bad = """<D:mkcol xmlns:D="DAV:"><D:set><D:prop>""" &
        """<D:resourcetype><D:collection/>""" &
        """<CR:addressbook xmlns:CR="urn:ietf:params:xml:ns:carddav"/>""" &
        """</D:resourcetype><D:getetag>x</D:getetag>""" &
        """</D:prop></D:set></D:mkcol>"""
      check client.request(HttpMkcol, base & "/bad", bad).getStatusCode() == Http403
      check client.request(HttpPropfind, base & "/bad", "",
        [("Depth", "0")]).getStatusCode() == Http404
      check client.request(HttpMkcol, base & "/good",
        buildMkcolAddressbook("Work", "Team")).getStatusCode() == Http201
      let f = client.request(HttpPropfind, base & "/good",
        """<D:propfind xmlns:D="DAV:"><D:prop><D:displayname/>""" &
        """</D:prop></D:propfind>""", [("Depth", "0")])
      check f.getStatusCode() == Http207
      check "Work" in f.getBodyString()

suite "put gate loopback":
  test "addressbook takes vcf, rejects junk; plain dirs unaffected":
    withAb(20973):
      check client.request(HttpMkcol, base & "/ab",
        buildMkcolAddressbook()).getStatusCode() == Http201
      check client.request(HttpPut, base & "/ab/ada.vcf", Ada).getStatusCode() == Http201
      check client.request(HttpPut, base & "/ab/bob.vcf", Bob).getStatusCode() == Http201
      check client.request(HttpPut, base & "/ab/junk.vcf",
        "hello").getStatusCode() == Http400
      check client.request(HttpPut, base & "/plain.txt",
        "hello").getStatusCode() == Http201

suite "addressbook-query loopback":
  test "filter selects matching cards":
    withAb(20974):
      discard client.request(HttpMkcol, base & "/ab", buildMkcolAddressbook())
      discard client.request(HttpPut, base & "/ab/ada.vcf", Ada)
      discard client.request(HttpPut, base & "/ab/bob.vcf", Bob)
      let q = client.request(HttpReport, base & "/ab", QueryFnAda,
        [("Depth", "1")])
      check q.getStatusCode() == Http207
      let qb = q.getBodyString()
      check "ada.vcf" in qb
      check "bob.vcf" notin qb
      check "BEGIN:VCARD" in qb
      let all = client.request(HttpReport, base & "/ab",
        buildAddressbookQuery(@[], ""), [("Depth", "1")])
      check all.getStatusCode() == Http207
      check "ada.vcf" in all.getBodyString()
      check "bob.vcf" in all.getBodyString()
      let lim = client.request(HttpReport, base & "/ab",
        buildAddressbookQuery(@[], "", true, true, @[], false, 1),
        [("Depth", "1")])
      check lim.getStatusCode() == Http207
      check lim.getBodyString().count("<D:response>") == 1

  test "non-addressbook target is 403, infinity depth is 400":
    withAb(20975):
      discard client.request(HttpMkcol, base & "/plain")
      check client.request(HttpReport, base & "/plain", QueryFnAda,
        [("Depth", "1")]).getStatusCode() == Http403
      discard client.request(HttpMkcol, base & "/ab", buildMkcolAddressbook())
      check client.request(HttpReport, base & "/ab", QueryFnAda,
        [("Depth", "infinity")]).getStatusCode() == Http400
      check client.request(HttpReport, base & "/ab",
        """<D:propfind xmlns:D="DAV:"/>""").getStatusCode() == Http501

suite "addressbook-multiget loopback":
  test "href list with data, etag, and 404 entry":
    withAb(20976):
      discard client.request(HttpMkcol, base & "/ab", buildMkcolAddressbook())
      discard client.request(HttpPut, base & "/ab/ada.vcf", Ada)
      let mg = buildAddressbookMultiget(@["/ab/ada.vcf", "/ab/missing.vcf"])
      let m = client.request(HttpReport, base & "/ab", mg)
      check m.getStatusCode() == Http207
      let mb = m.getBodyString()
      check "ada.vcf" in mb
      check "BEGIN:VCARD" in mb
      check "getetag" in mb
      check "404 Not Found" in mb

suite "ctag and marker lifetime":
  test "ctag moves on put, copy carries the addressbook flag":
    withAb(20977):
      discard client.request(HttpMkcol, base & "/ab", buildMkcolAddressbook())
      let tagBody = """<D:propfind xmlns:D="DAV:"><D:prop><D:getctag/>""" &
        """</D:prop></D:propfind>"""
      let t1 = client.request(HttpPropfind, base & "/ab", tagBody,
        [("Depth", "0")]).getBodyString()
      discard client.request(HttpPut, base & "/ab/ada.vcf", Ada)
      let t2 = client.request(HttpPropfind, base & "/ab", tagBody,
        [("Depth", "0")]).getBodyString()
      check t1 != t2
      check client.request(HttpCopy, base & "/ab", "",
        [("Destination", base & "/ab2")]).getStatusCode() == Http201
      let q = client.request(HttpReport, base & "/ab2",
        buildAddressbookQuery(@["FN"], "ada"), [("Depth", "1")])
      check q.getStatusCode() == Http207
      check "ada.vcf" in q.getBodyString()

suite "address-data negotiation":
  test "version preference parsed, bad content-type flagged":
    let r = parseCardReport(
      """<CR:addressbook-query xmlns:D="DAV:" xmlns:CR="urn:ietf:params:xml:ns:carddav">""" &
      """<D:prop><D:getetag/><CR:address-data version="3.0"/></D:prop>""" &
      """</CR:addressbook-query>""")
    check r.wantAddressData == true
    check r.addressDataPrefs.len == 1
    check r.addressDataPrefs[0].version == "3.0"
    check r.hasUnsupportedAddressData == false
    check addressDataTarget(r.addressDataPrefs) == vv30
    let bad = parseCardReport(
      """<CR:addressbook-query xmlns:D="DAV:" xmlns:CR="urn:ietf:params:xml:ns:carddav">""" &
      """<D:prop><CR:address-data content-type="application/json"/></D:prop>""" &
      """</CR:addressbook-query>""")
    check bad.hasUnsupportedAddressData == true
    check addressDataTarget(@[]) == vv40
    check addressDataTarget(@[CardAddressDataPref(version: "4.0")]) == vv40

  test "downgrade to 3.0 round-trips, same version passes through":
    let down = convertAddressData(Ada, vv30)
    check "VERSION:3.0" in down
    check parseVCard(down).fn == "Ada Lovelace"
    check convertAddressData(Ada, vv40) == Ada
    check convertAddressData("junk", vv30) == "junk"

  test "versioned query returns converted data, bad type is 415":
    withAb(20978):
      discard client.request(HttpMkcol, base & "/ab", buildMkcolAddressbook())
      discard client.request(HttpPut, base & "/ab/ada.vcf", Ada)
      let q = client.request(HttpReport, base & "/ab",
        buildAddressbookQuery(@[], "", true, true, @[], false, -1, "3.0"),
        [("Depth", "1")])
      check q.getStatusCode() == Http207
      check "VERSION:3.0" in q.getBodyString()
      let bad = """<CR:addressbook-query xmlns:D="DAV:" """ &
        """xmlns:CR="urn:ietf:params:xml:ns:carddav">""" &
        """<D:prop><CR:address-data content-type="application/json"/></D:prop>""" &
        """</CR:addressbook-query>"""
      check client.request(HttpReport, base & "/ab", bad,
        [("Depth", "1")]).getStatusCode() == Http415

suite "single-card and UID gates":
  test "requireSingleAddress accepts one, rejects multi and FN-less":
    check requireSingleAddress(AdaUid).uid.get() == "ada-1"
    expect OpenParserVCardError:
      discard requireSingleAddress(Multi)
    expect OpenParserVCardError:
      discard requireSingleAddress("junk")
    expect OpenParserVCardError:
      discard requireSingleAddress(
        "BEGIN:VCARD\r\nVERSION:4.0\r\nFN: \r\nEND:VCARD\r\n")

  test "multi-card PUT is 400":
    withAb(20979):
      discard client.request(HttpMkcol, base & "/ab", buildMkcolAddressbook())
      check client.request(HttpPut, base & "/ab/multi.vcf",
        Multi).getStatusCode() == Http400
      check client.request(HttpPut, base & "/ab/a.vcf",
        AdaUid).getStatusCode() == Http201

  test "UID reuse is 409, same-resource overwrite is fine":
    withAb(20980):
      discard client.request(HttpMkcol, base & "/ab", buildMkcolAddressbook())
      check client.request(HttpPut, base & "/ab/a.vcf",
        AdaUid).getStatusCode() == Http201
      let dup = client.request(HttpPut, base & "/ab/b.vcf", AdaUid)
      check dup.getStatusCode() == Http409
      check "/ab/a.vcf" in dup.getBodyString()
      # Same href, same UID: allowed update.
      check client.request(HttpPut, base & "/ab/a.vcf",
        AdaUid).getStatusCode() == Http204
      # Same href, changed UID: conflict.
      var changed = AdaUid.replace("ada-1", "ada-2")
      check client.request(HttpPut, base & "/ab/a.vcf",
        changed).getStatusCode() == Http409
      # UID-less cards never conflict.
      check client.request(HttpPut, base & "/ab/plain.vcf",
        Ada).getStatusCode() == Http201

  test "COPY into addressbook enforces gates":
    withAb(20981):
      discard client.request(HttpMkcol, base & "/ab", buildMkcolAddressbook())
      discard client.request(HttpPut, base & "/ab/a.vcf", AdaUid)
      discard client.request(HttpPut, base & "/outside.vcf", BobUid)
      # Conflicting UID at destination.
      var clash = BobUid.replace("bob-1", "ada-1")
      discard client.request(HttpPut, base & "/clash.vcf", clash)
      check client.request(HttpCopy, base & "/clash.vcf", "",
        [("Destination", base & "/ab/b.vcf")]).getStatusCode() == Http409
      # Clean copy lands.
      check client.request(HttpCopy, base & "/outside.vcf", "",
        [("Destination", base & "/ab/bob.vcf")]).getStatusCode() == Http201
      let g = client.get(base & "/ab/bob.vcf")
      check g.getStatusCode() == Http200
      check g.getBodyString() == BobUid

suite "content types and options":
  test "vcf serves text/vcard, options advertises addressbook":
    withAb(20982):
      discard client.request(HttpMkcol, base & "/ab", buildMkcolAddressbook())
      discard client.request(HttpPut, base & "/ab/ada.vcf", Ada)
      let g = client.get(base & "/ab/ada.vcf")
      check g.getStatusCode() == Http200
      check ($g.getHeaders()["Content-Type"]) == "text/vcard"
      let o = client.request(HttpOptions, base & "/")
      check "addressbook-access" in ($o.getHeaders()["DAV"])
      let f = client.request(HttpPropfind, base & "/ab/ada.vcf",
        """<D:propfind xmlns:D="DAV:"><D:prop><D:getcontenttype/>""" &
        """</D:prop></D:propfind>""", [("Depth", "0")])
      check "text/vcard" in f.getBodyString()

suite "sync-collection loopback":
  test "initial, steady and stale tokens":
    withAb(20983):
      discard client.request(HttpMkcol, base & "/ab", buildMkcolAddressbook())
      discard client.request(HttpPut, base & "/ab/ada.vcf", Ada)
      discard client.request(HttpPut, base & "/ab/bob.vcf", Bob)
      let s1 = client.request(HttpReport, base & "/ab", buildSyncCollection(),
        [("Depth", "1")])
      check s1.getStatusCode() == Http207
      let b1 = s1.getBodyString()
      check "ada.vcf" in b1
      check "bob.vcf" in b1
      check "sync-token" in b1
      let tok = syncTokenOf(b1)
      check tok.len > 0
      # Steady: same token, no member responses.
      let s2 = client.request(HttpReport, base & "/ab",
        buildSyncCollection(tok), [("Depth", "1")])
      check s2.getStatusCode() == Http207
      check "<D:response>" notin s2.getBodyString()
      check syncTokenOf(s2.getBodyString()) == tok
      # Change moves the token; the stale token resyncs fully.
      discard client.request(HttpPut, base & "/ab/c.vcf", AdaUid)
      let s3 = client.request(HttpReport, base & "/ab",
        buildSyncCollection(tok), [("Depth", "1")])
      check s3.getStatusCode() == Http207
      check "c.vcf" in s3.getBodyString()
      check syncTokenOf(s3.getBodyString()) != tok

  test "sync needs addressbook, depth 1, valid level":
    withAb(20984):
      discard client.request(HttpMkcol, base & "/plain")
      check client.request(HttpReport, base & "/plain", buildSyncCollection(),
        [("Depth", "1")]).getStatusCode() == Http403
      discard client.request(HttpMkcol, base & "/ab", buildMkcolAddressbook())
      check client.request(HttpReport, base & "/ab", buildSyncCollection(),
        [("Depth", "infinity")]).getStatusCode() == Http400
      let badLevel = """<D:sync-collection xmlns:D="DAV:">""" &
        """<D:prop><D:getetag/></D:prop>""" &
        """<D:sync-token/><D:sync-level>7</D:sync-level>""" &
        """</D:sync-collection>"""
      check client.request(HttpReport, base & "/ab", badLevel,
        [("Depth", "1")]).getStatusCode() == Http422
      expect DavClientError:
        discard syncTokenOf("""<D:multistatus xmlns:D="DAV:"/>""")

  test "deletes surface as 404 tombstones":
    withAb(20988):
      discard client.request(HttpMkcol, base & "/ab", buildMkcolAddressbook())
      discard client.request(HttpPut, base & "/ab/ada.vcf", Ada)
      discard client.request(HttpPut, base & "/ab/bob.vcf", Bob)
      let tok = syncTokenOf(client.request(HttpReport, base & "/ab",
        buildSyncCollection(), [("Depth", "1")]).getBodyString())
      discard client.request(HttpDelete, base & "/ab/ada.vcf")
      let s2 = client.request(HttpReport, base & "/ab",
        buildSyncCollection(tok), [("Depth", "1")])
      check s2.getStatusCode() == Http207
      let b2 = s2.getBodyString()
      check "bob.vcf" in b2
      check "ada.vcf" in b2
      check "404 Not Found" in b2
      let tok2 = syncTokenOf(b2)
      check tok2 != tok
      # Steady on the new token: no responses.
      let s3 = client.request(HttpReport, base & "/ab",
        buildSyncCollection(tok2), [("Depth", "1")])
      check "<D:response>" notin s3.getBodyString()
      # MOVE-out also leaves a tombstone at the source.
      discard client.request(HttpPut, base & "/ab/c.vcf", AdaUid)
      let tok3 = syncTokenOf(client.request(HttpReport, base & "/ab",
        buildSyncCollection(tok2), [("Depth", "1")]).getBodyString())
      discard client.request(HttpMove, base & "/ab/c.vcf", "",
        [("Destination", base & "/outside.vcf")])
      let s4 = client.request(HttpReport, base & "/ab",
        buildSyncCollection(tok3), [("Depth", "1")])
      check s4.getStatusCode() == Http207
      check "c.vcf" in s4.getBodyString()
      check "404 Not Found" in s4.getBodyString()
      # Unknown token: full resync, no tombstones.
      let s5 = client.request(HttpReport, base & "/ab",
        buildSyncCollection("bogus"), [("Depth", "1")])
      check "404 Not Found" notin s5.getBodyString()
