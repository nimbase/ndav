# WebDAV client (RFC 4918 + the CalDAV report subset in `caldav.nim`) on
# top of powpow's sync `HttpClient`.
#
# Sync only: one blocking request at a time per client. Responses are backed
# by the client's pooled parser, so extract headers and bodies before the
# next request on the same client.
#
# Paths are server-rooted (`/cal/ev.ics`); a full URL is accepted only where
# a `dest` argument allows it (`COPY`/`MOVE` `Destination`, passed through
# untouched for single-origin servers).

import ./davmethod # stage verb extensions before powpow compiles
export davmethod
import std/httpcore except HttpMethod
import std/strutils
import powpow
import ./auth
import ./davxml

export auth
export davxml

type
  DavClientError* = object of CatchableError

  DavClient* = ref object
    http*: HttpClient
    base*: string ## Origin + optional prefix, no trailing slash.
    authHeader*: string ## Full `Authorization` value, "" when anonymous.

proc wrapDavClient*(http: HttpClient, base: string): DavClient =
  ## Use a prebuilt client (custom TLS, pool tuning, or a loopback test
  ## client sharing its loop with a test server).
  DavClient(http: http, base: base.strip(leading = false, trailing = true,
    chars = {'/'}))

proc newDavClient*(base: string, timeoutMs = 0): DavClient =
  DavClient(http: newHttpClient(timeoutMs = timeoutMs),
    base: base.strip(leading = false, trailing = true, chars = {'/'}))

proc closeClient*(c: DavClient) =
  ## Close the wrapped HTTP client. Named apart from powpow's `close` so
  ## both overloads stay unambiguous in one scope.
  c.http.close()

proc setAuth*(c: DavClient, user, pass: string) =
  ## Attach HTTP Basic credentials to every request from this client.
  c.authHeader = encodeBasic(user, pass)

proc clearAuth*(c: DavClient) =
  ## Drop credentials; further requests go out anonymous.
  c.authHeader = ""

proc urlFor*(c: DavClient, path: string): string =
  if path.startsWith("/"): c.base & path
  else: c.base & "/" & path

proc destValue(c: DavClient, dest: string): string =
  if dest.startsWith("http://") or dest.startsWith("https://"): dest
  else: c.urlFor(dest)

proc tokenValue(token: string): string =
  let t = token.strip()
  if t.startsWith("<"): t else: "<" & t & ">"

proc raw*(c: DavClient, meth: HttpMethod, path: string; body = "",
    headers: openArray[(string, string)] = []): HttpClientResponse {.discardable.} =
  if c.authHeader.len > 0:
    var hs = @[("Authorization", c.authHeader)]
    for h in headers:
      hs.add(h)
    c.http.request(meth, c.urlFor(path), body, hs)
  else:
    c.http.request(meth, c.urlFor(path), body, headers)

# ── Request builders ─────────────────────────────────────────────────────

proc serializeProp(p: DavProp): XmlNode =
  let elem =
    if p.ns == DavNs: newDavElement(p.name)
    elif p.ns == CalNs: newCalElement(p.name)
    elif p.ns == CardNs: newCardElement(p.name)
    else: newXmlElement(p.name)
  if p.xml.len > 0:
    for n in parseFragment(p.xml):
      elem.addChild(n)
  elif p.value.len > 0:
    elem.addChild(newXmlText(p.value))
  elem

proc buildPropfindAllprop*(): string =
  let root = newDavElement("propfind")
  root.addAttr("xmlns:D", DavNs)
  root.addChild(newDavElement("allprop"))
  davDoc(root)

proc buildPropfindProp*(names: seq[string]): string =
  let root = newDavElement("propfind")
  root.addAttr("xmlns:D", DavNs)
  let prop = newDavElement("prop")
  for n in names:
    prop.addChild(newDavElement(n))
  root.addChild(prop)
  davDoc(root)

proc buildPropertyupdate*(sets, removes: seq[DavProp]): string =
  ## PROPPATCH body from dead-prop values. Raises `DavClientError` when both
  ## lists are empty (the server would reject it as `422` anyway).
  if sets.len == 0 and removes.len == 0:
    raise newException(DavClientError, "propertyupdate needs set or remove")
  let root = newDavElement("propertyupdate")
  root.addAttr("xmlns:D", DavNs)
  if sets.len > 0:
    let set = newDavElement("set")
    let prop = newDavElement("prop")
    for p in sets:
      prop.addChild(serializeProp(p))
    set.addChild(prop)
    root.addChild(set)
  if removes.len > 0:
    let remove = newDavElement("remove")
    let prop = newDavElement("prop")
    for p in removes:
      prop.addChild(serializeProp(p))
    remove.addChild(prop)
    root.addChild(remove)
  davDoc(root)

proc buildLockinfo*(scope = "exclusive", owner = ""): string =
  if scope != "exclusive" and scope != "shared":
    raise newException(DavClientError,
      "lock scope must be exclusive or shared")
  let root = newDavElement("lockinfo")
  root.addAttr("xmlns:D", DavNs)
  let ls = newDavElement("lockscope")
  ls.addChild(newDavElement(scope))
  root.addChild(ls)
  let lt = newDavElement("locktype")
  lt.addChild(newDavElement("write"))
  root.addChild(lt)
  if owner.len > 0:
    let own = newDavElement("owner")
    own.addChild(newXmlText(owner))
    root.addChild(own)
  davDoc(root)

proc buildCalendarQuery*(compName = "VEVENT", rangeStart = "",
    rangeEnd = "", wantEtag = true, wantCalData = true,
    extra: seq[string] = @[]): string =
  ## `calendar-query` REPORT body. Empty `compName` omits the filter
  ## (matches everything); empty bounds omit that side of `time-range`.
  let root = newXmlElement("C:calendar-query")
  root.addAttr("xmlns:D", DavNs)
  root.addAttr("xmlns:C", CalNs)
  let prop = newDavElement("prop")
  if wantEtag:
    prop.addChild(newDavElement("getetag"))
  if wantCalData:
    prop.addChild(newCalElement("calendar-data"))
  for n in extra:
    prop.addChild(newDavElement(n))
  root.addChild(prop)
  if compName.len > 0 or rangeStart.len > 0 or rangeEnd.len > 0:
    let filter = newCalElement("filter")
    let outer = newCalElement("comp-filter")
    outer.addAttr("name", "VCALENDAR")
    if compName.len > 0:
      let inner = newCalElement("comp-filter")
      inner.addAttr("name", compName)
      if rangeStart.len > 0 or rangeEnd.len > 0:
        let tr = newCalElement("time-range")
        if rangeStart.len > 0:
          tr.addAttr("start", rangeStart)
        if rangeEnd.len > 0:
          tr.addAttr("end", rangeEnd)
        inner.addChild(tr)
      outer.addChild(inner)
    filter.addChild(outer)
    root.addChild(filter)
  davDoc(root)

proc addressDataElement*(version = "", contentType = ""): XmlNode =
  ## `<address-data>` selector element with optional `version`
  ## (`3.0`/`4.0`) and `content-type` preferences.
  result = newCardElement("address-data")
  if contentType.len > 0:
    result.addAttr("content-type", contentType)
  if version.len > 0:
    result.addAttr("version", version)

proc buildAddressbookQuery*(filters: seq[string] = @["FN"],
    text: string = "", wantEtag = true, wantAddressData = true,
    extra: seq[string] = @[], testAnyOf = false, limit = -1,
    version = ""): string =
  ## `addressbook-query` REPORT body. Each entry of `filters` is a
  ## prop-filter on that vCard property; when `text` is non-empty every
  ## prop-filter carries one `contains` text-match. Empty `filters` omits
  ## `<filter>` (matches everything). `limit >= 0` adds `<limit><nresults>`.
  ## `version` (`3.0`/`4.0`) requests that `address-data` form.
  let root = newXmlElement("CR:addressbook-query")
  root.addAttr("xmlns:D", DavNs)
  root.addAttr("xmlns:CR", CardNs)
  let prop = newDavElement("prop")
  if wantEtag:
    prop.addChild(newDavElement("getetag"))
  if wantAddressData:
    prop.addChild(addressDataElement(version))
  for n in extra:
    prop.addChild(newDavElement(n))
  root.addChild(prop)
  if filters.len > 0 or limit >= 0:
    if filters.len > 0:
      let filter = newCardElement("filter")
      filter.addAttr("test", if testAnyOf: "anyof" else: "allof")
      for f in filters:
        let pf = newCardElement("prop-filter")
        pf.addAttr("name", f)
        if text.len > 0:
          let tm = newCardElement("text-match")
          tm.addAttr("collation", "i;unicode-casemap")
          tm.addAttr("match-type", "contains")
          tm.addChild(newXmlText(text))
          pf.addChild(tm)
        filter.addChild(pf)
      root.addChild(filter)
  if limit >= 0:
    let lim = newDavElement("limit")
    let nr = newDavElement("nresults")
    nr.addChild(newXmlText($limit))
    lim.addChild(nr)
    root.addChild(lim)
  davDoc(root)

proc buildPrincipalPropertySearch*(wanted: seq[string] = @[],
    searches: seq[(string, string)] = @[("displayname", "")],
    testAnyOf = true): string =
  ## RFC 3744 §9.4 `principal-property-search` REPORT body. `wanted` lists
  ## response prop local names (empty = all live props); each search entry
  ## is a (property, match-text) pair over `displayname` / `principal-URL`,
  ## matched case-insensitively as a substring. Raises `DavClientError`
  ## when no search clause is given.
  if searches.len == 0:
    raise newException(DavClientError,
      "principal-property-search needs a search")
  let root = newDavElement("principal-property-search")
  root.addAttr("xmlns:D", DavNs)
  if testAnyOf:
    root.addAttr("test", "anyof")
  let prop = newDavElement("prop")
  for n in wanted:
    prop.addChild(newDavElement(n))
  root.addChild(prop)
  root.addChild(newDavElement("apply-to-principal-collection-set"))
  for (pname, text) in searches:
    let ps = newDavElement("property-search")
    let sp = newDavElement("prop")
    sp.addChild(newDavElement(pname))
    ps.addChild(sp)
    let m = newDavElement("match")
    if text.len > 0:
      m.addChild(newXmlText(text))
    ps.addChild(m)
    root.addChild(ps)
  davDoc(root)

proc buildAddressbookMultiget*(hrefs: seq[string], wantEtag = true,
    wantAddressData = true, extra: seq[string] = @[],
    version = ""): string =
  if hrefs.len == 0:
    raise newException(DavClientError, "addressbook-multiget needs hrefs")
  let root = newXmlElement("CR:addressbook-multiget")
  root.addAttr("xmlns:D", DavNs)
  root.addAttr("xmlns:CR", CardNs)
  let prop = newDavElement("prop")
  if wantEtag:
    prop.addChild(newDavElement("getetag"))
  if wantAddressData:
    prop.addChild(addressDataElement(version))
  for n in extra:
    prop.addChild(newDavElement(n))
  root.addChild(prop)
  for h in hrefs:
    let href = newDavElement("href")
    href.addChild(newXmlText(h))
    root.addChild(href)
  davDoc(root)

proc buildSyncCollection*(token = "", wantEtag = true,
    wantAddressData = true, extra: seq[string] = @[],
    version = "", limit = -1): string =
  ## RFC 6578 `sync-collection` REPORT body for addressbooks. Empty `token`
  ## starts a new sync (server answers with all members plus the current
  ## token).
  let root = newDavElement("sync-collection")
  root.addAttr("xmlns:D", DavNs)
  root.addAttr("xmlns:CR", CardNs)
  let prop = newDavElement("prop")
  if wantEtag:
    prop.addChild(newDavElement("getetag"))
  if wantAddressData:
    prop.addChild(addressDataElement(version))
  for n in extra:
    prop.addChild(newDavElement(n))
  root.addChild(prop)
  let st = newDavElement("sync-token")
  if token.len > 0:
    st.addChild(newXmlText(token))
  root.addChild(st)
  let sl = newDavElement("sync-level")
  sl.addChild(newXmlText("1"))
  root.addChild(sl)
  if limit >= 0:
    let lim = newDavElement("limit")
    let nr = newDavElement("nresults")
    nr.addChild(newXmlText($limit))
    lim.addChild(nr)
    root.addChild(lim)
  davDoc(root)

proc buildCalSyncCollection*(token = "", wantEtag = true,
    wantCalData = true, extra: seq[string] = @[],
    limit = -1): string =
  ## RFC 6578 `sync-collection` REPORT body for calendars (CalDAV parity
  ## with `buildSyncCollection`). Empty `token` starts a new sync.
  let root = newDavElement("sync-collection")
  root.addAttr("xmlns:D", DavNs)
  root.addAttr("xmlns:C", CalNs)
  let prop = newDavElement("prop")
  if wantEtag:
    prop.addChild(newDavElement("getetag"))
  if wantCalData:
    prop.addChild(newCalElement("calendar-data"))
  for n in extra:
    prop.addChild(newDavElement(n))
  root.addChild(prop)
  let st = newDavElement("sync-token")
  if token.len > 0:
    st.addChild(newXmlText(token))
  root.addChild(st)
  let sl = newDavElement("sync-level")
  sl.addChild(newXmlText("1"))
  root.addChild(sl)
  if limit >= 0:
    let lim = newDavElement("limit")
    let nr = newDavElement("nresults")
    nr.addChild(newXmlText($limit))
    lim.addChild(nr)
    root.addChild(lim)
  davDoc(root)

proc buildMkcolAddressbook*(displayname = "", description = ""): string =
  ## Extended MKCOL body creating an addressbook collection, with optional
  ## dead-prop defaults stored by the server.
  let root = newDavElement("mkcol")
  root.addAttr("xmlns:D", DavNs)
  root.addAttr("xmlns:CR", CardNs)
  let setNode = newDavElement("set")
  let prop = newDavElement("prop")
  let rt = newDavElement("resourcetype")
  rt.addChild(newDavElement("collection"))
  rt.addChild(newCardElement("addressbook"))
  prop.addChild(rt)
  if displayname.len > 0:
    let dn = newDavElement("displayname")
    dn.addChild(newXmlText(displayname))
    prop.addChild(dn)
  if description.len > 0:
    let desc = newCardElement("addressbook-description")
    desc.addChild(newXmlText(description))
    prop.addChild(desc)
  setNode.addChild(prop)
  root.addChild(setNode)
  davDoc(root)

proc buildCalendarMultiget*(hrefs: seq[string], wantEtag = true,
    wantCalData = true, extra: seq[string] = @[]): string =
  if hrefs.len == 0:
    raise newException(DavClientError, "calendar-multiget needs hrefs")
  let root = newXmlElement("C:calendar-multiget")
  root.addAttr("xmlns:D", DavNs)
  root.addAttr("xmlns:C", CalNs)
  let prop = newDavElement("prop")
  if wantEtag:
    prop.addChild(newDavElement("getetag"))
  if wantCalData:
    prop.addChild(newCalElement("calendar-data"))
  for n in extra:
    prop.addChild(newDavElement(n))
  root.addChild(prop)
  for h in hrefs:
    let href = newDavElement("href")
    href.addChild(newXmlText(h))
    root.addChild(href)
  davDoc(root)

# ── Verb helpers ─────────────────────────────────────────────────────────

proc options*(c: DavClient, path = "/"): HttpClientResponse {.inline, discardable.} =
  c.raw(HttpOptions, path)

proc get*(c: DavClient, path: string,
    headers: openArray[(string, string)] = []): HttpClientResponse {.inline, discardable.} =
  c.raw(HttpGet, path, "", headers)

proc head*(c: DavClient, path: string,
    headers: openArray[(string, string)] = []): HttpClientResponse {.inline, discardable.} =
  c.raw(HttpHead, path, "", headers)

proc put*(c: DavClient, path, body: string,
    headers: openArray[(string, string)] = []): HttpClientResponse {.inline, discardable.} =
  c.raw(HttpPut, path, body, headers)

proc delete*(c: DavClient, path: string,
    headers: openArray[(string, string)] = []): HttpClientResponse {.inline, discardable.} =
  c.raw(HttpDelete, path, "", headers)

proc mkcol*(c: DavClient, path: string,
    body = ""): HttpClientResponse {.inline, discardable.} =
  c.raw(HttpMkcol, path, body)

proc mkcolAddressbook*(c: DavClient, path: string, displayname = "",
    description = ""): HttpClientResponse {.inline, discardable.} =
  ## Extended MKCOL creating an addressbook collection.
  c.raw(HttpMkcol, path, buildMkcolAddressbook(displayname, description))

proc mkcalendar*(c: DavClient, path: string; body = ""): HttpClientResponse {.inline, discardable.} =
  c.raw(HttpMkcalendar, path, body)

proc propfind*(c: DavClient, path: string, depth = "1",
    body = ""): HttpClientResponse {.inline, discardable.} =
  ## Empty `body` asks for the server default (`allprop`).
  c.raw(HttpPropfind, path, body, [("Depth", depth)])

proc proppatch*(c: DavClient, path: string, sets: seq[DavProp] = @[],
    removes: seq[DavProp] = @[]): HttpClientResponse {.inline, discardable.} =
  c.raw(HttpProppatch, path, buildPropertyupdate(sets, removes))

proc copy*(c: DavClient, path, dest: string, overwrite = true,
    depth = "infinity"): HttpClientResponse {.inline, discardable.} =
  c.raw(HttpCopy, path, "", [("Destination", c.destValue(dest)),
    ("Overwrite", if overwrite: "T" else: "F"), ("Depth", depth)])

proc move*(c: DavClient, path, dest: string,
    overwrite = true): HttpClientResponse {.inline, discardable.} =
  c.raw(HttpMove, path, "", [("Destination", c.destValue(dest)),
    ("Overwrite", if overwrite: "T" else: "F")])

proc lock*(c: DavClient, path: string, scope = "exclusive",
    depth = "infinity", timeout = "",
    owner = ""): HttpClientResponse {.discardable.} =
  var headers = @[("Depth", depth)]
  if timeout.len > 0:
    headers.add(("Timeout", timeout))
  c.raw(HttpLock, path, buildLockinfo(scope, owner), headers)

proc unlock*(c: DavClient, path, token: string): HttpClientResponse {.inline, discardable.} =
  c.raw(HttpUnlock, path, "", [("Lock-Token", tokenValue(token))])

proc report*(c: DavClient, path, body: string,
    depth = "1"): HttpClientResponse {.inline, discardable.} =
  c.raw(HttpReport, path, body, [("Depth", depth)])

# ── Response helpers ─────────────────────────────────────────────────────

proc ensure*(res: HttpClientResponse,
    expected: varargs[HttpCode]): HttpClientResponse {.discardable.} =
  ## Return `res` when its status is expected, else raise `DavClientError`
  ## carrying the status plus a body excerpt.
  for e in expected:
    if res.getStatusCode() == e:
      return res
  let body = res.getBodyString()
  raise newException(DavClientError, "unexpected status " &
    $res.getStatusCode() & ": " & body[0 ..< min(body.len, 200)])

proc multistatus*(res: HttpClientResponse): seq[DavResponse] =
  ## Parse a `207` body into responses. Raises `DavClientError` on any other
  ## status or on a malformed body.
  if res.getStatusCode() != Http207:
    raise newException(DavClientError, "expected 207 multistatus, got " &
      $res.getStatusCode())
  try:
    parseMultistatus(res.getBodyString())
  except DavXmlError as e:
    raise newException(DavClientError, "bad multistatus: " & e.msg)

proc lockTokenOf*(res: HttpClientResponse): string =
  ## The `Lock-Token` response header without angle brackets.
  try:
    ($res.getHeaders()["Lock-Token"]).strip(chars = {'<', '>'})
  except KeyError:
    raise newException(DavClientError, "response lacks Lock-Token")

proc syncTokenOf*(body: string): string =
  ## The `<sync-token>` of a `sync-collection` multistatus body.
  ## Raises `DavClientError` when absent or malformed.
  var root: XmlNode
  try:
    root = parseDavXml(body)
  except DavXmlError as e:
    raise newException(DavClientError, "bad multistatus: " & e.msg)
  if root.localNameOf() != "multistatus" or not root.hasDavNs():
    raise newException(DavClientError, "bad multistatus: no multistatus root")
  let st = root.findChild("sync-token")
  if st == nil:
    raise newException(DavClientError, "response lacks sync-token")
  for c in st.children:
    if c.kind == xnText:
      return c.text.strip()
  raise newException(DavClientError, "response lacks sync-token")

proc findResponse*(rs: seq[DavResponse], href: string): int =
  ## Index of the response for `href`, or -1.
  for i, r in rs:
    if r.href == href:
      return i
  -1

proc okProps*(r: DavResponse): seq[DavProp] =
  ## Props from the `200` propstat groups of one response.
  for ps in r.propstats:
    if propstatCode(ps.status) div 100 == 2:
      for p in ps.props:
        result.add(p)
