# WebDAV Class 1 request router (RFC 4918) as a powpow `OnRequestCallback`.
#
# Current scope and known limits (see module docs per item):
# - `Depth: infinity` is honored as depth 1 (capped, documented).
# - `HEAD` returns GET headers with an empty body (`Content-Length: 0`);
#   powpow's `send()` always frames `Content-Length` from the body length.
# - PROPPATCH applies best-effort in order (no atomic all-or-nothing yet).
# - `Destination` accepts absolute URIs and absolute paths; the host part
#   is ignored (single-origin deployment assumed).
# - Class 2 locking is enforced (`423 Locked`); `If` evaluation is a subset
#   (see `locks.nim`: untagged + tagged groups, `Not`, etag conditions ignored).
# - `GET` on a collection is `403` (no listing view yet).
#
# CalDAV core (RFC 4791, see `caldav.nim` for the documented subset):
# `MKCALENDAR` creates calendar collections; REPORT serves
# `calendar-query` (comp-filter + time-range with recurrence expansion),
# `calendar-multiget` and `sync-collection` (RFC 6578 parity with CardDAV).
# PUT into a calendar requires iCalendar object data. `OPTIONS` advertises
# `calendar-access`.
#
# CardDAV core (RFC 6352, see `carddav.nim` for the documented subset):
# extended `MKCOL` with `<resourcetype><addressbook/></resourcetype>`
# creates addressbook collections; REPORT serves `addressbook-query`
# (prop-filter + param-filter + text-match), `addressbook-multiget` and
# `sync-collection` (RFC 6578 with delete tombstones).
# PUT into an addressbook requires vCard object data. `OPTIONS` advertises
# `addressbook-access`.
#
# Auth (see `auth.nim`): HTTP Basic (RFC 7617) with Argon2id hashes from the
# `[users]` config table. Empty users means an open server; otherwise every
# request needs valid credentials (`401` + `WWW-Authenticate`). Principals
# live under virtual `/principals/` (no driver storage); any authenticated
# user has full access (no per-resource ACLs yet).

import ./davmethod # stage verb extensions before powpow compiles
export davmethod
import std/httpcore except HttpMethod
import std/[strutils, uri, options, tables, algorithm, sequtils]
import powpow
import ./auth
import ./backend
import ./props
import ./caldav
import ./carddav

export auth
export backend
export props
export caldav
export carddav

const
  DavAllow* = "OPTIONS, GET, HEAD, POST, PUT, DELETE, MKCOL, MKCALENDAR, " &
    "PROPFIND, PROPPATCH, COPY, MOVE, LOCK, UNLOCK, REPORT"

type
  DavServer* = ref object
    backend*: DavBackend

proc newDavServer*(driver: StorageDriver,
    users = initTable[string, string]()): DavServer =
  DavServer(backend: newDavBackend(driver, users))

proc serve*(srv: DavServer, req: HttpRequest, res: HttpResponse)

proc servePrincipalsPropfind(srv: DavServer, req: HttpRequest,
  res: HttpResponse, path, user: string)

proc davHandler*(srv: DavServer): OnRequestCallback =
  ## Build the request callback. Capture-safe for powpow's single-loop use.
  result = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    {.gcsafe.}:
      srv.serve(req, res)

# ── Small helpers ────────────────────────────────────────────────────────────

proc reqHeader(req: HttpRequest, name: string): string =
  let h = req.getHeaders()
  if h.hasKey(name): $h[name] else: ""

proc normPath(raw: string): string =
  ## Decode + normalize a request target. Returns "" when the path escapes
  ## the root or is malformed.
  var decoded: string
  try:
    decoded = decodeUrl(raw)
  except CatchableError:
    return ""
  if not decoded.startsWith("/"):
    return ""
  var parts: seq[string]
  for seg in decoded.split('/'):
    case seg
    of "", ".": discard
    of "..":
      if parts.len == 0:
        return ""
      discard parts.pop()
    else:
      parts.add(seg)
  "/" & parts.join("/")

proc parentOf(urlPath: string): string =
  let i = urlPath.rfind('/')
  if i <= 0: "/" else: urlPath[0 ..< i]

proc collHref(urlPath: string): string {.inline.} =
  ## Collection hrefs end with `/` per RFC 4918 (root already does).
  if urlPath.endsWith("/"): urlPath else: urlPath & "/"

proc parseDepthHeader(s: string): int =
  ## 0, 1, 2 (= infinity), or -1 when invalid.
  case s.strip().toLowerAscii()
  of "0": 0
  of "1": 1
  of "infinity": 2
  else: -1

proc destUrlPath(req: HttpRequest): string =
  let raw = reqHeader(req, "Destination")
  if raw.len == 0:
    return ""
  var path: string
  try:
    path = parseUri(raw).path
  except CatchableError:
    return ""
  normPath(path)

proc overwriteFlag(req: HttpRequest): bool =
  reqHeader(req, "Overwrite").strip().toUpperAscii() != "F"

proc lockedOut(b: DavBackend, urlPath: string, req: HttpRequest): bool =
  ## True when covering locks exist and the request presents no matching
  ## token via `If` or `Lock-Token`. Callers answer `423 Locked`.
  not b.locks.ifSatisfied(urlPath, reqHeader(req, "If"),
    parseLockTokens(reqHeader(req, "Lock-Token")))

# ── Backend queries ──────────────────────────────────────────────────────────

proc exists(b: DavBackend, urlPath: string): bool =
  b.driver.exists(toDriverPath(urlPath))

proc isCollection(b: DavBackend, urlPath: string): bool =
  b.driver.metadata(toDriverPath(urlPath)).isDir

proc parentIsCollection(b: DavBackend, urlPath: string): bool =
  let p = parentOf(urlPath)
  if p == "/":
    return true
  if not b.exists(p):
    return false
  b.isCollection(p)

# ── Method handlers ──────────────────────────────────────────────────────────

proc serveOptions(srv: DavServer, req: HttpRequest, res: HttpResponse) =
  res.status(Http200)
    .header("Allow", DavAllow)
    .header("DAV", "1, 2, calendar-access, addressbook-access")
    .header("Content-Length", "0")
    .send("")

proc serveGet(srv: DavServer, req: HttpRequest, res: HttpResponse,
    headOnly: bool) =
  let b = srv.backend
  let path = normPath(req.getPath())
  if path.len == 0 or not b.exists(path):
    res.sendError(Http404, "Not Found")
    return
  if b.isCollection(path):
    res.sendError(Http403, "GET on collections is not supported")
    return
  var content: string
  try:
    content = b.driver.read(toDriverPath(path))
  except CatchableError:
    res.sendError(Http500, "Read failed")
    return
  let meta = b.driver.metadata(toDriverPath(path))
  res.status(Http200)
    .header("Content-Type", b.davMimeType(path))
    .header("ETag", davEtag(meta.size, meta.lastModified))
    .header("Last-Modified", httpDate(meta.lastModified))
  if headOnly:
    res.send("")
  else:
    res.send(content)

proc uidConflict(b: DavBackend, collPath, uid, excludePath: string): string =
  ## Href of another member of addressbook `collPath` already using `uid`,
  ## or "". UID-less cards never conflict (UID presence itself is not
  ## enforced, only uniqueness when present).
  if uid.len == 0:
    return ""
  try:
    for m in b.driver.list(toDriverPath(collPath), recursive = false):
      let cp = "/" & m.path
      if cp == excludePath:
        continue
      var content = ""
      try:
        if b.isCollection(cp):
          continue
        content = b.driver.read(toDriverPath(cp))
      except CatchableError:
        continue
      var cards: seq[VCard]
      try:
        cards = parseVCards(content)
      except OpenParserVCardError:
        continue
      for c in cards:
        if c.uid.isSome and c.uid.get() == uid:
          return cp
  except CatchableError:
    discard
  ""

proc servePut(srv: DavServer, req: HttpRequest, res: HttpResponse) =
  let b = srv.backend
  let path = normPath(req.getPath())
  if path.len == 0 or path == "/":
    res.sendError(Http409, "Conflict")
    return
  if not b.parentIsCollection(path):
    res.sendError(Http409, "Parent collection does not exist")
    return
  if b.exists(path) and b.isCollection(path):
    res.sendError(Http409, "Cannot PUT over a collection")
    return
  if b.lockedOut(path, req):
    res.sendError(Http423, "Locked")
    return
  # CalDAV gate: resources inside a calendar must hold iCalendar object
  # data (at least one VEVENT/VTODO/VJOURNAL).
  if b.isCalendarCollection(parentOf(path)) and
      not isCalendarContent(req.getBodyString()):
    res.sendError(Http400, "Calendar resources must contain iCalendar data")
    return
  # CardDAV gates (RFC 6352 §6.3): exactly one vCard with non-empty FN,
  # plus UID uniqueness (`no-uid-conflict`: no reuse across resources,
  # no UID change on overwrite).
  if b.isAddressbookCollection(parentOf(path)):
    var card: VCard
    try:
      card = requireSingleAddress(req.getBodyString())
    except OpenParserVCardError as e:
      res.sendError(Http400, e.msg)
      return
    if card.uid.isSome:
      let conflict = b.uidConflict(parentOf(path), card.uid.get(), path)
      if conflict.len > 0:
        res.sendError(Http409, "UID already in use: " & conflict)
        return
      if b.exists(path) and not b.isCollection(path):
        var oldUid = ""
        try:
          for oc in parseVCards(b.driver.read(toDriverPath(path))):
            if oc.uid.isSome:
              oldUid = oc.uid.get()
              break
        except CatchableError:
          discard
        if oldUid.len > 0 and oldUid != card.uid.get():
          res.sendError(Http409, "Cannot change UID of an address object")
          return
  let created = not b.exists(path)
  try:
    b.driver.write(toDriverPath(path), req.getBodyString())
  except CatchableError:
    res.sendError(Http500, "Write failed")
    return
  if b.isSyncCollection(parentOf(path)):
    discard b.bumpSync(parentOf(path))
  res.status(if created: Http201 else: Http204).send("")

proc serveDelete(srv: DavServer, req: HttpRequest, res: HttpResponse) =
  let b = srv.backend
  let path = normPath(req.getPath())
  if path.len == 0 or not b.exists(path):
    res.sendError(Http404, "Not Found")
    return
  if path == "/":
    res.sendError(Http403, "Cannot DELETE the root collection")
    return
  if b.lockedOut(path, req):
    res.sendError(Http423, "Locked")
    return
  let wasCollection = b.isCollection(path)
  let parent = parentOf(path)
  let parentSynced = b.isSyncCollection(parent)
  try:
    if wasCollection:
      b.driver.deleteDir(toDriverPath(path), force = true)
    else:
      b.driver.delete(toDriverPath(path))
  except CatchableError:
    res.sendError(Http500, "Delete failed")
    return
  # forgetDead drops dead props, markers and sync logs for the subtree.
  b.forgetDead(path)
  # Only direct file members appear in depth-1 sync listings: a file
  # delete leaves a tombstone, a collection delete (its nested files were
  # never listed) just bumps the parent revision.
  if parentSynced and not wasCollection:
    discard b.recordSyncDelete(parent, path)
  elif parentSynced and wasCollection:
    discard b.bumpSync(parent)
  res.status(Http204).send("")

proc serveMkcol(srv: DavServer, req: HttpRequest, res: HttpResponse) =
  ## Plain MKCOL plus RFC 6352 extended MKCOL: a body carrying
  ## `<resourcetype><collection/><addressbook/></resourcetype>` creates an
  ## addressbook collection. Any other non-empty body is `415`, matching the
  ## previous Class 1 behavior. Addressbooks may nest (lenient, documented).
  let b = srv.backend
  let path = normPath(req.getPath())
  if path.len == 0 or path == "/":
    res.sendError(Http405, "Collection already exists")
    return
  if b.exists(path):
    res.sendError(Http405, "Resource already exists")
    return
  if not b.parentIsCollection(path):
    res.sendError(Http409, "Parent collection does not exist")
    return
  if b.lockedOut(path, req):
    res.sendError(Http423, "Locked")
    return
  if req.getBodyString().strip().len == 0:
    try:
      b.driver.makeDir(toDriverPath(path))
    except CatchableError:
      res.sendError(Http500, "MKCOL failed")
      return
    if b.isSyncCollection(parentOf(path)):
      discard b.bumpSync(parentOf(path))
    res.status(Http201).send("")
    return
  var isAb = false
  var bodyProps: seq[DavProp]
  try:
    (isAb, bodyProps) = parseMkcolAddressbook(req.getBodyString())
  except DavXmlError as e:
    # Non-XML bodies keep the historic Class 1 `415`; XML that fails
    # to parse as extended MKCOL is `422`.
    if req.getBodyString().strip().startsWith("<"):
      res.sendError(Http422, e.msg)
    else:
      res.sendError(Http415, "MKCOL with a body is not supported")
    return
  if not isAb:
    # A calendar resourcetype via MKCOL hints at the wrong verb.
    if "calendar" in req.getBodyString().toLowerAscii():
      res.sendError(Http403, "Use MKCALENDAR for calendars")
    else:
      res.sendError(Http415, "MKCOL with a body is not supported")
    return
  for p in bodyProps:
    if p.ns == DavNs and isProtectedLive(p.name):
      res.sendError(Http403, "Protected live property: " & p.name)
      return
  try:
    b.driver.makeDir(toDriverPath(path))
  except CatchableError:
    res.sendError(Http500, "MKCOL failed")
    return
  b.markAddressbook(path)
  for p in bodyProps:
    if p.xml.len > 0:
      b.setDead(path, p.ns, p.name, "", p.xml)
    else:
      b.setDead(path, p.ns, p.name, p.value, "")
  if b.isSyncCollection(parentOf(path)):
    discard b.bumpSync(parentOf(path))
  res.status(Http201).send("")

proc serveMkcalendar(srv: DavServer, req: HttpRequest, res: HttpResponse) =
  ## CalDAV MKCALENDAR (RFC 4791 §5.3.1): like MKCOL, plus the calendar
  ## marker. An XML body may carry `<set><prop>` defaults, stored as dead
  ## props; protected live props are rejected with `403` before anything
  ## is created. Calendars may nest (lenient, documented).
  let b = srv.backend
  let path = normPath(req.getPath())
  if path.len == 0 or path == "/":
    res.sendError(Http405, "Collection already exists")
    return
  if b.exists(path):
    res.sendError(Http405, "Resource already exists")
    return
  if not b.parentIsCollection(path):
    res.sendError(Http409, "Parent collection does not exist")
    return
  if b.lockedOut(path, req):
    res.sendError(Http423, "Locked")
    return
  var bodyProps: seq[DavProp]
  if req.getBodyString().strip().len > 0:
    try:
      bodyProps = parseMkcalendarProps(req.getBodyString())
    except DavXmlError as e:
      res.sendError(Http422, e.msg)
      return
  for p in bodyProps:
    if p.ns == DavNs and isProtectedLive(p.name):
      res.sendError(Http403, "Protected live property: " & p.name)
      return
  try:
    b.driver.makeDir(toDriverPath(path))
  except CatchableError:
    res.sendError(Http500, "MKCALENDAR failed")
    return
  b.markCalendar(path)
  for p in bodyProps:
    if p.xml.len > 0:
      b.setDead(path, p.ns, p.name, "", p.xml)
    else:
      b.setDead(path, p.ns, p.name, p.value, "")
  if b.isSyncCollection(parentOf(path)):
    discard b.bumpSync(parentOf(path))
  res.status(Http201).send("")

proc hrefToPath(href: string): string =
  ## Absolute URI or absolute path to a normalized URL path ("" when bad).
  var raw: string
  try:
    raw = parseUri(href.strip()).path
  except CatchableError:
    return ""
  if raw.len == 0:
    return ""
  normPath(raw)

proc calPropstats(b: DavBackend, urlPath, content: string,
    rep: CalReportRequest): seq[DavPropstat] =
  ## 200/404 propstat groups for one matched calendar object resource.
  var ok, missing: seq[DavProp]
  if rep.wantEtag:
    try:
      let meta = b.driver.metadata(toDriverPath(urlPath))
      ok.add(DavProp(ns: DavNs, name: "getetag",
        value: davEtag(meta.size, meta.lastModified)))
    except CatchableError:
      missing.add(DavProp(ns: DavNs, name: "getetag"))
  if rep.wantCalData:
    ok.add(calDataProp(content))
  if rep.extraProps.len > 0:
    let live = b.liveProps(urlPath)
    let dead = b.deadPropsList(urlPath)
    for name in rep.extraProps:
      let li = live.findLive(name)
      if li >= 0:
        ok.add(live[li])
        continue
      var found = false
      for pr in dead:
        if pr.name == name:
          ok.add(pr)
          found = true
          break
      if not found:
        missing.add(DavProp(ns: DavNs, name: name))
  if ok.len > 0:
    result.add(DavPropstat(props: ok, status: "HTTP/1.1 200 OK"))
  if missing.len > 0:
    result.add(DavPropstat(props: missing,
      status: "HTTP/1.1 404 Not Found"))

proc cardPropstats(b: DavBackend, urlPath, content: string,
    rep: CardReportRequest): seq[DavPropstat] =
  ## 200/404 propstat groups for one matched address object resource.
  var ok, missing: seq[DavProp]
  if rep.wantEtag:
    try:
      let meta = b.driver.metadata(toDriverPath(urlPath))
      ok.add(DavProp(ns: DavNs, name: "getetag",
        value: davEtag(meta.size, meta.lastModified)))
    except CatchableError:
      missing.add(DavProp(ns: DavNs, name: "getetag"))
  if rep.wantAddressData:
    ok.add(DavProp(ns: CardNs, name: "address-data",
      value: convertAddressData(content, addressDataTarget(rep.addressDataPrefs))))
  if rep.extraProps.len > 0:
    let live = b.liveProps(urlPath)
    let dead = b.deadPropsList(urlPath)
    for name in rep.extraProps:
      let li = live.findLive(name)
      if li >= 0:
        ok.add(live[li])
        continue
      var found = false
      for pr in dead:
        if pr.name == name:
          ok.add(pr)
          found = true
          break
      if not found:
        missing.add(DavProp(ns: DavNs, name: name))
  if ok.len > 0:
    result.add(DavPropstat(props: ok, status: "HTTP/1.1 200 OK"))
  if missing.len > 0:
    result.add(DavPropstat(props: missing,
      status: "HTTP/1.1 404 Not Found"))

proc cardPropstatsForSync(b: DavBackend, urlPath, content: string,
    sync: SyncCollectionRequest): seq[DavPropstat] =
  ## Same 200/404 groups as `cardPropstats` but driven by a sync request.
  var rep = CardReportRequest(kind: rkAddressQuery,
    wantEtag: sync.wantEtag, wantAddressData: sync.wantAddressData,
    addressDataPrefs: sync.addressDataPrefs, extraProps: sync.extraProps)
  b.cardPropstats(urlPath, content, rep)

proc calPropstatsForSync(b: DavBackend, urlPath, content: string,
    sync: SyncCollectionRequest): seq[DavPropstat] =
  ## Same 200/404 groups as `calPropstats` but driven by a sync request.
  var rep = CalReportRequest(kind: rkQuery,
    wantEtag: sync.wantEtag, wantCalData: sync.wantCalData,
    extraProps: sync.extraProps)
  b.calPropstats(urlPath, content, rep)

proc serveCardReport(srv: DavServer, req: HttpRequest, res: HttpResponse,
    path: string, rep: CardReportRequest) =
  ## CardDAV `addressbook-query` / `addressbook-multiget` (RFC 6352 §7-8).
  let b = srv.backend
  if rep.hasUnsupportedAddressData:
    res.sendError(Http415, "Unsupported address-data content-type")
    return
  if rep.kind == rkAddressMultiget:
    if not b.isAddressbookCollection(path):
      res.sendError(Http403, "addressbook-multiget needs an addressbook collection")
      return
    var responses: seq[DavResponse]
    var n = 0
    for href in rep.hrefs:
      if rep.hasLimit and n >= rep.limit:
        break
      let rp = hrefToPath(href)
      if rp.len == 0 or not b.exists(rp) or b.isCollection(rp) or
          (rp != path and not rp.startsWith(collHref(path))):
        responses.add(DavResponse(href: href,
          propstats: @[DavPropstat(props: @[],
            status: "HTTP/1.1 404 Not Found")]))
        continue
      var content = ""
      try:
        content = b.driver.read(toDriverPath(rp))
      except CatchableError:
        responses.add(DavResponse(href: href,
          propstats: @[DavPropstat(props: @[],
            status: "HTTP/1.1 404 Not Found")]))
        continue
      responses.add(DavResponse(href: rp,
        propstats: b.cardPropstats(rp, content, rep)))
      inc n
    res.status(Http207)
      .header("Content-Type", "application/xml; charset=utf-8")
      .send(buildMultistatus(responses))
    return
  # addressbook-query: Depth 0 or 1 (default 1); infinity is rejected.
  let rawDepth = reqHeader(req, "Depth")
  var depth = 1
  if rawDepth.len > 0:
    depth = parseDepthHeader(rawDepth)
    if depth != 0 and depth != 1:
      res.sendError(Http400, "REPORT Depth must be 0 or 1")
      return
  var candidates: seq[string]
  if b.isCollection(path):
    if not b.isAddressbookCollection(path):
      res.sendError(Http403, "addressbook-query needs an addressbook collection")
      return
    if depth == 1:
      try:
        for m in b.driver.list(toDriverPath(path), recursive = false):
          let cp = "/" & m.path
          if not b.isCollection(cp):
            candidates.add(cp)
      except CatchableError:
        res.sendError(Http500, "REPORT failed")
        return
  else:
    if not b.isAddressbookCollection(parentOf(path)):
      res.sendError(Http403, "addressbook-query needs an addressbook resource")
      return
    candidates.add(path)
  var responses: seq[DavResponse]
  for cp in candidates:
    if rep.hasLimit and responses.len >= rep.limit:
      break
    var content = ""
    try:
      content = b.driver.read(toDriverPath(cp))
    except CatchableError:
      continue
    if carddav.resourceMatches(content, rep.filters, rep.testAnyOf):
      responses.add(DavResponse(href: cp,
        propstats: b.cardPropstats(cp, content, rep)))
  res.status(Http207)
    .header("Content-Type", "application/xml; charset=utf-8")
    .send(buildMultistatus(responses))

proc serveSyncCollection(srv: DavServer, req: HttpRequest, res: HttpResponse,
    path: string, sync: SyncCollectionRequest) =
  ## RFC 6578 `sync-collection` over a calendar or addressbook. The sync
  ## token pairs the collection ctag with a revision (`ctag#rev`): a
  ## matching token answers with no member responses, while a missing,
  ## legacy (ctag-only) or unknown token answers with the full member
  ## listing. A known stale token answers with the full listing plus `404`
  ## tombstones for members deleted since that token. Tombstone history is
  ## in-memory and capped (`MaxSyncDeletes`); overflow falls back to a
  ## full resync without tombstones. `<limit>` caps total responses
  ## (members first, then tombstones).
  let b = srv.backend
  let isCal = b.isCalendarCollection(path)
  let isAb = b.isAddressbookCollection(path)
  if not isCal and not isAb:
    res.sendError(Http403, "sync-collection needs a calendar or addressbook collection")
    return
  if sync.hasUnsupportedAddressData:
    res.sendError(Http415, "Unsupported address-data content-type")
    return
  let rawDepth = reqHeader(req, "Depth")
  var depth = 1
  if rawDepth.len > 0:
    depth = parseDepthHeader(rawDepth)
    if depth != 1:
      res.sendError(Http400, "REPORT Depth must be 1")
      return
  let ctag =
    if isCal: b.calendarCtag(path)
    else: b.addressbookCtag(path)
  let current = b.makeSyncToken(path, ctag)
  if sync.hasToken and sync.token.len > 0 and sync.token == current:
    res.status(Http207)
      .header("Content-Type", "application/xml; charset=utf-8")
      .send(buildMultistatus(@[], current))
    return
  var responses: seq[DavResponse]
  var members: seq[string]
  try:
    for m in b.driver.list(toDriverPath(path), recursive = false):
      if sync.hasLimit and responses.len >= sync.limit:
        break
      let cp = "/" & m.path
      if b.isCollection(cp):
        continue
      var content = ""
      try:
        content = b.driver.read(toDriverPath(cp))
      except CatchableError:
        continue
      members.add(cp)
      if isCal:
        responses.add(DavResponse(href: cp,
          propstats: b.calPropstatsForSync(cp, content, sync)))
      else:
        responses.add(DavResponse(href: cp,
          propstats: b.cardPropstatsForSync(cp, content, sync)))
  except CatchableError:
    res.sendError(Http500, "REPORT failed")
    return
  # Tombstones for known stale tokens: deletes since the presented
  # revision, filtered to hrefs that do not exist again (recreates show
  # as live members, not deletes).
  if sync.hasToken and sync.token.len > 0:
    let (tokCtag, tokRev, ok) = splitSyncToken(sync.token)
    if ok and tokRev <= b.syncRevOf(path):
      # Same ctag but same rev is steady (handled above); a ctag match
      # with an older rev still carries deletes, so always consult the log.
      let (hrefs, known) = b.syncDeletesSince(path, tokRev)
      if known:
        discard tokCtag
        for h in hrefs:
          if sync.hasLimit and responses.len >= sync.limit:
            break
          if h in members:
            continue
          responses.add(DavResponse(href: h,
            propstats: @[DavPropstat(props: @[],
              status: "HTTP/1.1 404 Not Found")]))
  res.status(Http207)
    .header("Content-Type", "application/xml; charset=utf-8")
    .send(buildMultistatus(responses, current))

proc serveReport(srv: DavServer, req: HttpRequest, res: HttpResponse) =
  ## CalDAV `calendar-query` / `calendar-multiget` (RFC 4791 §7) plus
  ## CardDAV `addressbook-query` / `addressbook-multiget` (RFC 6352 §7-8)
  ## and `sync-collection` (RFC 6578, calendars and addressbooks).
  ## Anything else REPORT-shaped answers `501`. Reports against a
  ## non-matching collection type answer `403`.
  let b = srv.backend
  let path = normPath(req.getPath())
  if path.len == 0 or not b.exists(path):
    res.sendError(Http404, "Not Found")
    return
  # Dispatch on the root element so malformed CardDAV/`sync-collection`
  # bodies answer `422` (their own parser errors) instead of falling
  # through to the CalDAV branch and surfacing as `501`.
  var peek: XmlNode
  try:
    peek = parseDavXml(req.getBodyString())
  except DavXmlError as e:
    res.sendError(Http422, e.msg)
    return
  if peek.localNameOf() == "sync-collection" and peek.hasDavNs():
    var syncRep: SyncCollectionRequest
    try:
      syncRep = parseSyncCollection(req.getBodyString())
    except DavXmlError as e:
      res.sendError(Http422, e.msg)
      return
    srv.serveSyncCollection(req, res, path, syncRep)
    return
  if peek.hasCardNs():
    var cardRep: CardReportRequest
    try:
      cardRep = parseCardReport(req.getBodyString())
    except DavXmlError as e:
      res.sendError(Http422, e.msg)
      return
    srv.serveCardReport(req, res, path, cardRep)
    return
  var rep: CalReportRequest
  try:
    rep = parseCalReport(req.getBodyString())
  except DavXmlError as e:
    # Non-CalDAV/CardDAV REPORT roots (e.g. DAV-only bodies) are unimplemented.
    if "unsupported REPORT" in e.msg or "not a CalDAV element" in e.msg:
      res.sendError(Http501, "Not Implemented: " & e.msg)
    else:
      res.sendError(Http422, e.msg)
    return
  if rep.kind == rkMultiget:
    if not b.isCalendarCollection(path):
      res.sendError(Http403, "calendar-multiget needs a calendar collection")
      return
    var responses: seq[DavResponse]
    for href in rep.hrefs:
      let rp = hrefToPath(href)
      if rp.len == 0 or not b.exists(rp) or b.isCollection(rp) or
          (rp != path and not rp.startsWith(collHref(path))):
        responses.add(DavResponse(href: href,
          propstats: @[DavPropstat(props: @[],
            status: "HTTP/1.1 404 Not Found")]))
        continue
      var content = ""
      try:
        content = b.driver.read(toDriverPath(rp))
      except CatchableError:
        responses.add(DavResponse(href: href,
          propstats: @[DavPropstat(props: @[],
            status: "HTTP/1.1 404 Not Found")]))
        continue
      responses.add(DavResponse(href: rp,
        propstats: b.calPropstats(rp, content, rep)))
    res.status(Http207)
      .header("Content-Type", "application/xml; charset=utf-8")
      .send(buildMultistatus(responses))
    return
  # calendar-query: Depth 0 or 1 (default 1); infinity is rejected.
  let rawDepth = reqHeader(req, "Depth")
  var depth = 1
  if rawDepth.len > 0:
    depth = parseDepthHeader(rawDepth)
    if depth != 0 and depth != 1:
      res.sendError(Http400, "REPORT Depth must be 0 or 1")
      return
  var candidates: seq[string]
  if b.isCollection(path):
    if not b.isCalendarCollection(path):
      res.sendError(Http403, "calendar-query needs a calendar collection")
      return
    if depth == 1:
      try:
        for m in b.driver.list(toDriverPath(path), recursive = false):
          let cp = "/" & m.path
          if not b.isCollection(cp):
            candidates.add(cp)
      except CatchableError:
        res.sendError(Http500, "REPORT failed")
        return
  else:
    if not b.isCalendarCollection(parentOf(path)):
      res.sendError(Http403, "calendar-query needs a calendar resource")
      return
    candidates.add(path)
  var responses: seq[DavResponse]
  for cp in candidates:
    var content = ""
    try:
      content = b.driver.read(toDriverPath(cp))
    except CatchableError:
      continue
    if caldav.resourceMatches(content, rep.compName, rep.timeRange,
        rep.hasTimeRange):
      responses.add(DavResponse(href: cp,
        propstats: b.calPropstats(cp, content, rep)))
  res.status(Http207)
    .header("Content-Type", "application/xml; charset=utf-8")
    .send(buildMultistatus(responses))

proc resourceResponses(b: DavBackend, urlPath: string, depth: int,
    pf: PropfindRequest, currentUser = ""): seq[DavResponse] =
  ## Response list for PROPFIND: self plus direct children at depth >= 1.
  ## `depth == 2` (infinity) is capped to 1.
  var paths = @[urlPath]
  if depth >= 1 and b.isCollection(urlPath):
    # Driver listings are root-relative already (`col/f.txt`).
    for m in b.driver.list(toDriverPath(urlPath), recursive = false):
      paths.add("/" & m.path)
  for p in paths:
    let live = b.liveProps(p, currentUser)
    let dead = b.deadPropsList(p)
    var propstats: seq[DavPropstat]
    case pf.kind
    of pfAllprop:
      propstats.add(DavPropstat(props: live & dead,
        status: "HTTP/1.1 200 OK"))
    of pfPropname:
      var names: seq[DavProp]
      for pr in live:
        names.add(DavProp(ns: pr.ns, name: pr.name))
      for pr in dead:
        names.add(DavProp(ns: pr.ns, name: pr.name))
      propstats.add(DavPropstat(props: names, status: "HTTP/1.1 200 OK"))
    of pfProp:
      var ok, missing: seq[DavProp]
      for name in pf.props:
        let li = live.findLive(name)
        if li >= 0:
          ok.add(live[li])
          continue
        var found = false
        for pr in dead:
          if pr.ns == DavNs and pr.name == name:
            ok.add(pr)
            found = true
            break
        if not found:
          missing.add(DavProp(ns: DavNs, name: name))
      if ok.len > 0:
        propstats.add(DavPropstat(props: ok, status: "HTTP/1.1 200 OK"))
      if missing.len > 0:
        propstats.add(DavPropstat(props: missing,
          status: "HTTP/1.1 404 Not Found"))
    let href =
      if b.isCollection(p): collHref(p)
      else: p
    result.add(DavResponse(href: href, propstats: propstats))

proc servePropfind(srv: DavServer, req: HttpRequest, res: HttpResponse,
    currentUser = "") =
  let b = srv.backend
  let path = normPath(req.getPath())
  if path.len == 0 or not b.exists(path):
    res.sendError(Http404, "Not Found")
    return
  let rawDepth = reqHeader(req, "Depth")
  var depth: int
  if rawDepth.len == 0:
    depth = if b.isCollection(path): 2 else: 0
  else:
    depth = parseDepthHeader(rawDepth)
    if depth < 0:
      res.sendError(Http400, "Invalid Depth header")
      return
  var pf = PropfindRequest(kind: pfAllprop)
  if req.getBodyString().len > 0:
    try:
      pf = parsePropfind(req.getBodyString())
    except DavXmlError as e:
      res.sendError(Http422, e.msg)
      return
  var responses: seq[DavResponse]
  try:
    responses = b.resourceResponses(path, depth, pf, currentUser)
  except CatchableError:
    res.sendError(Http500, "PROPFIND failed")
    return
  res.status(Http207)
    .header("Content-Type", "application/xml; charset=utf-8")
    .send(buildMultistatus(responses))

proc serveProppatch(srv: DavServer, req: HttpRequest, res: HttpResponse) =
  let b = srv.backend
  let path = normPath(req.getPath())
  if path.len == 0 or not b.exists(path):
    res.sendError(Http404, "Not Found")
    return
  if b.lockedOut(path, req):
    res.sendError(Http423, "Locked")
    return
  var pu: PropertyupdateRequest
  try:
    pu = parsePropertyupdate(req.getBodyString())
  except DavXmlError as e:
    res.sendError(Http422, e.msg)
    return
  var ok, forbidden, missing: seq[DavProp]
  for op in pu.ops:
    case op.op
    of poSet:
      for p in op.props:
        if p.ns == DavNs and isProtectedLive(p.name):
          forbidden.add(DavProp(ns: p.ns, name: p.name))
        else:
          b.setDead(path, p.ns, p.name, p.value, p.xml)
          if p.xml.len > 0:
            ok.add(DavProp(ns: p.ns, name: p.name, xml: p.xml))
          else:
            ok.add(DavProp(ns: p.ns, name: p.name, value: p.value))
    of poRemove:
      for p in op.props:
        if p.ns == DavNs and isProtectedLive(p.name):
          forbidden.add(DavProp(ns: p.ns, name: p.name))
        elif b.delDead(path, p.ns, p.name):
          ok.add(DavProp(ns: p.ns, name: p.name))
        else:
          missing.add(DavProp(ns: p.ns, name: p.name))
  var propstats: seq[DavPropstat]
  if ok.len > 0:
    propstats.add(DavPropstat(props: ok, status: "HTTP/1.1 200 OK"))
  if forbidden.len > 0:
    propstats.add(DavPropstat(props: forbidden,
      status: "HTTP/1.1 403 Forbidden"))
  if missing.len > 0:
    propstats.add(DavPropstat(props: missing,
      status: "HTTP/1.1 404 Not Found"))
  if ok.len > 0 and not b.isCollection(path) and
      b.isSyncCollection(parentOf(path)):
    # Dead-prop edits do not touch mtime, so the ctag alone would miss
    # them; the revision bump makes sync notice member changes.
    discard b.bumpSync(parentOf(path))
  res.status(Http207)
    .header("Content-Type", "application/xml; charset=utf-8")
    .send(buildMultistatus(@[DavResponse(href: path, propstats: propstats)]))

proc serveCopyMove(srv: DavServer, req: HttpRequest, res: HttpResponse,
    isMove: bool) =
  let b = srv.backend
  let src = normPath(req.getPath())
  if src.len == 0 or not b.exists(src):
    res.sendError(Http404, "Not Found")
    return
  let dest = destUrlPath(req)
  if dest.len == 0:
    res.sendError(Http400, "Destination header required")
    return
  if dest == src or dest.startsWith(src & "/"):
    res.sendError(Http403, "Cannot copy onto itself or into itself")
    return
  if not b.parentIsCollection(dest):
    res.sendError(Http409, "Destination parent does not exist")
    return
  if b.lockedOut(src, req) or b.lockedOut(dest, req):
    res.sendError(Http423, "Locked")
    return
  let overwrite = overwriteFlag(req)
  let destExisted = b.exists(dest)
  if destExisted and not overwrite:
    res.sendError(Http412, "Destination exists and Overwrite is F")
    return
  let srcIsDir = b.isCollection(src)
  if not isMove:
    let rawDepth = reqHeader(req, "Depth")
    var depth = 2
    if rawDepth.len > 0:
      depth = parseDepthHeader(rawDepth)
      if depth != 0 and depth != 2:
        res.sendError(Http400, "COPY Depth must be 0 or infinity")
        return
  # RFC 6352 preconditions for address objects landing in an addressbook:
  # single vCard plus UID uniqueness. Collections pass through (nested
  # collections stay lenient, as with MKCOL/MKCALENDAR nesting).
  if b.isAddressbookCollection(parentOf(dest)) and not srcIsDir:
    var srcCard: VCard
    try:
      srcCard = requireSingleAddress(b.driver.read(toDriverPath(src)))
    except CatchableError as e:
      res.sendError(Http400, e.msg)
      return
    if srcCard.uid.isSome:
      let conflict = b.uidConflict(parentOf(dest), srcCard.uid.get(), dest)
      if conflict.len > 0:
        res.sendError(Http409, "UID already in use: " & conflict)
        return
      if destExisted and not b.isCollection(dest):
        var oldUid = ""
        try:
          for oc in parseVCards(b.driver.read(toDriverPath(dest))):
            if oc.uid.isSome:
              oldUid = oc.uid.get()
              break
        except CatchableError:
          discard
        if oldUid.len > 0 and oldUid != srcCard.uid.get():
          res.sendError(Http409, "Cannot change UID of an address object")
          return
  try:
    if destExisted:
      if b.isCollection(dest):
        b.driver.deleteDir(toDriverPath(dest), force = true)
      else:
        b.driver.delete(toDriverPath(dest))
      b.forgetDead(dest)
    if srcIsDir:
      let rawDepth = reqHeader(req, "Depth")
      let shallow = not isMove and rawDepth.len > 0 and
        parseDepthHeader(rawDepth) == 0
      if shallow:
        b.driver.makeDir(toDriverPath(dest))
      elif isMove:
        b.driver.moveDir(toDriverPath(src), toDriverPath(dest))
      else:
        b.driver.copyDir(toDriverPath(src), toDriverPath(dest))
    else:
      if isMove:
        b.driver.move(toDriverPath(src), toDriverPath(dest))
      else:
        b.driver.copy(toDriverPath(src), toDriverPath(dest))
  except CatchableError:
    res.sendError(Http500, (if isMove: "MOVE failed" else: "COPY failed"))
    return
  # Carry dead props to the destination (clearing a replaced destination
  # first). COPY duplicates, MOVE relocates.
  if isMove:
    b.moveDead(src, dest, destExisted)
  else:
    b.copyDead(src, dest, destExisted)
  # Sync revision accounting: destination parents gain a member (bump),
  # MOVE sources lose one (tombstone for files, bump for collections).
  # Nested files inside moved/copied collections never appeared in the
  # source parent's depth-1 listing, so only direct entries matter here.
  let destParent = parentOf(dest)
  let srcParent = parentOf(src)
  if not srcIsDir:
    if b.isSyncCollection(destParent):
      discard b.bumpSync(destParent)
    if isMove and b.isSyncCollection(srcParent):
      discard b.recordSyncDelete(srcParent, src)
  else:
    if b.isSyncCollection(destParent):
      discard b.bumpSync(destParent)
    if isMove and b.isSyncCollection(srcParent):
      discard b.bumpSync(srcParent)
  res.status(if destExisted: Http204 else: Http201).send("")

proc lockPropBody(lock: DavLock, href: string): string =
  let prop = newDavElement("prop")
  let ld = newDavElement("lockdiscovery")
  for n in parseFragment(activeLockXml(lock, href)):
    ld.addChild(n)
  prop.addChild(ld)
  davDoc(prop)

proc serveLock(srv: DavServer, req: HttpRequest, res: HttpResponse) =
  let b = srv.backend
  let path = normPath(req.getPath())
  if path.len == 0:
    res.sendError(Http400, "Bad path")
    return
  let rawDepth = reqHeader(req, "Depth")
  let depth =
    if rawDepth.len == 0: 2
    else: parseDepthLock(rawDepth)
  if depth < 0:
    res.sendError(Http400, "LOCK Depth must be 0 or infinity")
    return
  let timeout = parseTimeout(reqHeader(req, "Timeout"))
  let tokens = parseLockTokens(reqHeader(req, "Lock-Token"))
  let body = req.getBodyString()
  if body.len == 0:
    if tokens.len == 0:
      # Fresh lock with server defaults (exclusive/write).
      if not b.exists(path):
        if not b.parentIsCollection(path):
          res.sendError(Http409, "Parent collection does not exist")
          return
        try:
          b.driver.write(toDriverPath(path), "")
        except CatchableError:
          res.sendError(Http500, "Write failed")
          return
      var lock: DavLock
      try:
        lock = b.locks.acquire(path, lsExclusive, depth, "", timeout)
      except DavLockConflict:
        res.sendError(Http423, "Locked")
        return
      let href =
        if b.isCollection(path): collHref(path) else: path
      res.status(Http200)
        .header("Lock-Token", "<" & lock.token & ">")
        .header("Content-Type", "application/xml; charset=utf-8")
        .send(lockPropBody(lock, href))
      return
    for tok in tokens:
      if b.locks.refresh(tok, timeout):
        let lock = b.locks.getToken(tok)
        let href =
          if b.exists(path) and b.isCollection(path): collHref(path)
          else: path
        res.status(Http200)
          .header("Lock-Token", "<" & tok & ">")
          .header("Content-Type", "application/xml; charset=utf-8")
          .send(lockPropBody(lock, href))
        return
    res.sendError(Http400, "Unknown lock token")
    return
  var info: LockinfoRequest
  try:
    info = parseLockinfo(body)
  except DavXmlError as e:
    res.sendError(Http422, e.msg)
    return
  if not b.exists(path):
    if not b.parentIsCollection(path):
      res.sendError(Http409, "Parent collection does not exist")
      return
    try:
      b.driver.write(toDriverPath(path), "")
    except CatchableError:
      res.sendError(Http500, "Write failed")
      return
  let scope =
    if info.scope == "shared": lsShared else: lsExclusive
  var lock: DavLock
  try:
    lock = b.locks.acquire(path, scope, depth, info.owner, timeout)
  except DavLockConflict:
    res.sendError(Http423, "Locked")
    return
  let href =
    if b.isCollection(path): collHref(path) else: path
  res.status(Http200)
    .header("Lock-Token", "<" & lock.token & ">")
    .header("Content-Type", "application/xml; charset=utf-8")
    .send(lockPropBody(lock, href))

proc serveUnlock(srv: DavServer, req: HttpRequest, res: HttpResponse) =
  let b = srv.backend
  let path = normPath(req.getPath())
  if path.len == 0:
    res.sendError(Http400, "Bad path")
    return
  let tokens = parseLockTokens(reqHeader(req, "Lock-Token"))
  if tokens.len == 0:
    res.sendError(Http400, "Lock-Token header required")
    return
  for tok in tokens:
    if b.locks.release(tok, path):
      res.status(Http204).send("")
      return
  res.sendError(Http409, "Lock token does not match")

proc serveUnauthorized(res: HttpResponse) =
  ## `401` with the Basic challenge. Used whenever auth is enabled and the
  ## request carries missing or wrong credentials.
  res.status(Http401)
    .header("WWW-Authenticate", challengeHeader())
    .send("Unauthorized")

proc checkAuth(srv: DavServer, req: HttpRequest): string =
  ## Authenticated username, or "" when auth is disabled (open server).
  ## Raises `DavAuthError` when auth is enabled and the credentials are
  ## missing, malformed or wrong.
  if srv.backend.users.len == 0:
    return ""
  let creds = parseBasic(reqHeader(req, "Authorization"))
  if not verifyUser(srv.backend.users, creds.user, creds.pass):
    raise newException(DavAuthError, "bad credentials")
  creds.user

proc principalLiveProps(b: DavBackend, path, currentUser: string): seq[DavProp] =
  ## Live properties for the virtual principals collection (`/principals/`)
  ## and principal resources (`/principals/<name>`). Home sets point at `/`
  ## (root-as-home: existing root-level calendars and addressbooks keep
  ## working under auth).
  if isPrincipalsCollection(path):
    result.add(DavProp(ns: DavNs, name: "resourcetype",
      xml: """<D:collection xmlns:D="DAV:"/>"""))
    result.add(DavProp(ns: DavNs, name: "displayname", value: "principals"))
  else:
    let name = principalUserName(path)
    result.add(DavProp(ns: DavNs, name: "resourcetype",
      xml: """<D:principal xmlns:D="DAV:"/>"""))
    result.add(DavProp(ns: DavNs, name: "displayname", value: name))
    result.add(DavProp(ns: DavNs, name: "principal-URL",
      xml: hrefXml(principalHref(name))))
    result.add(DavProp(ns: CalNs, name: "calendar-home-set",
      xml: hrefXml("/")))
    result.add(DavProp(ns: CardNs, name: "addressbook-home-set",
      xml: hrefXml("/")))
  if currentUser.len > 0:
    result.add(DavProp(ns: DavNs, name: "current-user-principal",
      xml: hrefXml(principalHref(currentUser))))
    result.add(DavProp(ns: DavNs, name: "principal-collection-set",
      xml: hrefXml(PrincipalsRoot & "/")))

proc servePrincipalsPropfind(srv: DavServer, req: HttpRequest,
    res: HttpResponse, path, user: string) =
  ## PROPFIND over the virtual principals tree (no driver storage).
  let b = srv.backend
  if not b.isPrincipalPath(path):
    res.sendError(Http404, "Not Found")
    return
  let rawDepth = reqHeader(req, "Depth")
  var depth: int
  if rawDepth.len == 0:
    depth = if isPrincipalsCollection(path): 2 else: 0
  else:
    depth = parseDepthHeader(rawDepth)
    if depth < 0:
      res.sendError(Http400, "Invalid Depth header")
      return
  var pf = PropfindRequest(kind: pfAllprop)
  if req.getBodyString().len > 0:
    try:
      pf = parsePropfind(req.getBodyString())
    except DavXmlError as e:
      res.sendError(Http422, e.msg)
      return
  var paths = @[path]
  if depth >= 1 and isPrincipalsCollection(path):
    for name in sorted(toSeq(b.users.keys)):
      paths.add(principalHref(name))
  var responses: seq[DavResponse]
  for p in paths:
    let live = b.principalLiveProps(p, user)
    var propstats: seq[DavPropstat]
    case pf.kind
    of pfAllprop:
      propstats.add(DavPropstat(props: live, status: "HTTP/1.1 200 OK"))
    of pfPropname:
      var names: seq[DavProp]
      for pr in live:
        names.add(DavProp(ns: pr.ns, name: pr.name))
      propstats.add(DavPropstat(props: names, status: "HTTP/1.1 200 OK"))
    of pfProp:
      var ok, missing: seq[DavProp]
      for name in pf.props:
        var found = false
        for pr in live:
          if pr.name == name:
            ok.add(pr)
            found = true
            break
        if not found:
          missing.add(DavProp(ns: DavNs, name: name))
      if ok.len > 0:
        propstats.add(DavPropstat(props: ok, status: "HTTP/1.1 200 OK"))
      if missing.len > 0:
        propstats.add(DavPropstat(props: missing,
          status: "HTTP/1.1 404 Not Found"))
    responses.add(DavResponse(
      href: (if isPrincipalsCollection(p): collHref(p) else: p),
      propstats: propstats))
  res.status(Http207)
    .header("Content-Type", "application/xml; charset=utf-8")
    .send(buildMultistatus(responses))

proc serve*(srv: DavServer, req: HttpRequest, res: HttpResponse) =
  var user = ""
  if srv.backend.users.len > 0:
    try:
      user = srv.checkAuth(req)
    except DavAuthError:
      serveUnauthorized(res)
      return
  let meth = req.getMethod()
  let path = normPath(req.getPath())
  if path.len > 0 and isPrincipalsSubtree(path):
    # Virtual principals tree: read-only, served from the users table.
    case meth
    of HttpPropfind:
      srv.servePrincipalsPropfind(req, res, path, user)
    of HttpOptions:
      srv.serveOptions(req, res)
    of HttpGet, HttpHead:
      if isPrincipalsCollection(path):
        res.sendError(Http403, "GET on collections is not supported")
      else:
        res.sendError(Http404, "Not Found")
    else:
      res.sendError(Http403, "Principal resources are read-only")
    return
  case meth
  of HttpOptions:
    srv.serveOptions(req, res)
  of HttpGet:
    srv.serveGet(req, res, headOnly = false)
  of HttpHead:
    srv.serveGet(req, res, headOnly = true)
  of HttpPut:
    srv.servePut(req, res)
  of HttpDelete:
    srv.serveDelete(req, res)
  of HttpMkcol:
    srv.serveMkcol(req, res)
  of HttpMkcalendar:
    srv.serveMkcalendar(req, res)
  of HttpReport:
    srv.serveReport(req, res)
  of HttpPropfind:
    srv.servePropfind(req, res, user)
  of HttpProppatch:
    srv.serveProppatch(req, res)
  of HttpCopy:
    srv.serveCopyMove(req, res, isMove = false)
  of HttpMove:
    srv.serveCopyMove(req, res, isMove = true)
  of HttpLock:
    srv.serveLock(req, res)
  of HttpUnlock:
    srv.serveUnlock(req, res)
  else:
    # POST, PATCH and anything extended later.
    res.sendError(Http501, "Not Implemented: " & $meth)
