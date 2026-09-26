# CardDAV core (RFC 6352) on top of `pkg/openparser/vcard`.
#
# Scope and known limits (documented, not silent):
# - Addressbook creation is RFC-correct extended MKCOL: `<mkcol><set><prop>`
#   carrying `<resourcetype><collection/><addressbook/></resourcetype>`.
#   The `<set><prop>` defaults are stored best-effort as dead props;
#   protected live props in the body are rejected with `403`.
# - REPORT supports `addressbook-query` (prop-filter + param-filter +
#   text-match + is-not-defined), `addressbook-multiget` (href list) and
#   `sync-collection` (RFC 6578, ctag+revision tokens; deletions surface as
#   `404` tombstone responses for known stale tokens, unknown tokens answer
#   with a full member listing). Tombstone history is in-memory and capped
#   (`MaxSyncDeletes` in `backend.nim`); overflow falls back to full resync.
#   Query and multiget honor the `<prop>` selector: `getetag` and
#   `address-data` plus any other requested live/dead prop. Sync also
#   accepts `calendar-data` so one parser serves CalDAV sync parity
#   (see `server.nim`: calendar sync answers with `calendar-data`).
# - text-match collations: `i;unicode-casemap` (default, case-insensitive),
#   `i;ascii-casemap`, `i;octet` (byte-exact). match-types: `contains`
#   (default), `equals`, `starts-with`, `ends-with`. `negate-condition="yes"`
#   inverts a single text-match.
# - `test="anyof|allof"` defaults to `allof` on `<filter>`, `<prop-filter>`.
# - `<limit><nresults>` caps matched resources (server applies after scan).
# - Structured values (`N`, `ADR`, `ORG`) match when any component or the
#   joined form matches; `TEL`/`EMAIL` match on the value plus TYPE tokens
#   are visible to param-filters only. Groups (`item1.TEL`) are ignored for
#   matching (values still match). `X-` / unknown props in `extraProps`
#   participate under their literal names.
# - `address-data` `content-type`/`version` preferences are honored:
#   `version="3.0"` downgrades the returned card via openparser,
#   `version="4.0"` (or absent) returns 4.0 form; a `content-type` other
#   than `text/vcard` (or absent) answers `415`. Unknown `version` values
#   fall back to the stored bytes.
# - PUT into an addressbook requires exactly one vCard with non-empty `FN`
#   (RFC 6352 §6.3: one address object per resource).

import std/[strutils, tables, options, unicode]
import pkg/openparser/vcard
import ./davxml

export davxml
export vcard

const
  SupportedAddressData* = "text/vcard"
    ## Advertised content-type for `supported-address-data`.

type
  CardReportKind* = enum
    rkAddressQuery
    rkAddressMultiget

  CardTextMatch* = object
    value*: string
    collation*: string ## normalized lower-case; "" means default.
    matchType*: string ## normalized lower-case; "" means contains.
    negate*: bool

  CardParamFilter* = object
    name*: string ## upper-cased for comparison.
    isNotDefined*: bool
    hasTextMatch*: bool
    textMatch*: CardTextMatch

  CardPropFilter* = object
    name*: string ## upper-cased for comparison.
    isNotDefined*: bool
    testAnyOf*: bool
    textMatches*: seq[CardTextMatch]
    paramFilters*: seq[CardParamFilter]

  CardAddressDataPref* = object
    ## One requested `<address-data>` element's preferences, as sent.
    contentType*: string ## e.g. `text/vcard`; "" when absent.
    version*: string     ## e.g. `3.0`; "" when absent.

  CardReportRequest* = object
    kind*: CardReportKind
    hrefs*: seq[string]
    wantEtag*: bool
    wantAddressData*: bool
    addressDataPrefs*: seq[CardAddressDataPref]
    hasUnsupportedAddressData*: bool ## A non-`text/vcard` content-type
      ## was requested; the server answers the REPORT with `415`.
    extraProps*: seq[string]
    filters*: seq[CardPropFilter]
    testAnyOf*: bool ## top-level `<filter test="">`.
    hasLimit*: bool
    limit*: int

  SyncCollectionRequest* = object
    ## RFC 6578 `sync-collection` REPORT. The root element lives in the
    ## DAV: namespace (`<D:sync-collection>`), not CardDAV's. Shared by
    ## addressbook and calendar sync: `wantAddressData` selects vCard
    ## responses, `wantCalData` selects iCalendar responses.
    token*: string
    hasToken*: bool
    infinite*: bool ## `sync-level` was `infinite` (behaves as Depth 1 here).
    wantEtag*: bool
    wantAddressData*: bool
    wantCalData*: bool
    addressDataPrefs*: seq[CardAddressDataPref]
    hasUnsupportedAddressData*: bool
    extraProps*: seq[string]
    hasLimit*: bool
    limit*: int

# ── Small XML helpers ────────────────────────────────────────────────────

proc attrOf(node: XmlNode, name: string): string =
  if node == nil or node.kind != xnElement: return ""
  node.attrs.getOrDefault(name, "")

proc nodeText(node: XmlNode): string =
  if node == nil: return ""
  for c in node.children:
    if c.kind == xnText:
      result.add(c.text)

proc cardPropNs(tag: string, local: string): string =
  ## Namespace for a dead prop carried in an MKCOL-addressbook body.
  ## `C:` is ambiguous (CalDAV vs CardDAV), so CardDAV-known locals win.
  const CardLocals = ["addressbook", "address-data", "addressbook-description",
    "supported-address-data", "max-resource-size", "max-image-size"]
  let ci = tag.rfind(':')
  let prefix = if ci < 0: "" else: tag[0 ..< ci]
  case prefix
  of "D": DavNs
  of "CR", "CARD", "Card": CardNs
  of "C":
    if local in CardLocals: CardNs else: CalNs
  else:
    if local in CardLocals: CardNs else: DavNs

# ── Extended MKCOL body ──────────────────────────────────────────────────

proc parseMkcolAddressbook*(body: string): tuple[isAddressbook: bool,
    props: seq[DavProp]] =
  ## Inspect an MKCOL body. Returns `isAddressbook=true` when the body
  ## carries `<resourcetype>` containing an `addressbook` element.
  ## Other `<set><prop>` children are returned as dead props.
  ## Empty body yields `(false, @[])`. Raises `DavXmlError` on malformed XML.
  if body.strip().len == 0:
    return (false, @[])
  let root = parseDavXml(body)
  if root.localNameOf() != "mkcol" or not root.hasDavNs():
    raise newException(DavXmlError, "expected DAV <mkcol> root")
  var props: seq[DavProp]
  var isAb = false
  for setNode in root.childrenByLocal("set"):
    let prop = setNode.findChild("prop")
    if prop == nil:
      raise newException(DavXmlError, "mkcol set needs a prop child")
    for c in prop.elementChildren():
      if localName(c.tag) == "resourcetype":
        for inner in c.elementChildren():
          if localName(inner.tag) == "addressbook":
            isAb = true
        # resourcetype itself is live, never stored as dead.
      else:
        let ln = localName(c.tag)
        props.add(parsePropValue(c, cardPropNs(c.tag, ln)))
  (isAb, props)

# ── REPORT parsing ───────────────────────────────────────────────────────

proc parseCardTextMatch(node: XmlNode): CardTextMatch =
  result.value = nodeText(node)
  result.collation = attrOf(node, "collation").strip().toLowerAscii()
  result.matchType = attrOf(node, "match-type").strip().toLowerAscii()
  result.negate = attrOf(node, "negate-condition").strip().toLowerAscii() == "yes"
  if result.collation.len == 0:
    result.collation = "i;unicode-casemap"
  if result.matchType.len == 0:
    result.matchType = "contains"
  case result.collation
  of "i;unicode-casemap", "i;ascii-casemap", "i;octet":
    discard
  else:
    raise newException(DavXmlError,
      "unsupported text-match collation: " & attrOf(node, "collation"))
  case result.matchType
  of "contains", "equals", "starts-with", "ends-with":
    discard
  else:
    raise newException(DavXmlError,
      "unsupported text-match match-type: " & attrOf(node, "match-type"))

proc parseCardParamFilter(node: XmlNode): CardParamFilter =
  result.name = attrOf(node, "name").strip().toUpperAscii()
  if result.name.len == 0:
    raise newException(DavXmlError, "param-filter needs a name")
  for c in node.elementChildren():
    case localName(c.tag)
    of "is-not-defined":
      result.isNotDefined = true
    of "text-match":
      if result.hasTextMatch:
        raise newException(DavXmlError, "param-filter holds one text-match")
      result.hasTextMatch = true
      result.textMatch = parseCardTextMatch(c)
    else:
      raise newException(DavXmlError,
        "unsupported param-filter child: <" & localName(c.tag) & ">")
  if result.isNotDefined and result.hasTextMatch:
    raise newException(DavXmlError,
      "param-filter cannot combine is-not-defined with text-match")

proc parseCardPropFilter(node: XmlNode): CardPropFilter =
  result.name = attrOf(node, "name").strip().toUpperAscii()
  if result.name.len == 0:
    raise newException(DavXmlError, "prop-filter needs a name")
  result.testAnyOf = attrOf(node, "test").strip().toLowerAscii() == "anyof"
  let t = attrOf(node, "test").strip().toLowerAscii()
  if t.len > 0 and t != "anyof" and t != "allof":
    raise newException(DavXmlError, "filter test must be anyof or allof")
  for c in node.elementChildren():
    case localName(c.tag)
    of "is-not-defined":
      result.isNotDefined = true
    of "text-match":
      result.textMatches.add(parseCardTextMatch(c))
    of "param-filter":
      result.paramFilters.add(parseCardParamFilter(c))
    else:
      raise newException(DavXmlError,
        "unsupported prop-filter child: <" & localName(c.tag) & ">")
  if result.isNotDefined and
      (result.textMatches.len > 0 or result.paramFilters.len > 0):
    raise newException(DavXmlError,
      "prop-filter cannot combine is-not-defined with other tests")

proc parseCardPropSelector(prop: XmlNode, wantEtag, wantAddressData: var bool,
    prefs: var seq[CardAddressDataPref], hasUnsupported: var bool,
    extraProps: var seq[string], wantCalData: var bool) =
  ## Shared `<prop>` selector for query, multiget and sync-collection:
  ## `getetag`, `address-data` (with `content-type`/`version` preferences),
  ## `calendar-data` (calendar sync parity; no content negotiation),
  ## plus any other requested live/dead prop.
  for c in prop.elementChildren():
    case localName(c.tag)
    of "getetag": wantEtag = true
    of "calendar-data": wantCalData = true
    of "address-data":
      wantAddressData = true
      let ct = attrOf(c, "content-type").strip()
      let v = attrOf(c, "version").strip()
      prefs.add(CardAddressDataPref(contentType: ct, version: v))
      if ct.len > 0 and ct.toLowerAscii() != "text/vcard":
        hasUnsupported = true
    else: extraProps.add(localName(c.tag))

proc parseCardLimit(root: XmlNode, hasLimit: var bool, limit: var int) =
  let lim = root.findChild("limit")
  if lim != nil:
    let n = lim.findChild("nresults")
    if n == nil:
      raise newException(DavXmlError, "limit needs nresults")
    try:
      limit = max(parseInt(nodeText(n).strip()), 0)
      hasLimit = true
    except ValueError:
      raise newException(DavXmlError, "bad nresults value")

proc parseCardReport*(body: string): CardReportRequest =
  ## Parse an `addressbook-query` or `addressbook-multiget` REPORT body.
  ## Raises `DavXmlError` on any failure.
  if body.strip().len == 0:
    raise newException(DavXmlError, "empty REPORT body")
  let root = parseDavXml(body)
  if not root.hasCardNs():
    raise newException(DavXmlError, "REPORT root is not a CardDAV element")
  case root.localNameOf()
  of "addressbook-query":
    result.kind = rkAddressQuery
  of "addressbook-multiget":
    result.kind = rkAddressMultiget
  else:
    raise newException(DavXmlError,
      "unsupported REPORT: <" & root.localNameOf() & ">")
  let prop = root.findChild("prop")
  if prop == nil:
    raise newException(DavXmlError, "REPORT needs a prop child")
  var wantCalDataQ = false
  parseCardPropSelector(prop, result.wantEtag, result.wantAddressData,
    result.addressDataPrefs, result.hasUnsupportedAddressData,
    result.extraProps, wantCalDataQ)
  if wantCalDataQ:
    # `calendar-data` is only meaningful to calendar sync; in an
    # addressbook query/multiget it stays a 404 extra prop as before.
    result.extraProps.add("calendar-data")
  if result.kind == rkAddressMultiget:
    for h in root.childrenByLocal("href"):
      let v = nodeText(h).strip()
      if v.len > 0:
        result.hrefs.add(v)
    if result.hrefs.len == 0:
      raise newException(DavXmlError, "addressbook-multiget needs hrefs")
    parseCardLimit(root, result.hasLimit, result.limit)
    return
  # addressbook-query: optional filter + optional limit.
  let filter = root.findChild("filter")
  if filter != nil:
    let t = attrOf(filter, "test").strip().toLowerAscii()
    if t.len > 0 and t != "anyof" and t != "allof":
      raise newException(DavXmlError, "filter test must be anyof or allof")
    result.testAnyOf = t == "anyof"
    for pf in filter.childrenByLocal("prop-filter"):
      result.filters.add(parseCardPropFilter(pf))
  parseCardLimit(root, result.hasLimit, result.limit)

proc parseSyncCollection*(body: string): SyncCollectionRequest =
  ## Parse an RFC 6578 `sync-collection` REPORT body. The root element is
  ## DAV-namespaced (`<D:sync-collection>`). Raises `DavXmlError` on failure.
  if body.strip().len == 0:
    raise newException(DavXmlError, "empty REPORT body")
  let root = parseDavXml(body)
  if root.localNameOf() != "sync-collection" or not root.hasDavNs():
    raise newException(DavXmlError, "expected DAV <sync-collection> root")
  let prop = root.findChild("prop")
  if prop == nil:
    raise newException(DavXmlError, "REPORT needs a prop child")
  parseCardPropSelector(prop, result.wantEtag, result.wantAddressData,
    result.addressDataPrefs, result.hasUnsupportedAddressData,
    result.extraProps, result.wantCalData)
  let st = root.findChild("sync-token")
  if st != nil:
    result.hasToken = true
    result.token = nodeText(st).strip()
  let sl = root.findChild("sync-level")
  if sl != nil:
    case nodeText(sl).strip().toLowerAscii()
    of "", "1": discard
    of "infinite": result.infinite = true
    else:
      raise newException(DavXmlError,
        "sync-level must be 1 or infinite")
  parseCardLimit(root, result.hasLimit, result.limit)

# ── Matching ─────────────────────────────────────────────────────────────

proc foldForMatch(s, collation: string): string =
  case collation
  of "i;octet": s
  of "i;ascii-casemap": s.toLowerAscii()
  else: s.toLower() # i;unicode-casemap

proc textMatches(value: string, tm: CardTextMatch): bool =
  let hay = foldForMatch(value, tm.collation)
  let needle = foldForMatch(tm.value, tm.collation)
  var hit =
    case tm.matchType
    of "equals": hay == needle
    of "starts-with": hay.startsWith(needle)
    of "ends-with": hay.endsWith(needle)
    else: needle.len == 0 or needle in hay
  if tm.negate: not hit else: hit

proc cardPropValues*(card: VCard, propName: string): seq[string] =
  ## All searchable string values for a vCard property name
  ## (upper-cased `propName`). Structured values contribute both components
  ## and a joined form.
  result = @[]
  case propName
  of "FN": result = @[card.fn]
  of "N":
    if card.n.isSome:
      let n = card.n.get()
      result = @[n.family, n.given, n.additional, n.prefix, n.suffix,
        [n.family, n.given, n.additional, n.prefix, n.suffix].join(" ")]
  of "NICKNAME": result = card.nicknames
  of "PHOTO":
    for p in card.photos: result.add(p.value)
  of "BDAY":
    if card.bday.isSome: result = @[card.bday.get().value]
  of "ANNIVERSARY":
    if card.anniversary.isSome: result = @[card.anniversary.get().value]
  of "GENDER":
    if card.gender.isSome:
      result = @[card.gender.get().sex, card.gender.get().identity]
  of "ADR":
    for a in card.adrs:
      result.add([a.poBox, a.ext, a.street, a.locality, a.region,
        a.postal, a.country].join(" "))
      result.add(a.poBox)
      result.add(a.ext)
      result.add(a.street)
      result.add(a.locality)
      result.add(a.region)
      result.add(a.postal)
      result.add(a.country)
  of "TEL":
    for t in card.tels: result.add(t.value)
  of "EMAIL":
    for e in card.emails: result.add(e.value)
  of "IMPP":
    for i in card.impps: result.add(i.value)
  of "LANG":
    for l in card.langs: result.add(l.value)
  of "TZ":
    if card.tz.isSome: result = @[card.tz.get()]
  of "GEO":
    if card.geo.isSome: result = @[card.geo.get()]
  of "TITLE":
    if card.title.isSome: result = @[card.title.get()]
  of "ROLE":
    if card.role.isSome: result = @[card.role.get()]
  of "LOGO":
    if card.logo.isSome: result = @[card.logo.get()]
  of "ORG":
    if card.org.isSome:
      let o = card.org.get()
      result.add(o.name)
      for u in o.units: result.add(u)
      result.add((@[o.name] & o.units).join(" "))
  of "MEMBER":
    for m in card.members: result.add(m.value)
  of "RELATED":
    for r in card.related: result.add(r.value)
  of "CATEGORIES": result = card.categories
  of "NOTE":
    if card.note.isSome: result = @[card.note.get()]
  of "PRODID":
    if card.prodId.isSome: result = @[card.prodId.get()]
  of "REV":
    if card.rev.isSome: result = @[card.rev.get()]
  of "SORT-STRING":
    if card.sortString.isSome: result = @[card.sortString.get()]
  of "SOUND":
    if card.sound.isSome: result = @[card.sound.get()]
  of "UID":
    if card.uid.isSome: result = @[card.uid.get()]
  of "VERSION": result = @[$card.version]
  of "KIND":
    if card.kind.isSome: result = @[vcardKindStr(card.kind.get())]
  of "CLIENTPIDMAP":
    for cm in card.clientPidMaps: result.add($cm.pid & ";" & cm.uri)
  of "URL":
    for u in card.urls: result.add(u.value)
  of "KEY":
    if card.key.isSome: result = @[card.key.get()]
  of "FBURL":
    if card.fbUrl.isSome: result = @[card.fbUrl.get()]
  of "CALADRURI":
    if card.calAdrUri.isSome: result = @[card.calAdrUri.get()]
  of "CALURI":
    if card.calUri.isSome: result = @[card.calUri.get()]
  of "XML": result = card.xml
  else:
    for p in card.extraProps:
      if p.name.toUpperAscii() == propName:
        result.add(unescapeVCardText(p.value))

proc cardPropExists*(card: VCard, propName: string): bool =
  ## Presence check used by `is-not-defined` and bare prop-filters.
  ## Empty-string values still count as present (property was sent).
  case propName
  of "FN": true # required by vCard; gate ensures non-empty.
  of "N": card.n.isSome
  of "NICKNAME": card.nicknames.len > 0
  of "PHOTO": card.photos.len > 0
  of "BDAY": card.bday.isSome
  of "ANNIVERSARY": card.anniversary.isSome
  of "GENDER": card.gender.isSome
  of "ADR": card.adrs.len > 0
  of "TEL": card.tels.len > 0
  of "EMAIL": card.emails.len > 0
  of "IMPP": card.impps.len > 0
  of "LANG": card.langs.len > 0
  of "TZ": card.tz.isSome
  of "GEO": card.geo.isSome
  of "TITLE": card.title.isSome
  of "ROLE": card.role.isSome
  of "LOGO": card.logo.isSome
  of "ORG": card.org.isSome
  of "MEMBER": card.members.len > 0
  of "RELATED": card.related.len > 0
  of "CATEGORIES": card.categories.len > 0
  of "NOTE": card.note.isSome
  of "PRODID": card.prodId.isSome
  of "REV": card.rev.isSome
  of "SORT-STRING": card.sortString.isSome
  of "SOUND": card.sound.isSome
  of "UID": card.uid.isSome
  of "VERSION": true
  of "KIND": card.kind.isSome
  of "CLIENTPIDMAP": card.clientPidMaps.len > 0
  of "URL": card.urls.len > 0
  of "KEY": card.key.isSome
  of "FBURL": card.fbUrl.isSome
  of "CALADRURI": card.calAdrUri.isSome
  of "CALURI": card.calUri.isSome
  of "XML": card.xml.len > 0
  else:
    for p in card.extraProps:
      if p.name.toUpperAscii() == propName:
        return true
    false

proc cardParamValues*(card: VCard, propName, paramName: string): seq[string] =
  ## All values of `paramName` across every instance of `propName`.
  ## TYPE tokens, PREF, ALTID, LABEL and friends are covered; unknown params
  ## survive on the typed `params` sequences and in `extraProps`.
  let pn = paramName.toUpperAscii()
  template collectParams(params: seq[VCardParam]) =
    for p in params:
      if p.name.toUpperAscii() == pn:
        for v in p.values:
          result.add(v)
  case propName
  of "TEL":
    for t in card.tels:
      case pn
      of "TYPE":
        for v in t.types: result.add(v)
      of "PREF":
        if t.pref.isSome: result.add($t.pref.get())
      of "ALTID":
        if t.altId.isSome: result.add(t.altId.get())
      of "LABEL":
        if t.label.isSome: result.add(t.label.get())
      else: collectParams(t.params)
  of "EMAIL":
    for e in card.emails:
      case pn
      of "TYPE":
        for v in e.types: result.add(v)
      of "PREF":
        if e.pref.isSome: result.add($e.pref.get())
      of "ALTID":
        if e.altId.isSome: result.add(e.altId.get())
      else: collectParams(e.params)
  of "ADR":
    for a in card.adrs:
      case pn
      of "TYPE":
        for v in a.types: result.add(v)
      of "PREF":
        if a.pref.isSome: result.add($a.pref.get())
      of "ALTID":
        if a.altId.isSome: result.add(a.altId.get())
      of "LABEL":
        if a.label.isSome: result.add(a.label.get())
      of "GEO":
        if a.geo.isSome: result.add(a.geo.get())
      of "TZ":
        if a.tz.isSome: result.add(a.tz.get())
      else: collectParams(a.params)
  of "IMPP":
    for i in card.impps:
      case pn
      of "TYPE":
        for v in i.types: result.add(v)
      of "PREF":
        if i.pref.isSome: result.add($i.pref.get())
      of "ALTID":
        if i.altId.isSome: result.add(i.altId.get())
      else: collectParams(i.params)
  of "URL":
    for u in card.urls:
      case pn
      of "TYPE":
        for v in u.types: result.add(v)
      of "PREF":
        if u.pref.isSome: result.add($u.pref.get())
      of "ALTID":
        if u.altId.isSome: result.add(u.altId.get())
      of "LABEL":
        if u.label.isSome: result.add(u.label.get())
      else: collectParams(u.params)
  else:
    for p in card.extraProps:
      if p.name.toUpperAscii() == propName:
        for pr in p.params:
          if pr.name.toUpperAscii() == pn:
            for v in pr.values:
              result.add(v)
    # Typed singleton props keep their raw params on the date/prop object;
    # cover the common Param-carrying extras generically via extraProps only.
    # Known typed lists with params:
    if propName == "LANG":
      for l in card.langs:
        case pn
        of "TYPE":
          for v in l.types: result.add(v)
        of "PREF":
          if l.pref.isSome: result.add($l.pref.get())
        of "ALTID":
          if l.altId.isSome: result.add(l.altId.get())
        else: collectParams(l.params)
    elif propName == "RELATED":
      for r in card.related:
        case pn
        of "TYPE":
          for v in r.types: result.add(v)
        of "PREF":
          if r.pref.isSome: result.add($r.pref.get())
        of "ALTID":
          if r.altId.isSome: result.add(r.altId.get())
        else: collectParams(r.params)

proc paramFilterMatches(card: VCard, propName: string,
    pf: CardParamFilter): bool =
  let vals = cardParamValues(card, propName, pf.name)
  if pf.isNotDefined:
    return vals.len == 0
  if pf.hasTextMatch:
    for v in vals:
      if textMatches(v, pf.textMatch):
        return true
    return false
  vals.len > 0

proc propFilterMatches*(card: VCard, pf: CardPropFilter): bool =
  if pf.isNotDefined:
    return not cardPropExists(card, pf.name)
  var conds: seq[bool]
  for tm in pf.textMatches:
    var hit = false
    for v in cardPropValues(card, pf.name):
      if textMatches(v, tm):
        hit = true
        break
    # Absent prop with a negated text-match counts as match (nothing
    # contradicts the negation); absent prop with a positive text-match
    # never matches.
    if not cardPropExists(card, pf.name):
      hit = tm.negate
    conds.add(hit)
  for par in pf.paramFilters:
    conds.add(paramFilterMatches(card, pf.name, par))
  if conds.len == 0:
    return cardPropExists(card, pf.name)
  if pf.testAnyOf:
    for c in conds:
      if c: return true
    return false
  for c in conds:
    if not c: return false
  true

proc cardMatches*(card: VCard, filters: seq[CardPropFilter],
    testAnyOf: bool): bool =
  if filters.len == 0:
    return true
  if testAnyOf:
    for f in filters:
      if propFilterMatches(card, f):
        return true
    return false
  for f in filters:
    if not propFilterMatches(card, f):
      return false
  true

proc resourceMatches*(content: string, filters: seq[CardPropFilter],
    testAnyOf: bool): bool =
  ## True when any card in the `.vcf` `content` satisfies all filters.
  ## Unparsable content never matches. No filters matches any resource
  ## holding at least one card.
  var cards: seq[VCard]
  try:
    cards = parseVCards(content)
  except OpenParserVCardError:
    return false
  if cards.len == 0:
    return false
  if filters.len == 0:
    return true
  for c in cards:
    if cardMatches(c, filters, testAnyOf):
      return true
  false

proc isAddressContent*(content: string): bool =
  ## True when `content` parses as vCard holding at least one card with a
  ## non-empty `FN`.
  var cards: seq[VCard]
  try:
    cards = parseVCards(content)
  except OpenParserVCardError:
    return false
  for c in cards:
    if c.fn.strip().len > 0:
      return true
  false

proc requireSingleAddress*(content: string): VCard =
  ## The single address object of a resource. Raises
  ## `OpenParserVCardError` unless `content` holds exactly one vCard with
  ## non-empty `FN` (RFC 6352 §6.3: one address object per resource).
  ## This is the PUT/COPY/MOVE gate for addressbooks.
  let cards = parseVCards(content) # raises on garbage or empty input.
  if cards.len != 1:
    raise newException(OpenParserVCardError,
      "address object must contain exactly one vCard")
  if cards[0].fn.strip().len == 0:
    raise newException(OpenParserVCardError, "FN must not be empty")
  cards[0]

proc addressDataTarget*(prefs: seq[CardAddressDataPref]): VCardVersion =
  ## Requested vCard version for `address-data` responses. `3.0` wins only
  ## when every explicit `version` preference is `3.0`; otherwise 4.0
  ## (stored bytes pass through untouched when already at target).
  var seen = false
  for p in prefs:
    if p.version.len == 0:
      continue
    seen = true
    if p.version != "3.0":
      return vv40
  if seen: vv30 else: vv40

proc convertAddressData*(content: string, target: VCardVersion): string =
  ## Serialize the cards in `content` at `target` version (openparser
  ## downgrade to 3.0 / upgrade to 4.0). Content already at target passes
  ## through byte-identical; unparsable content (predates the PUT gate)
  ## is returned unchanged.
  var cards: seq[VCard]
  try:
    cards = parseVCards(content)
  except OpenParserVCardError:
    return content
  if cards.len == 0:
    return content
  for c in cards:
    if c.version != target:
      var opts = defaultVCardOptions()
      opts.targetVersion = target
      return toVCards(cards, opts)
  content

proc addressDataProp*(content: string): DavProp {.inline.} =
  DavProp(ns: CardNs, name: "address-data", value: content)
