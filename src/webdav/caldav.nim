# CalDAV core (RFC 4791) on top of `pkg/openparser/ical`.
#
# Scope and known limits (documented, not silent):
# - MKCALENDAR creates a collection flagged as a calendar. A request body
#   with `<set><prop>` children is stored best-effort as dead props;
#   protected live props in the body are rejected with `403`.
# - REPORT supports `calendar-query` (comp-filter + time-range),
#   `calendar-multiget` (href list) and `sync-collection` (RFC 6578,
#   ctag+revision tokens shared with CardDAV; deletions surface as `404`
#   tombstones for known stale tokens, unknown tokens answer with a full
#   member listing). All three honor the `<prop>` selector: `getetag` and
#   `calendar-data` plus any other requested live/dead prop.
# - time-range applies to VEVENT (`DTSTART`/`DTEND`/`DURATION`) and VTODO
#   (`DTSTART`/`DUE`). Components without usable dates only match a query
#   that carries no time-range.
# - Recurrence expansion subset: `FREQ=DAILY|WEEKLY|MONTHLY|YEARLY` with
#   `INTERVAL`, `COUNT`, `UNTIL`; `BYDAY` is honored for WEEKLY only.
#   Other `BYxxx` parts are ignored (the base instance still matches).
#   Monthly/yearly day overflow clamps (Jan 31 -> Feb 28) instead of the
#   RFC-mandated skip. `EXDATE`s are excluded. Expansion is capped at
#   `MaxInstances` occurrences per component.
# - Timezones are ignored: `TZID` and floating times are treated as UTC,
#   and DATE values are day-long UTC intervals.

import std/[strutils, tables, times, options, sets, math]
import pkg/openparser/ical
import ./davxml

export davxml
export ical

const
  MaxInstances* = 1000
    ## Max recurrence instances expanded per component per REPORT.

type
  CalReportKind* = enum
    rkQuery
    rkMultiget

  CalTimeRange* = object
    hasStart*: bool
    hasEnd*: bool
    startUnix*: int64
    endUnix*: int64

  CalReportRequest* = object
    kind*: CalReportKind
    hrefs*: seq[string]     ## Raw href values (multiget only).
    wantEtag*: bool
    wantCalData*: bool
    extraProps*: seq[string] ## Other requested DAV live/dead prop names.
    compName*: string        ## `VEVENT`, `VTODO`, ... or "" for unfiltered.
    timeRange*: CalTimeRange
    hasTimeRange*: bool

# ── Small XML helpers ────────────────────────────────────────────────────

proc nodeText*(node: XmlNode): string =
  ## Concatenated text content of `node` itself.
  if node == nil: return ""
  for c in node.children:
    if c.kind == xnText:
      result.add(c.text)

proc attrOf(node: XmlNode, name: string): string =
  if node == nil or node.kind != xnElement: return ""
  node.attrs.getOrDefault(name, "")

# ── MKCALENDAR body ──────────────────────────────────────────────────────

proc parseMkcalendarProps*(body: string): seq[DavProp] =
  ## Dead props carried by an MKCALENDAR body (`<mkcalendar><set><prop>`).
  ## Empty body yields `@[]`. Raises `DavXmlError` on malformed XML.
  if body.strip().len == 0:
    return @[]
  let root = parseDavXml(body)
  if root.localNameOf() != "mkcalendar" or not root.hasCalNs():
    raise newException(DavXmlError, "expected CalDAV <mkcalendar> root")
  for setNode in root.childrenByLocal("set"):
    let prop = setNode.findChild("prop")
    if prop == nil:
      raise newException(DavXmlError, "mkcalendar set needs a prop child")
    for c in prop.elementChildren():
      result.add(parsePropValue(c))

# ── Time conversion (all comparisons in UTC epoch seconds) ───────────────

proc icalToUnix*(dt: IcalDateTime): int64 =
  ## DATE values become the UTC midnight starting that day. `TZID` and
  ## floating times are treated as UTC (see module docs).
  if not dt.hasTime:
    dateTime(dt.year, Month(dt.month), dt.day, 0, 0, 0, 0, utc()).toTime().toUnix()
  else:
    dateTime(dt.year, Month(dt.month), dt.day, dt.hour, dt.minute,
      dt.second, 0, utc()).toTime().toUnix()

proc parseCalUnix(s: string): int64 =
  ## `YYYYMMDD[T185959Z]` filter bound to epoch seconds. Raises
  ## `DavXmlError` (server maps to `422`, never 500).
  var dt: IcalDateTime
  try:
    dt = parseIcalDateTime(s)
  except OpenParserIcalError as e:
    raise newException(DavXmlError, "bad time-range bound: " & e.msg)
  icalToUnix(dt)

proc parseCalTimeRange(node: XmlNode): CalTimeRange =
  let s = attrOf(node, "start")
  let e = attrOf(node, "end")
  if s.len > 0:
    result.hasStart = true
    result.startUnix = parseCalUnix(s)
  if e.len > 0:
    result.hasEnd = true
    result.endUnix = parseCalUnix(e)
  if result.hasStart and result.hasEnd and result.endUnix < result.startUnix:
    raise newException(DavXmlError, "time-range end precedes start")

proc weekdayMon1*(unix: int64): int =
  ## ISO weekday of `unix`: Monday = 1 .. Sunday = 7.
  ## 1970-01-01 (day 0) was a Thursday.
  let days = floorDiv(unix, 86400'i64)
  int(((days + 3) mod 7 + 7) mod 7) + 1

proc unixYmd(unix: int64): tuple[y, mo, d, h, mi, s: int] =
  let dt = fromUnix(unix).utc()
  (dt.year, ord(dt.month), dt.monthday, dt.hour, dt.minute, dt.second)

proc ymdToUnix(y, mo, d, h, mi, s: int): int64 =
  dateTime(y, Month(mo), d, h, mi, s, 0, utc()).toTime().toUnix()

proc shiftMonths(y, mo, d, h, mi, s, n: int): int64 =
  let total = y * 12 + (mo - 1) + n
  let ny = floorDiv(total, 12)
  let nm = floorMod(total, 12) + 1
  ymdToUnix(ny, nm, min(d, getDaysInMonth(Month(nm), ny)), h, mi, s)

proc shiftYears(y, mo, d, h, mi, s, n: int): int64 =
  shiftMonths(y, mo, d, h, mi, s, n * 12)

# ── REPORT parsing ───────────────────────────────────────────────────────

proc parseCalReport*(body: string): CalReportRequest =
  ## Parse a `calendar-query` or `calendar-multiget` REPORT body.
  ## Raises `DavXmlError` on any failure.
  if body.strip().len == 0:
    raise newException(DavXmlError, "empty REPORT body")
  let root = parseDavXml(body)
  if not root.hasCalNs():
    raise newException(DavXmlError, "REPORT root is not a CalDAV element")
  case root.localNameOf()
  of "calendar-query":
    result.kind = rkQuery
  of "calendar-multiget":
    result.kind = rkMultiget
  else:
    raise newException(DavXmlError,
      "unsupported REPORT: <" & root.localNameOf() & ">")
  let prop = root.findChild("prop")
  if prop == nil:
    raise newException(DavXmlError, "REPORT needs a prop child")
  for c in prop.elementChildren():
    case localName(c.tag)
    of "getetag": result.wantEtag = true
    of "calendar-data": result.wantCalData = true
    else: result.extraProps.add(localName(c.tag))
  if result.kind == rkMultiget:
    for h in root.childrenByLocal("href"):
      let v = nodeText(h).strip()
      if v.len > 0:
        result.hrefs.add(v)
    if result.hrefs.len == 0:
      raise newException(DavXmlError, "calendar-multiget needs hrefs")
  else:
    let filter = root.findChild("filter")
    if filter == nil:
      return
    var outer = filter.findChild("comp-filter")
    if outer == nil:
      raise newException(DavXmlError, "filter needs a comp-filter")
    var target = outer
    # `<VCALENDAR><VEVENT><time-range/></VEVENT></VCALENDAR>` is the
    # normal shape; a lone non-VCALENDAR comp-filter is accepted too.
    if attrOf(outer, "name").toUpperAscii() == "VCALENDAR":
      let inner = outer.findChild("comp-filter")
      if inner != nil:
        target = inner
    else:
      result.compName = attrOf(outer, "name").toUpperAscii()
      let tr = outer.findChild("time-range")
      if tr != nil:
        result.timeRange = parseCalTimeRange(tr)
        result.hasTimeRange = true
      return
    result.compName = attrOf(target, "name").toUpperAscii()
    let tr = target.findChild("time-range")
    if tr != nil:
      result.timeRange = parseCalTimeRange(tr)
      result.hasTimeRange = true

# ── RRULE subset ─────────────────────────────────────────────────────────

type
  Rrule* = object
    freq*: string ## DAILY, WEEKLY, MONTHLY, YEARLY, or "" when unusable.
    interval*: int
    hasCount*: bool
    count*: int
    hasUntil*: bool
    untilUnix*: int64
    byday*: seq[int] ## WEEKLY weekday set (Mon = 1), empty when absent.

proc parseRrule*(raw: string): Rrule =
  result = Rrule(freq: "", interval: 1)
  for part in raw.split(';'):
    let kv = part.split('=', maxsplit = 1)
    if kv.len != 2:
      continue
    let k = kv[0].strip().toUpperAscii()
    let v = kv[1].strip()
    case k
    of "FREQ":
      let f = v.toUpperAscii()
      if f in ["DAILY", "WEEKLY", "MONTHLY", "YEARLY"]:
        result.freq = f
      else:
        return Rrule(freq: "", interval: 1)
    of "INTERVAL":
      try:
        result.interval = max(parseInt(v), 1)
      except ValueError:
        discard
    of "COUNT":
      try:
        result.count = max(parseInt(v), 0)
        result.hasCount = true
      except ValueError:
        discard
    of "UNTIL":
      try:
        let dt = parseIcalDateTime(v)
        result.untilUnix = icalToUnix(dt)
        # A DATE UNTIL covers its whole day (inclusive per RFC 5545).
        if not dt.hasTime:
          result.untilUnix += 86399
        result.hasUntil = true
      except OpenParserIcalError:
        discard
    of "BYDAY":
      for tok in v.split(','):
        var t = tok.strip().toUpperAscii()
        # Drop numeric prefixes (1MO, -1FR): unsupported, WEEKLY-only
        # expansion uses bare weekday codes.
        var i = 0
        while i < t.len and (t[i] in {'0'..'9'} or t[i] == '-' or t[i] == '+'):
          inc i
        t = t[i .. ^1]
        case t
        of "MO": result.byday.add(1)
        of "TU": result.byday.add(2)
        of "WE": result.byday.add(3)
        of "TH": result.byday.add(4)
        of "FR": result.byday.add(5)
        of "SA": result.byday.add(6)
        of "SU": result.byday.add(7)
        else: discard
    else:
      # Other BYxxx parts are ignored (see module docs).
      discard
  if result.freq.len == 0:
    result = Rrule(freq: "", interval: 1)

proc expandStarts*(startUnix: int64, rrule: Rrule,
    exdates: HashSet[int64], rangeStart, rangeEnd: tuple[has: bool, v: int64],
    cap = MaxInstances): seq[int64] =
  ## Occurrence start times ascending, base instance included. `COUNT`
  ## counts generated candidates (an `EXDATE`d candidate still consumes
  ## count, per RFC 5545 ordering). Generation stops early once candidates
  ## reach a bounded `rangeEnd`, since all supported frequencies are
  ## monotonically increasing.
  if rrule.freq.len == 0:
    if startUnix notin exdates:
      return @[startUnix]
    return @[]
  if rrule.hasCount and rrule.count < 1:
    if startUnix notin exdates:
      return @[startUnix]
    return @[]
  let limit =
    if rrule.hasCount: min(rrule.count, cap)
    else: cap
  var generated = 0
  var stopped = false
  template consider(cand: int64) =
    if stopped:
      discard
    elif rrule.hasUntil and cand > rrule.untilUnix:
      stopped = true
    elif rangeEnd.has and cand >= rangeEnd.v:
      stopped = true
    else:
      inc generated
      if cand notin exdates:
        result.add(cand)
      if generated >= limit:
        stopped = true
  case rrule.freq
  of "DAILY":
    let step = rrule.interval.int64 * 86400
    var k = 0
    while not stopped:
      consider(startUnix + k.int64 * step)
      inc k
  of "WEEKLY":
    if rrule.byday.len == 0:
      let step = rrule.interval.int64 * 7 * 86400
      var k = 0
      while not stopped:
        consider(startUnix + k.int64 * step)
        inc k
    else:
      var days = rrule.byday
      # Sort + dedupe without sequtils (keeps this module dependency-free).
      for i in 1 ..< days.len:
        let x = days[i]
        var j = i - 1
        while j >= 0 and days[j] > x:
          days[j + 1] = days[j]
          dec j
        days[j + 1] = x
      var uniq: seq[int]
      for d in days:
        if uniq.len == 0 or uniq[^1] != d:
          uniq.add(d)
      let (_, _, _, h, mi, s) = unixYmd(startUnix)
      let tod = h * 3600 + mi * 60 + s
      let anchorMidnight = startUnix - (weekdayMon1(startUnix) - 1) * 86400 - tod
      var w = 0
      while not stopped:
        for dd in uniq:
          let cand = anchorMidnight + (w * rrule.interval * 7 + (dd - 1)).int64 *
            86400 + tod.int64
          if cand < startUnix:
            continue
          consider(cand)
          if stopped:
            break
        inc w
  of "MONTHLY":
    let (y, mo, d, h, mi, s) = unixYmd(startUnix)
    var k = 0
    while not stopped:
      consider(shiftMonths(y, mo, d, h, mi, s, k * rrule.interval))
      inc k
  of "YEARLY":
    let (y, mo, d, h, mi, s) = unixYmd(startUnix)
    var k = 0
    while not stopped:
      consider(shiftYears(y, mo, d, h, mi, s, k * rrule.interval))
      inc k
  else:
    if startUnix notin exdates:
      return @[startUnix]
    return @[]

# ── Overlap matching ───────────────────────────────────────────────────

const OpenBound = int64.high div 4
  ## Stand-in for an unbounded interval side; far outside real timestamps.

type
  Bounds = object
    ok*: bool
    s*, e*: int64
    hasS*, hasE*: bool

proc overlaps(b: Bounds, tr: CalTimeRange, hasTr: bool): bool =
  if not hasTr:
    return true
  if not b.ok:
    return false
  if b.hasS and tr.hasEnd and not (b.s < tr.endUnix):
    return false
  if b.hasE and tr.hasStart and not (b.e > tr.startUnix):
    return false
  true

proc eventBounds(ev: IcalEvent): Bounds =
  if ev.dtStart.isNone:
    return Bounds(ok: false)
  let s = icalToUnix(ev.dtStart.get.dt)
  if ev.dtEnd.isSome:
    return Bounds(ok: true, s: s, e: icalToUnix(ev.dtEnd.get.dt),
      hasS: true, hasE: true)
  if ev.duration.isSome:
    let d = max(totalSeconds(ev.duration.get), 0)
    return Bounds(ok: true, s: s, e: s + d, hasS: true, hasE: true)
  if not ev.dtStart.get.dt.hasTime:
    return Bounds(ok: true, s: s, e: s + 86400, hasS: true, hasE: true)
  Bounds(ok: true, s: s, e: s, hasS: true, hasE: true)

proc todoBounds(td: IcalTodo): Bounds =
  if td.dtStart.isSome and td.due.isSome:
    return Bounds(ok: true, s: icalToUnix(td.dtStart.get.dt),
      e: icalToUnix(td.due.get.dt), hasS: true, hasE: true)
  if td.dtStart.isSome:
    return Bounds(ok: true, s: icalToUnix(td.dtStart.get.dt), e: OpenBound,
      hasS: true, hasE: false)
  if td.due.isSome:
    return Bounds(ok: true, s: -OpenBound, e: icalToUnix(td.due.get.dt),
      hasS: false, hasE: true)
  if td.completed.isSome:
    let c = icalToUnix(td.completed.get.dt)
    return Bounds(ok: true, s: c, e: c, hasS: true, hasE: true)
  Bounds(ok: false)

proc compKindName*(comp: IcalComponent): string =
  case comp.kind
  of cckEvent: "VEVENT"
  of cckTodo: "VTODO"
  of cckJournal: "VJOURNAL"
  of cckTimezone: "VTIMEZONE"
  of cckOther: comp.other.name.toUpperAscii()

proc exdateSet*(dts: seq[IcalDt]): HashSet[int64] =
  result = initHashSet[int64]()
  for e in dts:
    try:
      result.incl(icalToUnix(e.dt))
    except CatchableError:
      discard

proc componentMatches*(comp: IcalComponent, compName: string,
    tr: CalTimeRange, hasTr: bool): bool =
  ## True when `comp` satisfies the comp-filter name plus time-range.
  if compName.len > 0 and compKindName(comp) != compName:
    return false
  if not hasTr:
    return true
  var bounds: Bounds
  var rruleRaw = ""
  var exdates = initHashSet[int64]()
  var anchor = 0'i64
  var durSecs = 0'i64
  var openEnd = false
  case comp.kind
  of cckEvent:
    bounds = eventBounds(comp.event)
    if comp.event.rrule.isSome:
      rruleRaw = comp.event.rrule.get
    exdates = exdateSet(comp.event.exdates)
  of cckTodo:
    bounds = todoBounds(comp.todo)
    if comp.todo.rrule.isSome:
      rruleRaw = comp.todo.rrule.get
  else:
    # VJOURNAL, VTIMEZONE and unknown components carry no usable date
    # interval in this subset, so a time-range never matches them.
    return false
  if not bounds.ok:
    return false
  if rruleRaw.len == 0:
    return overlaps(bounds, tr, hasTr)
  let rr = parseRrule(rruleRaw)
  if rr.freq.len == 0:
    return overlaps(bounds, tr, hasTr)
  # Recurring: expand the anchor; open-ended VTODOs keep an open end per
  # instance, open-started ones anchor on DUE.
  if bounds.hasS:
    anchor = bounds.s
  else:
    anchor = bounds.e
  if bounds.hasS and bounds.hasE:
    durSecs = max(bounds.e - anchor, 0)
  elif bounds.hasS and not bounds.hasE:
    openEnd = true
  let rs = (has: tr.hasStart, v: tr.startUnix)
  let re = (has: tr.hasEnd, v: tr.endUnix)
  for occ in expandStarts(anchor, rr, exdates, rs, re):
    if bounds.hasS:
      let e = if openEnd: OpenBound else: occ + durSecs
      if overlaps(Bounds(ok: true, s: occ, e: e, hasS: true, hasE: not openEnd),
          tr, hasTr):
        return true
    else:
      # Open-started VTODO: (-inf, occ] overlaps unless occ <= range start.
      if not tr.hasStart or occ > tr.startUnix:
        return true
  false

proc resourceMatches*(content: string, compName: string, tr: CalTimeRange,
    hasTr: bool): bool =
  ## True when any component of the `.ics` `content` satisfies the filter.
  ## Unparsable content never matches. An unconstrained query matches any
  ## resource holding at least one non-timezone component.
  var cal: IcalCalendar
  try:
    cal = parseIcal(content)
  except OpenParserIcalError:
    return false
  for comp in cal.components:
    if comp.kind == cckTimezone:
      continue
    if not hasTr and compName.len == 0:
      return true
    if componentMatches(comp, compName, tr, hasTr):
      return true
  false

proc isCalendarContent*(content: string): bool =
  ## True when `content` parses as iCalendar holding at least one
  ## VEVENT, VTODO or VJOURNAL component (the PUT gate for calendars).
  var cal: IcalCalendar
  try:
    cal = parseIcal(content)
  except OpenParserIcalError:
    return false
  for comp in cal.components:
    case comp.kind
    of cckEvent, cckTodo, cckJournal:
      return true
    else:
      discard
  false

proc calDataProp*(content: string): DavProp {.inline.} =
  DavProp(ns: CalNs, name: "calendar-data", value: content)
