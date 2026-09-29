# WebDAV live properties (RFC 4918 §15).
#
# ETag and date formats match powpow's `serveFile` (`"size-mtime"` quoted;
# IMF-fixdate) so conditional clients see consistent values.

import std/[times, strutils, tables]
import ./backend
import ./davxml

export davxml

const
  ProtectedLiveProps* = [
    "resourcetype", "getcontentlength", "getcontenttype",
    "getlastmodified", "creationdate", "getetag",
    "lockdiscovery", "supportedlock",
    "getctag", "supported-report-set",
    "current-user-principal", "principal-collection-set", "principal-URL",
  ]
    ## Live properties a PROPPATCH `set`/`remove` must reject with 403.
    ## `displayname` is live but client-writable per RFC 4918.

  SupportedLockXml* =
    """<D:lockentry xmlns:D="DAV:"><D:lockscope><D:exclusive/>""" &
    """</D:lockscope><D:locktype><D:write/></D:locktype></D:lockentry>""" &
    """<D:lockentry xmlns:D="DAV:"><D:lockscope><D:shared/>""" &
    """</D:lockscope><D:locktype><D:write/></D:locktype></D:lockentry>"""

func isProtectedLive*(name: string): bool {.inline.} =
  name.toLowerAscii() in ProtectedLiveProps

proc httpDate*(t: Time): string {.inline.} =
  format(t.utc, "ddd, dd MMM yyyy HH:mm:ss") & " GMT"

proc isoDate*(t: Time): string {.inline.} =
  format(t.utc, "yyyy-MM-dd'T'HH:mm:ss'Z'")

proc davEtag*(size: int64, mtime: Time): string {.inline.} =
  "\"" & $size & "-" & $mtime.toUnix & "\""

proc displayName*(urlPath: string): string =
  let parts = urlPath.split('/')
  for i in countdown(parts.high, 0):
    if parts[i].len > 0:
      return parts[i]
  "/"

proc addressbookCtag*(b: DavBackend, urlPath: string): string =
  ## Opaque change tag for an addressbook collection. Same construction as
  ## the calendar ctag: max member mtime plus member count.
  var best: int64 = 0
  var count = 0
  try:
    for m in b.driver.list(toDriverPath(urlPath), recursive = false):
      inc count
      let v = m.lastModified.toUnix * 1_000_000_000 + m.lastModified.nanosecond
      if v > best:
        best = v
  except CatchableError:
    best = 0
    count = 0
  if best == 0 and count == 0:
    try:
      let meta = b.driver.metadata(toDriverPath(urlPath))
      return "\"" & $meta.lastModified.toUnix & "-" &
        $meta.lastModified.nanosecond & "\""
    except CatchableError:
      return "\"0-0\""
  "\"" & $best & "-" & $count & "\""

proc calendarCtag*(b: DavBackend, urlPath: string): string =
  ## Opaque change tag for a calendar collection: max member mtime
  ## (nanosecond precision) plus member count, so PUT/DELETE of an event
  ## always moves the tag even when the collection mtime itself is stale.
  ## Falls back to the collection mtime when the listing fails.
  var best: int64 = 0
  var count = 0
  try:
    for m in b.driver.list(toDriverPath(urlPath), recursive = false):
      inc count
      let v = m.lastModified.toUnix * 1_000_000_000 + m.lastModified.nanosecond
      if v > best:
        best = v
  except CatchableError:
    best = 0
    count = 0
  if best == 0 and count == 0:
    try:
      let meta = b.driver.metadata(toDriverPath(urlPath))
      return "\"" & $meta.lastModified.toUnix & "-" &
        $meta.lastModified.nanosecond & "\""
    except CatchableError:
      return "\"0-0\""
  "\"" & $best & "-" & $count & "\""

proc davMimeType*(b: DavBackend, urlPath: string): string =
  ## MIME type for a resource. `.vcf` is pinned to `text/vcard` per
  ## RFC 6352 (mimedb reports the historic `text/x-vcard` instead).
  if urlPath.toLowerAscii().endsWith(".vcf"):
    return "text/vcard"
  try:
    b.driver.mimeType(toDriverPath(urlPath))
  except CatchableError:
    "application/octet-stream"

proc hrefXml*(href: string): string {.inline.} =
  ## `<D:href>` element for href-valued live properties.
  """<D:href xmlns:D="DAV:">""" & href & """</D:href>"""

proc liveProps*(b: DavBackend, urlPath: string, currentUser = ""): seq[DavProp] =
  ## All live properties for a resource. `currentUser` is the authenticated
  ## name ("", when auth is disabled); a non-empty value adds the RFC 5397
  ## identity props (`current-user-principal`, `principal-collection-set`).
  let meta = b.driver.metadata(toDriverPath(urlPath))
  let isDir = meta.isDir
  let isCal = isDir and b.isCalendarCollection(urlPath)
  let isAb = isDir and b.isAddressbookCollection(urlPath)
  let restypeXml =
    if not isDir: ""
    elif isCal:
      """<D:collection xmlns:D="DAV:"/>""" &
      """<C:calendar xmlns:C="""" & CalNs & """" />"""
    elif isAb:
      """<D:collection xmlns:D="DAV:"/>""" &
      """<CR:addressbook xmlns:CR="""" & CardNs & """" />"""
    else: """<D:collection xmlns:D="DAV:"/>"""
  result.add(DavProp(ns: DavNs, name: "resourcetype", xml: restypeXml))
  # `displayname` is live but client-writable (RFC 4918 §15.2.2): a stored
  # dead value (via PROPPATCH or MKCALENDAR) overrides the computed name.
  var dn = displayName(urlPath)
  for k, v in b.getDead(urlPath):
    if v.ns == DavNs and k.split('\x00')[^1] == "displayname":
      dn = v.value
      break
  result.add(DavProp(ns: DavNs, name: "displayname", value: dn))
  result.add(DavProp(ns: DavNs, name: "creationdate",
    value: isoDate(meta.lastModified)))
  result.add(DavProp(ns: DavNs, name: "getlastmodified",
    value: httpDate(meta.lastModified)))
  result.add(DavProp(ns: DavNs, name: "getetag",
    value: davEtag(meta.size, meta.lastModified)))
  result.add(DavProp(ns: DavNs, name: "lockdiscovery",
    xml: b.locks.lockDiscoveryXml(urlPath)))
  result.add(DavProp(ns: DavNs, name: "supportedlock",
    xml: SupportedLockXml))
  if isCal:
    result.add(DavProp(ns: DavNs, name: "getctag",
      value: b.calendarCtag(urlPath)))
    result.add(DavProp(ns: DavNs, name: "supported-report-set",
      xml: """<D:supported-report xmlns:D="DAV:">""" &
      """<D:report><C:calendar-query xmlns:C="""" & CalNs & """" />""" &
      """</D:report></D:supported-report>""" &
      """<D:supported-report xmlns:D="DAV:">""" &
      """<D:report><C:calendar-multiget xmlns:C="""" & CalNs & """" />""" &
      """</D:report></D:supported-report>""" &
      """<D:supported-report xmlns:D="DAV:">""" &
      """<D:report><D:sync-collection /></D:report></D:supported-report>"""))
  if isAb:
    result.add(DavProp(ns: DavNs, name: "getctag",
      value: b.addressbookCtag(urlPath)))
    result.add(DavProp(ns: DavNs, name: "supported-report-set",
      xml: """<D:supported-report xmlns:D="DAV:">""" &
      """<D:report><CR:addressbook-query xmlns:CR="""" & CardNs & """" />""" &
      """</D:report></D:supported-report>""" &
      """<D:supported-report xmlns:D="DAV:">""" &
      """<D:report><CR:addressbook-multiget xmlns:CR="""" & CardNs & """" />""" &
      """</D:report></D:supported-report>""" &
      """<D:supported-report xmlns:D="DAV:">""" &
      """<D:report><D:sync-collection /></D:report></D:supported-report>"""))
    result.add(DavProp(ns: CardNs, name: "supported-address-data",
      xml: """<CR:address-data-type content-type="text/vcard" version="3.0" """ &
      """xmlns:CR="""" & CardNs & """" />""" &
      """<CR:address-data-type content-type="text/vcard" version="4.0" """ &
      """xmlns:CR="""" & CardNs & """" />"""))
    var abDesc = ""
    for k, v in b.getDead(urlPath):
      if v.ns == CardNs and k.split('\x00')[^1] == "addressbook-description":
        abDesc = v.value
        break
    if abDesc.len > 0:
      result.add(DavProp(ns: CardNs, name: "addressbook-description",
        value: abDesc))
  if not isDir:
    result.add(DavProp(ns: DavNs, name: "getcontentlength",
      value: $meta.size))
    result.add(DavProp(ns: DavNs, name: "getcontenttype",
      value: b.davMimeType(urlPath)))
  if currentUser.len > 0:
    result.add(DavProp(ns: DavNs, name: "current-user-principal",
      xml: hrefXml(principalHref(currentUser))))
    result.add(DavProp(ns: DavNs, name: "principal-collection-set",
      xml: hrefXml(PrincipalsRoot & "/")))

proc deadPropsList*(b: DavBackend, urlPath: string): seq[DavProp] =
  for k, v in b.getDead(urlPath):
    let name = k.split('\x00')[^1]
    # `displayname` overrides surface through the live property above;
    # listing the dead copy too would duplicate it in allprop responses.
    if v.ns == DavNs and name == "displayname":
      continue
    result.add(DavProp(ns: v.ns, name: name, value: v.value, xml: v.xml))

proc findLive*(props: seq[DavProp], name: string): int =
  for i, p in props:
    if p.ns == DavNs and p.name == name:
      return i
  -1
