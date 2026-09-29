# DAV XML parsing and serialization on top of `pkg/openparser/xml`.
#
# openparser stores tags literally (`D:prop`), with no namespace model, so
# this module matches by local-name (after the last `:`) and verifies the
# `DAV:` namespace via the `xmlns` / `xmlns:prefix` attributes instead.
# openparser also enforces no depth limit on XML, so this module caps depth
# and node count before the server acts on a document.
#
# Parse failures raise `DavXmlError` (server maps to `422 Unprocessable
# Entity`, never 500).

import std/[strutils, tables]
import pkg/openparser/xml

export xml

const
  DavNs* = "DAV:"
    ## The WebDAV namespace URI (RFC 4918).
  CalNs* = "urn:ietf:params:xml:ns:caldav"
    ## The CalDAV namespace URI (RFC 4791).
  CardNs* = "urn:ietf:params:xml:ns:carddav"
    ## The CardDAV namespace URI (RFC 6352).
  MaxDavDepth* = 8
    ## Max nested-element depth accepted in a DAV request body.
  MaxDavNodes* = 2000
    ## Max total DOM nodes accepted in a DAV request body.

type
  DavXmlError* = object of CatchableError

  PropfindKind* = enum
    pfAllprop
    pfPropname
    pfProp

  PropfindRequest* = object
    kind*: PropfindKind
    props*: seq[string] ## Local names requested (only for `pfProp`).

  PropOp* = enum
    poSet
    poRemove

  PropUpdate* = object
    op*: PropOp
    props*: seq[DavProp]

  PropertyupdateRequest* = object
    ops*: seq[PropUpdate]

  LockinfoRequest* = object
    scope*: string    ## `exclusive` or `shared`.
    locktype*: string ## Always `write` per RFC 4918.
    owner*: string

  DavProp* = object
    ns*: string    ## Namespace URI, usually `DavNs`.
    name*: string  ## Local name.
    value*: string ## Text content; empty means an empty element.
    xml*: string   ## Verbatim inner XML; when set, used instead of `value`
      ## (for structured props like `resourcetype` and dead properties).

  DavPropstat* = object
    props*: seq[DavProp]
    status*: string ## Full status line, e.g. `HTTP/1.1 200 OK`.

  DavResponse* = object
    href*: string
    propstats*: seq[DavPropstat]

func localName*(tag: string): string {.inline.} =
  ## Local part of a possibly prefixed tag (`D:prop` -> `prop`).
  let i = tag.rfind(':')
  if i < 0: tag else: tag[i + 1 .. ^1]

func hasDavNs*(node: XmlNode): bool =
  ## True when any `xmlns` attribute on `node` declares the DAV namespace.
  if node == nil or node.kind != xnElement: return false
  for k, v in node.attrs:
    if (k == "xmlns" or k.startsWith("xmlns:")) and v == DavNs:
      return true
  false

proc checkCaps(node: XmlNode, depth: int, seen: var int) =
  inc seen
  if seen > MaxDavNodes:
    raise newException(DavXmlError, "DAV body exceeds node limit")
  if depth > MaxDavDepth:
    raise newException(DavXmlError, "DAV body exceeds depth limit")
  if node.kind == xnElement:
    for c in node.children:
      checkCaps(c, depth + 1, seen)

proc parseDavXml*(body: string): XmlNode =
  ## Parse a DAV request body into a DOM tree, hardened with depth and
  ## node-count caps. Raises `DavXmlError` on any failure.
  var root: XmlNode
  try:
    root = fromXml(body)
  except OpenParserXmlError as e:
    raise newException(DavXmlError, "invalid DAV XML: " & e.msg)
  if root == nil or root.kind != xnElement:
    raise newException(DavXmlError, "empty DAV body")
  var seen = 0
  checkCaps(root, 0, seen)
  root

func localNameOf*(node: XmlNode): string {.inline.} =
  if node != nil and node.kind == xnElement: localName(node.tag) else: ""

proc requireDavRoot*(root: XmlNode, local: string): XmlNode =
  ## Assert `root` is a DAV-namespaced `<local>` element.
  if root.localNameOf() != local or not root.hasDavNs():
    raise newException(DavXmlError,
      "expected DAV <" & local & "> root")
  root

proc findChild*(parent: XmlNode, local: string): XmlNode =
  ## First child element with the given local name, or nil.
  if parent == nil: return nil
  for c in parent.children:
    if c.kind == xnElement and localName(c.tag) == local:
      return c
  nil

proc childrenByLocal*(parent: XmlNode, local: string): seq[XmlNode] =
  if parent == nil: return @[]
  for c in parent.children:
    if c.kind == xnElement and localName(c.tag) == local:
      result.add(c)

proc childText*(parent: XmlNode, local: string): string =
  ## Concatenated text content of the first `<local>` child, or "".
  let node = parent.findChild(local)
  if node == nil: return ""
  for c in node.children:
    if c.kind == xnText:
      result.add(c.text)

proc elementChildren*(parent: XmlNode): seq[XmlNode] =
  if parent == nil: return @[]
  for c in parent.children:
    if c.kind == xnElement:
      result.add(c)

proc parsePropfind*(body: string): PropfindRequest =
  let root = parseDavXml(body).requireDavRoot("propfind")
  if root.findChild("allprop") != nil:
    return PropfindRequest(kind: pfAllprop)
  if root.findChild("propname") != nil:
    return PropfindRequest(kind: pfPropname)
  let prop = root.findChild("prop")
  if prop == nil:
    raise newException(DavXmlError,
      "propfind needs one of allprop, propname or prop")
  result = PropfindRequest(kind: pfProp)
  for c in prop.elementChildren():
    result.props.add(localName(c.tag))

proc parsePropValue*(node: XmlNode, ns = DavNs): DavProp =
  ## Pure-text values stay in `value`; anything structural is preserved
  ## verbatim in `xml` so dead properties round-trip exactly as sent.
  var hasElements = false
  for c in node.children:
    if c.kind == xnElement:
      hasElements = true
      break
  if not hasElements:
    var value = ""
    for c in node.children:
      if c.kind == xnText:
        value.add(c.text)
    return DavProp(ns: ns, name: localName(node.tag), value: value)
  var inner = ""
  for c in node.children:
    inner.add($c)
  DavProp(ns: ns, name: localName(node.tag), xml: inner)

proc parseFragment*(xmlStr: string): seq[XmlNode] =
  ## Parse an inner-XML fragment into nodes, graftable into a builder DOM.
  let root = parseDavXml(
    "<D:frag xmlns:D=\"" & DavNs & "\">" & xmlStr & "</D:frag>")
  root.elementChildren()

proc parsePropertyupdate*(body: string): PropertyupdateRequest =
  let root = parseDavXml(body).requireDavRoot("propertyupdate")
  for op in root.elementChildren():
    case localName(op.tag)
    of "set":
      let prop = op.findChild("prop")
      if prop == nil:
        raise newException(DavXmlError, "set needs a prop child")
      var update = PropUpdate(op: poSet)
      for c in prop.elementChildren():
        update.props.add(parsePropValue(c))
      result.ops.add(update)
    of "remove":
      let prop = op.findChild("prop")
      if prop == nil:
        raise newException(DavXmlError, "remove needs a prop child")
      var update = PropUpdate(op: poRemove)
      for c in prop.elementChildren():
        update.props.add(parsePropValue(c))
      result.ops.add(update)
    else:
      raise newException(DavXmlError,
        "propertyupdate needs set or remove, got <" & localName(op.tag) & ">")
  if result.ops.len == 0:
    raise newException(DavXmlError, "empty propertyupdate")

proc parseLockinfo*(body: string): LockinfoRequest =
  let root = parseDavXml(body).requireDavRoot("lockinfo")
  result = LockinfoRequest(locktype: "write", scope: "exclusive")
  let scope = root.findChild("lockscope")
  if scope != nil:
    if scope.findChild("exclusive") != nil:
      result.scope = "exclusive"
    elif scope.findChild("shared") != nil:
      result.scope = "shared"
    else:
      raise newException(DavXmlError, "lockscope needs exclusive or shared")
  let locktype = root.findChild("locktype")
  if locktype != nil and locktype.findChild("write") == nil:
    raise newException(DavXmlError, "only write locks are supported")
  result.owner = root.childText("owner")

proc newDavElement*(local: string): XmlNode =
  ## `<D:local>` element builder; output always uses the `D:` prefix.
  newXmlElement("D:" & local)

proc newCalElement*(local: string): XmlNode =
  ## `<C:local>` element builder; output always uses the `C:` prefix.
  newXmlElement("C:" & local)

proc newCardElement*(local: string): XmlNode =
  ## `<CR:local>` element builder; output always uses the `CR:` prefix.
  ## `C:` is reserved for CalDAV, so CardDAV uses `CR:` to avoid collision.
  newXmlElement("CR:" & local)

func hasCalNs*(node: XmlNode): bool =
  ## True when any `xmlns` attribute on `node` declares the CalDAV namespace.
  if node == nil or node.kind != xnElement: return false
  for k, v in node.attrs:
    if (k == "xmlns" or k.startsWith("xmlns:")) and v == CalNs:
      return true
  false

func hasCardNs*(node: XmlNode): bool =
  ## True when any `xmlns` attribute on `node` declares the CardDAV namespace.
  if node == nil or node.kind != xnElement: return false
  for k, v in node.attrs:
    if (k == "xmlns" or k.startsWith("xmlns:")) and v == CardNs:
      return true
  false

proc davDoc*(root: XmlNode): string =
  ## Serialize a DAV response document with XML declaration.
  "<?xml version=\"1.0\" encoding=\"utf-8\"?>" & $root

proc propstatCode*(status: string): int =
  ## Numeric code from a propstat status line (`HTTP/1.1 200 OK` -> 200),
  ## or 0 when the line does not parse.
  let parts = status.split(' ')
  if parts.len >= 2:
    try:
      return parseInt(parts[1])
    except ValueError:
      discard
  0

proc propNs(prefix: string): string {.inline.} =
  case prefix
  of "D": DavNs
  of "C": CalNs
  of "CR", "CARD", "Card": CardNs
  else: ""

proc parseMultistatus*(body: string): seq[DavResponse] =
  ## Parse a `207` multistatus body into responses. `D:`/`C:`/`CR:` prefixes
  ## map to `DavNs`/`CalNs`/`CardNs`; any other (or missing) prefix yields
  ## `ns == ""`, since the server serializes foreign-namespace dead props bare.
  ## Raises `DavXmlError` on any failure.
  let root = parseDavXml(body).requireDavRoot("multistatus")
  for resp in root.childrenByLocal("response"):
    var r = DavResponse(href: resp.childText("href"))
    for ps in resp.childrenByLocal("propstat"):
      var stat = DavPropstat(status: ps.childText("status"))
      let prop = ps.findChild("prop")
      if prop != nil:
        for e in prop.elementChildren():
          let tag = e.tag
          let ci = tag.rfind(':')
          if ci < 0:
            stat.props.add(parsePropValue(e, ""))
          else:
            stat.props.add(parsePropValue(e, propNs(tag[0 ..< ci])))
      r.propstats.add(stat)
    result.add(r)

proc buildMultistatus*(responses: seq[DavResponse], syncToken = ""): string =
  ## Build a `<D:multistatus>` 207 body. Text content is XML-escaped by the
  ## serializer; one `<response>` per resource, one `<propstat>` per status
  ## group (multiple groups cover per-prop `403`/`404` beside `200`).
  ## A non-empty `syncToken` appends a `<D:sync-token>` element for
  ## RFC 6578 `sync-collection` responses.
  let ms = newDavElement("multistatus")
  ms.addAttr("xmlns:D", DavNs)
  var needCal = false
  var needCard = false
  for r in responses:
    for ps in r.propstats:
      for p in ps.props:
        if p.ns == CalNs:
          needCal = true
        elif p.ns == CardNs:
          needCard = true
  if needCal:
    ms.addAttr("xmlns:C", CalNs)
  if needCard:
    ms.addAttr("xmlns:CR", CardNs)
  for r in responses:
    let resp = newDavElement("response")
    let href = newDavElement("href")
    href.addChild(newXmlText(r.href))
    resp.addChild(href)
    for ps in r.propstats:
      let propstat = newDavElement("propstat")
      let prop = newDavElement("prop")
      for p in ps.props:
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
        prop.addChild(elem)
      propstat.addChild(prop)
      let status = newDavElement("status")
      status.addChild(newXmlText(ps.status))
      propstat.addChild(status)
      resp.addChild(propstat)
    ms.addChild(resp)
  if syncToken.len > 0:
    let st = newDavElement("sync-token")
    st.addChild(newXmlText(syncToken))
    ms.addChild(st)
  davDoc(ms)
