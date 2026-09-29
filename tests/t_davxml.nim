## davxml: namespace-insensitive parsing, builders, hardening caps.
import std/unittest
import std/strutils

import ndav

suite "davxml propfind":
  test "allprop with D: prefix":
    let r = parsePropfind(
      """<?xml version="1.0" encoding="utf-8"?>""" &
      """<D:propfind xmlns:D="DAV:"><D:allprop/></D:propfind>""")
    check r.kind == pfAllprop

  test "arbitrary prefix and default namespace":
    let a = parsePropfind(
      """<dav:propfind xmlns:dav="DAV:"><dav:propname/></dav:propfind>""")
    check a.kind == pfPropname
    let b = parsePropfind(
      """<propfind xmlns="DAV:"><prop><getcontentlength/></prop></propfind>""")
    check b.kind == pfProp
    check b.props == @["getcontentlength"]

  test "prop collects local names":
    let r = parsePropfind(
      """<D:propfind xmlns:D="DAV:"><D:prop>""" &
      """<D:resourcetype/><D:getetag/><X:custom xmlns:X="urn:x:"/>""" &
      """</D:prop></D:propfind>""")
    check r.props == @["resourcetype", "getetag", "custom"]

  test "wrong namespace and garbage fail":
    expect DavXmlError:
      discard parsePropfind(
        """<D:propfind xmlns:D="urn:nope:"><D:allprop/></D:propfind>""")
    expect DavXmlError:
      discard parsePropfind("""<D:propfind xmlns:D="DAV:"/>""")
    expect DavXmlError:
      discard parsePropfind("this is not xml")
    expect DavXmlError:
      discard parsePropfind("")

suite "davxml propertyupdate":
  test "set and remove round-trip":
    let r = parsePropertyupdate(
      """<D:propertyupdate xmlns:D="DAV:">""" &
      """<D:set><D:prop><D:displayname>hi</D:displayname></D:prop></D:set>""" &
      """<D:remove><D:prop><D:oldd /></D:prop></D:remove>""" &
      """</D:propertyupdate>""")
    check r.ops.len == 2
    check r.ops[0].op == poSet
    check r.ops[0].props[0].name == "displayname"
    check r.ops[0].props[0].value == "hi"
    check r.ops[1].op == poRemove
    check r.ops[1].props[0].name == "oldd"

  test "unknown op fails":
    expect DavXmlError:
      discard parsePropertyupdate(
        """<D:propertyupdate xmlns:D="DAV:">""" &
        """<D:frob><D:prop/></D:frob></D:propertyupdate>""")

suite "davxml lockinfo":
  test "exclusive with owner":
    let r = parseLockinfo(
      """<D:lockinfo xmlns:D="DAV:">""" &
      """<D:lockscope><D:exclusive/></D:lockscope>""" &
      """<D:locktype><D:write/></D:locktype>""" &
      """<D:owner>alice</D:owner></D:lockinfo>""")
    check r.scope == "exclusive"
    check r.locktype == "write"
    check r.owner == "alice"

  test "shared":
    let r = parseLockinfo(
      """<D:lockinfo xmlns:D="DAV:">""" &
      """<D:lockscope><D:shared/></D:lockscope>""" &
      """<D:locktype><D:write/></D:locktype></D:lockinfo>""")
    check r.scope == "shared"

suite "davxml multistatus builder":
  test "builds parseable 207 with escaping":
    let body = buildMultistatus(@[
      DavResponse(href: "/a&b", propstats: @[
        DavPropstat(
          props: @[DavProp(ns: DavNs, name: "displayname", value: "A<B")],
          status: "HTTP/1.1 200 OK"),
        DavPropstat(
          props: @[DavProp(ns: DavNs, name: "secret", value: "")],
          status: "HTTP/1.1 404 Not Found"),
      ]),
    ])
    check body.startsWith("<?xml")
    let root = parseDavXml(body)
    check root.localNameOf() == "multistatus"
    check root.hasDavNs()
    let resp = root.findChild("response")
    check resp.childText("href") == "/a&b"
    check resp.childrenByLocal("propstat").len == 2

suite "davxml hardening":
  test "deep nesting rejected":
    var body = """<D:propfind xmlns:D="DAV:">"""
    for i in 0 .. 12:
      body.add("<D:wrap>")
    for i in 0 .. 12:
      body.add("</D:wrap>")
    body.add("</D:propfind>")
    expect DavXmlError:
      discard parseDavXml(body)

  test "unknown entity rejected, not crashed":
    expect DavXmlError:
      discard parseDavXml(
        """<D:propfind xmlns:D="DAV:"><D:prop><D:x>&bogus;</D:x>""" &
        """</D:prop></D:propfind>""")
