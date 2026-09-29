## Class 1 end-to-end over loopback: server on the sync client's loop,
## in-memory backend. Ports 20951+.
import std/unittest
import std/strutils
import std/httpcore except HttpMethod

import ndav

proc withDav(body: proc(srv: DavServer, client: HttpClient, base: string)) =
  let client = newHttpClient()
  let srv = newDavServer(newMemoryDriver())
  let server = newHttpServer(client.getLoop())
  server.handler = srv.davHandler()
  server.listen("127.0.0.1", 20951)
  try:
    body(srv, client, "http://127.0.0.1:20951")
  finally:
    server.close()
    client.close()

proc status(client: HttpClient, meth: HttpMethod, url: string,
    body = "", headers: openArray[(string, string)] = []): HttpCode =
  client.request(meth, url, body, headers).getStatusCode()

suite "class1 options/put/get/head/delete":
  test "options advertises DAV":
    withDav proc(srv: DavServer, client: HttpClient, base: string) =
      let res = client.request(HttpOptions, base & "/")
      check res.getStatusCode() == Http200
      let allow: string = res.getHeaders()["Allow"]
      check "PROPFIND" in allow
      check "REPORT" in allow
      let dav: string = res.getHeaders()["DAV"]
      check "1, 2" in dav
      check "calendar-access" in dav

  test "put/get/head round-trip":
    withDav proc(srv: DavServer, client: HttpClient, base: string) =
      check client.status(HttpPut, base & "/hello.txt", "hi") == Http201
      check client.status(HttpPut, base & "/hello.txt", "hi!") == Http204
      let res = client.get(base & "/hello.txt")
      check res.getStatusCode() == Http200
      check res.getBodyString() == "hi!"
      check res.getHeaders()["ETag"].len > 0
      let head = client.head(base & "/hello.txt")
      check head.getStatusCode() == Http200
      check head.getBodyString() == ""
      check client.status(HttpGet, base & "/missing") == Http404
      check client.status(HttpGet, base & "/") == Http403

  test "put needs existing parent":
    withDav proc(srv: DavServer, client: HttpClient, base: string) =
      check client.status(HttpPut, base & "/no/such.txt", "x") == Http409

  test "delete file and missing":
    withDav proc(srv: DavServer, client: HttpClient, base: string) =
      check client.status(HttpPut, base & "/gone.txt", "x") == Http201
      check client.status(HttpDelete, base & "/gone.txt") == Http204
      check client.status(HttpGet, base & "/gone.txt") == Http404
      check client.status(HttpDelete, base & "/gone.txt") == Http404
      check client.status(HttpDelete, base & "/") == Http403

suite "class1 mkcol":
  test "make collection and errors":
    withDav proc(srv: DavServer, client: HttpClient, base: string) =
      check client.status(HttpMkcol, base & "/col") == Http201
      check client.status(HttpMkcol, base & "/col") == Http405
      check client.status(HttpMkcol, base & "/a/b") == Http409
      check client.status(HttpMkcol, base & "/bod", "non-empty") == Http415
      check client.status(HttpPut, base & "/col/f.txt", "data") == Http201
      check client.status(HttpDelete, base & "/col") == Http204
      check client.status(HttpGet, base & "/col/f.txt") == Http404

suite "class1 propfind":
  test "allprop file and depth listing":
    withDav proc(srv: DavServer, client: HttpClient, base: string) =
      discard client.request(HttpMkcol, base & "/col")
      discard client.request(HttpPut, base & "/col/f.txt", "hey")
      let f = client.request(HttpPropfind, base & "/col/f.txt", "",
        [("Depth", "0")])
      check f.getStatusCode() == Http207
      check "getcontentlength" in f.getBodyString()
      check ">3<" in f.getBodyString()
      let d = client.request(HttpPropfind, base & "/col", "",
        [("Depth", "1")])
      check d.getStatusCode() == Http207
      check "/col/" in d.getBodyString()
      check "/col/f.txt" in d.getBodyString()
      check client.status(HttpPropfind, base & "/nope") == Http404
      check client.status(HttpPropfind, base & "/col",
        "", [("Depth", "sideways")]) == Http400

  test "infinity capped at depth 1":
    withDav proc(srv: DavServer, client: HttpClient, base: string) =
      discard client.request(HttpMkcol, base & "/c")
      discard client.request(HttpMkcol, base & "/c/sub")
      discard client.request(HttpPut, base & "/c/sub/deep.txt", "d")
      let r = client.request(HttpPropfind, base & "/c", "", [("Depth", "infinity")])
      check r.getStatusCode() == Http207
      check "/c/sub" in r.getBodyString()
      check "/c/sub/deep.txt" notin r.getBodyString()

  test "prop selection with 404 group":
    withDav proc(srv: DavServer, client: HttpClient, base: string) =
      discard client.request(HttpPut, base & "/p.txt", "v")
      let body = """<D:propfind xmlns:D="DAV:"><D:prop>""" &
        """<D:getetag/><D:nosuchprop/></D:prop></D:propfind>"""
      let r = client.request(HttpPropfind, base & "/p.txt", body,
        [("Depth", "0"), ("Content-Type", "application/xml")])
      check r.getStatusCode() == Http207
      check "200 OK" in r.getBodyString()
      check "404 Not Found" in r.getBodyString()

  test "bad xml is 422":
    withDav proc(srv: DavServer, client: HttpClient, base: string) =
      check client.status(HttpPropfind, base & "/", "not xml") == Http422

suite "class1 proppatch":
  test "set, read back, remove":
    withDav proc(srv: DavServer, client: HttpClient, base: string) =
      discard client.request(HttpPut, base & "/d.txt", "v")
      let setBody = """<D:propertyupdate xmlns:D="DAV:"><D:set><D:prop>""" &
        """<D:author>Alice</D:author></D:prop></D:set></D:propertyupdate>"""
      let s = client.request(HttpProppatch, base & "/d.txt", setBody,
        [("Content-Type", "application/xml")])
      check s.getStatusCode() == Http207
      check "200 OK" in s.getBodyString()
      let f = client.request(HttpPropfind, base & "/d.txt",
        """<D:propfind xmlns:D="DAV:"><D:prop><D:author/></D:prop></D:propfind>""",
        [("Depth", "0")])
      check "Alice" in f.getBodyString()
      let remBody = """<D:propertyupdate xmlns:D="DAV:">""" &
        """<D:remove><D:prop><D:author/></D:prop></D:remove></D:propertyupdate>"""
      let rem = client.request(HttpProppatch, base & "/d.txt", remBody,
        [("Content-Type", "application/xml")])
      check "200 OK" in rem.getBodyString()
      let f2 = client.request(HttpPropfind, base & "/d.txt",
        """<D:propfind xmlns:D="DAV:"><D:prop><D:author/></D:prop></D:propfind>""",
        [("Depth", "0")])
      check "404 Not Found" in f2.getBodyString()

  test "protected props rejected, missing remove is 404":
    withDav proc(srv: DavServer, client: HttpClient, base: string) =
      discard client.request(HttpPut, base & "/e.txt", "v")
      let setBody = """<D:propertyupdate xmlns:D="DAV:">""" &
        """<D:set><D:prop><D:getetag>x</D:getetag></D:prop></D:set>""" &
        """</D:propertyupdate>"""
      let s = client.request(HttpProppatch, base & "/e.txt", setBody,
        [("Content-Type", "application/xml")])
      check "403 Forbidden" in s.getBodyString()
      let remBody = """<D:propertyupdate xmlns:D="DAV:">""" &
        """<D:remove><D:prop><D:ghost/></D:prop></D:remove></D:propertyupdate>"""
      let r = client.request(HttpProppatch, base & "/e.txt", remBody,
        [("Content-Type", "application/xml")])
      check "404 Not Found" in r.getBodyString()

suite "class1 copy/move":
  test "copy file keeps source, honors overwrite":
    withDav proc(srv: DavServer, client: HttpClient, base: string) =
      discard client.request(HttpPut, base & "/a.txt", "A")
      check client.status(HttpCopy, base & "/a.txt", "",
        [("Destination", base & "/b.txt")]) == Http201
      check client.get(base & "/b.txt").getBodyString() == "A"
      check client.get(base & "/a.txt").getBodyString() == "A"
      check client.status(HttpCopy, base & "/a.txt", "",
        [("Destination", base & "/b.txt"), ("Overwrite", "F")]) == Http412
      check client.status(HttpCopy, base & "/a.txt", "",
        [("Destination", base & "/b.txt"), ("Overwrite", "F")]) == Http412
      discard client.request(HttpPut, base & "/b.txt", "B")
      check client.status(HttpCopy, base & "/a.txt", "",
        [("Destination", base & "/b.txt")]) == Http204
      check client.get(base & "/b.txt").getBodyString() == "A"
      check client.status(HttpCopy, base & "/a.txt") == Http400
      check client.status(HttpCopy, base & "/missing", "",
        [("Destination", base & "/x.txt")]) == Http404
      check client.status(HttpCopy, base & "/a.txt", "",
        [("Destination", base & "/nodir/x.txt")]) == Http409

  test "copy carries dead props":
    withDav proc(srv: DavServer, client: HttpClient, base: string) =
      discard client.request(HttpPut, base & "/s.txt", "v")
      discard client.request(HttpProppatch, base & "/s.txt",
        """<D:propertyupdate xmlns:D="DAV:"><D:set><D:prop>""" &
        """<D:tag>t1</D:tag></D:prop></D:set></D:propertyupdate>""",
        [("Content-Type", "application/xml")])
      discard client.request(HttpCopy, base & "/s.txt", "",
        [("Destination", base & "/d.txt")])
      let f = client.request(HttpPropfind, base & "/d.txt",
        """<D:propfind xmlns:D="DAV:"><D:prop><D:tag/></D:prop></D:propfind>""",
        [("Depth", "0")])
      check "t1" in f.getBodyString()
      let fs = client.request(HttpPropfind, base & "/s.txt",
        """<D:propfind xmlns:D="DAV:"><D:prop><D:tag/></D:prop></D:propfind>""",
        [("Depth", "0")])
      check "t1" in fs.getBodyString()

  test "move file and collection":
    withDav proc(srv: DavServer, client: HttpClient, base: string) =
      discard client.request(HttpPut, base & "/m.txt", "M")
      check client.status(HttpMove, base & "/m.txt", "",
        [("Destination", base & "/n.txt")]) == Http201
      check client.status(HttpGet, base & "/m.txt") == Http404
      check client.get(base & "/n.txt").getBodyString() == "M"
      discard client.request(HttpMkcol, base & "/tree")
      discard client.request(HttpPut, base & "/tree/leaf.txt", "L")
      check client.status(HttpMove, base & "/tree", "",
        [("Destination", base & "/bush")]) == Http201
      check client.get(base & "/bush/leaf.txt").getBodyString() == "L"
      check client.status(HttpPropfind, base & "/tree") == Http404

  test "copy depth 0 on collection copies shell only":
    withDav proc(srv: DavServer, client: HttpClient, base: string) =
      discard client.request(HttpMkcol, base & "/big")
      discard client.request(HttpPut, base & "/big/in.txt", "in")
      check client.status(HttpCopy, base & "/big", "",
        [("Destination", base & "/shell"), ("Depth", "0")]) == Http201
      check client.status(HttpGet, base & "/shell/in.txt") == Http404
      let r = client.request(HttpPropfind, base & "/shell", "",
        [("Depth", "1")])
      check "/shell/" in r.getBodyString()
