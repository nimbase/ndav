## WebDAV verb extension: every DAV method parses, validates and
## round-trips, base methods keep working, garbage is still rejected.
import std/unittest
import std/httpcore except HttpMethod

import ndav

suite "davmethod extension":
  test "all seven WebDAV verbs parse":
    for (raw, meth, wire) in [
      ("PROPFIND /r HTTP/1.1\r\nHost: x\r\n\r\n", HttpPropfind, "PROPFIND"),
      ("MKCOL /c HTTP/1.1\r\nHost: x\r\n\r\n", HttpMkcol, "MKCOL"),
      ("COPY /a HTTP/1.1\r\nHost: x\r\nDestination: /b\r\n\r\n",
        HttpCopy, "COPY"),
      ("MOVE /a HTTP/1.1\r\nHost: x\r\nDestination: /b\r\n\r\n",
        HttpMove, "MOVE"),
      ("LOCK /r HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n",
        HttpLock, "LOCK"),
      ("UNLOCK /r HTTP/1.1\r\nHost: x\r\nLock-Token: <x>\r\n\r\n",
        HttpUnlock, "UNLOCK"),
    ]:
      let p = newHttpParser()
      p.feed(raw)
      check p.isComplete()
      check p.peekMethod() == meth
      check p.getRequest().getMethod() == meth
      check $meth == wire

  test "proppatch parses":
    let p = newHttpParser()
    p.feed("PROPPATCH /r HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
    check p.isComplete()
    check p.getRequest().getMethod() == HttpProppatch

  test "report parses (CalDAV/CardDAV)":
    let p = newHttpParser()
    p.feed("REPORT /cal HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
    check p.isComplete()
    check p.getRequest().getMethod() == HttpReport
    check $HttpReport == "REPORT"

  test "base methods unaffected, garbage rejected":
    let g = newHttpParser()
    g.feed("GET /a HTTP/1.1\r\nHost: x\r\n\r\n")
    check g.getRequest().getMethod() == HttpGet
    let c = newHttpParser()
    c.feed("CONNECT e:443 HTTP/1.1\r\nHost: x\r\n\r\n")
    check c.getRequest().getMethod() == HttpConnect
    for raw in [
      "GETTY /a HTTP/1.1\r\nHost: x\r\n\r\n",
      "MADEUP /a HTTP/1.1\r\nHost: x\r\n\r\n",
      "get /a HTTP/1.1\r\nHost: x\r\n\r\n",
    ]:
      let p = newHttpParser()
      p.feed(raw)
      check p.phase == PhaseError
