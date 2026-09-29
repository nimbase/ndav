# WebDAV HTTP verbs for powpow, registered at compile time via pkg/voodoo.
#
# Import this module BEFORE any powpow module so the extensions are staged
# before powpow compiles:
#
#   import ndav/davmethod  # first
#   import powpow            # after
#
# In practice just `import ndav`, which orders this correctly.

import pkg/voodoo/extensibles

extendEnum HttpMethod:
  HttpPropfind = "PROPFIND"
  HttpProppatch = "PROPPATCH"
  HttpMkcol = "MKCOL"
  HttpMkcalendar = "MKCALENDAR"
  HttpCopy = "COPY"
  HttpMove = "MOVE"
  HttpLock = "LOCK"
  HttpUnlock = "UNLOCK"
  HttpReport = "REPORT"

# `P*` verbs share a first-byte branch with POST/PUT/PATCH in powpow's
# fast-path parser, so they are injected as a snippet rather than a new
# `case` branch (which would collide).
injectSnippet "powpow.parseMethod.P":
  if len == 8 and char(buf[1]) == 'R' and char(buf[2]) == 'O' and
      char(buf[3]) == 'P' and char(buf[4]) == 'F' and char(buf[5]) == 'I' and
      char(buf[6]) == 'N' and char(buf[7]) == 'D':
    return HttpPropfind
  if len == 9 and char(buf[1]) == 'R' and char(buf[2]) == 'O' and
      char(buf[3]) == 'P' and char(buf[4]) == 'P' and char(buf[5]) == 'A' and
      char(buf[6]) == 'T' and char(buf[7]) == 'C' and char(buf[8]) == 'H':
    return HttpProppatch

# `COPY` shares its first byte with CONNECT.
injectSnippet "powpow.parseMethod.C":
  if len == 4 and char(buf[1]) == 'O' and char(buf[2]) == 'P' and
      char(buf[3]) == 'Y':
    return HttpCopy

# `M*`, `L*`, `U*`, `R*` have no base-branch collision,
# so plain new branches work.
extendCaseStmt "powpow.parseMethod":
  case '\0':
  of 'R':
    if len == 6 and char(buf[1]) == 'E' and char(buf[2]) == 'P' and
        char(buf[3]) == 'O' and char(buf[4]) == 'R' and char(buf[5]) == 'T':
      return HttpReport
    return HttpGet
  of 'M':
    if len == 5 and char(buf[1]) == 'K' and char(buf[2]) == 'C' and
        char(buf[3]) == 'O' and char(buf[4]) == 'L':
      return HttpMkcol
    if len == 10 and char(buf[1]) == 'K' and char(buf[2]) == 'C' and
        char(buf[3]) == 'A' and char(buf[4]) == 'L' and char(buf[5]) == 'E' and
        char(buf[6]) == 'N' and char(buf[7]) == 'D' and char(buf[8]) == 'A' and
        char(buf[9]) == 'R':
      return HttpMkcalendar
    if len == 4 and char(buf[1]) == 'O' and char(buf[2]) == 'V' and
        char(buf[3]) == 'E':
      return HttpMove
    return HttpGet
  of 'L':
    if len == 4 and char(buf[1]) == 'O' and char(buf[2]) == 'C' and
        char(buf[3]) == 'K':
      return HttpLock
    return HttpGet
  of 'U':
    if len == 6 and char(buf[1]) == 'N' and char(buf[2]) == 'L' and
        char(buf[3]) == 'O' and char(buf[4]) == 'C' and char(buf[5]) == 'K':
      return HttpUnlock
    return HttpGet

extendCaseStmt "powpow.methodToken":
  case HttpGet:
  of HttpPropfind: return "PROPFIND"
  of HttpProppatch: return "PROPPATCH"
  of HttpMkcol: return "MKCOL"
  of HttpMkcalendar: return "MKCALENDAR"
  of HttpCopy: return "COPY"
  of HttpMove: return "MOVE"
  of HttpLock: return "LOCK"
  of HttpUnlock: return "UNLOCK"
  of HttpReport: return "REPORT"
