# WebDAV shared types (RFC 4918).

import std/strutils

type
  DavDepth* = enum
    ## Value of the `Depth` header.
    DepthZero = "0"
    DepthOne = "1"
    DepthInfinity = "infinity"

proc parseDepth*(s: string, default: DavDepth): DavDepth =
  ## Parse a `Depth` header value case-insensitively. Unknown values fall
  ## back to `default`; callers that must reject garbage (400) should check
  ## membership explicitly instead.
  case s.strip().toLowerAscii()
  of "0": DepthZero
  of "1": DepthOne
  of "infinity": DepthInfinity
  else: default
