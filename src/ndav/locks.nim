# WebDAV Class 2 locking (RFC 4918 §6-8).
#
# Known limits (documented, not silent):
# - `If` evaluation is a subset: untagged and tagged token groups with
#   `Not` are understood; etag-based conditions are ignored (a group that
#   contains only etag conditions is treated as satisfied).
# - Expiry is lazy: expired locks are purged on every manager operation,
#   no background timer needed for single-loop deployments.
# - Principal checking is absent (no auth layer yet): any client presenting
#   a valid token satisfies the lock.

import std/[times, strutils, tables, oids]
import ./davxml

export davxml

const
  DefaultLockTimeout* = 3600
    ## Seconds used when the LOCK request carries no usable Timeout.
  MaxLockTimeout* = 7 * 24 * 3600
    ## Upper clamp for requested timeouts.

type
  DavLockConflict* = object of CatchableError
    ## Raised by `acquire` when the requested lock is incompatible with
    ## existing locks.

  DavLockScope* = enum
    lsExclusive
    lsShared

  DavLock* = ref object
    token*: string
    path*: string  ## Locked URL path (collection or resource).
    scope*: DavLockScope
    depth*: int    ## 0 or 2 (infinity).
    owner*: string
    timeout*: int  ## Seconds; -1 means infinite.
    created*: Time

  LockManager* = ref object
    locks: Table[string, DavLock] ## token -> lock

  IfToken* = object
    token*: string
    negated*: bool

  IfGroup* = object
    resource*: string ## Tagged-list resource, "" for untagged.
    tokens*: seq[IfToken]

proc newLockManager*(): LockManager =
  LockManager(locks: initTable[string, DavLock]())

proc newLockToken*(): string =
  "opaquelocktoken:" & $genOid()

proc isExpired*(lock: DavLock, now = getTime()): bool {.inline.} =
  lock.timeout >= 0 and (now - lock.created).inSeconds > lock.timeout

proc purgeExpired*(m: LockManager) =
  let now = getTime()
  var dead: seq[string]
  for tok, lock in m.locks:
    if lock.isExpired(now):
      dead.add(tok)
  for tok in dead:
    m.locks.del(tok)

proc covers*(lock: DavLock, path: string): bool {.inline.} =
  ## True when `lock` applies to `path` (directly or via depth-infinity
  ## on an ancestor collection).
  path == lock.path or
    (lock.depth == 2 and path.startsWith(lock.path & "/"))

proc findCovering*(m: LockManager, path: string): seq[DavLock] =
  m.purgeExpired()
  for lock in m.locks.values:
    if lock.covers(path):
      result.add(lock)

proc conflicts(a, b: DavLockScope): bool {.inline.} =
  ## Exclusive conflicts with everything; shared only with exclusive.
  a == lsExclusive or b == lsExclusive

proc acquire*(m: LockManager, path: string, scope: DavLockScope,
    depth: int, owner: string, timeout: int): DavLock =
  ## Create a lock or raise `DavLockConflict`. Depth is 0 or 2 (infinity).
  m.purgeExpired()
  for lock in m.locks.values:
    let overlap =
      lock.path == path or
      lock.covers(path) or
      (depth == 2 and path != lock.path and
        lock.path.startsWith(path & "/"))
    if overlap and conflicts(lock.scope, scope):
      raise newException(DavLockConflict,
        "incompatible with lock " & lock.token)
  result = DavLock(token: newLockToken(), path: path, scope: scope,
    depth: depth, owner: owner, timeout: timeout, created: getTime())
  m.locks[result.token] = result

proc getToken*(m: LockManager, token: string): DavLock =
  ## The live lock for `token`, or nil.
  m.purgeExpired()
  if token in m.locks: m.locks[token] else: nil

proc refresh*(m: LockManager, token: string, timeout: int): bool =
  ## Renew an existing lock's timeout. False when the token is unknown.
  m.purgeExpired()
  if token notin m.locks:
    return false
  m.locks[token].timeout = timeout
  m.locks[token].created = getTime()
  true

proc release*(m: LockManager, token, path: string): bool =
  ## Release `token` when it exists and covers `path`.
  m.purgeExpired()
  if token notin m.locks:
    return false
  if not m.locks[token].covers(path):
    return false
  m.locks.del(token)
  true

proc parseTimeout*(s: string, default = DefaultLockTimeout): int =
  ## Parse a `Timeout` header (`Second-N`, `Infinite`, comma lists).
  ## Unknown values fall back to `default`; requests are clamped to
  ## `MaxLockTimeout`.
  for part in s.split(','):
    let p = part.strip()
    if p.toLowerAscii() == "infinite":
      return -1
    if p.len > 7 and p[0 .. 6].toLowerAscii() == "second-":
      try:
        return min(parseInt(p[7 .. ^1]), MaxLockTimeout)
      except ValueError:
        discard
  default

proc parseDepthLock*(s: string): int =
  ## LOCK Depth: 0 or 2 (infinity), else -1.
  case s.strip().toLowerAscii()
  of "0": 0
  of "infinity": 2
  else: -1

proc parseLockTokens*(s: string): seq[string] =
  ## Extract `<...>` tokens from a `Lock-Token` (or similar) header value.
  var i = 0
  while i < s.len:
    let a = s.find('<', i)
    if a < 0:
      break
    let b = s.find('>', a + 1)
    if b < 0:
      break
    result.add(s[a + 1 ..< b])
    i = b + 1

proc parseIf*(s: string): seq[IfGroup] =
  ## Parse an `If` header into token groups (subset: untagged and tagged
  ## lists with `Not`; etag conditions are dropped, see module docs).
  var i = 0
  while i < s.len:
    while i < s.len and s[i] in {' ', '\t', ','}:
      inc i
    if i >= s.len:
      break
    var resource = ""
    if s[i] == '<':
      let b = s.find('>', i + 1)
      if b < 0:
        break
      # Lookahead: a `<uri>` followed by `(` is a tagged list.
      var j = b + 1
      while j < s.len and s[j] in {' ', '\t'}:
        inc j
      if j < s.len and s[j] == '(':
        resource = s[i + 1 ..< b]
        i = j
      else:
        # Bare token outside a group; skip it (belongs to no group).
        i = b + 1
        continue
    if i >= s.len or s[i] != '(':
      inc i
      continue
    inc i # consume '('
    var group = IfGroup(resource: resource)
    while i < s.len and s[i] != ')':
      while i < s.len and s[i] in {' ', '\t'}:
        inc i
      var negated = false
      if i + 3 <= s.len and s[i ..< i + 3].toLowerAscii() == "not" and
          (i + 3 >= s.len or s[i + 3] in {' ', '\t'}):
        negated = true
        i += 3
        while i < s.len and s[i] in {' ', '\t'}:
          inc i
      if i < s.len and s[i] == '<':
        let b = s.find('>', i + 1)
        if b < 0:
          break
        let tok = s[i + 1 ..< b]
        if tok.startsWith("opaquelocktoken:"):
          group.tokens.add(IfToken(token: tok, negated: negated))
        # else: etag condition — dropped (see module docs).
        i = b + 1
      elif i < s.len and s[i] != ')':
        inc i
    if i < s.len and s[i] == ')':
      inc i
    if group.tokens.len > 0:
      result.add(group)

proc ifSatisfied*(m: LockManager, path: string, ifHeader: string,
    lockTokens: seq[string] = @[]): bool =
  ## True when `path` may be modified: no covering locks, or a presented
  ## token satisfies them (via `If` groups or `Lock-Token` values).
  let covering = m.findCovering(path)
  if covering.len == 0:
    return true
  var held: seq[string]
  for lock in covering:
    held.add(lock.token)
  if ifHeader.strip().len > 0:
    for group in parseIf(ifHeader):
      if group.resource.len > 0 and group.resource != path:
        continue
      var ok = true
      for t in group.tokens:
        if t.negated:
          if t.token in held:
            ok = false
            break
        elif t.token notin held:
          ok = false
          break
      if ok:
        return true
    return false
  for tok in lockTokens:
    if tok in held:
      return true
  false

func xmlEscape*(s: string): string =
  result = newStringOfCap(s.len + 8)
  for c in s:
    case c
    of '&': result.add("&amp;")
    of '<': result.add("&lt;")
    of '>': result.add("&gt;")
    of '"': result.add("&quot;")
    else: result.add(c)

proc activeLockXml*(lock: DavLock, href: string): string =
  ## `<D:activelock>` fragment for lockdiscovery and LOCK responses.
  let scopeTag =
    if lock.scope == lsExclusive: "exclusive" else: "shared"
  let depthVal =
    if lock.depth == 2: "infinity" else: "0"
  let timeoutVal =
    if lock.timeout < 0: "Infinite"
    else: "Second-" & $lock.timeout
  var ownerXml = ""
  if lock.owner.len > 0:
    ownerXml = "<D:owner xmlns:D=\"DAV:\">" & xmlEscape(lock.owner) &
      "</D:owner>"
  "<D:activelock xmlns:D=\"DAV:\"><D:locktype><D:write/>" &
    "</D:locktype><D:lockscope><D:" & scopeTag & "/></D:lockscope>" &
    "<D:depth>" & depthVal & "</D:depth>" & ownerXml &
    "<D:timeout>" & timeoutVal & "</D:timeout>" &
    "<D:locktoken><D:href>" & xmlEscape(lock.token) & "</D:href>" &
    "</D:locktoken><D:lockroot><D:href>" & xmlEscape(href) &
    "</D:href></D:lockroot></D:activelock>"

proc lockDiscoveryXml*(m: LockManager, path: string): string =
  ## Inner XML for the `lockdiscovery` live property of `path`.
  for lock in m.findCovering(path):
    result.add(activeLockXml(lock, lock.path))
