# WebDAV storage backend on top of `pkg/flysystem`.
#
# `DavBackend` pairs any flysystem `StorageDriver` (e.g. `LocalDriver` for
# disk, `MemoryDriver` below for tests) with the WebDAV-side state that
# drivers don't own: dead (custom) properties per resource.
#
# Path convention: server-side URL paths (`/a/b`, decoded, normalized);
# driver-side relative paths (`a/b`). The root collection is `/` (driver
# path "") and always exists.

import std/[tables, times, strutils, options, sequtils, os]
import pkg/flysystem
import pkg/mimedb
import ./locks

export flysystem
export locks

type
  DeadProp* = object
    ns*: string    ## Namespace URI of the dead property.
    value*: string ## Text content (when the stored prop was pure text).
    xml*: string   ## Verbatim inner XML (when structural), round-tripped.

  SyncChange* = object
    rev*: int    ## Per-collection revision that introduced the delete.
    href*: string ## Deleted member href (URL path).

  DavBackend* = ref object
    driver*: StorageDriver
    locks*: LockManager
    deadProps*: Table[string, Table[string, DeadProp]] ## urlPath -> key -> prop
    calendars*: Table[string, bool] ## urlPath of a collection -> is calendar
    addressbooks*: Table[string, bool] ## urlPath of a collection -> is addressbook
    syncRevs*: Table[string, int] ## sync collection -> current revision.
    syncDeletes*: Table[string, seq[SyncChange]] ## sync collection -> tombstones.
    users*: Table[string, string] ## name -> Argon2id `salt:hash`.
      ## Empty means auth is disabled (open server).

  MemNode = ref object
    isDir: bool
    data: string
    mtime: Time
    vis: Visibility

  MemoryDriver* = ref object of StorageDriver
    ## In-memory `StorageDriver` for tests. Unimplemented surface
    ## (`readStream`, `checksum`, `search`, ...) raises `StorageError`
    ## via the abstract base — the DAV server only uses the implemented
    ## subset. `GET` serves via `read()`, so very large files cost RAM;
    ## disk-backed deployments should use `LocalDriver`.
    nodes: Table[string, MemNode]

func memKey(path: string): string =
  path.strip(chars = {'/'})

proc ensureParents(d: MemoryDriver, key: string, now: Time) =
  var parts = key.split('/')
  for i in 0 ..< parts.len - 1:
    let p = parts[0 .. i].join("/")
    if p notin d.nodes:
      d.nodes[p] = MemNode(isDir: true, mtime: now, vis: visPrivate)

proc newMemoryDriver*(): MemoryDriver =
  MemoryDriver(nodes: {"": MemNode(isDir: true, mtime: getTime(),
    vis: visPrivate)}.toTable)

method write*(d: MemoryDriver, path, content: string,
    visibility = visPrivate) =
  let key = memKey(path)
  if key.len == 0:
    raise newException(StorageError, "cannot write root collection")
  let now = getTime()
  d.ensureParents(key, now)
  d.nodes[key] = MemNode(isDir: false, data: content, mtime: now,
    vis: visibility)

method read*(d: MemoryDriver, path: string): string =
  let key = memKey(path)
  if key notin d.nodes or d.nodes[key].isDir:
    raise newException(StorageError, "not a file: " & path)
  d.nodes[key].data

method delete*(d: MemoryDriver, path: string) =
  let key = memKey(path)
  if key.len == 0:
    raise newException(StorageError, "cannot delete root collection")
  if key notin d.nodes:
    raise newException(StorageError, "not found: " & path)
  if d.nodes[key].isDir:
    for k in toSeq(d.nodes.keys):
      if k != key and k.startsWith(key & "/"):
        raise newException(StorageError, "directory not empty: " & path)
  d.nodes.del(key)

method exists*(d: MemoryDriver, path: string): bool =
  memKey(path) in d.nodes

proc memMeta(d: MemoryDriver, key: string): FileMetadata =
  let n = d.nodes[key]
  FileMetadata(path: key, size: (if n.isDir: 0 else: n.data.len).int64,
    lastModified: n.mtime, visibility: n.vis, isDir: n.isDir)

method metadata*(d: MemoryDriver, path: string): FileMetadata =
  let key = memKey(path)
  if key notin d.nodes:
    raise newException(StorageError, "not found: " & path)
  d.memMeta(key)

method list*(d: MemoryDriver, path: string,
    recursive = false): seq[FileMetadata] =
  let key = memKey(path)
  if key notin d.nodes or not d.nodes[key].isDir:
    raise newException(StorageError, "not a collection: " & path)
  let prefix = if key.len == 0: "" else: key & "/"
  for k in d.nodes.keys:
    if not k.startsWith(prefix) or k == key:
      continue
    let rest = k[prefix.len .. ^1]
    if not recursive and "/" in rest:
      continue
    result.add(d.memMeta(k))

method makeDir*(d: MemoryDriver, path: string) =
  let key = memKey(path)
  if key.len == 0:
    return
  let now = getTime()
  d.ensureParents(key, now)
  if key in d.nodes:
    if not d.nodes[key].isDir:
      raise newException(StorageError, "not a directory: " & path)
  else:
    d.nodes[key] = MemNode(isDir: true, mtime: now, vis: visPrivate)

method deleteDir*(d: MemoryDriver, path: string, force = false) =
  let key = memKey(path)
  if key.len == 0:
    raise newException(StorageError, "cannot delete root collection")
  if key notin d.nodes or not d.nodes[key].isDir:
    raise newException(StorageError, "not a collection: " & path)
  if not force:
    for k in d.nodes.keys:
      if k.startsWith(key & "/"):
        raise newException(StorageError, "directory not empty: " & path)
    d.nodes.del(key)
  else:
    let prefix = if key.len == 0: "" else: key & "/"
    var doomed: seq[string]
    for k in d.nodes.keys:
      if k == key or (key.len > 0 and k.startsWith(prefix)) or
          (key.len == 0 and k != ""):
        doomed.add(k)
    for k in doomed:
      d.nodes.del(k)

proc copyNode(d: MemoryDriver, srcKey, destKey: string, now: Time) =
  let s = d.nodes[srcKey]
  d.nodes[destKey] = MemNode(isDir: s.isDir, data: s.data, mtime: now,
    vis: s.vis)

method copy*(d: MemoryDriver, src, dest: string) =
  let sk = memKey(src)
  let dk = memKey(dest)
  if sk notin d.nodes or d.nodes[sk].isDir:
    raise newException(StorageError, "not a file: " & src)
  if dk.len == 0:
    raise newException(StorageError, "cannot copy over root")
  let now = getTime()
  d.ensureParents(dk, now)
  d.copyNode(sk, dk, now)

method copyDir*(d: MemoryDriver, src, dest: string) =
  let sk = memKey(src)
  let dk = memKey(dest)
  if sk notin d.nodes or not d.nodes[sk].isDir:
    raise newException(StorageError, "not a collection: " & src)
  let now = getTime()
  d.ensureParents(dk, now)
  if dk notin d.nodes:
    d.nodes[dk] = MemNode(isDir: true, mtime: now, vis: visPrivate)
  let prefix = if sk.len == 0: "" else: sk & "/"
  for k in toSeq(d.nodes.keys):
    if sk.len == 0:
      if k == "":
        continue
      d.copyNode(k, (if dk.len == 0: k else: dk & "/" & k), now)
    elif k.startsWith(prefix):
      d.copyNode(k, dk & "/" & k[prefix.len .. ^1], now)

method move*(d: MemoryDriver, src, dest: string) =
  d.copy(src, dest)
  d.nodes.del(memKey(src))

method moveDir*(d: MemoryDriver, src, dest: string) =
  d.copyDir(src, dest)
  d.deleteDir(src, force = true)

method touch*(d: MemoryDriver, path: string) =
  let key = memKey(path)
  if key in d.nodes:
    d.nodes[key].mtime = getTime()
  else:
    d.write(path, "")

method setVisibility*(d: MemoryDriver, path: string,
    visibility: Visibility) =
  let key = memKey(path)
  if key notin d.nodes:
    raise newException(StorageError, "not found: " & path)
  d.nodes[key].vis = visibility

method visibility*(d: MemoryDriver, path: string): Visibility =
  let key = memKey(path)
  if key notin d.nodes:
    raise newException(StorageError, "not found: " & path)
  d.nodes[key].vis

method mimeType*(d: MemoryDriver, path: string): string =
  let ext = splitFile(path).ext
  if ext.len == 0:
    return "application/octet-stream"
  getMimeType(ext[1 .. ^1]).get("application/octet-stream")

method append*(d: MemoryDriver, path, content: string) =
  let key = memKey(path)
  if key in d.nodes and not d.nodes[key].isDir:
    d.nodes[key].data.add(content)
    d.nodes[key].mtime = getTime()
  else:
    d.write(path, content)

# ── DavBackend helpers ───────────────────────────────────────────────────────

proc newDavBackend*(driver: StorageDriver,
    users = initTable[string, string]()): DavBackend =
  DavBackend(driver: driver, locks: newLockManager(),
    deadProps: initTable[string, Table[string, DeadProp]](),
    calendars: initTable[string, bool](),
    addressbooks: initTable[string, bool](),
    syncRevs: initTable[string, int](),
    syncDeletes: initTable[string, seq[SyncChange]](),
    users: users)

proc isCalendarCollection*(b: DavBackend, urlPath: string): bool {.inline.} =
  ## True when `urlPath` was created via MKCALENDAR (CalDAV calendar).
  b.calendars.getOrDefault(urlPath, false)

proc markCalendar*(b: DavBackend, urlPath: string) =
  b.calendars[urlPath] = true
  if urlPath notin b.syncRevs:
    b.syncRevs[urlPath] = 0
    b.syncDeletes[urlPath] = @[]

proc isAddressbookCollection*(b: DavBackend, urlPath: string): bool {.inline.} =
  ## True when `urlPath` was created via extended MKCOL (CardDAV addressbook).
  b.addressbooks.getOrDefault(urlPath, false)

const PrincipalsRoot* = "/principals"
  ## Virtual collection listing one principal resource per configured user.
  ## Served from the users table; never touches the storage driver.

proc principalUserName*(urlPath: string): string =
  ## User part of a `/principals/<name>` path, else "". Nested paths and
  ## the collection itself yield "".
  if not urlPath.startsWith(PrincipalsRoot & "/"):
    return ""
  let rest = urlPath[PrincipalsRoot.len + 1 .. ^1]
  if rest.len == 0 or "/" in rest:
    return ""
  rest

proc isPrincipalsCollection*(urlPath: string): bool {.inline.} =
  urlPath == PrincipalsRoot

proc isPrincipalResource*(b: DavBackend, urlPath: string): bool =
  ## True when `urlPath` names a configured user under `/principals/`.
  let name = principalUserName(urlPath)
  name.len > 0 and name in b.users

proc isPrincipalPath*(b: DavBackend, urlPath: string): bool {.inline.} =
  ## True for the virtual principals collection or any principal resource.
  isPrincipalsCollection(urlPath) or b.isPrincipalResource(urlPath)

proc isPrincipalsSubtree*(urlPath: string): bool {.inline.} =
  ## True for anything under `/principals/` (collection, resource, or
  ## unknown): the whole subtree is virtual and read-only.
  urlPath == PrincipalsRoot or urlPath.startsWith(PrincipalsRoot & "/")

proc principalHref*(name: string): string {.inline.} =
  ## URL path of a principal resource.
  PrincipalsRoot & "/" & name

proc markAddressbook*(b: DavBackend, urlPath: string) =
  b.addressbooks[urlPath] = true
  if urlPath notin b.syncRevs:
    b.syncRevs[urlPath] = 0
    b.syncDeletes[urlPath] = @[]

func toDriverPath*(urlPath: string): string {.inline.} =
  ## `/a/b` -> `a/b`; `/` -> `""`.
  urlPath.strip(chars = {'/'})

proc deadKey(ns, name: string): string {.inline.} =
  ns & "\x00" & name

proc getDead*(b: DavBackend, urlPath: string): Table[string, DeadProp] =
  b.deadProps.getOrDefault(urlPath)

proc setDead*(b: DavBackend, urlPath, ns, name, value, xml: string) =
  if urlPath notin b.deadProps:
    b.deadProps[urlPath] = initTable[string, DeadProp]()
  b.deadProps[urlPath][deadKey(ns, name)] = DeadProp(ns: ns, value: value,
    xml: xml)

proc delDead*(b: DavBackend, urlPath, ns, name: string): bool =
  if urlPath notin b.deadProps:
    return false
  if deadKey(ns, name) notin b.deadProps[urlPath]:
    return false
  b.deadProps[urlPath].del(deadKey(ns, name))
  true

proc forgetDead*(b: DavBackend, urlPath: string) =
  ## Drop dead props for a resource and, for collections, its members.
  ## Calendar / addressbook markers travel with the same lifetime.
  ## Sync revision logs travel too (deleted collections lose history).
  var doomed: seq[string]
  for k in b.deadProps.keys:
    if k == urlPath or k.startsWith(urlPath & "/"):
      doomed.add(k)
  for k in doomed:
    b.deadProps.del(k)
  var doomedCal: seq[string]
  for k in b.calendars.keys:
    if k == urlPath or k.startsWith(urlPath & "/"):
      doomedCal.add(k)
  for k in doomedCal:
    b.calendars.del(k)
  var doomedAb: seq[string]
  for k in b.addressbooks.keys:
    if k == urlPath or k.startsWith(urlPath & "/"):
      doomedAb.add(k)
  for k in doomedAb:
    b.addressbooks.del(k)
  var doomedSync: seq[string]
  for k in b.syncRevs.keys:
    if k == urlPath or k.startsWith(urlPath & "/"):
      doomedSync.add(k)
  for k in doomedSync:
    b.syncRevs.del(k)
    b.syncDeletes.del(k)

proc copyDead*(b: DavBackend, src, dest: string, overwrite: bool) =
  ## Duplicate dead props across COPY. For collections, remap members.
  ## The source entries stay in place. Calendar / addressbook markers
  ## are carried too.
  if overwrite:
    b.forgetDead(dest)
  var carried: seq[(string, Table[string, DeadProp])]
  for k, v in b.deadProps:
    if k == src or k.startsWith(src & "/"):
      carried.add((k, v))
  for (k, v) in carried:
    let nk =
      if k == src: dest
      else: dest & k[src.len .. ^1]
    b.deadProps[nk] = v
  var carriedCal: seq[string]
  for k in b.calendars.keys:
    if k == src or k.startsWith(src & "/"):
      carriedCal.add(k)
  for k in carriedCal:
    let nk =
      if k == src: dest
      else: dest & k[src.len .. ^1]
    b.calendars[nk] = true
  var carriedAb: seq[string]
  for k in b.addressbooks.keys:
    if k == src or k.startsWith(src & "/"):
      carriedAb.add(k)
  for k in carriedAb:
    let nk =
      if k == src: dest
      else: dest & k[src.len .. ^1]
    b.addressbooks[nk] = true
  # Sync delete history is never carried: hrefs are collection-scoped and
  # old revisions are meaningless at the destination. Fresh logs give new
  # tokens (unknown old tokens fall back to full resync).
  for k in carriedCal:
    let nk =
      if k == src: dest
      else: dest & k[src.len .. ^1]
    b.syncRevs[nk] = 0
    b.syncDeletes[nk] = @[]
  for k in carriedAb:
    let nk =
      if k == src: dest
      else: dest & k[src.len .. ^1]
    b.syncRevs[nk] = 0
    b.syncDeletes[nk] = @[]

proc moveDead*(b: DavBackend, src, dest: string, overwrite: bool) =
  ## Carry dead props across MOVE. For collections, remap members.
  b.copyDead(src, dest, overwrite)
  b.forgetDead(src)

const MaxSyncDeletes* = 100
  ## Cap on tombstones kept per sync collection. Older entries are dropped;
  ## tokens predating the retained window answer as unknown (full resync).

proc isSyncCollection*(b: DavBackend, urlPath: string): bool {.inline.} =
  ## True when `urlPath` is a calendar or addressbook collection.
  b.isCalendarCollection(urlPath) or b.isAddressbookCollection(urlPath)

proc syncRevOf*(b: DavBackend, coll: string): int {.inline.} =
  b.syncRevs.getOrDefault(coll, 0)

proc ensureSyncLog*(b: DavBackend, coll: string) =
  ## Start revision history for a fresh sync collection (idempotent).
  if coll notin b.syncRevs:
    b.syncRevs[coll] = 0
    b.syncDeletes[coll] = @[]

proc bumpSync*(b: DavBackend, coll: string): int =
  ## Record a member change (PUT overwrite, PROPPATCH, COPY-in). Returns
  ## the new revision. Initializes the log for freshly copied collections.
  b.ensureSyncLog(coll)
  inc b.syncRevs[coll]
  result = b.syncRevs[coll]
  # Prune oldest tombstones past the cap (keeps newest).
  var log = b.syncDeletes.getOrDefault(coll, @[])
  if log.len > MaxSyncDeletes:
    b.syncDeletes[coll] = log[^MaxSyncDeletes .. ^1]

proc recordSyncDelete*(b: DavBackend, coll, href: string): int =
  ## Record a member removal (DELETE, MOVE-out). Bumps the revision and
  ## appends a tombstone. Replaces any older tombstone for the same href
  ## so a delete/recreate/delete cycle keeps a single entry.
  b.ensureSyncLog(coll)
  inc b.syncRevs[coll]
  result = b.syncRevs[coll]
  var log = b.syncDeletes.getOrDefault(coll, @[])
  var kept: seq[SyncChange]
  for c in log:
    if c.href != href:
      kept.add(c)
  kept.add(SyncChange(rev: result, href: href))
  if kept.len > MaxSyncDeletes:
    kept = kept[^MaxSyncDeletes .. ^1]
  b.syncDeletes[coll] = kept

proc makeSyncToken*(b: DavBackend, coll, ctag: string): string =
  ## Opaque token pairing the ctag with the revision: `ctag#rev`.
  ## Legacy ctag-only tokens (pre-tombstone clients) parse as unknown rev
  ## and fall back to a full resync without tombstones.
  ctag & "#" & $b.syncRevOf(coll)

proc splitSyncToken*(tok: string): tuple[ctag: string, rev: int, ok: bool] =
  ## Split `ctag#rev`. `ok` is false for legacy or malformed tokens.
  let i = tok.rfind('#')
  if i < 0:
    return ("", -1, false)
  try:
    (tok[0 ..< i], parseInt(tok[i + 1 .. ^1]), true)
  except ValueError:
    ("", -1, false)

proc syncDeletesSince*(b: DavBackend, coll: string,
    sinceRev: int): tuple[hrefs: seq[string], known: bool] =
  ## Tombstones with `rev > sinceRev`. `known=false` when `sinceRev` is
  ## newer than current, negative, or older than the retained window
  ## (caller must answer a full resync without tombstones).
  let cur = b.syncRevOf(coll)
  if sinceRev < 0 or sinceRev > cur:
    return (@[], false)
  let log = b.syncDeletes.getOrDefault(coll, @[])
  if log.len == 0:
    return (@[], true)
  if sinceRev < log[0].rev - 1 and cur > MaxSyncDeletes:
    # Window overflow: oldest retained rev already newer than requested.
    # When within cap the first entry check below still applies; this
    # guards the case where pruning dropped history before log[0].
    if sinceRev < cur - MaxSyncDeletes:
      return (@[], false)
  # If history was pruned exactly at the boundary, a token older than the
  # oldest retained delete is unknown unless it predates all deletes.
  if sinceRev < log[0].rev - 1 and log.len >= MaxSyncDeletes:
    return (@[], false)
  var hrefs: seq[string]
  for c in log:
    if c.rev > sinceRev:
      hrefs.add(c.href)
  (hrefs, true)
