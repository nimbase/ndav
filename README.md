<p align="center">
  nDAV - A WebDAV Class 1 + 2 and CalDAV/CardDAV core for Nim<br>
  Made with the PowPow event library
</p>

<p align="center">
  <code>nimble install ndav</code>
</p>

<p align="center">
  <a href="https://nimbase.github.io/ndav/">API reference</a><br>
  <img src="https://github.com/nimbase/ndav/workflows/test/badge.svg" alt="Github Actions">  <img src="https://github.com/nimbase/ndav/workflows/docs/badge.svg" alt="Github Actions">
</p>

## Features

**General**

- Built on [PowPow](https://github.com/openpeeps/powpow) async event loop HTTP/1 + HTTP/2 server.
- Quick downloads through zero-copy file serving
- [Flysystem](https://github.com/openpeeps/flysystem) sandboxed storage to its
  own folder, crash-safe writes,<br>and ready for new backends such as cloud disks
- Calendars and contacts parsed with [openparser's](https://github.com/openpeeps/openparser) **iCalendar** and **vCard** formats
- Runs on Linux, macOS and Windows (should)
- Use it as a library (build on top of nDAV) or as a CLI binary
- Optional HTTP Basic auth with Argon2id password hashes using [nimcypher](https://github.com/nimbase/nimcypher)

**File sharing**

- Upload, download, copy, move and delete files and folders
- Folder listings with file details like size, type and modification time
- Custom metadata that sticks to files, even across copy and move
- Malformed requests are rejected safely

**File locking**

- Lock files so concurrent edits do not overwrite each other
- Shared and exclusive locks, with timeouts and tokens
- Locked files refuse changes until they are unlocked

**Calendars**

- Host calendars with events
- Search events by type and time range, fetch many at once
- Recurring events: daily, weekly, monthly and yearly
- Only valid calendar data gets stored

**Contacts**

- Host address books with contacts
- Search with field filters and text matching
- Sync support, so clients fetch only what changed
- One contact per file, duplicates rejected
- Standard vCard download format

**Plumbing**

- Any storage backend works, disk included, in-memory for tests
- No background threads, friendly to a single event loop

**Client library**

- One helper per operation, for files, calendars and contacts
- Helpers to build requests and read responses

## Examples

### Run the example server

`webdav.config.toml` (all keys optional, as written by `init`):

```toml
root = "./davroot"
port = 9001
address = "127.0.0.1"
```

### Talk to it with curl

```sh
# Class 1: upload and inspect
curl -X PUT http://localhost:9001/hello.txt -d 'hi' -i
curl -X PROPFIND http://localhost:9001/ -H 'Depth: 1' -i

# Locking: lock, fail without a token, succeed with one
TOK=$(curl -s -i -X LOCK http://localhost:9001/hello.txt \
  -H 'Depth: 0' -H 'Content-Type: application/xml' \
  -d '<D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockinfo>' \
  | grep -o 'Lock-Token: <[^>]*>')
curl -X PUT http://localhost:9001/hello.txt -d 'no' -i            # 423
curl -X PUT http://localhost:9001/hello.txt -d 'yes' -H "If: (<${TOK#Lock-Token: <})" -i

# CalDAV: calendar, event, time-range query
curl -X MKCALENDAR http://localhost:9001/cal -i
curl -X PUT http://localhost:9001/cal/ev.ics -H 'Content-Type: text/calendar' \
  -d 'BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Example//EN
BEGIN:VEVENT
UID:ev1
DTSTAMP:20260101T000000Z
DTSTART:20260105T100000Z
DTEND:20260105T110000Z
SUMMARY:Hi
END:VEVENT
END:VCALENDAR' -i
curl -X REPORT http://localhost:9001/cal -H 'Depth: 1' \
  -H 'Content-Type: application/xml' \
  -d '<C:calendar-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav"><D:prop><D:getetag/><C:calendar-data/></D:prop><C:filter><C:comp-filter name="VCALENDAR"><C:comp-filter name="VEVENT"><C:time-range start="20260105T000000Z" end="20260106T000000Z"/></C:comp-filter></C:comp-filter></C:filter></C:calendar-query>' -i

# CardDAV: addressbook, contact, FN query
curl -X MKCOL http://localhost:9001/ab -H 'Content-Type: application/xml' \
  -d '<D:mkcol xmlns:D="DAV:" xmlns:CR="urn:ietf:params:xml:ns:carddav"><D:set><D:prop><D:resourcetype><D:collection/><CR:addressbook/></D:resourcetype><D:displayname>Contacts</D:displayname></D:prop></D:set></D:mkcol>' -i
curl -X PUT http://localhost:9001/ab/ada.vcf -H 'Content-Type: text/vcard' \
  -d 'BEGIN:VCARD
VERSION:4.0
FN:Ada Lovelace
N:Lovelace;Ada;;;
END:VCARD' -i
curl -X REPORT http://localhost:9001/ab -H 'Depth: 1' \
  -H 'Content-Type: application/xml' \
  -d '<CR:addressbook-query xmlns:D="DAV:" xmlns:CR="urn:ietf:params:xml:ns:carddav"><D:prop><D:getetag/><CR:address-data/></D:prop><CR:filter><CR:prop-filter name="FN"><CR:text-match collation="i;unicode-casemap" match-type="contains">ada</CR:text-match></CR:prop-filter></CR:filter></CR:addressbook-query>' -i
```

### Embed it in your app

```nim
import ndav

let srv = newDavServer(newLocalDriver("./davroot"))
newHttpServer().start(srv.davHandler(), Port(9001))
```

Use `newMemoryDriver()` instead of `newLocalDriver()` for tests (see
`tests/t_server_mem.nim` for the loopback pattern).

### Use the client

```nim
import ndav

let dav = newDavClient("http://localhost:9001")
dav.mkcalendar("/cal").ensure(Http201)
dav.put("/cal/ev.ics", readFile("ev.ics")).ensure(Http201)
let found = dav.report("/cal",
  buildCalendarQuery("VEVENT", "20260105T000000Z", "20260106T000000Z"),
  ).multistatus()
for r in found:
  echo r.href
dav.closeClient()
```

### Auth

No `[users]` table means an open server. Add users to require HTTP Basic
on every request (passwords are stored as Argon2id hashes via nimcypher):

```sh
webdav passwd alice --config=./webdav.config.toml
# Password: … / Confirm: …
```

```toml
root = "./davroot"
port = 9001
address = "127.0.0.1"

[users]
alice = "CE5B8909…:F22D0AD0…"
```

```sh
curl -u alice:s3cret -X PROPFIND http://localhost:9001/ -H 'Depth: 0' \
  -d '<D:propfind xmlns:D="DAV:"><D:prop><D:current-user-principal/></D:prop></D:propfind>' -i
# → 207 with <D:href>/principals/alice</D:href>
```

Authenticated clients see `current-user-principal` and
`principal-collection-set` live props, and a read-only `/principals/`
collection with one resource per user (`principal-URL`,
`calendar-home-set` and `addressbook-home-set` point at `/`). In code:

```nim
let dav = newDavClient("http://localhost:9001")
dav.setAuth("alice", "s3cret")
dav.put("/hello.txt", "hi").ensure(Http201)
dav.clearAuth()
```

## Modules

| Module | Job |
|---|---|
| `webdav/davmethod` | Compile-time verb registration (`PROPFIND` … `REPORT`, `MKCALENDAR`) |
| `webdav/types` | Shared DAV types |
| `webdav/davxml` | Hardened DAV XML parsing + `multistatus` builder |
| `webdav/auth` | HTTP Basic parsing, Argon2id verification (nimcypher) |
| `webdav/backend` | flysystem pairing, dead props, calendar/addressbook markers, users |
| `webdav/props` | Live property computation |
| `webdav/locks` | Lock manager, `Timeout`/`If` parsing |
| `webdav/caldav` | REPORT parsing, time-range + recurrence matching, calendar sync |
| `webdav/carddav` | REPORT parsing, prop/param-filter + text-match matching, addressbook sync |
| `webdav/server` | Request router (`DavServer`, `davHandler`) |
| `webdav/client` | Sync client (`DavClient`, builders, response helpers) |
| `webdav/config` | Server config (`DavConfig`, TOML overlay, flag precedence) |

## Tests

Run `clue test` or `nimble test`.

440+ checks total across unit suites and loopback servers (in-memory backend
plus live curl runs against the disk-backed example).

## Known limits

- `Depth: infinity` on `PROPFIND` is capped to depth 1
- `PROPPATCH` applies best-effort in order (no atomic all-or-nothing)
- `If` evaluation is a subset (`Not` supported, etag conditions ignored)
- Auth is HTTP Basic only (no Digest/OAuth); any authenticated user has full
  access (no per-resource ACLs yet); password hashes are Argon2id at the
  interactive profile (1 MiB, 3 passes)
- `GET` on a collection answers `403` (no HTML listing view)
- Recurrence and timezone handling follow the documented subset in
  `src/ndav/caldav.nim` (clamped month overflow, UTC-normalized times)
- CardDAV handling follows the documented subset in
  `src/ndav/carddav.nim` (UID presence not required but unique when present,
  unknown `address-data` versions fall back to stored bytes,
  `sync-collection` keeps capped in-memory delete tombstones so known stale
  tokens surface deletions as `404` entries while unknown tokens fall back
  to a full resync, no `principal-property-search`/ACLs yet)
- `sync-collection` tokens pair the collection ctag with a revision
  (`ctag#rev`); legacy ctag-only tokens still answer with a full resync
- Tombstone history is in-memory like the existing calendar/addressbook
  markers, so it resets on restart

## Roadmap

- [x] WebDAV client to match the server
- [x] CardDAV (requires `openparser >= 0.3.3` for vCard support)
- [x] CalDAV `sync-collection` REPORT parity with CardDAV
- [x] Sync delete tombstones (404 entries instead of full resync)
- [ ] Discovery + principals (`/.well-known`, `current-user-principal`, `*-home-set`, `principal-property-search`)
- [ ] CalDAV scheduling and `free-busy-query` REPORTs
- [x] Auth + principal collections (`calendar-home-set`, `current-user-principal`)
- [ ] Full `Depth: infinity` and atomic `PROPPATCH`
- [ ] Collection listing view for `GET`
- [ ] Interop pass against real clients (Thunderbird, DAVx⁵, macOS)

### ❤ Contributions & Support
- 🐛 Found a bug? [Create a new Issue](https://github.com/nimbase/ndav/issues)
- 👋 Wanna help? [Fork it!](https://github.com/nimbase/ndav/fork)

### 🎩 License
MIT license | Nim Community.
