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
- Calendars and contacts parsed with OpenParser's **iCalendar** and **vCard** formats
- Runs on Linux, macOS and Windows (should)
- Use it as a library (build on top of nDAV) or as a CLI binary

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

## Modules

| Module | Job |
|---|---|
| `webdav/davmethod` | Compile-time verb registration (`PROPFIND` … `REPORT`, `MKCALENDAR`) |
| `webdav/types` | Shared DAV types |
| `webdav/davxml` | Hardened DAV XML parsing + `multistatus` builder |
| `webdav/backend` | flysystem pairing, dead props, calendar/addressbook markers |
| `webdav/props` | Live property computation |
| `webdav/locks` | Lock manager, `Timeout`/`If` parsing |
| `webdav/caldav` | REPORT parsing, time-range + recurrence matching |
| `webdav/carddav` | REPORT parsing, prop/param-filter + text-match matching |
| `webdav/server` | Request router (`DavServer`, `davHandler`) |
| `webdav/client` | Sync client (`DavClient`, builders, response helpers) |
| `webdav/config` | Server config (`DavConfig`, TOML overlay, flag precedence) |

## Tests

```sh
clue build tests/t_davmethod.nim  --out:/tmp/t_davmethod  && /tmp/t_davmethod
clue build tests/t_davxml.nim     --out:/tmp/t_davxml     && /tmp/t_davxml
clue build tests/t_locks.nim      --out:/tmp/t_locks      && /tmp/t_locks
clue build tests/t_server_mem.nim --out:/tmp/t_server_mem && /tmp/t_server_mem
clue build tests/t_caldav.nim     --out:/tmp/t_caldav     && /tmp/t_caldav
clue build tests/t_carddav.nim    --out:/tmp/t_carddav    && /tmp/t_carddav
clue build tests/t_client.nim     --out:/tmp/t_client     && /tmp/t_client
clue build tests/t_cli.nim        --out:/tmp/t_cli        && /tmp/t_cli
```

440+ checks total across unit suites and loopback servers (in-memory backend
plus live curl runs against the disk-backed example).

## Known limits

- `Depth: infinity` on `PROPFIND` is capped to depth 1
- `PROPPATCH` applies best-effort in order (no atomic all-or-nothing)
- `If` evaluation is a subset (`Not` supported, etag conditions ignored)
- No auth or principal model yet (any valid lock token satisfies a lock)
- `GET` on a collection answers `403` (no HTML listing view)
- Recurrence and timezone handling follow the documented subset in
  `src/webdav/caldav.nim` (clamped month overflow, UTC-normalized times)
- CardDAV handling follows the documented subset in
  `src/webdav/carddav.nim` (UID presence not required but unique when present,
  unknown `address-data` versions fall back to stored bytes,
  `sync-collection` keeps no delete tombstones so deletions surface as a full
  resync, no `principal-property-search`/ACLs yet)

## Roadmap

- [x] WebDAV client to match the server
- [x] CardDAV (requires `openparser >= 0.3.3` for vCard support)
- [ ] CalDAV `sync-collection` REPORT parity with CardDAV
- [ ] Sync delete tombstones (404 entries instead of full resync)
- [ ] Discovery + principals (`/.well-known`, `current-user-principal`, `*-home-set`, `principal-property-search`)
- [ ] CalDAV scheduling and `free-busy-query` REPORTs
- [ ] Auth + principal collections (`calendar-home-set`, `current-user-principal`)
- [ ] Full `Depth: infinity` and atomic `PROPPATCH`
- [ ] Collection listing view for `GET`
- [ ] Interop pass against real clients (Thunderbird, DAVx⁵, macOS)

### ❤ Contributions & Support
- 🐛 Found a bug? [Create a new Issue](https://github.com/nimbase/webdav/issues)
- 👋 Wanna help? [Fork it!](https://github.com/nimbase/webdav/fork)

### 🎩 License
MIT license | Nim Community.
