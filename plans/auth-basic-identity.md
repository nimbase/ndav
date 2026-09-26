# Plan: Auth — HTTP Basic + identity (nimcypher crypto)

Decisions: **Basic only** (RFC 7617), **credentials in config TOML `[users]`**
with a `webdav passwd` CLI, **gate + identity** (no per-resource ACLs).
Crypto from nimcypher 0.2.4 (`requires "nimcypher >= 0.2.4"`; devel repo at
`~/development/nimbase/ports/nimcypher` for iteration via path override).

## 1. New module `src/webdav/auth.nim`

- Types: `DavUser {name, pwhash}`, `BasicCreds {user, pass}`.
- `parseBasic(header): BasicCreds` — split `Basic <b64>`, `std/base64.decode`,
  split on first `:`; any malformation raises `DavAuthError` (server maps to
  `401`, never `400`, so malformed creds are indistinguishable from wrong ones).
- `verifyUser(users, user, pass): bool` — `nimcypher/password.verifyPassword`
  (Argon2id, constant-time compare inside). Anti-enumeration: unknown users
  verify against a fixed dummy hash so timing matches a wrong-password rejection.
- `challengeHeader(realm = "nDAV"): string` — `Basic realm="nDAV"`.
- Argon2id cost note: nimcypher default is 1 MiB/3 passes (interactive profile)
  — fine per-request; tests precompute hashes once in setup.

## 2. Config + CLI (`src/webdav/config.nim`, `src/webdav.nim`)

- `DavConfig`/`DavFlags` gain `users: Table[string,string]` (name → `salt:hash`).
- TOML: `[users]` table overlay in `loadConfig` (unknown keys already ignored;
  type mismatch already `ValueError`). `defaultConfigToml` unchanged.
- **Open-mode rule**: empty `[users]` = auth disabled, current behavior intact
  (all existing tests keep passing with `newDavServer(driver)` defaults).
- New `webdav passwd <username> [--config path]` (kapsis):
  `readPasswordFromStdin` x2 with confirmation, `nimcypher/password.hashPassword`,
  write back into the TOML `[users]` table. Open point: verify TOML write-back
  API and kapsis positional-arg support at implementation time.

## 3. Server gate + identity (`src/webdav/server.nim`, `props.nim`, `backend.nim`)

- `DavServer` gains `users` table; `newDavServer(driver, users = initTable())`.
- Gate at top of `serve()`: if `users` non-empty and Basic invalid → `401` +
  `WWW-Authenticate`. No exemptions (no `/.well-known` exists yet; discovery
  stays a separate item).
- Thread the authenticated name per-request (explicit param through the `serve*`
  chain, not shared mutable state — powpow's single loop interleaves requests).
- Identity surface (all `DAV:`-namespaced, so the known `pfProp` DAV-only
  lookup limitation doesn't apply):
  - `current-user-principal` + `principal-collection-set` (`→ /principals/`)
    live props, starting on `/`.
  - Virtual `/principals/` collection + `/principals/{user}` resources served
    from the users table (no driver storage): `displayname`,
    `resourcetype=principal`, `calendar-home-set` + `addressbook-home-set`
    → `/` (root-as-home, keeps existing `/cal`, `/ab` layouts working).
    Read-only: PUT/DELETE/MKCOL/MKCALENDAR → `403`/`405`.
  - Locks: no owner-check changes (possession still suffices; per-user lock
    ownership = ACL scope, explicitly out).
  - `DAV` header unchanged (no `access-control` advertisement).
- Order: gate first, identity second (separate reviewable steps).

## 4. Client (`src/webdav/client.nim`)

- `DavClient` gains optional credentials + `setAuth(user, pass)`; `raw()`
  attaches `Authorization: Basic ...`. Builders untouched.

## 5. Tests — new `tests/t_auth.nim` (free ports `20990+`)

- Open mode: no `WWW-Authenticate`, everything works (regression guard).
- Gate: `401` + realm on GET/PUT/PROPFIND/REPORT/PROPPATCH/LOCK; wrong pass,
  unknown user, malformed header all `401`.
- Happy path via `setAuth`: full round trip incl. CalDAV PUT + REPORT.
- Identity: `current-user-principal` href on `/`, principal resource props +
  home-sets, principals tree read-only.
- Unit: `decodeBasic` edge cases (bad base64, missing colon, empty).

## 6. Docs + roadmap

- README: new Auth section (config snippet, `passwd` usage, curl example),
  Known limits (`Basic only — no Digest/OAuth; any authenticated user has full
  access, no ACLs; Argon2id interactive profile`), check off
  `Auth + principal collections`. Discovery (`/.well-known`,
  `principal-property-search`) stays open.

## Risks

- TOML edit round-trip for `passwd` may need a small serializer shim if the
  TOML lib is read-only.
- `serve()` signature threading touches ~12 procs; mechanical but wide.
- Per-request user param must never fall back to a shared field (concurrency
  correctness on the event loop).
