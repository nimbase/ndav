# HTTP Basic auth (RFC 7617) with Argon2id password hashes.
#
# Password hashing and verification come from `pkg/nimcypher/password`
# (Argon2id, 1 MiB / 3 passes interactive profile). Hashes are stored as
# `hex(salt):hex(hash)` strings; verification is constant-time.
# Any malformed credential raises `DavAuthError`, which the server maps to
# `401` (never `400`), so malformed input is indistinguishable from a wrong
# password on the wire.

import std/[base64, strutils, tables]
import pkg/nimcypher/password

export password

type
  DavAuthError* = object of CatchableError

  BasicCreds* = object
    user*: string
    pass*: string

const
  AuthRealm* = "nDAV"
    ## Realm sent in the `WWW-Authenticate` challenge.

  DummyHash* = "00000000000000000000000000000000:" &
    "0000000000000000000000000000000000000000000000000000000000000000"
    ## Valid-format Argon2id hash (zero salt, zero digest) used to verify
    ## unknown users: runs the full Argon2id pass so the timing matches a
    ## wrong-password rejection and usernames cannot be enumerated.

proc validUserName*(name: string): bool =
  ## True when `name` is safe as a TOML key, principal path segment and log
  ## token: 1..64 chars of letters, digits and `. _ - @ +`.
  if name.len == 0 or name.len > 64:
    return false
  for c in name:
    if c notin {'a'..'z', 'A'..'Z', '0'..'9', '.', '_', '-', '@', '+'}:
      return false
  true

proc parseBasic*(header: string): BasicCreds =
  ## Split a `Basic <base64>` authorization value into credentials.
  ## The scheme match is case-insensitive; the userinfo splits on the first
  ## `:` (passwords may contain colons, usernames may not). Raises
  ## `DavAuthError` on any failure, including an empty username.
  let h = header.strip()
  if h.len <= 6 or h[0 .. 5].cmpIgnoreCase("basic ") != 0:
    raise newException(DavAuthError, "not a Basic credential")
  var decoded: string
  try:
    decoded = decode(h[6 .. ^1].strip())
  except CatchableError:
    raise newException(DavAuthError, "bad Basic encoding")
  let i = decoded.find(':')
  if i <= 0:
    raise newException(DavAuthError, "bad Basic userinfo")
  result = BasicCreds(user: decoded[0 ..< i], pass: decoded[i + 1 .. ^1])
  if not validUserName(result.user):
    raise newException(DavAuthError, "bad Basic username")

proc verifyUser*(users: Table[string, string], user, pass: string): bool =
  ## True when `user` exists and `pass` verifies against its stored hash.
  ## Unknown users still run the full Argon2id pass against `DummyHash`.
  let known = user in users
  verifyPassword(pass, users.getOrDefault(user, DummyHash)) and known

proc encodeBasic*(user, pass: string): string =
  ## Build an `Authorization` header value from credentials.
  "Basic " & encode(user & ":" & pass)

proc challengeHeader*(realm = AuthRealm): string {.inline.} =
  ## Value for the `WWW-Authenticate` header on `401` responses.
  "Basic realm=\"" & realm & "\""
