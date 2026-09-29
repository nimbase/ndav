# `webdav` server configuration: built-in defaults, TOML file overlay,
# and CLI flag overrides.
#
# Precedence (highest first): explicit CLI flags > TOML file > built-ins.
# The file layer maps onto `DavConfig` via openparser's typed `fromToml`;
# keys absent from the file keep their current (default) values, unknown
# keys are ignored, and type mismatches raise `ValueError` naming the file.

import std/[os, tables, strutils]
import pkg/openparser/toml
import ./auth

type
  DavConfig* = object
    root*: string
    port*: int
    address*: string
    users*: Table[string, string] ## name -> Argon2id `salt:hash`.
      ## Empty means auth is disabled (open server).

  FileOverlay = object
    ## The scalar keys `fromToml` maps; `users` is parsed manually below
    ## because the typed mapper does not support `Table` fields.
    root: string
    port: int
    address: string

  DavFlags* = object
    ## Raw CLI values; empty string / zero port means "not passed".
    root*: string
    port*: int
    address*: string
    config*: string

const defaultConfigName* = "webdav.config.toml"
  ## File `webdav init` writes and `webdav serve` auto-loads from the cwd.

proc defaultDavConfig*(): DavConfig =
  DavConfig(root: getCurrentDir() / "davroot", port: 9001,
    address: "127.0.0.1")

proc defaultConfigToml*(): string =
  ## Defaults rendered as TOML: what `webdav init` writes to disk.
  # `root` stays relative so the file works wherever the project lives.
  """# webdav server config - created by `webdav init`.
# CLI flags override these values; see `webdav serve --help`.
root = "./davroot"
port = 9001
address = "127.0.0.1"
"""

proc initConfigFile*(path = defaultConfigName, force = false) =
  ## Write defaults to `path`; refuse to overwrite unless `force`.
  if fileExists(path) and not force:
    raise newException(IOError, "Config file `" & path &
      "` already exists (use --force to overwrite)")
  writeFile(path, defaultConfigToml())

proc autoConfigPath*(): string =
  ## `webdav.config.toml` in the cwd when present, else "".
  result = getCurrentDir() / defaultConfigName
  if not fileExists(result):
    result = ""

proc loadUsers(doc: TomlDocument, path: string): Table[string, string] =
  ## Manual `[users]` mapping (name -> hash). Absent section yields an empty
  ## table; non-string values raise `ValueError` naming the file.
  result = initTable[string, string]()
  if not doc.tableVal.hasKey("users"):
    return
  let u = doc.tableVal["users"]
  if u == nil or u.kind != tvkTable:
    raise newException(ValueError,
      "Invalid config file `" & path & "`: Expected a TOML table at `users`")
  for name, node in u.tableVal:
    if node == nil or node.kind != tvkString:
      raise newException(ValueError, "Invalid config file `" & path &
        "`: Expected a TOML string at `users." & name & "`")
    result[name] = node.strVal

proc loadConfig*(path: string): DavConfig =
  ## Built-in defaults overlaid with the TOML file at `path`.
  result = defaultDavConfig()
  var content: string
  try:
    content = readFile(path)
  except IOError as e:
    raise newException(IOError, "Cannot read config file `" & path & "`: " & e.msg)
  var doc: TomlDocument
  try:
    doc = parseTOML(content)
  except OpenParserTomlError as e:
    raise newException(ValueError,
      "Invalid config file `" & path & "`: " & e.msg)
  var overlay = FileOverlay(root: result.root, port: result.port,
    address: result.address)
  try:
    fromToml(doc, overlay)
  except OpenParserTomlError as e:
    raise newException(ValueError,
      "Invalid config file `" & path & "`: " & e.msg)
  result.root = overlay.root
  result.port = overlay.port
  result.address = overlay.address
  result.users = loadUsers(doc, path)

proc resolveConfig*(flags: DavFlags): DavConfig =
  ## Merge built-ins, optional TOML file, and explicit flags.
  result = if flags.config.len > 0: loadConfig(flags.config)
           else: defaultDavConfig()
  if flags.root.len > 0:
    result.root = flags.root
  if flags.port > 0:
    result.port = flags.port
  if flags.address.len > 0:
    result.address = flags.address
  if result.port < 1 or result.port > 65535:
    raise newException(ValueError, "Port out of range: " & $result.port)

proc setUserHash*(path, name, pwhash: string) =
  ## Insert or replace `name = "hash"` in the `[users]` section of the TOML
  ## file at `path`, creating the file/section when missing. Raises `ValueError`
  ## on a bad username and `IOError` on write failure. The result is
  ## re-parsed so a corrupt edit never lands silently.
  if not validUserName(name):
    raise newException(ValueError, "Invalid username `" & name &
      "`: use letters, digits and `. _ - @ +` (1..64 chars)")
  var lines: seq[string]
  if fileExists(path):
    try:
      lines = readFile(path).splitLines()
    except IOError as e:
      raise newException(IOError, "Cannot read config file `" & path & "`: " & e.msg)
  let entry = name & " = \"" & pwhash & "\""
  var inUsers = false
  var replaced = false
  var outLines: seq[string]
  for line in lines:
    let s = line.strip()
    if s.startsWith("["):
      if inUsers and not replaced:
        outLines.add(entry)
        replaced = true
      inUsers = s == "[users]"
      outLines.add(line)
      continue
    if inUsers and not replaced and s.len > 0 and not s.startsWith("#"):
      let eq = s.find('=')
      if eq > 0:
        var key = s[0 ..< eq].strip()
        if key.len >= 2 and key[0] == '"' and key[^1] == '"':
          key = key[1 .. ^2]
        if key == name:
          outLines.add(entry)
          replaced = true
          continue
    outLines.add(line)
  if not replaced:
    if inUsers:
      outLines.add(entry)
    else:
      if outLines.len > 0 and outLines[^1].strip().len > 0:
        outLines.add("")
      outLines.add("[users]")
      outLines.add(entry)
  var text = outLines.join("\n")
  if not text.endsWith("\n"):
    text.add("\n")
  try:
    writeFile(path, text)
  except IOError as e:
    raise newException(IOError, "Cannot write config file `" & path & "`: " & e.msg)
  # Validate the edited file parses and carries the entry.
  let check = loadConfig(path)
  if check.users.getOrDefault(name) != pwhash:
    raise newException(IOError, "Config edit did not stick for `" & name & "`")
