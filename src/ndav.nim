# WebDAV server and client on top of powpow.
#
# `davmethod` must be imported first so the WebDAV verbs are staged via
# pkg/voodoo before powpow compiles. Keep that order here and in user code
# (`import ndav` before any direct `import powpow`).

import ndav/davmethod
import powpow
import ndav/[types, davxml, auth, backend, props, caldav, carddav, server, client]

export davmethod
export powpow
export types
export davxml
export auth
export backend
export props
export caldav
export carddav
export server
export client

when isMainModule:
  # Server binary: `clue build` (see `bin`/`binDir` in ndav.nimble).
  # Library users (`import ndav`) never compile this block.
  # Implemented on stdlib only (`parseopt`, `terminal`) to avoid an
  # extra CLI dependency. Option values use the `--opt=value` form;
  # `--opt value` (space) works for string/int options as well.
  import std/[os, parseopt, strutils, terminal]
  import ndav/config

  const progName = "ndav"

  proc printHeading(s: string) =
    ## Section titles (`Commands:`, `Options:`) in white bold on a tty,
    ## plain otherwise so piped output stays clean.
    if isatty(stdout):
      stdout.setForegroundColor(fgWhite)
      stdout.setStyle({styleBright})
    echo s
    if isatty(stdout):
      stdout.resetAttributes()

  proc printUsage() =
    if isatty(stdout):
      stdout.setForegroundColor(fgBlack, bright = true)
    echo "WebDAV server and client. Supporting CalDAV, CardDAV and Delta-V\nextensions and basic authentication (LDAP, OAuth)."
    echo "  MIT License | Made by Humans from OpenPeeps"
    echo "  https://github.com/nimbase/ndav\n"
    if isatty(stdout):
      stdout.resetAttributes()
    echo "Usage: " & progName & " <command> [options]"
    echo ""
    printHeading("Commands:")
    echo "  serve    Start the WebDAV server"
    echo "  init     Write webdav.config.toml with default settings"
    echo "  passwd   Set a user's password (Argon2id hash in the config file)"
    echo "  help     Show this help or help for a command"
    echo ""
    echo "Run `" & progName & " <command> --help` for command help."

  proc printServeHelp() =
    echo "Usage: " & progName & " serve [--root=PATH] [--port=PORT] " &
      "[--address=ADDR] [--config=FILE]"
    echo ""
    echo "Start the WebDAV server. CLI flags override the TOML file, which"
    echo "overrides built-in defaults. With no flags and no"
    echo "./webdav.config.toml in the cwd, run `" & progName & " init` first."
    echo ""
    printHeading("Options:")
    echo "  --root=PATH      Filesystem root to serve (default: ./davroot)"
    echo "  --port=PORT      TCP port 1..65535 (default: 9001)"
    echo "  --address=ADDR   Bind address (default: 127.0.0.1)"
    echo "  --config=FILE    TOML config file (default: ./webdav.config.toml when present)"
    echo "  -h, --help       Show this help"

  proc printInitHelp() =
    echo "Usage: " & progName & " init [--path=FILE] [--force]"
    echo ""
    echo "Write webdav.config.toml with default settings."
    echo ""
    printHeading("Options:")
    echo "  --path=FILE      Destination file (default: webdav.config.toml)"
    echo "  --force          Overwrite the file when it exists"
    echo "  -h, --help       Show this help"

  proc printPasswdHelp() =
    echo "Usage: " & progName & " passwd [--config=FILE] <username>"
    echo ""
    echo "Set a user's password (Argon2id hash in the config file)."
    echo ""
    printHeading("Options:")
    echo "  --config=FILE    TOML config file (default: ./webdav.config.toml when present)"
    echo "  -h, --help       Show this help"

  proc parseBoolOpt(cmd, key, val: string): bool =
    ## Accepts `--flag`, `--flag=true` and `--flag=false`.
    case val.toLowerAscii()
    of "":
      true
    of "1", "true", "yes", "on":
      true
    of "0", "false", "no", "off":
      false
    else:
      quit(cmd & ": invalid value for --" & key & ": `" & val &
        "` (expected true/false)", 1)

  proc parsePortOpt(cmd, val: string): int =
    try:
      result = parseInt(val)
    except ValueError:
      quit(cmd & ": invalid value for --port: `" & val & "` (expected integer)", 1)

  proc doServe(flags: DavFlags) =
    var cfgPath = flags.config
    if flags.root == "" and flags.port == 0 and flags.address == "" and
        flags.config == "":
      cfgPath = autoConfigPath()
      if cfgPath == "":
        quit("serve: no options given and no ./webdav.config.toml found.\n" &
          "Run `" & progName & " init` or `" & progName & " serve --help`.", 1)
      let cfg = try:
        resolveConfig(DavFlags(config: cfgPath))
      except IOError as e:
        quit(e.msg, 1)
      except ValueError as e:
        quit(e.msg, 1)
      let srv = newDavServer(newLocalDriver(cfg.root), cfg.users)
      echo progName & " serving " & cfg.root & " on http://" & cfg.address &
        ":" & $cfg.port
      echo "  Press Ctrl+C to stop"
      newHttpServer().start(srv.davHandler(), cfg.address, Port(cfg.port))
      return
    let cfg = try:
      resolveConfig(DavFlags(root: flags.root, port: flags.port,
        address: flags.address, config: cfgPath))
    except IOError as e:
      quit(e.msg, 1)
    except ValueError as e:
      quit(e.msg, 1)
    let srv = newDavServer(newLocalDriver(cfg.root), cfg.users)
    echo progName & " serving " & cfg.root & " on http://" & cfg.address &
      ":" & $cfg.port
    echo "  Press Ctrl+C to stop"
    newHttpServer().start(srv.davHandler(), cfg.address, Port(cfg.port))

  proc cmdServe(args: seq[string]) =
    var root, address, config = ""
    var port = 0
    var pending = "" # long option waiting for a space-separated value
    var p = initOptParser(args)
    for kind, key, val in p.getopt():
      case kind
      of cmdEnd:
        break
      of cmdShortOption, cmdLongOption:
        if pending != "":
          quit("serve: option --" & pending & " requires a value", 1)
        case key
        of "h", "help":
          printServeHelp()
          return
        of "root", "address", "config":
          if val != "":
            case key
            of "root": root = val
            of "address": address = val
            else: config = val
          else:
            pending = key
        of "port":
          if val != "":
            port = parsePortOpt("serve", val)
          else:
            pending = key
        else:
          quit("serve: unknown option --" & key &
            " (see `" & progName & " serve --help`)", 1)
      of cmdArgument:
        if pending != "":
          case pending
          of "root": root = key
          of "address": address = key
          of "config": config = key
          of "port": port = parsePortOpt("serve", key)
          else: discard
          pending = ""
        else:
          quit("serve: unexpected argument `" & key &
            "` (see `" & progName & " serve --help`)", 1)
    if pending != "":
      quit("serve: option --" & pending & " requires a value", 1)
    doServe(DavFlags(root: root, port: port, address: address, config: config))

  proc cmdInit(args: seq[string]) =
    var path = defaultConfigName
    var force = false
    var pending = ""
    var p = initOptParser(args)
    for kind, key, val in p.getopt():
      case kind
      of cmdEnd:
        break
      of cmdShortOption, cmdLongOption:
        if pending != "":
          quit("init: option --" & pending & " requires a value", 1)
        case key
        of "h", "help":
          printInitHelp()
          return
        of "path":
          if val != "":
            path = val
          else:
            pending = key
        of "force":
          force = parseBoolOpt("init", key, val)
        else:
          quit("init: unknown option --" & key &
            " (see `" & progName & " init --help`)", 1)
      of cmdArgument:
        if pending == "path":
          path = key
          pending = ""
        else:
          quit("init: unexpected argument `" & key &
            "` (see `" & progName & " init --help`)", 1)
    if pending != "":
      quit("init: option --" & pending & " requires a value", 1)
    try:
      initConfigFile(path, force)
    except IOError as e:
      quit(e.msg, 1)
    echo "wrote " & path

  proc cmdPasswd(args: seq[string]) =
    var config = ""
    var username = ""
    var pending = ""
    var p = initOptParser(args)
    for kind, key, val in p.getopt():
      case kind
      of cmdEnd:
        break
      of cmdShortOption, cmdLongOption:
        if pending != "":
          quit("passwd: option --" & pending & " requires a value", 1)
        case key
        of "h", "help":
          printPasswdHelp()
          return
        of "config":
          if val != "":
            config = val
          else:
            pending = key
        else:
          quit("passwd: unknown option --" & key &
            " (see `" & progName & " passwd --help`)", 1)
      of cmdArgument:
        if pending == "config":
          config = key
          pending = ""
        elif username == "":
          username = key
        else:
          quit("passwd: unexpected argument `" & key &
            "` (see `" & progName & " passwd --help`)", 1)
    if pending != "":
      quit("passwd: option --" & pending & " requires a value", 1)
    if username == "":
      quit("passwd: missing <username> (see `" & progName & " passwd --help`)", 1)
    if not validUserName(username):
      quit("passwd: invalid username `" & username &
        "` (letters, digits and `. _ - @ +`, 1..64 chars)", 1)
    var cfgPath = config
    if cfgPath.len == 0:
      cfgPath = autoConfigPath()
      if cfgPath.len == 0:
        cfgPath = defaultConfigName
    let p1 = readPasswordFromStdin("Password: ")
    if p1.len == 0:
      quit("passwd: empty password rejected", 1)
    let p2 = readPasswordFromStdin("Confirm: ")
    if p1 != p2:
      quit("passwd: passwords do not match", 1)
    try:
      setUserHash(cfgPath, username, hashPassword(p1))
    except IOError as e:
      quit(e.msg, 1)
    except ValueError as e:
      quit(e.msg, 1)
    echo "set password for " & username & " in " & cfgPath

  proc cmdHelp(args: seq[string]) =
    if args.len == 0:
      printUsage()
      return
    case args[0]
    of "serve": printServeHelp()
    of "init": printInitHelp()
    of "passwd": printPasswdHelp()
    else:
      quit("unknown command `" & args[0] & "`", 1)

  let params = commandLineParams()
  if params.len == 0:
    printUsage()
    quit(0)
  let cmd = params[0]
  let rest = if params.len > 1: params[1 .. ^1] else: @[]
  case cmd
  of "serve": cmdServe(rest)
  of "init": cmdInit(rest)
  of "passwd": cmdPasswd(rest)
  of "help": cmdHelp(rest)
  of "-h", "--help":
    if rest.len == 0:
      printUsage()
    else:
      cmdHelp(rest)
  else:
    quit("unknown command `" & cmd & "` (see `" & progName & " help`)", 1)
