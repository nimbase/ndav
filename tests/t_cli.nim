## Server config: defaults, TOML overlay, flag precedence (no sockets).
import std/unittest
import std/os

import ndav/config

proc tmpToml(name, content: string): string =
  result = getTempDir() / name
  writeFile(result, content)

suite "cli defaults":
  test "built-ins match the example server":
    let c = defaultDavConfig()
    check c.root == getCurrentDir() / "davroot"
    check c.port == 9001
    check c.address == "127.0.0.1"

suite "cli toml overlay":
  test "full file replaces defaults":
    let p = tmpToml("davcli-full.toml", """
root = "/tmp/davcli-root"
port = 8080
address = "0.0.0.0"
""")
    let c = loadConfig(p)
    check c.root == "/tmp/davcli-root"
    check c.port == 8080
    check c.address == "0.0.0.0"
    removeFile(p)

  test "partial file keeps defaults for missing keys":
    let p = tmpToml("davcli-partial.toml", "port = 8080\n")
    let c = loadConfig(p)
    check c.root == getCurrentDir() / "davroot"
    check c.port == 8080
    check c.address == "127.0.0.1"
    removeFile(p)

  test "unknown keys are ignored":
    let p = tmpToml("davcli-unknown.toml", "port = 8080\nfuture = true\n")
    check loadConfig(p).port == 8080
    removeFile(p)

  test "missing file and bad values raise":
    expect IOError:
      discard loadConfig(getTempDir() / "davcli-absent.toml")
    let bad = tmpToml("davcli-bad.toml", "port = \"nope\"\n")
    expect ValueError:
      discard loadConfig(bad)
    removeFile(bad)

suite "cli precedence":
  test "flags beat file beats defaults":
    let p = tmpToml("davcli-prec.toml", """
root = "/tmp/from-file"
port = 8080
address = "0.0.0.0"
""")
    let fromFile = resolveConfig(DavFlags(config: p))
    check fromFile.root == "/tmp/from-file"
    check fromFile.port == 8080
    let over = resolveConfig(DavFlags(config: p, port: 9090))
    check over.root == "/tmp/from-file"
    check over.port == 9090
    check over.address == "0.0.0.0"
    let flagsOnly = resolveConfig(DavFlags(root: "/tmp/from-flag"))
    check flagsOnly.root == "/tmp/from-flag"
    check flagsOnly.port == 9001
    removeFile(p)

  test "out-of-range ports are rejected":
    expect ValueError:
      discard resolveConfig(DavFlags(port: 99999))
    let p = tmpToml("davcli-range.toml", "port = 0\n")
    expect ValueError:
      discard resolveConfig(DavFlags(config: p))
    removeFile(p)

suite "cli init":
  test "writes defaults that load back unchanged":
    let p = getTempDir() / "davcli-init.toml"
    removeFile(p)
    initConfigFile(p)
    let c = loadConfig(p)
    check c.root == "./davroot"
    check c.port == 9001
    check c.address == "127.0.0.1"
    removeFile(p)

  test "refuses to overwrite without --force":
    let p = tmpToml("davcli-init-guard.toml", "port = 1234\n")
    expect IOError:
      initConfigFile(p)
    check loadConfig(p).port == 1234
    initConfigFile(p, force = true)
    check loadConfig(p).port == 9001
    removeFile(p)

  test "auto-load finds webdav.config.toml in the cwd":
    let dir = getTempDir() / "davcli-autodir"
    createDir(dir)
    let saved = getCurrentDir()
    setCurrentDir(dir)
    try:
      check autoConfigPath() == ""
      initConfigFile()
      check autoConfigPath() == expandFilename(dir / defaultConfigName)
      let c = resolveConfig(DavFlags(config: autoConfigPath()))
      check c.port == 9001
    finally:
      setCurrentDir(saved)
    removeFile(dir / defaultConfigName)
    removeDir(dir)
