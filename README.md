# Lnksmith

Build and parse Windows `.lnk` shortcut files in pure Python.

Implements the [MS-SHLLINK] specification with zero dependencies -- just the
standard library `struct` module. Runs on any platform; the resulting `.lnk`
files are valid on Windows.

[MS-SHLLINK]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/

Requires **Python 3.14+**.

## Install

```bash
pip install lnksmith
```

Or from source:

```bash
git clone https://github.com/EuanKerr/lnksmith.git
cd lnksmith
pip install .
```

## Usage

### Build a shortcut

```bash
lnksmith build "C:\Windows\notepad.exe" \
    -o notepad.lnk \
    --description "Notepad" \
    --icon "C:\Windows\notepad.exe" \
    --show normal
```

The target path is positional -- no `--target` flag needed. The working
directory is auto-derived from the target's parent (here `C:\Windows`) unless
you override it with `--working-dir`.

**CLI flags** (common options):

| Flag                       | Description                                                 |
| -------------------------- | ----------------------------------------------------------- |
| (positional)               | Full Windows target path (required)                         |
| `-o`, `--output`           | Output file path (default: `output.lnk`)                    |
| `-j`, `--from-json`        | JSON config file (keys match `build_lnk()` kwargs)          |
| `--icon`                   | Icon source path (StringData)                               |
| `--icon-env`               | Icon path with `%env%` variables                            |
| `--env-target`             | Target path with `%env%` variables                          |
| `--icon-index`             | Icon resource index (default: `0`)                          |
| `--description`            | Tooltip / comment text                                      |
| `--relative-path`          | Relative path to target                                     |
| `--working-dir`            | Start-in directory (auto-derived from target if omitted)    |
| `--arguments`              | Command-line arguments                                      |
| `--show`                   | Window state: `normal`, `maximized`, `minimized`            |
| `--file-size`              | Target file size in bytes                                   |
| `--hotkey`                 | Hotkey combo (e.g. `CTRL+C`, `ALT+SHIFT+F5`)               |
| `--creation-time`          | CreationTime (ISO 8601 or FILETIME ticks)                   |
| `--access-time`            | AccessTime (ISO 8601 or FILETIME ticks)                     |
| `--write-time`             | WriteTime (ISO 8601 or FILETIME ticks)                      |
| `--known-folder`           | Known folder GUID or name (e.g. `Desktop`)                  |

**JSON-only fields** (via `--from-json`):

Advanced MS-SHLLINK fields like tracker metadata, volume info, darwin/shim
blocks, special folders, network provider details, and property stores are
set through a JSON config file. JSON keys match `build_lnk()` kwargs
directly. CLI flags override JSON values when both are provided.

### More build examples

Environment-variable target (resolved by Windows at launch):

```bash
lnksmith build "C:\Windows\System32\cmd.exe" \
    --env-target "%COMSPEC%" \
    --arguments "/k echo hello" \
    --show minimized \
    -o cmd.lnk
```

UNC network path with a mapped drive letter (via JSON config):

```bash
echo '{"network_device_name": "Z:"}' > config.json
lnksmith build "\\\\fileserver\shared\report.xlsx" \
    -j config.json \
    -o report.lnk
```

Custom timestamps and volume metadata (via JSON config):

```json
{
  "volume_label": "DATA",
  "drive_serial": 3735928559,
  "tracker_machine_id": "WORKSTATION01"
}
```

```bash
lnksmith build "C:\Tools\app.exe" \
    --creation-time "2025-06-15T08:30:00Z" \
    --write-time "2025-06-15T09:00:00Z" \
    -j config.json \
    -o app.lnk
```

Hotkey binding (Ctrl+Shift+T) with a known folder:

```bash
lnksmith build "C:\Tools\terminal.exe" \
    --hotkey CTRL+SHIFT+T \
    --known-folder "Desktop" \
    -o terminal.lnk
```

Supported modifier names: `SHIFT`, `CTRL`, `ALT`. Key names include `A`-`Z`,
`0`-`9`, `F1`-`F24`, `NUMPAD0`-`NUMPAD9`, and special keys like `BACKSPACE`,
`TAB`, `ENTER`, `SPACE`, `DELETE`, etc.

Icon from an environment-variable path with a custom index:

```bash
lnksmith build "C:\Program Files\MyApp\app.exe" \
    --icon-env "%ProgramFiles%\MyApp\app.exe" \
    --icon-index 1 \
    --description "My Application" \
    -o myapp.lnk
```

### Parse a shortcut

```bash
# Human-readable output
lnksmith parse shortcut.lnk

# JSON output
lnksmith parse shortcut.lnk --json

# Multiple files
lnksmith parse *.lnk
```

### Python API

```python
from lnksmith import build_lnk, write_lnk, parse_lnk, format_lnk

# Build and write a .lnk file
write_lnk("notepad.lnk", target=r"C:\Windows\notepad.exe",
           description="Notepad", working_dir=r"C:\Windows")

# Build to bytes (useful for sending over a network, embedding, etc.)
data = build_lnk(target=r"C:\Windows\System32\cmd.exe",
                 arguments="/k whoami", show_command=7)

# Parse from a file path or raw bytes
info = parse_lnk("notepad.lnk")
print(info.target_path)       # C:\Windows\notepad.exe
print(info.description)       # Notepad
print(info.working_dir)       # C:\Windows

# Human-readable dump
print(format_lnk(info))

# JSON-friendly dict
from dataclasses import asdict
print(asdict(info))
```

## License

MIT
