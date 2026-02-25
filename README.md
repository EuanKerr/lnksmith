# lnksmith

Build and parse Windows `.lnk` shortcut files in pure Python.

Implements the [MS-SHLLINK] specification with zero dependencies -- just the
standard library `struct` module. Runs on any platform; the resulting `.lnk`
files are valid on Windows.

[MS-SHLLINK]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/

Requires **Python 3.14+**.

## Usage

### Build a shortcut

```bash
lnksmith build \
    --target "C:\Windows\notepad.exe" \
    --output notepad.lnk \
    --description "Notepad" \
    --working-dir "C:\Windows" \
    --icon "C:\Windows\notepad.exe" \
    --show normal
```

All build options:

| Flag              | Description                                                |
| ----------------- | ---------------------------------------------------------- |
| `--target`        | Full Windows target path (required)                        |
| `-o`, `--output`  | Output file path (default: `output.lnk`)                   |
| `--icon`          | Icon source path (StringData)                              |
| `--icon-env`      | Icon path with `%env%` variables                           |
| `--env-target`    | Target path with `%env%` variables                         |
| `--icon-index`    | Icon resource index (default: 0)                           |
| `--description`   | Tooltip / comment text                                     |
| `--relative-path` | Relative path to target                                    |
| `--working-dir`   | Start-in directory                                         |
| `--arguments`     | Command-line arguments                                     |
| `--show`          | Window state: `normal`, `maximized`, `minimized`           |
| `--file-size`     | Target file size in bytes                                  |
| `--hotkey-vk`     | Virtual key code (hex, e.g. `0x43`)                        |
| `--hotkey-mod`    | Modifier mask (hex: `0x01`=Shift, `0x02`=Ctrl, `0x04`=Alt) |

### Parse a shortcut

```bash
# Human-readable output
lnksmith parse shortcut.lnk

# JSON output
lnksmith parse shortcut.lnk --json

# Multiple files
lnksmith parse *.lnk
```
