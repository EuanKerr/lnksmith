"""CLI entry point: ``lnksmith build`` / ``lnksmith parse``."""

import argparse
import json
import sys
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from ._constants import (
    HOTKEY_MOD,
    HOTKEY_VK_VALID,
    SW_SHOWMAXIMIZED,
    SW_SHOWMINNOACTIVE,
    SW_SHOWNORMAL,
    VK_KEYS,
)
from .builder import build_lnk
from .parser import LnkInfo, format_lnk, parse_lnk

SHOW_MAP = {
    "normal": SW_SHOWNORMAL,
    "maximized": SW_SHOWMAXIMIZED,
    "minimized": SW_SHOWMINNOACTIVE,
}

# Reverse lookups for --hotkey parsing
_MOD_NAMES = {v: k for k, v in HOTKEY_MOD.items()}
_VK_NAMES = {v.upper(): k for k, v in VK_KEYS.items()}


def _parse_timestamp(val: str) -> datetime | int | None:
    """Parse a CLI timestamp string into a datetime or int."""
    if not val:
        return None
    from datetime import datetime, timezone

    try:
        dt = datetime.fromisoformat(val)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        try:
            return int(val, 0)
        except ValueError:
            raise ValueError(
                f"Invalid timestamp: {val!r} (expected ISO 8601 or FILETIME ticks)"
            ) from None


def _parse_hotkey(val: str) -> tuple[int, int]:
    """Parse a hotkey string like ``CTRL+C`` into ``(vk_code, modifier_mask)``.

    Format: ``MOD[+MOD]+KEY`` where MOD is SHIFT/CTRL/ALT and KEY is a
    virtual key name (A-Z, 0-9, F1-F24, NUMPAD0-9, or special keys like
    BACKSPACE, TAB, etc.).
    """
    parts = [p.strip().upper() for p in val.split("+")]
    if len(parts) < 2:
        raise argparse.ArgumentTypeError(
            f"Invalid hotkey: {val!r} (expected MOD+KEY, e.g. CTRL+C)"
        )

    key_name = parts[-1]
    mod_mask = 0
    for mod in parts[:-1]:
        if mod not in _MOD_NAMES:
            raise argparse.ArgumentTypeError(
                f"Unknown modifier: {mod!r} (expected SHIFT, CTRL, or ALT)"
            )
        mod_mask |= _MOD_NAMES[mod]

    if key_name not in _VK_NAMES:
        raise argparse.ArgumentTypeError(f"Unknown key: {key_name!r}")

    vk = _VK_NAMES[key_name]
    if vk not in HOTKEY_VK_VALID:
        raise argparse.ArgumentTypeError(
            f"Key {key_name!r} (0x{vk:02X}) is not valid for .lnk hotkeys "
            f"(spec allows 0-9, A-Z, F1-F24, NUM LOCK, SCROLL LOCK)"
        )
    return vk, mod_mask


def _parse_size(val: str) -> int:
    """Parse a human-readable size string into bytes.

    Accepts plain integers or suffixes: KB, MB, GB (powers of 1024).
    Raises :class:`argparse.ArgumentTypeError` on invalid input.
    """
    try:
        raw = val.strip().upper()
        multipliers = {"KB": 1024, "MB": 1024**2, "GB": 1024**3}
        for suffix, mult in multipliers.items():
            if raw.endswith(suffix):
                result = int(raw[: -len(suffix)].strip()) * mult
                if result < 0:
                    raise argparse.ArgumentTypeError(
                        f"pad size must be non-negative, got {val!r}"
                    )
                return result
        result = int(raw, 0)
        if result < 0:
            raise argparse.ArgumentTypeError(
                f"pad size must be non-negative, got {val!r}"
            )
        return result
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"Invalid size: {val!r} (expected integer or suffix like 100MB, 1GB)"
        ) from None


def _derive_working_dir(target: str) -> str:
    """Derive working directory from target path's parent directory."""
    if target.startswith("\\\\"):
        parts = target.split("\\")
        # ['', '', 'server', 'share', 'dir', 'file.txt'] -> \\server\share\dir
        if len(parts) > 4:
            return "\\".join(parts[:-1])
        return target
    if "\\" in target:
        return target.rsplit("\\", 1)[0]
    return ""


def _cmd_build(args: argparse.Namespace) -> None:
    # Load JSON config as base (keys match build_lnk kwargs)
    cfg: dict = {}
    if args.from_json:
        cfg = json.loads(Path(args.from_json).read_text())

    # Target always comes from CLI (positional)
    cfg["target"] = args.target

    # Map CLI attr -> build_lnk kwarg; only override if explicitly set
    _cli_overrides = {
        "icon": "icon_location",
        "icon_env": "icon_env_path",
        "env_target": "env_target_path",
        "env_target_ansi": "env_target_ansi",
        "env_target_unicode": "env_target_unicode",
        "icon_index": "icon_index",
        "description": "description",
        "relative_path": "relative_path",
        "arguments": "arguments",
        "file_size": "file_size",
        "creation_time": "creation_time",
        "access_time": "access_time",
        "write_time": "write_time",
        "known_folder": "known_folder_id",
    }
    for attr, key in _cli_overrides.items():
        val = getattr(args, attr, None)
        if val is not None:
            cfg[key] = val

    # Show command
    if args.show is not None:
        cfg["show_command"] = SHOW_MAP[args.show]

    # Hotkey (combined flag)
    if args.hotkey is not None:
        vk, mod = _parse_hotkey(args.hotkey)
        cfg["hotkey_vk"] = vk
        cfg["hotkey_mod"] = mod

    # Argument padding
    if args.pad_args is not None:
        if args.pad_args < 0:
            sys.exit("Error: --pad-args must be non-negative")
        cfg["pad_args"] = args.pad_args

    # Pad character (with escape interpretation)
    if args.pad_char is not None:
        pc = args.pad_char
        pc = pc.replace("\\n", "\n").replace("\\r", "\r").replace("\\t", "\t")
        cfg["pad_char"] = pc

    # Null env block
    if args.null_env_block:
        cfg["null_env_block"] = True

    # Force ANSI StringData
    if args.force_ansi:
        cfg["force_ansi"] = True

    # Binary padding
    if args.pad_size is not None:
        cfg["pad_size"] = args.pad_size

    # Payload append (read file bytes)
    if args.append is not None:
        append_path = Path(args.append)
        if not append_path.is_file():
            sys.exit(f"Error: append file not found: {args.append}")
        try:
            cfg["append_data"] = append_path.read_bytes()
        except OSError as exc:
            sys.exit(f"Error: cannot read append file: {exc}")

    # MotW stomp
    if args.stomp_motw is not None:
        cfg["stomp_motw"] = args.stomp_motw

    # Parse string timestamps into datetime/int
    for key in ("creation_time", "access_time", "write_time"):
        if key in cfg and isinstance(cfg[key], str):
            cfg[key] = _parse_timestamp(cfg[key])

    # Auto-derive working_dir from target parent if not set anywhere
    if args.working_dir is not None:
        cfg["working_dir"] = args.working_dir
    elif "working_dir" not in cfg:
        target = cfg["target"]
        if isinstance(target, str):
            cfg["working_dir"] = _derive_working_dir(target)

    # Reject reserved FileAttributes bits at the CLI boundary (spec 2.1.2).
    fa = cfg.get("file_attributes", 0x20)
    if fa & 0x48:
        sys.exit(
            f"Error: file_attributes 0x{fa:08X} has reserved bits set "
            f"(bits 3 and 6 MUST be zero per MS-SHLLINK section 2.1.2)"
        )

    try:
        data = build_lnk(**cfg)
    except TypeError as exc:
        sys.exit(f"Error: {exc}\nCheck JSON keys against: lnksmith build --help")
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(data)
    print(f"[+] Written {len(data)} bytes -> {out}")


def _serialize_lnk_info(info: LnkInfo) -> dict:
    """Convert LnkInfo to a JSON-friendly dict."""
    d = asdict(info)
    # ExtraBlock.raw is bytes -- encode as hex
    for block in d.get("extra_blocks", []):
        block["raw"] = block["raw"].hex()
    return d


def _cmd_parse(args: argparse.Namespace) -> None:
    for path in args.files:
        info = parse_lnk(path)
        if args.json:
            print(json.dumps(_serialize_lnk_info(info), indent=2))
        else:
            header = f"FILE: {path}"
            print(f"\n{'=' * 70}")
            print(header)
            print(f"{'=' * 70}")
            print(format_lnk(info))
            print()


def main(argv: list[str] | None = None) -> None:
    # suggest_on_error and color require Python 3.14+
    ap_kwargs: dict = {}
    if sys.version_info >= (3, 14):
        ap_kwargs["suggest_on_error"] = True
        ap_kwargs["color"] = True
    parser = argparse.ArgumentParser(
        prog="lnksmith",
        description="Build and parse Windows .lnk files (MS-SHLLINK)",
        **ap_kwargs,
    )
    sub = parser.add_subparsers(dest="command")

    # -- build --
    bp = sub.add_parser(
        "build",
        help="Build a .lnk file",
        epilog=(
            "Advanced fields (tracker, darwin, shim, special-folder, "
            "volume, network, property-store, etc.) can be set via "
            "--from-json. JSON keys match build_lnk() kwargs directly."
        ),
    )
    bp.add_argument("target", help="Full Windows target path")
    bp.add_argument("-o", "--output", default="output.lnk", help="Output file path")
    bp.add_argument(
        "-j",
        "--from-json",
        default="",
        metavar="FILE",
        help="JSON config file (keys match build_lnk kwargs)",
    )
    bp.add_argument("--icon", default=None, help="Icon source path (StringData)")
    bp.add_argument("--icon-env", default=None, help="Icon path with %%env%% vars")
    bp.add_argument("--env-target", default=None, help="Target path with %%env%% vars")
    bp.add_argument(
        "--env-target-ansi",
        default=None,
        help="ANSI-only EnvironmentVariableDataBlock target (Beukema Variant 4)",
    )
    bp.add_argument(
        "--env-target-unicode",
        default=None,
        help="Unicode-only EnvironmentVariableDataBlock target",
    )
    bp.add_argument(
        "--null-env-block",
        action="store_true",
        default=False,
        help="Emit all-zeros EnvironmentVariableDataBlock (Beukema Variant 1)",
    )
    bp.add_argument("--icon-index", type=int, default=None, help="Icon resource index")
    bp.add_argument("--description", default=None, help="Tooltip / comment text")
    bp.add_argument("--relative-path", default=None, help="Relative path to target")
    bp.add_argument(
        "--working-dir",
        default=None,
        help="Start-in directory (auto-derived from target if omitted)",
    )
    bp.add_argument("--arguments", default=None, help="Command-line arguments")
    bp.add_argument(
        "--show",
        choices=["normal", "maximized", "minimized"],
        default=None,
        help="Window show state",
    )
    bp.add_argument("--file-size", type=int, default=None, help="Target file size")
    bp.add_argument(
        "--hotkey",
        default=None,
        help="Hotkey combo (e.g. CTRL+C, ALT+SHIFT+F5)",
    )
    bp.add_argument(
        "--creation-time",
        default=None,
        help="CreationTime (ISO 8601 or FILETIME ticks)",
    )
    bp.add_argument(
        "--access-time",
        default=None,
        help="AccessTime (ISO 8601 or FILETIME ticks)",
    )
    bp.add_argument(
        "--write-time",
        default=None,
        help="WriteTime (ISO 8601 or FILETIME ticks)",
    )
    bp.add_argument(
        "--known-folder",
        default=None,
        help="Known folder GUID or name (e.g. 'Desktop')",
    )
    bp.add_argument(
        "--pad-args",
        type=int,
        default=None,
        metavar="N",
        help="Prepend N fill chars to arguments (ZDI-CAN-25373 / CVE-2025-9491)",
    )
    bp.add_argument(
        "--pad-char",
        default=None,
        metavar="CHAR",
        help="Fill character(s) for --pad-args (default: space; use \\n\\r for CVE-2025-9491)",
    )
    bp.add_argument(
        "--force-ansi",
        action="store_true",
        default=False,
        help="Suppress IsUnicode flag; encode StringData as cp1252",
    )
    bp.add_argument(
        "--pad-size",
        type=_parse_size,
        default=None,
        metavar="SIZE",
        help="Append null bytes to inflate file size (e.g. 100MB, 1GB)",
    )
    bp.add_argument(
        "--append",
        default=None,
        metavar="FILE",
        help="Append file content after terminal block (polyglot payload)",
    )
    bp.add_argument(
        "--stomp-motw",
        choices=["dot", "relative"],
        default=None,
        help="MotW bypass via malformed IDList paths (CVE-2024-38217)",
    )

    # -- parse --
    pp = sub.add_parser("parse", help="Parse and display .lnk file(s)")
    pp.add_argument("files", nargs="+", help="LNK file(s) to parse")
    pp.add_argument("--json", action="store_true", help="Output as JSON")

    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        sys.exit(1)

    if args.command == "build":
        _cmd_build(args)
    elif args.command == "parse":
        _cmd_parse(args)


if __name__ == "__main__":
    main()
