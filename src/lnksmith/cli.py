"""CLI entry point: ``lnksmith build`` / ``lnksmith parse``."""

import argparse
import json
import sys
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from ._constants import HOTKEY_MOD, SW_MAXIMIZED, SW_MINIMIZED, SW_SHOWNORMAL, VK_KEYS
from .builder import build_lnk
from .parser import LnkInfo, format_lnk, parse_lnk

SHOW_MAP = {
    "normal": SW_SHOWNORMAL,
    "maximized": SW_MAXIMIZED,
    "minimized": SW_MINIMIZED,
}

# Reverse lookups for --hotkey parsing
_MOD_NAMES = {v: k for k, v in HOTKEY_MOD.items()}
_VK_NAMES = {v.upper(): k for k, v in VK_KEYS.items()}


def _parse_timestamp(val: str) -> datetime | int | None:
    """Parse a CLI timestamp string into a datetime or int."""
    if not val:
        return None
    from datetime import UTC, datetime

    try:
        dt = datetime.fromisoformat(val)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=UTC)
        return dt.astimezone(UTC)
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

    return _VK_NAMES[key_name], mod_mask


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

    data = build_lnk(**cfg)
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
    parser = argparse.ArgumentParser(
        prog="lnksmith",
        description="Build and parse Windows .lnk files (MS-SHLLINK)",
        suggest_on_error=True,
        color=True,
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
