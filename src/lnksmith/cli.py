"""CLI entry point: ``lnksmith build`` / ``lnksmith parse``."""

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from ._constants import SW_MAXIMIZED, SW_MINIMIZED, SW_SHOWNORMAL
from .builder import build_lnk
from .parser import LnkInfo, format_lnk, parse_lnk

SHOW_MAP = {
    "normal": SW_SHOWNORMAL,
    "maximized": SW_MAXIMIZED,
    "minimized": SW_MINIMIZED,
}


def _cmd_build(args):
    kwargs = dict(
        target=args.target,
        icon_location=args.icon or "",
        icon_env_path=args.icon_env or "",
        env_target_path=args.env_target or "",
        icon_index=args.icon_index,
        description=args.description or "",
        relative_path=args.relative_path or "",
        working_dir=args.working_dir or "",
        arguments=args.arguments or "",
        show_command=SHOW_MAP.get(args.show, SW_SHOWNORMAL),
        file_size=args.file_size,
        hotkey_vk=args.hotkey_vk,
        hotkey_mod=args.hotkey_mod,
        tracker_machine_id=args.tracker_machine_id or "",
        known_folder_id=args.known_folder or "",
    )

    if args.property_store_json:
        ps_path = Path(args.property_store_json)
        kwargs["property_stores"] = json.loads(ps_path.read_text())

    data = build_lnk(**kwargs)
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


def _cmd_parse(args):
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


def main(argv: list[str] | None = None):
    parser = argparse.ArgumentParser(
        prog="lnksmith",
        description="Build and parse Windows .lnk files (MS-SHLLINK)",
        suggest_on_error=True,
        color=True,
    )
    sub = parser.add_subparsers(dest="command")

    # -- build --
    bp = sub.add_parser("build", help="Build a .lnk file")
    bp.add_argument("--target", required=True, help="Full Windows target path")
    bp.add_argument("-o", "--output", default="output.lnk", help="Output file path")
    bp.add_argument("--icon", default="", help="Icon source path (StringData)")
    bp.add_argument("--icon-env", default="", help="Icon path with %%env%% vars")
    bp.add_argument("--env-target", default="", help="Target path with %%env%% vars")
    bp.add_argument("--icon-index", type=int, default=0, help="Icon resource index")
    bp.add_argument("--description", default="", help="Tooltip / comment text")
    bp.add_argument("--relative-path", default="", help="Relative path to target")
    bp.add_argument("--working-dir", default="", help="Start-in directory")
    bp.add_argument("--arguments", default="", help="Command-line arguments")
    bp.add_argument(
        "--show",
        choices=["normal", "maximized", "minimized"],
        default="normal",
        help="Window show state",
    )
    bp.add_argument("--file-size", type=int, default=0, help="Target file size")
    bp.add_argument(
        "--hotkey-vk",
        type=lambda x: int(x, 0),
        default=0,
        help="Virtual key code (hex, e.g. 0x43)",
    )
    bp.add_argument(
        "--hotkey-mod",
        type=lambda x: int(x, 0),
        default=0,
        help="Modifier mask (hex, e.g. 0x02=CTRL)",
    )
    bp.add_argument(
        "--tracker-machine-id",
        default="",
        help="Tracker MachineID (ASCII, max 15 chars)",
    )
    bp.add_argument(
        "--known-folder",
        default="",
        help="Known folder GUID or name (e.g. 'Desktop')",
    )
    bp.add_argument(
        "--property-store-json",
        default="",
        help="Path to JSON file defining property stores",
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
