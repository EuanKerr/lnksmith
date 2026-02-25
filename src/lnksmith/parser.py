"""Parse Windows .lnk files (MS-SHLLINK) into structured data."""

import struct
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from ._constants import (
    ANSI_CODEPAGE,
    DRIVE_TYPES,
    EXTRA_SIGS,
    FLAG_NAMES,
    HOTKEY_MOD,
    KNOWN_FOLDER_NAMES,
    PROPERTY_SET_GUIDS,
    SHOW_CMD,
    VK_KEYS,
    VT_TYPES,
    WNNC_NET_TYPES,
)
from ._util import decode_utf16le_at, format_guid


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------
class FormatError(Exception):
    """Raised when data does not conform to the MS-SHLLINK format."""


class MissingFieldError(FormatError):
    """Raised when a required field is absent or truncated."""


# ---------------------------------------------------------------------------
# Low-level readers
# ---------------------------------------------------------------------------
def _read_u16(data, off):
    return struct.unpack_from("<H", data, off)[0]


def _read_u32(data, off):
    return struct.unpack_from("<I", data, off)[0]


def _read_i32(data, off):
    return struct.unpack_from("<i", data, off)[0]


def _dos_date_str(val):
    day = val & 0x1F
    month = (val >> 5) & 0x0F
    year = ((val >> 9) & 0x7F) + 1980
    return f"{year}-{month:02d}-{day:02d}"


def _dos_time_str(val):
    sec = (val & 0x1F) * 2
    minute = (val >> 5) & 0x3F
    hour = (val >> 11) & 0x1F
    return f"{hour:02d}:{minute:02d}:{sec:02d}"


def _filetime_to_str(data, off):
    ft = struct.unpack_from("<Q", data, off)[0]
    if ft == 0:
        return "0 (unset)"
    unix_ts = (ft - 116444736000000000) / 10000000
    try:
        dt = datetime.fromtimestamp(unix_ts, tz=UTC)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except OSError, OverflowError, ValueError:
        return f"0x{ft:016X}"


def _decode_flags(val):
    bits = []
    for bit in range(32):
        if val & (1 << bit):
            bits.append(FLAG_NAMES.get(bit, f"Bit{bit}"))
    return bits


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class IdItem:
    """One SHITEMID entry from the LinkTargetIDList."""

    offset: int
    size: int
    type_byte: int
    description: str


@dataclass(slots=True)
class ExtraBlock:
    """One ExtraData block."""

    signature: int
    name: str
    size: int
    data: dict[str, str] = field(default_factory=dict)
    raw: bytes = b""


@dataclass(slots=True)
class PropertyValue:
    """A single property from a Serialized Property Store."""

    id: int | str
    type: int
    type_name: str
    value: object


@dataclass(slots=True)
class PropertyStore:
    """One serialized property storage (one Format ID's properties)."""

    format_id: str
    format_name: str
    properties: list[PropertyValue] = field(default_factory=list)


@dataclass(slots=True)
class LnkInfo:
    """Structured representation of a parsed .lnk file."""

    # Header
    flags: int = 0
    flag_names: list[str] = field(default_factory=list)
    file_attributes: int = 0
    creation_time: str = ""
    access_time: str = ""
    write_time: str = ""
    file_size: int = 0
    icon_index: int = 0
    show_command: int = 0
    show_command_name: str = ""
    hotkey_vk: int = 0
    hotkey_mod: int = 0
    hotkey_str: str = ""

    # IDList
    id_items: list[IdItem] = field(default_factory=list)

    # LinkInfo
    volume_label: str = ""
    drive_type: int = 0
    drive_type_name: str = ""
    drive_serial: int = 0
    local_base_path: str = ""
    common_path: str = ""

    # Network (CommonNetworkRelativeLink)
    network_share_name: str = ""
    device_name: str = ""
    network_provider_type: int = 0
    network_provider_name: str = ""

    # StringData
    description: str = ""
    relative_path: str = ""
    working_dir: str = ""
    arguments: str = ""
    icon_location: str = ""

    # ExtraData
    extra_blocks: list[ExtraBlock] = field(default_factory=list)

    # TrackerDataBlock (promoted from ExtraBlock.data)
    tracker_machine_id: str = ""
    tracker_droid_volume_id: str = ""
    tracker_droid_file_id: str = ""
    tracker_birth_droid_volume_id: str = ""
    tracker_birth_droid_file_id: str = ""

    # KnownFolderDataBlock
    known_folder_id: str = ""
    known_folder_name: str = ""

    # VistaAndAboveIDListDataBlock
    vista_id_items: list[IdItem] = field(default_factory=list)

    # PropertyStoreDataBlock
    property_stores: list[PropertyStore] = field(default_factory=list)

    # Resolved (convenience)
    target_path: str = ""


# ---------------------------------------------------------------------------
# IDList item parser
# ---------------------------------------------------------------------------
def _parse_idlist_item(data, off, idx):
    """Parse one SHITEMID and return (next_offset, IdItem | None)."""
    size = _read_u16(data, off)
    if size == 0:
        return off + 2, None  # terminator

    body = data[off + 2 : off + size]
    type_byte = body[0] if body else 0

    desc = f"type=0x{type_byte:02X}"

    if type_byte == 0x1F:
        sort_idx = body[1] if len(body) > 1 else 0
        guid = body[2:18] if len(body) >= 18 else b""
        guid_str = format_guid(guid) if len(guid) >= 16 else "?"
        desc = f"[Root] sort=0x{sort_idx:02X} CLSID={{{guid_str}}}"

    elif type_byte == 0x2F:
        drive = body[1:].split(b"\x00")[0].decode(ANSI_CODEPAGE, errors="replace")
        desc = f"[Drive] {drive}"

    elif type_byte in (0x31, 0x32, 0x35, 0x36):
        kind = "Dir" if type_byte in (0x31, 0x35) else "File"
        fsize = struct.unpack_from("<I", body, 2)[0] if len(body) >= 6 else 0
        date_w = _read_u16(data, off + 2 + 6) if len(body) >= 8 else 0
        time_w = _read_u16(data, off + 2 + 8) if len(body) >= 10 else 0
        attrs = _read_u16(data, off + 2 + 10) if len(body) >= 12 else 0

        name_start = 12
        name_end = body.find(b"\x00", name_start)
        if name_end < 0:
            name_end = len(body)
        short_name = body[name_start:name_end].decode(ANSI_CODEPAGE, errors="replace")

        long_name = ""
        # Parse BEEF0004 extension block
        pad_pos = name_end + 1
        if pad_pos % 2:
            pad_pos += 1
        ext_off = pad_pos
        if ext_off + 8 <= len(body):
            ext = body[ext_off:]
            ext_size = struct.unpack_from("<H", ext, 0)[0]
            ext_ver = struct.unpack_from("<H", ext, 2)[0]
            ext_sig = struct.unpack_from("<I", ext, 4)[0] if len(ext) >= 8 else 0

            if ext_sig == 0xBEEF0004 and ext_size <= len(ext):
                if ext_ver >= 9 and len(ext) >= 46:
                    uname_off = struct.unpack_from("<H", ext, 16)[0]
                    if uname_off < ext_size:
                        long_name = decode_utf16le_at(ext, uname_off)
                elif ext_ver >= 3:
                    uname_start = 12
                    if uname_start < len(ext) - 1:
                        long_name = decode_utf16le_at(ext, uname_start)

        desc = (
            f'[{kind}] short="{short_name}" long="{long_name}" '
            f"fsize={fsize} date={_dos_date_str(date_w)} time={_dos_time_str(time_w)} "
            f"attrs=0x{attrs:04X}"
        )

    elif type_byte & 0x70 == 0x40:
        # Network location item
        net_name = (
            body[2:].split(b"\x00")[0].decode(ANSI_CODEPAGE, errors="replace")
            if len(body) > 2
            else ""
        )
        desc = f"[Network] {net_name}"

    item = IdItem(offset=off, size=size, type_byte=type_byte, description=desc)
    return off + size, item


# ---------------------------------------------------------------------------
# Property Store parser
# ---------------------------------------------------------------------------
def _parse_typed_value(data, off, end):
    """Parse a VARIANT-typed value at *off*.  Returns ``(value, vtype)``."""
    if off + 4 > end:
        return None, 0
    vtype = _read_u16(data, off)
    val_off = off + 4  # 2 type + 2 padding

    if vtype == 0x001F:  # VT_LPWSTR
        if val_off + 4 > end:
            return None, vtype
        char_count = _read_u32(data, val_off)
        byte_count = char_count * 2
        if val_off + 4 + byte_count > end:
            byte_count = end - val_off - 4
        raw = data[val_off + 4 : val_off + 4 + byte_count]
        value = raw.decode("utf-16-le", errors="replace").rstrip("\x00")
        return value, vtype
    elif vtype == 0x0013:  # VT_UI4
        if val_off + 4 > end:
            return None, vtype
        return _read_u32(data, val_off), vtype
    elif vtype == 0x0003:  # VT_I4
        if val_off + 4 > end:
            return None, vtype
        return _read_i32(data, val_off), vtype
    elif vtype == 0x0014:  # VT_UI8
        if val_off + 8 > end:
            return None, vtype
        return struct.unpack_from("<Q", data, val_off)[0], vtype
    elif vtype == 0x000B:  # VT_BOOL
        if val_off + 2 > end:
            return None, vtype
        return bool(_read_u16(data, val_off)), vtype
    elif vtype == 0x0040:  # VT_FILETIME
        if val_off + 8 > end:
            return None, vtype
        return _filetime_to_str(data, val_off), vtype
    elif vtype == 0x0048:  # VT_CLSID
        if val_off + 16 > end:
            return None, vtype
        return "{" + format_guid(data, val_off) + "}", vtype
    else:
        remaining = data[val_off:end]
        return remaining.hex(), vtype


def _parse_property_store(data, start, end):
    """Parse a Serialized Property Store.  Returns a list of PropertyStore."""
    stores = []
    pos = start

    while pos + 4 <= end:
        storage_size = _read_u32(data, pos)
        if storage_size == 0 or storage_size < 28:
            break
        if pos + storage_size > end:
            break

        storage_end = pos + storage_size
        fmt_id = "{" + format_guid(data, pos + 8) + "}"
        fmt_name = PROPERTY_SET_GUIDS.get(fmt_id, "Unknown")

        store = PropertyStore(format_id=fmt_id, format_name=fmt_name)

        prop_pos = pos + 24
        while prop_pos + 9 <= storage_end:
            value_size = _read_u32(data, prop_pos)
            if value_size == 0 or value_size < 9:
                break
            if prop_pos + value_size > storage_end:
                break

            pid = _read_u32(data, prop_pos + 4)
            typed_off = prop_pos + 9
            value, vtype = _parse_typed_value(data, typed_off, prop_pos + value_size)
            type_name = VT_TYPES.get(vtype, f"0x{vtype:04X}")

            prop = PropertyValue(id=pid, type=vtype, type_name=type_name, value=value)
            store.properties.append(prop)
            prop_pos += value_size

        stores.append(store)
        pos += storage_size

    return stores


# ---------------------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------------------
def parse_lnk(source: str | Path | bytes) -> LnkInfo:
    """Parse a .lnk file and return a :class:`LnkInfo`.

    Args:
        source: A file path (str or Path) or raw bytes of a .lnk file.
    """
    data = Path(source).read_bytes() if isinstance(source, (str, Path)) else source

    if len(data) < 76:
        raise FormatError("Data too short for an MS-SHLLINK header (need >= 76 bytes)")

    info = LnkInfo()

    # -- Header --
    hdr_size = _read_u32(data, 0)
    if hdr_size != 0x4C:
        raise FormatError(f"Invalid header size 0x{hdr_size:08X} (expected 0x4C)")

    info.flags = _read_u32(data, 20)
    info.flag_names = _decode_flags(info.flags)
    info.file_attributes = _read_u32(data, 24)
    info.creation_time = _filetime_to_str(data, 28)
    info.access_time = _filetime_to_str(data, 36)
    info.write_time = _filetime_to_str(data, 44)
    info.file_size = _read_u32(data, 52)
    info.icon_index = _read_i32(data, 56)
    info.show_command = _read_u32(data, 60)
    info.show_command_name = SHOW_CMD.get(info.show_command, "?")

    info.hotkey_vk = data[64]
    info.hotkey_mod = data[65]
    mod_parts = [n for b, n in HOTKEY_MOD.items() if info.hotkey_mod & b]
    vk_name = (
        VK_KEYS.get(info.hotkey_vk, f"0x{info.hotkey_vk:02X}") if info.hotkey_vk else ""
    )
    if mod_parts or vk_name:
        info.hotkey_str = "+".join(mod_parts + ([vk_name] if vk_name else []))

    pos = 76

    # -- IDList --
    if info.flags & 1:
        idlist_size = _read_u16(data, pos)
        pos += 2
        end_of_idlist = pos + idlist_size
        idx = 0
        while pos < end_of_idlist:
            next_pos, item = _parse_idlist_item(data, pos, idx)
            if item is None:
                pos = next_pos
                break
            info.id_items.append(item)
            pos = next_pos
            idx += 1
        pos = end_of_idlist

    # -- LinkInfo --
    if info.flags & 2:
        li_size = _read_u32(data, pos)
        li_hdr_size = _read_u32(data, pos + 4)
        li_flags = _read_u32(data, pos + 8)

        if li_flags & 1:  # VolumeIDAndLocalBasePath
            vol_off = _read_u32(data, pos + 12)
            base_off = _read_u32(data, pos + 16)
            # VolumeID
            vol_pos = pos + vol_off
            vol_size = _read_u32(data, vol_pos)
            info.drive_type = _read_u32(data, vol_pos + 4)
            info.drive_type_name = DRIVE_TYPES.get(info.drive_type, "?")
            info.drive_serial = _read_u32(data, vol_pos + 8)
            label_off = _read_u32(data, vol_pos + 12)
            info.volume_label = (
                data[vol_pos + label_off : vol_pos + vol_size]
                .split(b"\x00")[0]
                .decode(ANSI_CODEPAGE, errors="replace")
            )
            # LocalBasePath (ANSI)
            info.local_base_path = (
                data[pos + base_off : pos + li_size]
                .split(b"\x00")[0]
                .decode(ANSI_CODEPAGE, errors="replace")
            )
            info.target_path = info.local_base_path

            # CommonPathSuffix (ANSI) at offset +24
            suffix_off = _read_u32(data, pos + 24)
            if suffix_off > 0 and pos + suffix_off < pos + li_size:
                info.common_path = (
                    data[pos + suffix_off : pos + li_size]
                    .split(b"\x00")[0]
                    .decode(ANSI_CODEPAGE, errors="replace")
                )

            # Unicode variants when header size >= 0x24
            if li_hdr_size >= 0x24:
                uni_base_off = _read_u32(data, pos + 28)
                if uni_base_off > 0 and pos + uni_base_off < pos + li_size:
                    info.local_base_path = decode_utf16le_at(
                        data, pos + uni_base_off, li_size - uni_base_off
                    )
                    info.target_path = info.local_base_path
            if li_hdr_size >= 0x24:
                uni_suffix_off = _read_u32(data, pos + 32)
                if uni_suffix_off > 0 and pos + uni_suffix_off < pos + li_size:
                    info.common_path = decode_utf16le_at(
                        data, pos + uni_suffix_off, li_size - uni_suffix_off
                    )

            if info.common_path:
                info.target_path = info.local_base_path + info.common_path

        if li_flags & 2:  # CommonNetworkRelativeLinkAndPathSuffix
            cnr_off = _read_u32(data, pos + 20)
            suffix_off = _read_u32(data, pos + 24)

            cnr_pos = pos + cnr_off
            cnr_size = _read_u32(data, cnr_pos)
            cnr_flags = _read_u32(data, cnr_pos + 4)
            net_name_off = _read_u32(data, cnr_pos + 8)
            device_name_off = _read_u32(data, cnr_pos + 12)
            net_provider_type = _read_u32(data, cnr_pos + 16)

            info.network_share_name = (
                data[cnr_pos + net_name_off : cnr_pos + cnr_size]
                .split(b"\x00")[0]
                .decode(ANSI_CODEPAGE, errors="replace")
            )

            if cnr_flags & 1:  # ValidDevice
                info.device_name = (
                    data[cnr_pos + device_name_off : cnr_pos + cnr_size]
                    .split(b"\x00")[0]
                    .decode(ANSI_CODEPAGE, errors="replace")
                )

            if cnr_flags & 2:  # ValidNetType
                info.network_provider_type = net_provider_type
                info.network_provider_name = WNNC_NET_TYPES.get(
                    net_provider_type, f"0x{net_provider_type:08X}"
                )

            # Unicode variants if CNR has extended header
            if net_name_off > 0x14:
                uni_net_off = _read_u32(data, cnr_pos + 20)
                if uni_net_off > 0 and cnr_pos + uni_net_off < cnr_pos + cnr_size:
                    info.network_share_name = decode_utf16le_at(
                        data, cnr_pos + uni_net_off, cnr_size - uni_net_off
                    )

            # CommonPathSuffix
            if suffix_off > 0 and pos + suffix_off < pos + li_size:
                info.common_path = (
                    data[pos + suffix_off : pos + li_size]
                    .split(b"\x00")[0]
                    .decode(ANSI_CODEPAGE, errors="replace")
                )

            # Compose target path from UNC share + suffix
            info.target_path = info.network_share_name
            if info.common_path:
                info.target_path = info.network_share_name + "\\" + info.common_path

        pos += li_size

    # -- StringData --
    string_order = []
    if info.flags & 0x04:
        string_order.append("Name")
    if info.flags & 0x08:
        string_order.append("RelativePath")
    if info.flags & 0x10:
        string_order.append("WorkingDir")
    if info.flags & 0x20:
        string_order.append("Arguments")
    if info.flags & 0x40:
        string_order.append("IconLocation")

    is_unicode = bool(info.flags & 0x80)
    for name in string_order:
        count = _read_u16(data, pos)
        pos += 2
        if is_unicode:
            raw = data[pos : pos + count * 2]
            val = raw.decode("utf-16-le", errors="replace")
            pos += count * 2
        else:
            val = data[pos : pos + count].decode(ANSI_CODEPAGE, errors="replace")
            pos += count

        if name == "Name":
            info.description = val
        elif name == "RelativePath":
            info.relative_path = val
        elif name == "WorkingDir":
            info.working_dir = val
        elif name == "Arguments":
            info.arguments = val
        elif name == "IconLocation":
            info.icon_location = val

    # -- ExtraData --
    icon_env = ""
    while pos + 4 <= len(data):
        block_size = _read_u32(data, pos)
        if block_size < 4:
            break
        sig = _read_u32(data, pos + 4) if block_size >= 8 else 0
        sig_name = EXTRA_SIGS.get(sig, f"Unknown(0x{sig:08X})")

        block = ExtraBlock(
            signature=sig,
            name=sig_name,
            size=block_size,
            raw=data[pos : pos + block_size],
        )

        if sig == 0xA0000001 and block_size >= 268:
            ansi = (
                data[pos + 8 : pos + 268]
                .split(b"\x00")[0]
                .decode(ANSI_CODEPAGE, errors="replace")
            )
            block.data["TargetAnsi"] = ansi
            if block_size >= 528:
                block.data["TargetUnicode"] = decode_utf16le_at(data, pos + 268, 520)

        elif sig == 0xA0000007 and block_size >= 268:
            ansi = (
                data[pos + 8 : pos + 268]
                .split(b"\x00")[0]
                .decode(ANSI_CODEPAGE, errors="replace")
            )
            block.data["IconAnsi"] = ansi
            icon_env = ansi
            if block_size >= 788:
                uni_str = decode_utf16le_at(data, pos + 268, 520)
                block.data["IconUnicode"] = uni_str
                if uni_str:
                    icon_env = uni_str

        elif sig == 0xA0000005 and block_size >= 16:
            block.data["SpecialFolderID"] = str(_read_u32(data, pos + 8))
            block.data["IDListOffset"] = str(_read_u32(data, pos + 12))

        elif sig == 0xA000000B and block_size >= 28:
            guid_str = "{" + format_guid(data, pos + 8) + "}"
            block.data["KnownFolderID"] = guid_str
            folder_name = KNOWN_FOLDER_NAMES.get(guid_str, "Unknown")
            block.data["KnownFolderName"] = folder_name
            block.data["IDListOffset"] = str(_read_u32(data, pos + 24))
            info.known_folder_id = guid_str
            info.known_folder_name = folder_name

        elif sig == 0xA0000003 and block_size >= 96:
            machine = (
                data[pos + 16 : pos + 32]
                .split(b"\x00")[0]
                .decode("ascii", errors="replace")
            )
            block.data["MachineID"] = machine
            info.tracker_machine_id = machine

            dvol = "{" + format_guid(data, pos + 32) + "}"
            dfile = "{" + format_guid(data, pos + 48) + "}"
            bvol = "{" + format_guid(data, pos + 64) + "}"
            bfile = "{" + format_guid(data, pos + 80) + "}"
            block.data["DroidVolumeID"] = dvol
            block.data["DroidFileID"] = dfile
            block.data["BirthDroidVolumeID"] = bvol
            block.data["BirthDroidFileID"] = bfile
            info.tracker_droid_volume_id = dvol
            info.tracker_droid_file_id = dfile
            info.tracker_birth_droid_volume_id = bvol
            info.tracker_birth_droid_file_id = bfile

        elif sig == 0xA000000C and block_size > 10:
            # VistaAndAboveIDListDataBlock: embedded IDList
            idlist_size = _read_u16(data, pos + 8)
            idlist_start = pos + 10
            idlist_end = min(idlist_start + idlist_size, pos + block_size)
            vista_items = []
            item_pos = idlist_start
            vidx = 0
            while item_pos < idlist_end:
                next_pos, item = _parse_idlist_item(data, item_pos, vidx)
                if item is None:
                    break
                vista_items.append(item)
                item_pos = next_pos
                vidx += 1
            info.vista_id_items = vista_items
            block.data["ItemCount"] = str(len(vista_items))

        elif sig == 0xA0000009 and block_size > 8:
            stores = _parse_property_store(data, pos + 8, pos + block_size)
            info.property_stores = stores
            block.data["StoreCount"] = str(len(stores))
            for i, s in enumerate(stores):
                block.data[f"Store[{i}].FormatID"] = s.format_id
                block.data[f"Store[{i}].FormatName"] = s.format_name
                block.data[f"Store[{i}].PropertyCount"] = str(len(s.properties))

        info.extra_blocks.append(block)
        pos += block_size

    # Override icon_location with env-expanded path if present
    if icon_env:
        info.icon_location = icon_env

    return info


# ---------------------------------------------------------------------------
# Human-readable formatter
# ---------------------------------------------------------------------------
def format_lnk(info: LnkInfo) -> str:
    """Return a human-readable string representation of *info*."""
    lines: list[str] = []

    lines.append("--- HEADER ---")
    lines.append(f"  LinkFlags:       0x{info.flags:08X}")
    for name in info.flag_names:
        lines.append(f"    - {name}")
    lines.append(f"  FileAttributes:  0x{info.file_attributes:08X}")
    lines.append(f"  CreationTime:    {info.creation_time}")
    lines.append(f"  AccessTime:      {info.access_time}")
    lines.append(f"  WriteTime:       {info.write_time}")
    lines.append(f"  FileSize:        {info.file_size} (0x{info.file_size:08X})")
    lines.append(f"  IconIndex:       {info.icon_index}")
    lines.append(f"  ShowCommand:     {info.show_command} ({info.show_command_name})")
    hk_display = info.hotkey_str if info.hotkey_str else "None"
    lines.append(
        f"  HotKey:          {hk_display} (vk=0x{info.hotkey_vk:02X} mod=0x{info.hotkey_mod:02X})"
    )

    if info.id_items:
        lines.append("")
        lines.append("--- LINK TARGET ID LIST ---")
        for i, item in enumerate(info.id_items):
            lines.append(
                f"  Item[{i}]: @0x{item.offset:04X} size={item.size}  {item.description}"
            )

    if info.local_base_path or info.volume_label or info.network_share_name:
        lines.append("")
        lines.append("--- LINK INFO ---")
        if info.volume_label:
            lines.append(f'  VolumeLabel:     "{info.volume_label}"')
        if info.drive_type or info.drive_type_name:
            lines.append(
                f"  DriveType:       {info.drive_type} ({info.drive_type_name})"
            )
            lines.append(f"  DriveSerial:     0x{info.drive_serial:08X}")
        if info.local_base_path:
            lines.append(f'  LocalBasePath:   "{info.local_base_path}"')
        if info.common_path:
            lines.append(f'  CommonPath:      "{info.common_path}"')
        if info.network_share_name:
            lines.append(f'  NetworkShare:    "{info.network_share_name}"')
        if info.device_name:
            lines.append(f'  DeviceName:      "{info.device_name}"')
        if info.network_provider_name:
            lines.append(f"  NetProvider:     {info.network_provider_name}")

    has_strings = any(
        [
            info.description,
            info.relative_path,
            info.working_dir,
            info.arguments,
            info.icon_location,
        ]
    )
    if has_strings:
        lines.append("")
        lines.append("--- STRING DATA ---")
        if info.description:
            lines.append(f'  Name:              "{info.description}"')
        if info.relative_path:
            lines.append(f'  RelativePath:      "{info.relative_path}"')
        if info.working_dir:
            lines.append(f'  WorkingDir:        "{info.working_dir}"')
        if info.arguments:
            lines.append(f'  Arguments:         "{info.arguments}"')
        if info.icon_location:
            lines.append(f'  IconLocation:      "{info.icon_location}"')

    if info.extra_blocks:
        lines.append("")
        lines.append("--- EXTRA DATA ---")
        for block in info.extra_blocks:
            lines.append(
                f"  Block: size={block.size} sig=0x{block.signature:08X} ({block.name})"
            )
            for k, v in block.data.items():
                lines.append(f'    {k}: "{v}"')

    if info.vista_id_items:
        lines.append("")
        lines.append("--- VISTA AND ABOVE ID LIST ---")
        for i, item in enumerate(info.vista_id_items):
            lines.append(
                f"  Item[{i}]: @0x{item.offset:04X} size={item.size}  {item.description}"
            )

    if info.property_stores:
        lines.append("")
        lines.append("--- PROPERTY STORES ---")
        for i, store in enumerate(info.property_stores):
            lines.append(f"  Store[{i}]: {store.format_id} ({store.format_name})")
            for prop in store.properties:
                lines.append(
                    f"    PID={prop.id} Type={prop.type_name} Value={prop.value!r}"
                )

    lines.append("")
    lines.append("--- RESOLVED ---")
    lines.append(f"  TargetPath:      {info.target_path or '(empty)'}")
    lines.append(f"  Arguments:       {info.arguments or '(empty)'}")
    lines.append(f"  WorkingDirectory: {info.working_dir or '(empty)'}")
    lines.append(f"  Description:     {info.description or '(empty)'}")
    icon_display = info.icon_location
    if icon_display:
        icon_display = f"{icon_display},{info.icon_index}"
    lines.append(f"  IconLocation:    {icon_display or '(empty)'}")
    lines.append(f"  Hotkey:          {info.hotkey_str or '(empty)'}")
    lines.append(f"  WindowStyle:     {info.show_command}")

    return "\n".join(lines)
