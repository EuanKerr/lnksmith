"""Build Windows .lnk files per the MS-SHLLINK spec -- pure struct packing."""

import struct
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ._constants import (
    ANSI_CODEPAGE,
    CLSID_MY_COMPUTER,
    CLSID_NETWORK,
    EXT_HEADER_SIZE,
    EXT_SIG,
    EXT_VERSION,
    KNOWN_FOLDER_GUIDS,
    LINK_CLSID,
    SW_SHOWNORMAL,
)
from ._types import TargetPath, Timestamp
from ._util import parse_guid_str

# ---------------------------------------------------------------------------
# Timestamp epoch
# ---------------------------------------------------------------------------
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _to_filetime(val: Timestamp = None) -> bytes:
    """Convert *val* to 8-byte packed Windows FILETIME.

    Accepts ``None`` (current UTC), ``int`` (raw 100-ns ticks), or
    ``datetime`` (timezone-aware).
    """
    if val is None:
        td = datetime.now(UTC) - _FILETIME_EPOCH
    elif isinstance(val, int):
        return struct.pack("<Q", val)
    elif isinstance(val, datetime):
        if val.tzinfo is None:
            raise TypeError("datetime must be timezone-aware (e.g. tzinfo=UTC)")
        td = val - _FILETIME_EPOCH
    else:
        raise TypeError(f"Expected None, int, or datetime, got {type(val).__name__}")
    ticks = td.days * 864_000_000_000 + td.seconds * 10_000_000 + td.microseconds * 10
    return struct.pack("<Q", ticks)


def _to_dos_datetime(val: Timestamp = None) -> tuple[int, int]:
    """Convert *val* to (date_word, time_word) DOS format.

    Accepts ``None`` (current UTC), ``int`` (raw FILETIME ticks), or
    ``datetime``.  Returns ``(uint16_date, uint16_time)``.
    """
    if val is None:
        dt = datetime.now(UTC)
    elif isinstance(val, int):
        unix_ts = (val - 116444736000000000) / 10_000_000
        dt = datetime.fromtimestamp(unix_ts, tz=UTC)
    elif isinstance(val, datetime):
        if val.tzinfo is None:
            raise TypeError("datetime must be timezone-aware (e.g. tzinfo=UTC)")
        dt = val
    else:
        raise TypeError(f"Expected None, int, or datetime, got {type(val).__name__}")
    if dt.year < 1980 or dt.year > 2107:
        raise ValueError(f"DOS datetime requires year in 1980..2107, got {dt.year}")
    date_w = ((dt.year - 1980) << 9) | (dt.month << 5) | dt.day
    time_w = (dt.hour << 11) | (dt.minute << 5) | (dt.second // 2)
    return date_w, time_w


def _counted_utf16(s: str, *, max_length: int = 0) -> bytes:
    """StringData entry: uint16 char_count followed by UTF-16LE chars.

    Args:
        s: The string to encode.
        max_length: Maximum character count (0 = unbounded).  Per the v10.0
            spec (section 2.4), NAME_STRING, RELATIVE_PATH, WORKING_DIR, and
            ICON_LOCATION MUST NOT exceed 260 characters.
            COMMAND_LINE_ARGUMENTS is unbounded.
    """
    if max_length and len(s) > max_length:
        raise ValueError(
            f"StringData field exceeds {max_length}-character limit "
            f"(got {len(s)} characters)"
        )
    return struct.pack("<H", len(s)) + s.encode("utf-16-le")


# ---------------------------------------------------------------------------
# IDList item builders
# ---------------------------------------------------------------------------
def _id_root() -> bytes:
    """My Computer root shell item (type 0x1F, sort 0x50)."""
    body = b"\x1f\x50" + CLSID_MY_COMPUTER
    return struct.pack("<H", len(body) + 2) + body


def _id_network_root() -> bytes:
    """Network Neighborhood root shell item (type 0x1F, sort 0x47)."""
    body = b"\x1f\x47" + CLSID_NETWORK
    return struct.pack("<H", len(body) + 2) + body


def _id_drive(letter: str) -> bytes:
    """Drive-letter volume item (type 0x2F), padded to 25 bytes like Windows."""
    body = bytearray(23)  # 25 total - 2 size prefix = 23 body
    body[0] = 0x2F
    drive_str = f"{letter}:\\".encode(ANSI_CODEPAGE)
    body[1 : 1 + len(drive_str)] = drive_str
    return struct.pack("<H", 25) + bytes(body)


def _id_network_share(share_path: str) -> bytes:
    """Network share shell item (type 0x46).

    *share_path* should be like ``\\\\server\\share``.
    """
    body = bytearray()
    body.append(0x46)
    body.append(0x80)  # flags
    unc = share_path.encode(ANSI_CODEPAGE) + b"\x00"
    body += unc
    body += b"\x00"  # empty comment
    return struct.pack("<H", len(body) + 2) + bytes(body)


def _build_extension(name: str, mod_date: int, mod_time: int, base_size: int) -> bytes:
    """Build a version 9 BEEF0004 extension block for a shell item.

    Fields derived from reverse-engineering a real Win10/11 Chrome.lnk:
      +00: size (uint16)          +02: version (9)
      +04: signature (0xBEEF0004) +08: created date (DOS)
      +10: created time (DOS)     +12: accessed date (DOS)
      +14: accessed time (DOS)    +16: unicode name offset (46)
      +18: unknown (0)            +20: NTFS MFT ref (8 bytes, zeroed)
      +28: unknown (8 bytes, 0)   +36: localized name offset (uint32, 0)
      +40: unknown (0)            +42: unknown/hash (uint32, 0)
      +46: unicode name (null-terminated UTF-16LE)
      trailing: base_size (uint16) -- back-reference to pre-extension item size
    """
    uname = name.encode("utf-16-le") + b"\x00\x00"
    total = EXT_HEADER_SIZE + len(uname) + 2  # +2 for trailing base_size

    ext = bytearray()
    ext += struct.pack("<H", total)  # +00 size
    ext += struct.pack("<H", EXT_VERSION)  # +02 version
    ext += struct.pack("<I", EXT_SIG)  # +04 signature
    ext += struct.pack("<H", mod_date)  # +08 created date (reuse mod)
    ext += struct.pack("<H", mod_time)  # +10 created time
    ext += struct.pack("<H", mod_date)  # +12 accessed date
    ext += struct.pack("<H", mod_time)  # +14 accessed time
    ext += struct.pack("<H", EXT_HEADER_SIZE)  # +16 unicode name offset
    ext += struct.pack("<H", 0)  # +18 unknown
    ext += b"\x00" * 8  # +20 NTFS MFT ref
    ext += b"\x00" * 8  # +28 unknown
    ext += struct.pack("<I", 0)  # +36 localized name offset
    ext += struct.pack("<H", 0)  # +40 unknown
    ext += struct.pack("<I", 0)  # +42 hash
    ext += uname  # +46 unicode name
    ext += struct.pack("<H", base_size)  # trailing

    return bytes(ext)


def _id_fs_entry(
    name: str,
    is_dir: bool,
    file_size: int = 0,
    long_name: str | None = None,
    write_time: Timestamp = None,
) -> bytes:
    """File-system item with version 9 BEEF0004 extension block.

    Args:
        name:       Short name (8.3 format), encoded with the ANSI code page.
        is_dir:     True for directory entries, False for file entries.
        file_size:  File size in bytes (used for file entries).
        long_name:  Unicode long name for the BEEF0004 extension block.
                    Defaults to name if not provided.
        write_time: Optional timestamp for the item (None, int, or datetime).
    """
    if long_name is None:
        long_name = name

    mod_date, mod_time = _to_dos_datetime(write_time)

    type_byte = 0x31 if is_dir else 0x32
    attrs = 0x10 if is_dir else 0x20

    # Base body: type + pad + fsize + date + time + attrs + shortname + pad
    base = bytearray()
    base.append(type_byte)
    base.append(0x00)
    base += struct.pack("<I", file_size)
    base += struct.pack("<HH", mod_date, mod_time)  # date first, time second
    base += struct.pack("<H", attrs)
    base += name.encode(ANSI_CODEPAGE) + b"\x00"
    if len(base) % 2:
        base += b"\x00"

    base_size = len(base) + 2  # including the 2-byte item size prefix
    ext = _build_extension(long_name, mod_date, mod_time, base_size)
    body = bytes(base) + ext
    return struct.pack("<H", len(body) + 2) + body


def _build_idlist(
    target_path: TargetPath, file_size: int = 0, write_time: Timestamp = None
) -> bytes:
    """Full LinkTargetIDList section for an absolute Windows path.

    Args:
        target_path: Absolute Windows path. Each component can be a plain
                     string or a (short_name, long_name) tuple for 8.3
                     short name support.
        file_size:   Size of the target file (applied to the final entry).
        write_time:  Optional timestamp for IDList items (None, int, or datetime).
    """
    items = bytearray()
    items += _id_root()

    # Accept either a plain path string or pre-split list of segments
    if isinstance(target_path, str):
        parts = target_path.replace("/", "\\").split("\\")
        drive = parts[0].rstrip(":")
        path_parts = [p for p in parts[1:] if p]
    else:
        # target_path is a list: first element is drive letter, rest are
        # path segments (str or (short, long) tuples)
        drive = target_path[0]
        path_parts = target_path[1:]

    items += _id_drive(drive)

    for i, segment in enumerate(path_parts):
        is_dir = i < len(path_parts) - 1
        entry_size = file_size if not is_dir else 0
        if isinstance(segment, tuple):
            short_name, long_name = segment
            items += _id_fs_entry(
                short_name,
                is_dir,
                file_size=entry_size,
                long_name=long_name,
                write_time=write_time,
            )
        else:
            items += _id_fs_entry(
                segment, is_dir, file_size=entry_size, write_time=write_time
            )

    items += struct.pack("<H", 0)  # terminator
    return struct.pack("<H", len(items)) + items


def _build_idlist_unc(
    unc_path: str, file_size: int = 0, write_time: Timestamp = None
) -> bytes:
    """Full LinkTargetIDList for a UNC path like ``\\\\server\\share\\...``."""
    parts = unc_path.lstrip("\\").split("\\")
    if len(parts) < 2:
        parts.append("")

    server = parts[0]
    share = parts[1]
    share_path = f"\\\\{server}\\{share}"
    fs_parts = [p for p in parts[2:] if p]

    items = bytearray()
    items += _id_network_root()
    items += _id_network_share(share_path)

    for i, segment in enumerate(fs_parts):
        is_dir = i < len(fs_parts) - 1
        entry_size = file_size if not is_dir else 0
        if isinstance(segment, tuple):
            short_name, long_name = segment
            items += _id_fs_entry(
                short_name,
                is_dir,
                file_size=entry_size,
                long_name=long_name,
                write_time=write_time,
            )
        else:
            items += _id_fs_entry(
                segment, is_dir, file_size=entry_size, write_time=write_time
            )

    items += struct.pack("<H", 0)  # terminator
    return struct.pack("<H", len(items)) + items


def _build_idlist_items(
    target_path: TargetPath, file_size: int = 0, write_time: Timestamp = None
) -> bytes:
    """Build just the IDList item bytes (no outer size prefix).

    Used by VistaAndAboveIDListDataBlock builder.
    """
    items = bytearray()
    items += _id_root()

    if isinstance(target_path, str):
        parts = target_path.replace("/", "\\").split("\\")
        drive = parts[0].rstrip(":")
        path_parts = [p for p in parts[1:] if p]
    else:
        drive = target_path[0]
        path_parts = target_path[1:]

    items += _id_drive(drive)

    for i, segment in enumerate(path_parts):
        is_dir = i < len(path_parts) - 1
        entry_size = file_size if not is_dir else 0
        if isinstance(segment, tuple):
            short_name, long_name = segment
            items += _id_fs_entry(
                short_name,
                is_dir,
                file_size=entry_size,
                long_name=long_name,
                write_time=write_time,
            )
        else:
            items += _id_fs_entry(
                segment, is_dir, file_size=entry_size, write_time=write_time
            )

    items += struct.pack("<H", 0)  # terminator
    return bytes(items)


# ---------------------------------------------------------------------------
# LinkInfo
# ---------------------------------------------------------------------------
def _build_linkinfo(
    target_path: str, vol_label: str = "", serial: int = 0x4A2D5E79, drive_type: int = 3
) -> bytes:
    """LinkInfo section with VolumeID + local base path (ANSI + Unicode)."""
    path = target_path.replace("/", "\\")

    # VolumeID -- use Unicode label when content is not pure ASCII/CP1252
    use_unicode_label = False
    if vol_label:
        try:
            vol_label.encode(ANSI_CODEPAGE)
        except UnicodeEncodeError:
            use_unicode_label = True

    vol_id = bytearray()
    vol_id += struct.pack("<I", 0)  # VolumeIDSize (fill later)
    vol_id += struct.pack("<I", drive_type)  # DriveType
    vol_id += struct.pack("<I", serial)  # DriveSerialNumber

    if use_unicode_label:
        # GAP-D: VolumeLabelOffset=0x14 signals Unicode label
        vol_id += struct.pack("<I", 0x14)  # VolumeLabelOffset (trigger)
        uni_label_off = len(vol_id) + 4  # after VolumeLabelOffsetUnicode
        vol_id += struct.pack("<I", uni_label_off)  # VolumeLabelOffsetUnicode
        vol_id += vol_label.encode("utf-16-le") + b"\x00\x00"
    else:
        label_bytes = (
            vol_label.encode(ANSI_CODEPAGE) + b"\x00" if vol_label else b"\x00"
        )
        vol_id += struct.pack("<I", 0x10)  # VolumeLabelOffset (= 16)
        vol_id += label_bytes

    struct.pack_into("<I", vol_id, 0, len(vol_id))

    local_base_ansi = path.encode(ANSI_CODEPAGE) + b"\x00"
    local_base_uni = path.encode("utf-16-le") + b"\x00\x00"
    suffix_ansi = b"\x00"
    suffix_uni = b"\x00\x00"

    hdr_size = 0x24  # 36 bytes -- includes Unicode offset fields
    vol_offset = hdr_size
    base_offset = vol_offset + len(vol_id)
    suffix_offset = base_offset + len(local_base_ansi)
    uni_base_offset = suffix_offset + len(suffix_ansi)
    uni_suffix_offset = uni_base_offset + len(local_base_uni)

    info = bytearray()
    info += struct.pack("<I", 0)  # LinkInfoSize (fill later)
    info += struct.pack("<I", hdr_size)  # LinkInfoHeaderSize
    info += struct.pack("<I", 0x01)  # Flags: VolumeIDAndLocalBasePath
    info += struct.pack("<I", vol_offset)  # VolumeIDOffset
    info += struct.pack("<I", base_offset)  # LocalBasePathOffset
    info += struct.pack("<I", 0)  # CommonNetworkRelativeLinkOffset
    info += struct.pack("<I", suffix_offset)  # CommonPathSuffixOffset
    info += struct.pack("<I", uni_base_offset)  # LocalBasePathOffsetUnicode
    info += struct.pack("<I", uni_suffix_offset)  # CommonPathSuffixOffsetUnicode
    info += vol_id
    info += local_base_ansi
    info += suffix_ansi
    info += local_base_uni
    info += suffix_uni
    struct.pack_into("<I", info, 0, len(info))

    return bytes(info)


def _build_linkinfo_unc(
    unc_path: str, device_name: str = "", network_provider_type: int = 0x00020000
) -> bytes:
    """LinkInfo section with CommonNetworkRelativeLink for UNC paths.

    Args:
        unc_path: UNC path string (e.g. ``\\\\server\\share\\path``).
        device_name: Optional mapped drive letter (e.g. ``"Z:"``).
        network_provider_type: WNNC_NET_* value (default WNNC_NET_LANMAN).
    """
    path = unc_path.replace("/", "\\")
    parts = path.lstrip("\\").split("\\")
    if len(parts) < 2:
        parts.append("")

    share_name = "\\\\" + parts[0] + "\\" + parts[1]
    suffix = "\\".join(parts[2:]) if len(parts) > 2 else ""

    # ANSI encoded fields
    share_bytes = share_name.encode(ANSI_CODEPAGE) + b"\x00"
    device_bytes = (
        (device_name.encode(ANSI_CODEPAGE) + b"\x00") if device_name else b"\x00"
    )

    # CNR flags
    cnr_flags = 0x02  # ValidNetType
    if device_name:
        cnr_flags |= 0x01  # ValidDevice

    # GAP-E: Extended header with Unicode variants (NetNameOffset > 0x14)
    cnr_hdr_size = 0x1C  # 28 bytes (extended, with Unicode offset fields)
    cnr_net_name_off = cnr_hdr_size
    cnr_device_off = cnr_net_name_off + len(share_bytes)

    # Unicode fields follow ANSI fields
    share_uni = share_name.encode("utf-16-le") + b"\x00\x00"
    device_uni = (
        (device_name.encode("utf-16-le") + b"\x00\x00") if device_name else b"\x00\x00"
    )
    ansi_end = cnr_device_off + len(device_bytes)
    cnr_net_name_uni_off = ansi_end
    cnr_device_name_uni_off = cnr_net_name_uni_off + len(share_uni)

    cnr = bytearray()
    cnr += struct.pack("<I", 0)  # CNR size (fill later)
    cnr += struct.pack("<I", cnr_flags)
    cnr += struct.pack("<I", cnr_net_name_off)  # NetNameOffset (ANSI)
    cnr += struct.pack("<I", cnr_device_off)  # DeviceNameOffset (ANSI)
    cnr += struct.pack("<I", network_provider_type)
    cnr += struct.pack("<I", cnr_net_name_uni_off)  # NetNameOffsetUnicode
    cnr += struct.pack("<I", cnr_device_name_uni_off)  # DeviceNameOffsetUnicode
    cnr += share_bytes
    cnr += device_bytes
    cnr += share_uni
    cnr += device_uni
    struct.pack_into("<I", cnr, 0, len(cnr))

    suffix_ansi = suffix.encode(ANSI_CODEPAGE) + b"\x00" if suffix else b"\x00"
    suffix_uni = suffix.encode("utf-16-le") + b"\x00\x00" if suffix else b"\x00\x00"

    hdr_size = 0x24  # 36 bytes -- includes Unicode offset fields
    cnr_offset = hdr_size
    suffix_offset = cnr_offset + len(cnr)
    # Unicode offsets follow ANSI suffix
    uni_base_offset = suffix_offset + len(
        suffix_ansi
    )  # LocalBasePathOffsetUnicode (unused, but required)
    uni_suffix_offset = uni_base_offset  # CommonPathSuffixOffsetUnicode

    info = bytearray()
    info += struct.pack("<I", 0)  # LinkInfoSize
    info += struct.pack("<I", hdr_size)
    info += struct.pack("<I", 0x02)  # Flags: CommonNetworkRelativeLink
    info += struct.pack("<I", 0)  # VolumeIDOffset (unused)
    info += struct.pack("<I", 0)  # LocalBasePathOffset (unused)
    info += struct.pack("<I", cnr_offset)  # CommonNetworkRelativeLinkOffset
    info += struct.pack("<I", suffix_offset)  # CommonPathSuffixOffset
    info += struct.pack("<I", 0)  # LocalBasePathOffsetUnicode (unused)
    info += struct.pack("<I", uni_suffix_offset)  # CommonPathSuffixOffsetUnicode
    info += cnr
    info += suffix_ansi
    info += suffix_uni
    struct.pack_into("<I", info, 0, len(info))

    return bytes(info)


# ---------------------------------------------------------------------------
# ExtraData blocks
# ---------------------------------------------------------------------------
def _build_icon_env_block(icon_env_path: str) -> bytes:
    """IconEnvironmentDataBlock (sig 0xA0000007).

    788 bytes: 4 size + 4 sig + 260 ANSI + 520 Unicode.
    Provides the icon path using environment variables like %ProgramFiles%.
    """
    block = bytearray(788)
    struct.pack_into("<I", block, 0, 788)  # size
    struct.pack_into("<I", block, 4, 0xA0000007)  # signature
    # TargetAnsi (260 bytes at offset 8) -- truncate to fit slot
    ansi = icon_env_path[:259].encode(ANSI_CODEPAGE) + b"\x00"
    block[8 : 8 + len(ansi)] = ansi
    # TargetUnicode (520 bytes at offset 268) -- truncate to fit slot
    uni = icon_env_path[:259].encode("utf-16-le") + b"\x00\x00"
    block[268 : 268 + len(uni)] = uni
    return bytes(block)


def _build_env_var_block(env_path: str) -> bytes:
    """EnvironmentVariableDataBlock (sig 0xA0000001).

    788 bytes: 4 size + 4 sig + 260 ANSI + 520 Unicode.
    Provides the target path using environment variables for resolution.
    """
    block = bytearray(788)
    struct.pack_into("<I", block, 0, 788)  # size
    struct.pack_into("<I", block, 4, 0xA0000001)  # signature
    # TargetAnsi (260 bytes at offset 8) -- truncate to fit slot
    ansi = env_path[:259].encode(ANSI_CODEPAGE) + b"\x00"
    block[8 : 8 + len(ansi)] = ansi
    # TargetUnicode (520 bytes at offset 268) -- truncate to fit slot
    uni = env_path[:259].encode("utf-16-le") + b"\x00\x00"
    block[268 : 268 + len(uni)] = uni
    return bytes(block)


def _build_tracker_block(
    machine_id: str = "",
    droid_volume_id: str = "",
    droid_file_id: str = "",
    birth_droid_volume_id: str = "",
    birth_droid_file_id: str = "",
) -> bytes:
    """TrackerDataBlock (sig 0xA0000003), 96 bytes total."""
    block = bytearray(96)
    struct.pack_into("<I", block, 0, 96)  # BlockSize
    struct.pack_into("<I", block, 4, 0xA0000003)  # Signature
    struct.pack_into("<I", block, 8, 0x00000058)  # Length (88)
    struct.pack_into("<I", block, 12, 0)  # Version
    # MachineID: 16 bytes at offset 16
    mid = machine_id.encode("ascii")[:15] + b"\x00"
    block[16 : 16 + len(mid)] = mid
    # GUIDs (16 bytes each)
    if droid_volume_id:
        block[32:48] = parse_guid_str(droid_volume_id)
    if droid_file_id:
        block[48:64] = parse_guid_str(droid_file_id)
    if birth_droid_volume_id:
        block[64:80] = parse_guid_str(birth_droid_volume_id)
    if birth_droid_file_id:
        block[80:96] = parse_guid_str(birth_droid_file_id)
    return bytes(block)


def _build_known_folder_block(folder_id: str, idlist_offset: int = 0) -> bytes:
    """KnownFolderDataBlock (sig 0xA000000B), 28 bytes.

    Args:
        folder_id: GUID string (with or without braces) or a friendly name
                   from KNOWN_FOLDER_GUIDS (e.g. ``"Desktop"``).
        idlist_offset: Offset into the IDList for this folder.
    """
    if not folder_id.startswith("{"):
        folder_id = KNOWN_FOLDER_GUIDS.get(folder_id, folder_id)

    block = bytearray(28)
    struct.pack_into("<I", block, 0, 28)  # Size
    struct.pack_into("<I", block, 4, 0xA000000B)  # Signature
    block[8:24] = parse_guid_str(folder_id)  # KnownFolderID
    struct.pack_into("<I", block, 24, idlist_offset)  # Offset
    return bytes(block)


def _build_vista_idlist_block(idlist_bytes: bytes) -> bytes:
    """VistaAndAboveIDListDataBlock (sig 0xA000000C).

    Args:
        idlist_bytes: Pre-built IDList item bytes (items + terminator,
                      no outer size prefix).
    """
    # IDList is prefixed with its own uint16 size
    idlist_with_size = struct.pack("<H", len(idlist_bytes)) + idlist_bytes
    block_size = 4 + 4 + len(idlist_with_size)
    block = bytearray()
    block += struct.pack("<I", block_size)
    block += struct.pack("<I", 0xA000000C)
    block += idlist_with_size
    return bytes(block)


def _build_property_store_block(stores: list[dict[str, object]]) -> bytes:
    """PropertyStoreDataBlock (sig 0xA0000009).

    Args:
        stores: list of dicts, each with:
            - ``"format_id"``: GUID string
            - ``"properties"``: list of dicts with ``"id"``, ``"type"``,
              ``"value"``
    """
    body = bytearray()

    for store_def in stores:
        storage = bytearray()
        storage += struct.pack("<I", 0)  # StorageSize (fill later)
        storage += struct.pack("<I", 0x53505331)  # Version "1SPS"
        storage += parse_guid_str(store_def["format_id"])  # FormatID (16 bytes)

        for prop in store_def.get("properties", []):
            storage += _serialize_property(prop)

        struct.pack_into("<I", storage, 0, len(storage))
        body += storage

    # Terminal storage (4 zero bytes)
    body += struct.pack("<I", 0)

    block_size = 4 + 4 + len(body)
    block = bytearray()
    block += struct.pack("<I", block_size)
    block += struct.pack("<I", 0xA0000009)
    block += body
    return bytes(block)


def _serialize_property(prop: dict[str, object]) -> bytes:
    """Serialize a single property record for a PropertyStore."""
    pid = prop["id"]
    vtype = prop["type"]
    value = prop["value"]

    # Build typed value
    typed = bytearray()
    typed += struct.pack("<H", vtype)  # Type
    typed += struct.pack("<H", 0)  # Padding

    if vtype == 0x001F:  # VT_LPWSTR
        encoded = value.encode("utf-16-le") + b"\x00\x00"
        char_count = len(encoded) // 2
        typed += struct.pack("<I", char_count)
        typed += encoded
    elif vtype == 0x001E:  # VT_LPSTR
        encoded = value.encode(ANSI_CODEPAGE) + b"\x00"
        typed += struct.pack("<I", len(encoded))
        typed += encoded
    elif vtype == 0x0002:  # VT_I2
        typed += struct.pack("<h", value)
        typed += b"\x00\x00"  # padding to 4-byte align
    elif vtype == 0x0013:  # VT_UI4
        typed += struct.pack("<I", value)
    elif vtype == 0x0003:  # VT_I4
        typed += struct.pack("<i", value)
    elif vtype == 0x0014:  # VT_UI8
        typed += struct.pack("<Q", value)
    elif vtype == 0x000B:  # VT_BOOL
        typed += struct.pack("<H", 0xFFFF if value else 0x0000)
        typed += b"\x00\x00"  # padding to 4-byte align
    elif vtype == 0x0040:  # VT_FILETIME
        typed += struct.pack("<Q", value)
    elif vtype == 0x0048:  # VT_CLSID
        typed += parse_guid_str(value)

    # Property record: ValueSize(4) + ID(4) + Reserved(1) + TypedValue
    value_size = 4 + 4 + 1 + len(typed)
    record = bytearray()
    record += struct.pack("<I", value_size)
    record += struct.pack("<I", pid)
    record += struct.pack("<B", 0)  # Reserved
    record += typed
    return bytes(record)


def _build_darwin_block(darwin_data: str) -> bytes:
    """DarwinDataBlock (sig 0xA0000006).

    788 bytes: 4 size + 4 sig + 260 ANSI + 520 Unicode.
    Identical layout to EnvironmentVariableDataBlock.
    """
    block = bytearray(788)
    struct.pack_into("<I", block, 0, 788)  # size
    struct.pack_into("<I", block, 4, 0xA0000006)  # signature
    # Truncate to fit fixed-size slots (259 chars + null terminator)
    ansi = darwin_data[:259].encode(ANSI_CODEPAGE) + b"\x00"
    block[8 : 8 + len(ansi)] = ansi
    uni = darwin_data[:259].encode("utf-16-le") + b"\x00\x00"
    block[268 : 268 + len(uni)] = uni
    return bytes(block)


def _build_console_fe_block(codepage: int) -> bytes:
    """ConsoleFEDataBlock (sig 0xA0000004), 12 bytes.

    Fields: BlockSize (4) + BlockSignature (4) + CodePage (4).
    """
    block = bytearray(12)
    struct.pack_into("<I", block, 0, 12)  # size
    struct.pack_into("<I", block, 4, 0xA0000004)  # signature
    struct.pack_into("<I", block, 8, codepage)  # CodePage
    return bytes(block)


def _build_shim_block(layer_name: str) -> bytes:
    """ShimDataBlock (sig 0xA0000008), variable size.

    The LayerName is a Unicode (UTF-16LE) string following the 8-byte header.
    Spec 2.5.8: BlockSize MUST be >= 0x88.
    """
    uni = layer_name.encode("utf-16-le") + b"\x00\x00"
    payload_size = len(uni)
    # Spec requires minimum 0x88 bytes; pad if needed.
    block_size = max(0x88, 8 + payload_size)
    block = bytearray()
    block += struct.pack("<I", block_size)  # size
    block += struct.pack("<I", 0xA0000008)  # signature
    block += uni
    # Pad to declared block_size
    if len(block) < block_size:
        block += b"\x00" * (block_size - len(block))
    return bytes(block)


def _build_console_block(data: dict[str, object]) -> bytes:
    """ConsoleDataBlock (sig 0xA0000002), 204 bytes fixed.

    Args:
        data: Dict with optional keys: fill_attributes, popup_fill_attributes,
              screen_buffer_size_x, screen_buffer_size_y, window_size_x,
              window_size_y, window_origin_x, window_origin_y, font_size,
              font_family, font_weight, face_name, cursor_size, full_screen,
              quick_edit, insert_mode, auto_position, history_buffer_size,
              number_of_history_buffers, history_no_dup, color_table.
    """
    block = bytearray(204)
    struct.pack_into("<I", block, 0, 0xCC)  # BlockSize
    struct.pack_into("<I", block, 4, 0xA0000002)  # BlockSignature
    struct.pack_into("<H", block, 8, data.get("fill_attributes", 0))
    struct.pack_into("<H", block, 10, data.get("popup_fill_attributes", 0))
    struct.pack_into("<h", block, 12, data.get("screen_buffer_size_x", 80))
    struct.pack_into("<h", block, 14, data.get("screen_buffer_size_y", 300))
    struct.pack_into("<h", block, 16, data.get("window_size_x", 80))
    struct.pack_into("<h", block, 18, data.get("window_size_y", 25))
    struct.pack_into("<h", block, 20, data.get("window_origin_x", 0))
    struct.pack_into("<h", block, 22, data.get("window_origin_y", 0))
    # Unused1 (offset 24, 4 bytes) and Unused2 (offset 28, 4 bytes) = 0
    struct.pack_into("<I", block, 32, data.get("font_size", 0))
    struct.pack_into("<I", block, 36, data.get("font_family", 0))
    struct.pack_into("<I", block, 40, data.get("font_weight", 0))
    # FaceName: 64 bytes (32 wchars) at offset 44
    face = data.get("face_name", "")
    if face:
        face_encoded = face.encode("utf-16-le")[:62] + b"\x00\x00"
        block[44 : 44 + min(len(face_encoded), 64)] = face_encoded[:64]
    struct.pack_into("<I", block, 108, data.get("cursor_size", 25))
    struct.pack_into("<I", block, 112, data.get("full_screen", 0))
    struct.pack_into("<I", block, 116, data.get("quick_edit", 0))
    struct.pack_into("<I", block, 120, data.get("insert_mode", 0))
    struct.pack_into("<I", block, 124, data.get("auto_position", 0))
    struct.pack_into("<I", block, 128, data.get("history_buffer_size", 50))
    struct.pack_into("<I", block, 132, data.get("number_of_history_buffers", 4))
    struct.pack_into("<I", block, 136, data.get("history_no_dup", 0))
    # ColorTable: 16 uint32 RGB values at offset 140 (64 bytes)
    color_table = data.get("color_table", [])
    for i, color in enumerate(color_table[:16]):
        struct.pack_into("<I", block, 140 + i * 4, color)
    return bytes(block)


def _build_special_folder_block(folder_id: int, offset: int = 0) -> bytes:
    """SpecialFolderDataBlock (sig 0xA0000005), 16 bytes.

    Args:
        folder_id: The special folder integer ID (uint32).
        offset: Offset into the IDList (uint32).
    """
    block = bytearray(16)
    struct.pack_into("<I", block, 0, 16)  # BlockSize
    struct.pack_into("<I", block, 4, 0xA0000005)  # BlockSignature
    struct.pack_into("<I", block, 8, folder_id)  # SpecialFolderID
    struct.pack_into("<I", block, 12, offset)  # Offset
    return bytes(block)


def _build_terminal_block() -> bytes:
    """Terminal ExtraData block (4 zero bytes)."""
    return b"\x00\x00\x00\x00"


# ---------------------------------------------------------------------------
# Main builder
# ---------------------------------------------------------------------------
def build_lnk(
    target: TargetPath,
    icon_location: str = "",
    icon_env_path: str = "",
    env_target_path: str = "",
    icon_index: int = 0,
    description: str = "",
    relative_path: str = "",
    working_dir: str = "",
    arguments: str = "",
    show_command: int = SW_SHOWNORMAL,
    file_size: int = 0,
    file_attributes: int = 0x20,
    hotkey_vk: int = 0,
    hotkey_mod: int = 0,
    link_flags: int = 0,
    creation_time: Timestamp = None,
    access_time: Timestamp = None,
    write_time: Timestamp = None,
    tracker_machine_id: str = "",
    tracker_droid_volume_id: str = "",
    tracker_droid_file_id: str = "",
    tracker_birth_droid_volume_id: str = "",
    tracker_birth_droid_file_id: str = "",
    known_folder_id: str = "",
    vista_idlist: TargetPath | None = None,
    property_stores: list[dict[str, object]] | None = None,
    darwin_data: str = "",
    console_fe_codepage: int = 0,
    shim_layer_name: str = "",
    console_data: dict[str, object] | None = None,
    special_folder_id: int | None = None,
    special_folder_offset: int = 0,
    volume_label: str = "",
    drive_serial: int = 0x4A2D5E79,
    drive_type: int = 3,
    network_device_name: str = "",
    network_provider_type: int = 0x00020000,
) -> bytes:
    """Return the raw bytes of a complete .lnk file.

    Args:
        target:          Full Windows path string, OR a list of path
                         segments for 8.3 short name support. List form:
                         ["C", ("PROGRA~1", "Program Files"), "subdir", ...]
                         where each element is a string or (short, long) tuple.
                         UNC paths (starting with ``\\\\``) are supported.
        icon_location:   Full Windows path to the icon source (StringData).
        icon_env_path:   Icon path with env vars for IconEnvironmentDataBlock.
        env_target_path: Target path with env vars for EnvironmentVariableDataBlock.
        icon_index:      Icon resource index within icon_location.
        description:     Tooltip / comment text (Name StringData).
        relative_path:   Relative path from LNK location to target.
        working_dir:     Start-in directory.
        arguments:       Command-line arguments for the target.
        show_command:    Window state: SW_SHOWNORMAL (1), SW_MAXIMIZED (3),
                         or SW_MINIMIZED (7).
        file_size:       Target file size in bytes (populates header + IDList).
        file_attributes: FileAttributesFlags (section 2.1.2).  Defaults to
                         0x20 (FILE_ATTRIBUTE_ARCHIVE).
        hotkey_vk:       Virtual key code (e.g. 0x43 for 'C').
        hotkey_mod:      Modifier mask (0x02=CTRL, 0x01=SHIFT, 0x04=ALT).
        link_flags:      Additional LinkFlags bits to OR into the auto-computed
                         flags (e.g. 0x00040000 for ForceNoLinkTrack).
        creation_time:   Header CreationTime. None (current UTC), int (raw
                         FILETIME ticks), or datetime. Default None.
        access_time:     Header AccessTime.  Same types as creation_time.
        write_time:      Header WriteTime and IDList item timestamps.  Same
                         types as creation_time.
        tracker_machine_id:          Tracker MachineID (ASCII, max 15 chars).
        tracker_droid_volume_id:     Tracker DroidVolumeID (GUID string).
        tracker_droid_file_id:       Tracker DroidFileID (GUID string).
        tracker_birth_droid_volume_id: Tracker BirthDroidVolumeID (GUID string).
        tracker_birth_droid_file_id:   Tracker BirthDroidFileID (GUID string).
        known_folder_id: Known folder GUID or friendly name (e.g. "Desktop").
        vista_idlist:    Path segments for VistaAndAboveIDListDataBlock (same
                         format as *target*).
        property_stores: List of dicts for PropertyStoreDataBlock. Each dict
                         has ``"format_id"`` (GUID) and ``"properties"``
                         (list of ``{"id": int, "type": int, "value": ...}``).
        darwin_data:     Application identifier for DarwinDataBlock (MSI
                         descriptor string).  Sets HasDarwinID flag.
        console_fe_codepage: Code page for ConsoleFEDataBlock (uint32).
        shim_layer_name: Shim layer name for ShimDataBlock (Unicode string).
                         Sets RunWithShimLayer flag.
        console_data:    Dict of ConsoleDataBlock fields (see
                         ``_build_console_block``).
        special_folder_id: Folder ID (uint32) for SpecialFolderDataBlock.
        special_folder_offset: IDList offset for SpecialFolderDataBlock.
        volume_label:    Volume label string for VolumeID in LinkInfo.
                         Non-ASCII labels are written as Unicode (spec 2.3.1).
        drive_serial:    Drive serial number (uint32, default 0x4A2D5E79).
        drive_type:      Drive type (uint32).  3=DRIVE_FIXED (default),
                         0=UNKNOWN, 2=REMOVABLE, 4=REMOTE, 5=CDROM, 6=RAMDISK.
        network_device_name: Mapped drive letter for UNC targets (e.g. ``"Z:"``).
                         Sets ValidDevice flag in CommonNetworkRelativeLink.
        network_provider_type: WNNC_NET_* network provider type for UNC targets.
                         Default 0x00020000 (WNNC_NET_LANMAN).
    """
    # Resolve target to a path string for LinkInfo / StringData
    if isinstance(target, list):

        def _long(seg):
            return seg[1] if isinstance(seg, tuple) else seg

        target_path_str = target[0] + ":\\" + "\\".join(_long(s) for s in target[1:])
    else:
        target_path_str = target

    is_unc = isinstance(target, str) and target.startswith("\\\\")

    # GAP-L: Validate ShowCommand (spec 2.1 -- only 1, 3, 7 are valid)
    if show_command not in (1, 3, 7):
        raise ValueError(
            f"Invalid show_command {show_command}; "
            f"must be SW_SHOWNORMAL (1), SW_MAXIMIZED (3), or SW_MINIMIZED (7)"
        )

    # -- Flags --
    flags = 0x00000001 | 0x00000002 | 0x00000080  # IDList + LinkInfo + IsUnicode
    if description:
        flags |= 0x00000004  # HasName
    if relative_path:
        flags |= 0x00000008  # HasRelativePath
    if working_dir:
        flags |= 0x00000010  # HasWorkingDir
    if arguments:
        flags |= 0x00000020  # HasArguments
    if icon_location:
        flags |= 0x00000040  # HasIconLocation
    if env_target_path:
        flags |= 0x00000200  # HasExpString
    if icon_env_path:
        flags |= 0x00004000  # HasExpIcon
    if darwin_data:
        flags |= 0x00001000  # HasDarwinID
    if shim_layer_name:
        flags |= 0x00020000  # RunWithShimLayer
    if is_unc:
        flags |= 0x04000000  # KeepLocalIDListForUNCTarget
    flags |= link_flags  # merge caller-supplied additional bits

    # -- 76-byte header --
    hdr = bytearray(76)
    struct.pack_into("<I", hdr, 0, 0x4C)
    hdr[4:20] = LINK_CLSID
    struct.pack_into("<I", hdr, 20, flags)
    struct.pack_into("<I", hdr, 24, file_attributes)
    hdr[28:36] = _to_filetime(creation_time)
    hdr[36:44] = _to_filetime(access_time)
    hdr[44:52] = _to_filetime(write_time)
    struct.pack_into("<I", hdr, 52, file_size)  # FileSize
    struct.pack_into("<i", hdr, 56, icon_index)  # IconIndex
    struct.pack_into("<I", hdr, 60, show_command)  # ShowCommand
    struct.pack_into("<B", hdr, 64, hotkey_vk)  # HotKey low byte (vk)
    struct.pack_into("<B", hdr, 65, hotkey_mod)  # HotKey high byte (mod)

    out = bytearray(hdr)

    if is_unc:
        out += _build_idlist_unc(target, file_size=file_size, write_time=write_time)
        out += _build_linkinfo_unc(
            target,
            device_name=network_device_name,
            network_provider_type=network_provider_type,
        )
    else:
        out += _build_idlist(target, file_size=file_size, write_time=write_time)
        out += _build_linkinfo(
            target_path_str,
            vol_label=volume_label,
            serial=drive_serial,
            drive_type=drive_type,
        )

    # -- StringData (spec order: Name, RelPath, WorkDir, Args, IconLoc) --
    # v10.0 spec (section 2.4): all except COMMAND_LINE_ARGUMENTS are
    # limited to 260 characters.
    if description:
        out += _counted_utf16(description, max_length=260)
    if relative_path:
        out += _counted_utf16(relative_path, max_length=260)
    if working_dir:
        out += _counted_utf16(working_dir, max_length=260)
    if arguments:
        out += _counted_utf16(arguments)  # unbounded per spec
    if icon_location:
        out += _counted_utf16(icon_location, max_length=260)

    # -- ExtraData --
    if env_target_path:
        out += _build_env_var_block(env_target_path)
    if icon_env_path:
        out += _build_icon_env_block(icon_env_path)
    if darwin_data:
        out += _build_darwin_block(darwin_data)
    if console_data is not None:
        out += _build_console_block(console_data)
    if console_fe_codepage:
        out += _build_console_fe_block(console_fe_codepage)
    if shim_layer_name:
        out += _build_shim_block(shim_layer_name)
    if special_folder_id is not None:
        out += _build_special_folder_block(special_folder_id, special_folder_offset)
    if tracker_machine_id:
        out += _build_tracker_block(
            machine_id=tracker_machine_id,
            droid_volume_id=tracker_droid_volume_id,
            droid_file_id=tracker_droid_file_id,
            birth_droid_volume_id=tracker_birth_droid_volume_id,
            birth_droid_file_id=tracker_birth_droid_file_id,
        )
    if known_folder_id:
        out += _build_known_folder_block(known_folder_id)
    if vista_idlist is not None:
        idlist_items = _build_idlist_items(vista_idlist, write_time=write_time)
        out += _build_vista_idlist_block(idlist_items)
    if property_stores:
        out += _build_property_store_block(property_stores)
    out += _build_terminal_block()

    return bytes(out)


def write_lnk(path: str | Path, **kwargs: Any) -> int:
    """Build a .lnk and write it to *path*.

    Accepts the same keyword arguments as :func:`build_lnk`.
    Returns the number of bytes written.
    """
    data = build_lnk(**kwargs)
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    return len(data)
