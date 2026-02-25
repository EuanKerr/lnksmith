"""Internal utility helpers for GUID encoding and binary formatting."""

import struct


def format_guid(data: bytes, off: int = 0) -> str:
    """Format 16 bytes at *off* as an uppercase UUID string (no braces).

    Windows GUIDs are stored in mixed-endian layout:
    uint32-LE, uint16-LE, uint16-LE, 8 raw bytes.
    """
    if len(data) - off < 16:
        return "?"
    d1 = struct.unpack_from("<I", data, off)[0]
    d2 = struct.unpack_from("<H", data, off + 4)[0]
    d3 = struct.unpack_from("<H", data, off + 6)[0]
    d4 = data[off + 8 : off + 10].hex().upper()
    d5 = data[off + 10 : off + 16].hex().upper()
    return f"{d1:08X}-{d2:04X}-{d3:04X}-{d4}-{d5}"


def parse_guid_str(guid_str: str) -> bytes:
    """Parse a UUID string into 16 bytes in Windows mixed-endian layout.

    Accepts with or without braces, e.g.
    ``'{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}'`` or without braces.
    """
    s = guid_str.strip("{}").replace("-", "")
    d1 = int(s[0:8], 16)
    d2 = int(s[8:12], 16)
    d3 = int(s[12:16], 16)
    rest = bytes.fromhex(s[16:32])
    return struct.pack("<IHH", d1, d2, d3) + rest


def find_utf16le_null(data: bytes, start: int = 0) -> int:
    """Find the first UTF-16LE null terminator (two zero bytes at even offset).

    Returns the byte offset of the null terminator relative to *start*,
    or ``len(data) - start`` if not found.  The result is always even.
    """
    pos = start
    end = len(data) - 1
    while pos < end:
        if data[pos] == 0 and data[pos + 1] == 0:
            return pos - start
        pos += 2
    return len(data) - start


def decode_utf16le_at(data: bytes, off: int, limit: int | None = None) -> str:
    """Decode a null-terminated UTF-16LE string starting at *off*.

    If *limit* is given it caps the search range (byte count from *off*).
    """
    end = off + limit if limit is not None else len(data)
    search_data = data[off:end]
    null_pos = find_utf16le_null(search_data)
    return search_data[:null_pos].decode("utf-16-le", errors="replace")
