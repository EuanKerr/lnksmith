"""lnksmith -- build and parse Windows .lnk files (MS-SHLLINK)."""

__version__ = "0.1.0"

from .builder import build_lnk, write_lnk
from .parser import (
    ExtraBlock,
    FormatError,
    IdItem,
    LnkInfo,
    MissingFieldError,
    PropertyStore,
    PropertyValue,
    format_lnk,
    parse_lnk,
)

__all__ = [
    "build_lnk",
    "write_lnk",
    "parse_lnk",
    "format_lnk",
    "LnkInfo",
    "IdItem",
    "ExtraBlock",
    "PropertyStore",
    "PropertyValue",
    "FormatError",
    "MissingFieldError",
    "__version__",
]
