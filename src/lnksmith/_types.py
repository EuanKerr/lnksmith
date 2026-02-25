"""Shared type aliases for lnksmith modules."""

from datetime import datetime

TargetPath = str | list[str | tuple[str, str]]
Timestamp = int | datetime | None
