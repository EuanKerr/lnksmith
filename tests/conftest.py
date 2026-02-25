"""Shared fixtures for lnksmith tests."""

import pytest

from lnksmith.builder import build_lnk


@pytest.fixture
def simple_lnk_bytes():
    """A minimal .lnk targeting notepad.exe."""
    return build_lnk(target=r"C:\Windows\notepad.exe")


@pytest.fixture
def full_lnk_bytes():
    """A feature-rich .lnk with all optional fields populated."""
    return build_lnk(
        target=r"C:\Windows\notepad.exe",
        icon_location=r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        icon_env_path=r"%ProgramFiles%\Google\Chrome\Application\chrome.exe",
        icon_index=0,
        description="Google Chrome",
        relative_path=r"..\..\..\Windows\notepad.exe",
        working_dir=r"C:\Windows",
        arguments="--flag value",
        file_size=201216,
        hotkey_vk=0x43,
        hotkey_mod=0x02,
    )


@pytest.fixture
def short_name_lnk_bytes():
    """A .lnk using 8.3 short name list-style target."""
    return build_lnk(
        target=[
            "C",
            ("PROGRA~1", "Program Files"),
            "Google",
            "Chrome",
            ("APPLIC~1", "Application"),
            "chrome.exe",
        ],
        icon_location=r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        file_size=3309208,
        description="Google Chrome",
    )


@pytest.fixture
def tracker_lnk_bytes():
    """A .lnk with TrackerDataBlock (all 5 fields populated)."""
    return build_lnk(
        target=r"C:\Windows\notepad.exe",
        tracker_machine_id="WORKSTATION01",
        tracker_droid_volume_id="{12345678-1234-1234-1234-123456789ABC}",
        tracker_droid_file_id="{AABBCCDD-AABB-CCDD-EEFF-001122334455}",
        tracker_birth_droid_volume_id="{11111111-2222-3333-4444-555566667777}",
        tracker_birth_droid_file_id="{DEADBEEF-CAFE-BABE-F00D-ABCDEF012345}",
    )


@pytest.fixture
def known_folder_lnk_bytes():
    """A .lnk with KnownFolderDataBlock (Desktop)."""
    return build_lnk(
        target=r"C:\Users\test\Desktop",
        known_folder_id="Desktop",
    )


@pytest.fixture
def unc_lnk_bytes():
    """A .lnk targeting a UNC path."""
    return build_lnk(target=r"\\server\share\folder\file.txt")


@pytest.fixture
def property_store_lnk_bytes():
    """A .lnk with PropertyStoreDataBlock."""
    return build_lnk(
        target=r"C:\Windows\notepad.exe",
        property_stores=[
            {
                "format_id": "{B9B4B3FC-2B51-4A42-B5D8-324146AFCF25}",
                "properties": [
                    {"id": 2, "type": 0x001F, "value": "test string"},
                    {"id": 3, "type": 0x0013, "value": 42},
                    {"id": 4, "type": 0x000B, "value": True},
                ],
            }
        ],
    )


@pytest.fixture
def vista_idlist_lnk_bytes():
    """A .lnk with VistaAndAboveIDListDataBlock."""
    return build_lnk(
        target=r"C:\Windows\notepad.exe",
        vista_idlist=r"C:\Windows\System32",
    )
