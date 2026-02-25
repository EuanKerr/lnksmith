"""Tests for lnksmith.parser."""

import pytest

from lnksmith._constants import EXTRA_SIGS
from lnksmith.parser import FormatError, LnkInfo, format_lnk, parse_lnk


class TestParseBasic:
    """Parse a generated LNK and verify fields are extracted."""

    def test_returns_lnk_info(self, simple_lnk_bytes):
        info = parse_lnk(simple_lnk_bytes)
        assert isinstance(info, LnkInfo)

    def test_flags_nonzero(self, simple_lnk_bytes):
        info = parse_lnk(simple_lnk_bytes)
        assert info.flags != 0

    def test_flag_names_populated(self, simple_lnk_bytes):
        info = parse_lnk(simple_lnk_bytes)
        assert "HasLinkTargetIDList" in info.flag_names
        assert "HasLinkInfo" in info.flag_names
        assert "IsUnicode" in info.flag_names

    def test_timestamps_present(self, simple_lnk_bytes):
        info = parse_lnk(simple_lnk_bytes)
        assert "UTC" in info.creation_time
        assert "UTC" in info.access_time
        assert "UTC" in info.write_time

    def test_show_command_default(self, simple_lnk_bytes):
        info = parse_lnk(simple_lnk_bytes)
        assert info.show_command == 1
        assert info.show_command_name == "SW_SHOWNORMAL"


class TestParseFullLnk:
    """Parse a feature-rich LNK and verify all optional fields."""

    def test_target_path(self, full_lnk_bytes):
        info = parse_lnk(full_lnk_bytes)
        assert info.target_path == r"C:\Windows\notepad.exe"

    def test_description(self, full_lnk_bytes):
        info = parse_lnk(full_lnk_bytes)
        assert info.description == "Google Chrome"

    def test_relative_path(self, full_lnk_bytes):
        info = parse_lnk(full_lnk_bytes)
        assert info.relative_path == r"..\..\..\Windows\notepad.exe"

    def test_working_dir(self, full_lnk_bytes):
        info = parse_lnk(full_lnk_bytes)
        assert info.working_dir == r"C:\Windows"

    def test_arguments(self, full_lnk_bytes):
        info = parse_lnk(full_lnk_bytes)
        assert info.arguments == "--flag value"

    def test_file_size(self, full_lnk_bytes):
        info = parse_lnk(full_lnk_bytes)
        assert info.file_size == 201216

    def test_hotkey(self, full_lnk_bytes):
        info = parse_lnk(full_lnk_bytes)
        assert info.hotkey_vk == 0x43
        assert info.hotkey_mod == 0x02
        assert "CTRL" in info.hotkey_str
        assert "C" in info.hotkey_str

    def test_icon_location_from_env_block(self, full_lnk_bytes):
        info = parse_lnk(full_lnk_bytes)
        assert "chrome.exe" in info.icon_location

    def test_extra_blocks_present(self, full_lnk_bytes):
        info = parse_lnk(full_lnk_bytes)
        sigs = [b.signature for b in info.extra_blocks]
        assert 0xA0000007 in sigs

    def test_id_items_populated(self, full_lnk_bytes):
        info = parse_lnk(full_lnk_bytes)
        assert len(info.id_items) >= 3


class TestParseBytesInput:
    """Verify parse_lnk accepts raw bytes."""

    def test_bytes_input(self, simple_lnk_bytes):
        info = parse_lnk(simple_lnk_bytes)
        assert info.target_path == r"C:\Windows\notepad.exe"


class TestParseErrors:
    """Verify proper error handling for invalid input."""

    def test_too_short(self):
        with pytest.raises(FormatError, match="too short"):
            parse_lnk(b"\x00" * 10)

    def test_invalid_header_size(self):
        bad = bytearray(76)
        bad[0:4] = b"\xff\x00\x00\x00"
        with pytest.raises(FormatError, match="Invalid header size"):
            parse_lnk(bytes(bad))


class TestFormatLnk:
    """Verify the human-readable formatter produces output."""

    def test_format_returns_string(self, full_lnk_bytes):
        info = parse_lnk(full_lnk_bytes)
        text = format_lnk(info)
        assert isinstance(text, str)
        assert "HEADER" in text
        assert "RESOLVED" in text

    def test_format_contains_target(self, full_lnk_bytes):
        info = parse_lnk(full_lnk_bytes)
        text = format_lnk(info)
        assert "notepad.exe" in text


# ---- MS-SHLLINK v10 feature tests ----


class TestExtraSigLabels:
    """Verify EXTRA_SIGS has correct labels after the fix."""

    def test_shim_data_block_sig(self):
        assert EXTRA_SIGS[0xA0000008] == "ShimDataBlock"

    def test_vista_idlist_sig(self):
        assert EXTRA_SIGS[0xA000000C] == "VistaAndAboveIDListDataBlock"

    def test_no_sig_0a(self):
        assert 0xA000000A not in EXTRA_SIGS


class TestParseTrackerDataBlock:
    """Verify full TrackerDataBlock parsing (all 5 fields)."""

    def test_machine_id(self, tracker_lnk_bytes):
        info = parse_lnk(tracker_lnk_bytes)
        assert info.tracker_machine_id == "WORKSTATION01"

    def test_droid_volume_id(self, tracker_lnk_bytes):
        info = parse_lnk(tracker_lnk_bytes)
        assert info.tracker_droid_volume_id == "{12345678-1234-1234-1234-123456789ABC}"

    def test_droid_file_id(self, tracker_lnk_bytes):
        info = parse_lnk(tracker_lnk_bytes)
        assert info.tracker_droid_file_id == "{AABBCCDD-AABB-CCDD-EEFF-001122334455}"

    def test_birth_droid_volume_id(self, tracker_lnk_bytes):
        info = parse_lnk(tracker_lnk_bytes)
        assert (
            info.tracker_birth_droid_volume_id
            == "{11111111-2222-3333-4444-555566667777}"
        )

    def test_birth_droid_file_id(self, tracker_lnk_bytes):
        info = parse_lnk(tracker_lnk_bytes)
        assert (
            info.tracker_birth_droid_file_id == "{DEADBEEF-CAFE-BABE-F00D-ABCDEF012345}"
        )

    def test_tracker_in_extra_blocks(self, tracker_lnk_bytes):
        info = parse_lnk(tracker_lnk_bytes)
        sigs = [b.signature for b in info.extra_blocks]
        assert 0xA0000003 in sigs
        block = next(b for b in info.extra_blocks if b.signature == 0xA0000003)
        assert block.size == 96
        assert block.data["MachineID"] == "WORKSTATION01"
        assert "DroidVolumeID" in block.data
        assert "DroidFileID" in block.data
        assert "BirthDroidVolumeID" in block.data
        assert "BirthDroidFileID" in block.data


class TestParseKnownFolderDataBlock:
    """Verify KnownFolderDataBlock parsing with name resolution."""

    def test_known_folder_id(self, known_folder_lnk_bytes):
        info = parse_lnk(known_folder_lnk_bytes)
        assert info.known_folder_id == "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}"

    def test_known_folder_name(self, known_folder_lnk_bytes):
        info = parse_lnk(known_folder_lnk_bytes)
        assert info.known_folder_name == "Desktop"

    def test_known_folder_in_extra_blocks(self, known_folder_lnk_bytes):
        info = parse_lnk(known_folder_lnk_bytes)
        block = next(b for b in info.extra_blocks if b.signature == 0xA000000B)
        assert block.data["KnownFolderName"] == "Desktop"


class TestParseUNCPath:
    """Verify parsing of UNC path .lnk files."""

    def test_network_share_name(self, unc_lnk_bytes):
        info = parse_lnk(unc_lnk_bytes)
        assert info.network_share_name == r"\\server\share"

    def test_common_path(self, unc_lnk_bytes):
        info = parse_lnk(unc_lnk_bytes)
        assert info.common_path == r"folder\file.txt"

    def test_target_path_composed(self, unc_lnk_bytes):
        info = parse_lnk(unc_lnk_bytes)
        assert info.target_path == r"\\server\share\folder\file.txt"

    def test_network_provider(self, unc_lnk_bytes):
        info = parse_lnk(unc_lnk_bytes)
        assert info.network_provider_name == "WNNC_NET_LANMAN"
        assert info.network_provider_type == 0x00020000


class TestParseVistaIdList:
    """Verify VistaAndAboveIDListDataBlock parsing."""

    def test_vista_id_items_populated(self, vista_idlist_lnk_bytes):
        info = parse_lnk(vista_idlist_lnk_bytes)
        assert len(info.vista_id_items) >= 2

    def test_vista_block_in_extra(self, vista_idlist_lnk_bytes):
        info = parse_lnk(vista_idlist_lnk_bytes)
        sigs = [b.signature for b in info.extra_blocks]
        assert 0xA000000C in sigs
        block = next(b for b in info.extra_blocks if b.signature == 0xA000000C)
        assert block.name == "VistaAndAboveIDListDataBlock"


class TestParsePropertyStore:
    """Verify PropertyStoreDataBlock parsing."""

    def test_property_stores_populated(self, property_store_lnk_bytes):
        info = parse_lnk(property_store_lnk_bytes)
        assert len(info.property_stores) == 1

    def test_format_id(self, property_store_lnk_bytes):
        info = parse_lnk(property_store_lnk_bytes)
        store = info.property_stores[0]
        assert store.format_id == "{B9B4B3FC-2B51-4A42-B5D8-324146AFCF25}"
        assert store.format_name == "SID_SPS_METADATA"

    def test_string_property(self, property_store_lnk_bytes):
        info = parse_lnk(property_store_lnk_bytes)
        props = info.property_stores[0].properties
        string_prop = next(p for p in props if p.id == 2)
        assert string_prop.type == 0x001F
        assert string_prop.type_name == "VT_LPWSTR"
        assert string_prop.value == "test string"

    def test_uint32_property(self, property_store_lnk_bytes):
        info = parse_lnk(property_store_lnk_bytes)
        props = info.property_stores[0].properties
        uint_prop = next(p for p in props if p.id == 3)
        assert uint_prop.type == 0x0013
        assert uint_prop.value == 42

    def test_bool_property(self, property_store_lnk_bytes):
        info = parse_lnk(property_store_lnk_bytes)
        props = info.property_stores[0].properties
        bool_prop = next(p for p in props if p.id == 4)
        assert bool_prop.type == 0x000B
        assert bool_prop.value is True

    def test_property_store_in_extra_blocks(self, property_store_lnk_bytes):
        info = parse_lnk(property_store_lnk_bytes)
        block = next(b for b in info.extra_blocks if b.signature == 0xA0000009)
        assert block.data["StoreCount"] == "1"
        assert "SID_SPS_METADATA" in block.data["Store[0].FormatName"]


class TestFormatLnkExtended:
    """Verify format_lnk output for new features."""

    def test_format_tracker(self, tracker_lnk_bytes):
        info = parse_lnk(tracker_lnk_bytes)
        text = format_lnk(info)
        assert "MachineID" in text
        assert "WORKSTATION01" in text

    def test_format_known_folder(self, known_folder_lnk_bytes):
        info = parse_lnk(known_folder_lnk_bytes)
        text = format_lnk(info)
        assert "Desktop" in text

    def test_format_unc(self, unc_lnk_bytes):
        info = parse_lnk(unc_lnk_bytes)
        text = format_lnk(info)
        assert "NetworkShare" in text
        assert r"\\server\share" in text

    def test_format_property_store(self, property_store_lnk_bytes):
        info = parse_lnk(property_store_lnk_bytes)
        text = format_lnk(info)
        assert "PROPERTY STORES" in text

    def test_format_vista_idlist(self, vista_idlist_lnk_bytes):
        info = parse_lnk(vista_idlist_lnk_bytes)
        text = format_lnk(info)
        assert "VISTA AND ABOVE ID LIST" in text
