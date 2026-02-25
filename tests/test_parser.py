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


# ---- v10.0 Gap Fix Parser Tests ----


class TestShowCommandNormalization:
    """GAP-12: Unknown ShowCommand values normalized to SW_SHOWNORMAL."""

    def test_unknown_show_command_normalized(self):
        import struct

        from lnksmith.builder import build_lnk

        data = bytearray(build_lnk(target=r"C:\t.exe"))
        # Patch ShowCommand at offset 60 to an unknown value (99)
        struct.pack_into("<I", data, 60, 99)
        info = parse_lnk(bytes(data))
        assert info.show_command == 1  # normalized to SW_SHOWNORMAL
        assert info.show_command_name == "SW_SHOWNORMAL"

    def test_valid_show_commands_unchanged(self):
        from lnksmith.builder import build_lnk

        for cmd in (1, 3, 7):
            data = build_lnk(target=r"C:\t.exe", show_command=cmd)
            info = parse_lnk(data)
            assert info.show_command == cmd


class TestReservedFieldValidation:
    """GAP-11: Reserved header fields MUST be zero."""

    def test_nonzero_reserved_warns(self):
        import struct
        import warnings

        from lnksmith.builder import build_lnk

        data = bytearray(build_lnk(target=r"C:\t.exe"))
        # Patch Reserved1 (offset 66) to a non-zero value
        struct.pack_into("<H", data, 66, 0xBEEF)
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            parse_lnk(bytes(data))
            assert any("Reserved" in str(warning.message) for warning in w)

    def test_zero_reserved_no_warning(self):
        import warnings

        from lnksmith.builder import build_lnk

        data = build_lnk(target=r"C:\t.exe")
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            parse_lnk(data)
            assert not any("Reserved" in str(warning.message) for warning in w)


class TestParseDarwinDataBlock:
    """GAP-2: DarwinDataBlock parsing."""

    def test_darwin_data_parsed(self):
        from lnksmith.builder import build_lnk

        data = build_lnk(target=r"C:\t.exe", darwin_data="MSI-App-ID-12345")
        info = parse_lnk(data)
        assert info.darwin_data_ansi == "MSI-App-ID-12345"
        assert info.darwin_data_unicode == "MSI-App-ID-12345"

    def test_darwin_in_extra_blocks(self):
        from lnksmith.builder import build_lnk

        data = build_lnk(target=r"C:\t.exe", darwin_data="TestApp")
        info = parse_lnk(data)
        block = next(b for b in info.extra_blocks if b.signature == 0xA0000006)
        assert block.name == "DarwinDataBlock"
        assert block.data["DarwinDataAnsi"] == "TestApp"


class TestParseConsoleDataBlock:
    """GAP-3: ConsoleDataBlock parsing."""

    def test_console_data_parsed(self):
        from lnksmith.builder import build_lnk

        console = {
            "window_size_x": 120,
            "window_size_y": 50,
            "face_name": "Consolas",
            "font_weight": 400,
        }
        data = build_lnk(target=r"C:\t.exe", console_data=console)
        info = parse_lnk(data)
        assert info.console_data["window_size_x"] == 120
        assert info.console_data["window_size_y"] == 50
        assert info.console_data["face_name"] == "Consolas"
        assert info.console_data["font_weight"] == 400

    def test_console_color_table(self):
        from lnksmith.builder import build_lnk

        colors = [0x000000, 0x800000, 0x008000] + [0] * 13
        data = build_lnk(target=r"C:\t.exe", console_data={"color_table": colors})
        info = parse_lnk(data)
        assert info.console_data["color_table"][0] == 0x000000
        assert info.console_data["color_table"][1] == 0x800000
        assert info.console_data["color_table"][2] == 0x008000


class TestParseConsoleFEDataBlock:
    """GAP-4: ConsoleFEDataBlock parsing."""

    def test_console_fe_codepage(self):
        from lnksmith.builder import build_lnk

        data = build_lnk(target=r"C:\t.exe", console_fe_codepage=65001)
        info = parse_lnk(data)
        assert info.console_fe_codepage == 65001

    def test_console_fe_in_extra_blocks(self):
        from lnksmith.builder import build_lnk

        data = build_lnk(target=r"C:\t.exe", console_fe_codepage=932)
        info = parse_lnk(data)
        block = next(b for b in info.extra_blocks if b.signature == 0xA0000004)
        assert block.data["CodePage"] == "932"


class TestParseShimDataBlock:
    """GAP-5: ShimDataBlock parsing."""

    def test_shim_layer_name(self):
        from lnksmith.builder import build_lnk

        data = build_lnk(target=r"C:\t.exe", shim_layer_name="WinXPSP3")
        info = parse_lnk(data)
        assert info.shim_layer_name == "WinXPSP3"

    def test_shim_in_extra_blocks(self):
        from lnksmith.builder import build_lnk

        data = build_lnk(target=r"C:\t.exe", shim_layer_name="Win7RTM")
        info = parse_lnk(data)
        block = next(b for b in info.extra_blocks if b.signature == 0xA0000008)
        assert block.data["LayerName"] == "Win7RTM"


class TestParseSpecialFolderDataBlock:
    """GAP-6: SpecialFolderDataBlock parsing with promoted fields."""

    def test_special_folder_id_promoted(self):
        from lnksmith.builder import build_lnk

        data = build_lnk(
            target=r"C:\t.exe", special_folder_id=0x25, special_folder_offset=0x20
        )
        info = parse_lnk(data)
        assert info.special_folder_id == 0x25
        assert info.special_folder_offset == 0x20


class TestParseWNNCNetTypes:
    """GAP-9: Verify complete WNNC_NET_TYPES lookup."""

    def test_new_net_types_present(self):
        from lnksmith._constants import WNNC_NET_TYPES

        # Spot-check some of the newly added types
        assert 0x002E0000 in WNNC_NET_TYPES  # WNNC_NET_DAV
        assert WNNC_NET_TYPES[0x002E0000] == "WNNC_NET_DAV"
        assert 0x00430000 in WNNC_NET_TYPES  # WNNC_NET_GOOGLE
        assert WNNC_NET_TYPES[0x00430000] == "WNNC_NET_GOOGLE"
        assert 0x003F0000 in WNNC_NET_TYPES  # WNNC_NET_VMWARE
        assert WNNC_NET_TYPES[0x003F0000] == "WNNC_NET_VMWARE"


class TestParseVKCodes:
    """GAP-10: Verify VK_NUMLOCK and VK_SCROLL in lookup."""

    def test_vk_numlock(self):
        from lnksmith._constants import VK_KEYS

        assert 0x90 in VK_KEYS
        assert VK_KEYS[0x90] == "NUM LOCK"

    def test_vk_scroll_lock(self):
        from lnksmith._constants import VK_KEYS

        assert 0x91 in VK_KEYS
        assert VK_KEYS[0x91] == "SCROLL LOCK"


class TestForceNoLinkInfo:
    """GAP-A: ForceNoLinkInfo (bit 8) causes LinkInfo to be ignored."""

    def test_linkinfo_discarded_when_force_no_linkinfo(self):
        from lnksmith.builder import build_lnk

        # Build with ForceNoLinkInfo flag (0x100) merged in
        data = build_lnk(target=r"C:\Windows\notepad.exe", link_flags=0x100)
        info = parse_lnk(data)
        assert info.flags & 0x100  # ForceNoLinkInfo set
        # LinkInfo fields must be cleared despite binary data being present
        assert info.local_base_path == ""
        assert info.volume_label == ""
        assert info.drive_type == 0
        assert info.drive_serial == 0
        assert info.common_path == ""
        assert info.target_path == ""

    def test_stringdata_still_parsed_with_force_no_linkinfo(self):
        from lnksmith.builder import build_lnk

        data = build_lnk(
            target=r"C:\Windows\notepad.exe",
            description="test desc",
            arguments="--test",
            link_flags=0x100,
        )
        info = parse_lnk(data)
        # StringData and other sections should still work
        assert info.description == "test desc"
        assert info.arguments == "--test"

    def test_unc_linkinfo_discarded_when_force_no_linkinfo(self):
        from lnksmith.builder import build_lnk

        data = build_lnk(target=r"\\server\share\file.txt", link_flags=0x100)
        info = parse_lnk(data)
        assert info.network_share_name == ""
        assert info.network_provider_type == 0
        assert info.device_name == ""
        assert info.target_path == ""


class TestTrackerDataBlockValidation:
    """GAP-H: TrackerDataBlock Length and Version validation."""

    def test_valid_tracker_no_warning(self):
        import warnings

        from lnksmith.builder import build_lnk

        data = build_lnk(target=r"C:\t.exe", tracker_machine_id="TEST")
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            parse_lnk(data)
            tracker_warnings = [x for x in w if "TrackerDataBlock" in str(x.message)]
            assert len(tracker_warnings) == 0

    def test_bad_tracker_length_warns(self):
        import struct
        import warnings

        from lnksmith.builder import build_lnk

        data = bytearray(build_lnk(target=r"C:\t.exe", tracker_machine_id="TEST"))
        # Find the tracker block (sig 0xA0000003) and patch Length at +8
        for i in range(76, len(data) - 8):
            if struct.unpack_from("<I", data, i + 4)[0] == 0xA0000003:
                struct.pack_into("<I", data, i + 8, 0x99)  # bad Length
                break
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            parse_lnk(bytes(data))
            assert any("TrackerDataBlock Length" in str(x.message) for x in w)

    def test_bad_tracker_version_warns(self):
        import struct
        import warnings

        from lnksmith.builder import build_lnk

        data = bytearray(build_lnk(target=r"C:\t.exe", tracker_machine_id="TEST"))
        for i in range(76, len(data) - 8):
            if struct.unpack_from("<I", data, i + 4)[0] == 0xA0000003:
                struct.pack_into("<I", data, i + 12, 5)  # bad Version
                break
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            parse_lnk(bytes(data))
            assert any("TrackerDataBlock Version" in str(x.message) for x in w)


class TestShimDataBlockValidation:
    """GAP-I: ShimDataBlock minimum size validation."""

    def test_undersized_shim_warns(self):
        import struct
        import warnings

        from lnksmith.builder import build_lnk

        data = bytearray(build_lnk(target=r"C:\t.exe", shim_layer_name="XP"))
        # Builder now correctly pads to 0x88. Manually shrink the block
        # to simulate a malformed file and verify the parser warns.
        sig_bytes = struct.pack("<I", 0xA0000008)
        idx = data.index(sig_bytes)
        block_start = idx - 4  # size field is 4 bytes before signature
        old_size = struct.unpack_from("<I", data, block_start)[0]
        # Replace with a minimal undersized block: 8-byte header + "XP" UTF-16LE + null
        shim_payload = "XP".encode("utf-16-le") + b"\x00\x00"
        new_size = 8 + len(shim_payload)  # 14 bytes, well under 0x88
        new_block = struct.pack("<II", new_size, 0xA0000008) + shim_payload
        # Replace old block (keep terminal dword intact after it)
        data[block_start : block_start + old_size] = new_block
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            parse_lnk(bytes(data))
            assert any("ShimDataBlock BlockSize" in str(x.message) for x in w)
