"""Round-trip tests: build -> parse -> verify fields match."""

import pytest

from lnksmith._constants import SW_MAXIMIZED, SW_MINIMIZED, SW_SHOWNORMAL
from lnksmith.builder import build_lnk
from lnksmith.parser import parse_lnk


class TestRoundtripSimple:
    """Build a minimal LNK, parse it back, verify key fields."""

    def test_target_path_roundtrip(self):
        data = build_lnk(target=r"C:\Windows\System32\cmd.exe")
        info = parse_lnk(data)
        assert info.target_path == r"C:\Windows\System32\cmd.exe"

    def test_file_size_roundtrip(self):
        data = build_lnk(target=r"C:\t.exe", file_size=12345)
        info = parse_lnk(data)
        assert info.file_size == 12345


class TestRoundtripStringData:
    """Verify all StringData fields survive a round trip."""

    def test_description_roundtrip(self):
        data = build_lnk(target=r"C:\t.exe", description="My App")
        info = parse_lnk(data)
        assert info.description == "My App"

    def test_relative_path_roundtrip(self):
        data = build_lnk(target=r"C:\t.exe", relative_path=r".\t.exe")
        info = parse_lnk(data)
        assert info.relative_path == r".\t.exe"

    def test_working_dir_roundtrip(self):
        data = build_lnk(target=r"C:\t.exe", working_dir=r"C:\Work")
        info = parse_lnk(data)
        assert info.working_dir == r"C:\Work"

    def test_arguments_roundtrip(self):
        data = build_lnk(target=r"C:\t.exe", arguments="--verbose --output=foo")
        info = parse_lnk(data)
        assert info.arguments == "--verbose --output=foo"

    def test_icon_location_roundtrip(self):
        data = build_lnk(target=r"C:\t.exe", icon_location=r"C:\icons\app.ico")
        info = parse_lnk(data)
        # icon_location in parser may be overridden by env block, but without
        # icon_env_path it should be the StringData value
        assert "app.ico" in info.icon_location


class TestRoundtripShowCommand:
    """Verify show_command values survive a round trip."""

    @pytest.mark.parametrize(
        "cmd,name",
        [
            (SW_SHOWNORMAL, "SW_SHOWNORMAL"),
            (SW_MAXIMIZED, "SW_MAXIMIZED"),
            (SW_MINIMIZED, "SW_MINIMIZED"),
        ],
    )
    def test_show_command_roundtrip(self, cmd, name):
        data = build_lnk(target=r"C:\t.exe", show_command=cmd)
        info = parse_lnk(data)
        assert info.show_command == cmd
        assert info.show_command_name == name


class TestRoundtripHotkey:
    """Verify hotkey combos survive a round trip."""

    @pytest.mark.parametrize(
        "vk,mod,expected_parts",
        [
            (0x43, 0x02, ["CTRL", "C"]),  # Ctrl+C
            (0x41, 0x01, ["SHIFT", "A"]),  # Shift+A
            (0x70, 0x04, ["ALT", "F1"]),  # Alt+F1
            (0x42, 0x03, ["SHIFT", "CTRL", "B"]),  # Shift+Ctrl+B
        ],
    )
    def test_hotkey_roundtrip(self, vk, mod, expected_parts):
        data = build_lnk(target=r"C:\t.exe", hotkey_vk=vk, hotkey_mod=mod)
        info = parse_lnk(data)
        assert info.hotkey_vk == vk
        assert info.hotkey_mod == mod
        for part in expected_parts:
            assert part in info.hotkey_str


class TestRoundtripExtraData:
    """Verify ExtraData blocks survive a round trip."""

    def test_env_var_block_roundtrip(self):
        env = r"%WINDIR%\System32\cmd.exe"
        data = build_lnk(target=r"C:\t.exe", env_target_path=env)
        info = parse_lnk(data)
        sigs = [b.signature for b in info.extra_blocks]
        assert 0xA0000001 in sigs
        block = next(b for b in info.extra_blocks if b.signature == 0xA0000001)
        assert block.data["TargetAnsi"] == env

    def test_icon_env_block_roundtrip(self):
        icon_env = r"%ProgramFiles%\App\icon.exe"
        data = build_lnk(target=r"C:\t.exe", icon_env_path=icon_env)
        info = parse_lnk(data)
        sigs = [b.signature for b in info.extra_blocks]
        assert 0xA0000007 in sigs
        block = next(b for b in info.extra_blocks if b.signature == 0xA0000007)
        assert block.data["IconAnsi"] == icon_env


class TestRoundtripListTarget:
    """Verify list-style targets with 8.3 short names round-trip."""

    def test_list_target_path(self):
        data = build_lnk(
            target=[
                "C",
                ("PROGRA~1", "Program Files"),
                "Google",
                "Chrome",
                ("APPLIC~1", "Application"),
                "chrome.exe",
            ],
            file_size=3309208,
        )
        info = parse_lnk(data)
        assert (
            info.target_path == r"C:\Program Files\Google\Chrome\Application\chrome.exe"
        )


# ---- MS-SHLLINK v10 roundtrip tests ----


class TestRoundtripTracker:
    """Verify TrackerDataBlock fields survive a round trip."""

    def test_machine_id_roundtrip(self):
        data = build_lnk(target=r"C:\t.exe", tracker_machine_id="MYPC")
        info = parse_lnk(data)
        assert info.tracker_machine_id == "MYPC"

    def test_all_tracker_guids_roundtrip(self):
        dvol = "{12345678-1234-1234-1234-123456789ABC}"
        dfile = "{AABBCCDD-AABB-CCDD-EEFF-001122334455}"
        bvol = "{11111111-2222-3333-4444-555566667777}"
        bfile = "{DEADBEEF-CAFE-BABE-F00D-ABCDEF012345}"
        data = build_lnk(
            target=r"C:\t.exe",
            tracker_machine_id="HOST",
            tracker_droid_volume_id=dvol,
            tracker_droid_file_id=dfile,
            tracker_birth_droid_volume_id=bvol,
            tracker_birth_droid_file_id=bfile,
        )
        info = parse_lnk(data)
        assert info.tracker_droid_volume_id == dvol
        assert info.tracker_droid_file_id == dfile
        assert info.tracker_birth_droid_volume_id == bvol
        assert info.tracker_birth_droid_file_id == bfile


class TestRoundtripKnownFolder:
    """Verify KnownFolderDataBlock survives a round trip."""

    def test_known_folder_by_name(self):
        data = build_lnk(target=r"C:\t.exe", known_folder_id="Desktop")
        info = parse_lnk(data)
        assert info.known_folder_id == "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}"
        assert info.known_folder_name == "Desktop"

    def test_known_folder_by_guid(self):
        guid = "{374DE290-123F-4565-9164-39C4925E467B}"
        data = build_lnk(target=r"C:\t.exe", known_folder_id=guid)
        info = parse_lnk(data)
        assert info.known_folder_id == guid
        assert info.known_folder_name == "Downloads"


class TestRoundtripUNC:
    """Verify UNC path survives a round trip."""

    def test_unc_simple(self):
        data = build_lnk(target=r"\\server\share\file.txt")
        info = parse_lnk(data)
        assert info.target_path == r"\\server\share\file.txt"

    def test_unc_deep_path(self):
        data = build_lnk(target=r"\\fileserver\data\projects\docs\report.docx")
        info = parse_lnk(data)
        assert info.target_path == r"\\fileserver\data\projects\docs\report.docx"

    def test_unc_share_only(self):
        data = build_lnk(target=r"\\server\share")
        info = parse_lnk(data)
        assert info.network_share_name == r"\\server\share"


class TestRoundtripVistaIdList:
    """Verify VistaAndAboveIDListDataBlock survives a round trip."""

    def test_vista_idlist_items_present(self):
        data = build_lnk(
            target=r"C:\Windows\notepad.exe",
            vista_idlist=r"C:\Windows\System32",
        )
        info = parse_lnk(data)
        assert len(info.vista_id_items) >= 2  # root + drive + at least 1 dir


class TestRoundtripPropertyStore:
    """Verify PropertyStoreDataBlock survives a round trip."""

    def test_string_property_roundtrip(self):
        data = build_lnk(
            target=r"C:\t.exe",
            property_stores=[
                {
                    "format_id": "{B9B4B3FC-2B51-4A42-B5D8-324146AFCF25}",
                    "properties": [
                        {"id": 5, "type": 0x001F, "value": "hello world"},
                    ],
                }
            ],
        )
        info = parse_lnk(data)
        assert len(info.property_stores) == 1
        props = info.property_stores[0].properties
        assert len(props) == 1
        assert props[0].value == "hello world"

    def test_uint32_property_roundtrip(self):
        data = build_lnk(
            target=r"C:\t.exe",
            property_stores=[
                {
                    "format_id": "{B9B4B3FC-2B51-4A42-B5D8-324146AFCF25}",
                    "properties": [
                        {"id": 10, "type": 0x0013, "value": 99},
                    ],
                }
            ],
        )
        info = parse_lnk(data)
        props = info.property_stores[0].properties
        assert props[0].value == 99

    def test_bool_property_roundtrip(self):
        data = build_lnk(
            target=r"C:\t.exe",
            property_stores=[
                {
                    "format_id": "{B9B4B3FC-2B51-4A42-B5D8-324146AFCF25}",
                    "properties": [
                        {"id": 7, "type": 0x000B, "value": False},
                    ],
                }
            ],
        )
        info = parse_lnk(data)
        props = info.property_stores[0].properties
        assert props[0].value is False

    def test_multiple_stores_roundtrip(self):
        data = build_lnk(
            target=r"C:\t.exe",
            property_stores=[
                {
                    "format_id": "{B9B4B3FC-2B51-4A42-B5D8-324146AFCF25}",
                    "properties": [
                        {"id": 2, "type": 0x001F, "value": "first"},
                    ],
                },
                {
                    "format_id": "{46588AE2-4CBC-4338-BBFC-139326986DCE}",
                    "properties": [
                        {"id": 3, "type": 0x0013, "value": 123},
                    ],
                },
            ],
        )
        info = parse_lnk(data)
        assert len(info.property_stores) == 2
        assert info.property_stores[0].format_name == "SID_SPS_METADATA"
        assert info.property_stores[1].format_name == "SID_SPS_METADATA2"
