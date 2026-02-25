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


# ---- v10.0 Gap Fix Roundtrip Tests ----


class TestRoundtripDarwinDataBlock:
    """GAP-2: DarwinDataBlock survives a round trip."""

    def test_darwin_data_roundtrip(self):
        data = build_lnk(target=r"C:\t.exe", darwin_data="TestMSIApp-v2")
        info = parse_lnk(data)
        assert info.darwin_data_ansi == "TestMSIApp-v2"
        assert info.darwin_data_unicode == "TestMSIApp-v2"

    def test_darwin_has_darwin_id_flag(self):
        import struct

        data = build_lnk(target=r"C:\t.exe", darwin_data="AppID")
        flags = struct.unpack_from("<I", data, 20)[0]
        assert flags & 0x00001000  # HasDarwinID


class TestRoundtripConsoleFEDataBlock:
    """GAP-4: ConsoleFEDataBlock survives a round trip."""

    def test_codepage_roundtrip(self):
        data = build_lnk(target=r"C:\t.exe", console_fe_codepage=65001)
        info = parse_lnk(data)
        assert info.console_fe_codepage == 65001

    def test_codepage_932(self):
        data = build_lnk(target=r"C:\t.exe", console_fe_codepage=932)
        info = parse_lnk(data)
        assert info.console_fe_codepage == 932


class TestRoundtripShimDataBlock:
    """GAP-5: ShimDataBlock survives a round trip."""

    def test_shim_roundtrip(self):
        data = build_lnk(target=r"C:\t.exe", shim_layer_name="WinXPSP3")
        info = parse_lnk(data)
        assert info.shim_layer_name == "WinXPSP3"

    def test_shim_run_with_shim_flag(self):
        import struct

        data = build_lnk(target=r"C:\t.exe", shim_layer_name="Win7RTM")
        flags = struct.unpack_from("<I", data, 20)[0]
        assert flags & 0x00020000  # RunWithShimLayer


class TestRoundtripConsoleDataBlock:
    """GAP-3: ConsoleDataBlock survives a round trip."""

    def test_console_window_size_roundtrip(self):
        console = {"window_size_x": 132, "window_size_y": 43}
        data = build_lnk(target=r"C:\t.exe", console_data=console)
        info = parse_lnk(data)
        assert info.console_data["window_size_x"] == 132
        assert info.console_data["window_size_y"] == 43

    def test_console_face_name_roundtrip(self):
        console = {"face_name": "Cascadia Code"}
        data = build_lnk(target=r"C:\t.exe", console_data=console)
        info = parse_lnk(data)
        assert info.console_data["face_name"] == "Cascadia Code"

    def test_console_defaults_roundtrip(self):
        data = build_lnk(target=r"C:\t.exe", console_data={})
        info = parse_lnk(data)
        assert info.console_data["screen_buffer_size_x"] == 80
        assert info.console_data["screen_buffer_size_y"] == 300
        assert info.console_data["cursor_size"] == 25


class TestRoundtripSpecialFolderDataBlock:
    """GAP-6: SpecialFolderDataBlock survives a round trip."""

    def test_special_folder_roundtrip(self):
        data = build_lnk(
            target=r"C:\t.exe", special_folder_id=0x25, special_folder_offset=0x14
        )
        info = parse_lnk(data)
        assert info.special_folder_id == 0x25
        assert info.special_folder_offset == 0x14


class TestRoundtripFileAttributes:
    """GAP-8: file_attributes parameter round trip."""

    def test_custom_attrs_roundtrip(self):
        data = build_lnk(target=r"C:\t.exe", file_attributes=0x22)
        info = parse_lnk(data)
        assert info.file_attributes == 0x22


class TestRoundtripLinkFlags:
    """GAP-7: Additional link_flags round trip."""

    def test_extra_flags_roundtrip(self):
        data = build_lnk(target=r"C:\t.exe", link_flags=0x00040000)
        info = parse_lnk(data)
        assert info.flags & 0x00040000  # ForceNoLinkTrack
        assert "ForceNoLinkTrack" in info.flag_names


class TestRoundtripTimestamps:
    """GAP-B: Custom timestamps survive a round trip."""

    def test_datetime_timestamps(self):
        from datetime import UTC, datetime

        ts = datetime(2020, 6, 15, 12, 30, 0, tzinfo=UTC)
        data = build_lnk(
            target=r"C:\t.exe",
            creation_time=ts,
            access_time=ts,
            write_time=ts,
        )
        info = parse_lnk(data)
        assert info.creation_time == "2020-06-15 12:30:00 UTC"
        assert info.access_time == "2020-06-15 12:30:00 UTC"
        assert info.write_time == "2020-06-15 12:30:00 UTC"

    def test_int_filetime_ticks(self):
        # 2020-01-01 00:00:00 UTC = 132223104000000000 ticks
        ticks = 132223104000000000
        data = build_lnk(target=r"C:\t.exe", creation_time=ticks)
        info = parse_lnk(data)
        assert info.creation_time == "2020-01-01 00:00:00 UTC"

    def test_none_uses_current_time(self):
        data = build_lnk(target=r"C:\t.exe")
        info = parse_lnk(data)
        # Default should produce a recent timestamp, not "0 (unset)"
        assert "UTC" in info.creation_time
        assert "unset" not in info.creation_time

    def test_independent_timestamps(self):
        from datetime import UTC, datetime

        t1 = datetime(2019, 1, 1, 0, 0, 0, tzinfo=UTC)
        t2 = datetime(2021, 6, 15, 0, 0, 0, tzinfo=UTC)
        t3 = datetime(2023, 12, 31, 23, 59, 58, tzinfo=UTC)
        data = build_lnk(
            target=r"C:\t.exe",
            creation_time=t1,
            access_time=t2,
            write_time=t3,
        )
        info = parse_lnk(data)
        assert "2019-01-01" in info.creation_time
        assert "2021-06-15" in info.access_time
        assert "2023-12-31" in info.write_time


class TestRoundtripVolumeMetadata:
    """GAP-C/D: Volume metadata parameters survive a round trip."""

    def test_volume_label_ascii(self):
        data = build_lnk(target=r"C:\t.exe", volume_label="SYSTEM")
        info = parse_lnk(data)
        assert info.volume_label == "SYSTEM"

    def test_drive_serial(self):
        data = build_lnk(target=r"C:\t.exe", drive_serial=0xDEADBEEF)
        info = parse_lnk(data)
        assert info.drive_serial == 0xDEADBEEF

    def test_drive_type_removable(self):
        data = build_lnk(target=r"C:\t.exe", drive_type=2)
        info = parse_lnk(data)
        assert info.drive_type == 2
        assert info.drive_type_name == "REMOVABLE"

    def test_drive_type_cdrom(self):
        data = build_lnk(target=r"D:\setup.exe", drive_type=5)
        info = parse_lnk(data)
        assert info.drive_type == 5
        assert info.drive_type_name == "CDROM"

    def test_all_volume_fields(self):
        data = build_lnk(
            target=r"E:\data.bin",
            volume_label="BACKUP",
            drive_serial=0x12345678,
            drive_type=2,
        )
        info = parse_lnk(data)
        assert info.volume_label == "BACKUP"
        assert info.drive_serial == 0x12345678
        assert info.drive_type == 2


class TestRoundtripCNR:
    """GAP-E/F/G: CNR Unicode, device name, and provider type."""

    def test_unc_with_device_name(self):
        data = build_lnk(
            target=r"\\server\share\file.txt",
            network_device_name="Z:",
        )
        info = parse_lnk(data)
        assert info.network_share_name == r"\\server\share"
        assert info.device_name == "Z:"
        assert info.target_path == r"\\server\share\file.txt"

    def test_unc_with_custom_provider_type(self):
        data = build_lnk(
            target=r"\\webdav\docs\report.pdf",
            network_provider_type=0x002E0000,  # WNNC_NET_DAV
        )
        info = parse_lnk(data)
        assert info.network_provider_type == 0x002E0000
        assert info.network_provider_name == "WNNC_NET_DAV"

    def test_unc_unicode_share_name(self):
        data = build_lnk(target=r"\\server\share\file.txt")
        info = parse_lnk(data)
        # Unicode variant should now be parsed (NetNameOffset > 0x14)
        assert info.network_share_name == r"\\server\share"

    def test_unc_device_and_provider(self):
        data = build_lnk(
            target=r"\\nas\backup\data.zip",
            network_device_name="M:",
            network_provider_type=0x00020000,  # WNNC_NET_LANMAN
        )
        info = parse_lnk(data)
        assert info.device_name == "M:"
        assert info.network_provider_name == "WNNC_NET_LANMAN"
        assert info.target_path == r"\\nas\backup\data.zip"


class TestRoundtripPropertyTypes:
    """GAP-J: VT_I2 and VT_LPSTR property types survive round trip."""

    def test_vt_i2_roundtrip(self):
        data = build_lnk(
            target=r"C:\t.exe",
            property_stores=[
                {
                    "format_id": "{B9B4B3FC-2B51-4A42-B5D8-324146AFCF25}",
                    "properties": [
                        {"id": 10, "type": 0x0002, "value": -42},
                    ],
                }
            ],
        )
        info = parse_lnk(data)
        prop = info.property_stores[0].properties[0]
        assert prop.type == 0x0002
        assert prop.value == -42

    def test_vt_lpstr_roundtrip(self):
        data = build_lnk(
            target=r"C:\t.exe",
            property_stores=[
                {
                    "format_id": "{B9B4B3FC-2B51-4A42-B5D8-324146AFCF25}",
                    "properties": [
                        {"id": 11, "type": 0x001E, "value": "hello ansi"},
                    ],
                }
            ],
        )
        info = parse_lnk(data)
        prop = info.property_stores[0].properties[0]
        assert prop.type == 0x001E
        assert prop.value == "hello ansi"


class TestShowCommandValidation:
    """GAP-L: ShowCommand validation in builder."""

    def test_valid_show_commands_accepted(self):
        for cmd in (1, 3, 7):
            build_lnk(target=r"C:\t.exe", show_command=cmd)

    def test_invalid_show_command_raises(self):
        import pytest

        with pytest.raises(ValueError, match="Invalid show_command"):
            build_lnk(target=r"C:\t.exe", show_command=99)
