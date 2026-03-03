"""Tests for lnksmith.builder."""

import struct

import pytest

from lnksmith._constants import (
    LINK_CLSID,
    SW_SHOWMAXIMIZED,
    SW_SHOWMINNOACTIVE,
    SW_SHOWNORMAL,
)
from lnksmith.builder import build_lnk


class TestHeaderStructure:
    """Verify the 76-byte LNK header is well-formed."""

    def test_header_size_is_0x4c(self, simple_lnk_bytes):
        assert struct.unpack_from("<I", simple_lnk_bytes, 0)[0] == 0x4C

    def test_link_clsid(self, simple_lnk_bytes):
        assert simple_lnk_bytes[4:20] == LINK_CLSID

    def test_minimum_flags(self, simple_lnk_bytes):
        flags = struct.unpack_from("<I", simple_lnk_bytes, 20)[0]
        # Must have IDList (0x01), LinkInfo (0x02), IsUnicode (0x80)
        assert flags & 0x83 == 0x83

    def test_file_attribute_archive(self, simple_lnk_bytes):
        attrs = struct.unpack_from("<I", simple_lnk_bytes, 24)[0]
        assert attrs == 0x20  # FILE_ATTRIBUTE_ARCHIVE

    def test_timestamps_nonzero(self, simple_lnk_bytes):
        for offset in (28, 36, 44):
            ft = struct.unpack_from("<Q", simple_lnk_bytes, offset)[0]
            assert ft > 0

    def test_terminal_block(self, simple_lnk_bytes):
        # Last 4 bytes must be the terminal block (all zeros)
        assert simple_lnk_bytes[-4:] == b"\x00\x00\x00\x00"


class TestFlagEncoding:
    """Verify flags are set correctly for optional fields."""

    def test_has_name_flag(self):
        data = build_lnk(target=r"C:\test.exe", description="desc")
        flags = struct.unpack_from("<I", data, 20)[0]
        assert flags & 0x04  # HasName

    def test_has_relative_path_flag(self):
        data = build_lnk(target=r"C:\test.exe", relative_path=r".\test.exe")
        flags = struct.unpack_from("<I", data, 20)[0]
        assert flags & 0x08  # HasRelativePath

    def test_has_working_dir_flag(self):
        data = build_lnk(target=r"C:\test.exe", working_dir="C:\\")
        flags = struct.unpack_from("<I", data, 20)[0]
        assert flags & 0x10  # HasWorkingDir

    def test_has_arguments_flag(self):
        data = build_lnk(target=r"C:\test.exe", arguments="--help")
        flags = struct.unpack_from("<I", data, 20)[0]
        assert flags & 0x20  # HasArguments

    def test_has_icon_location_flag(self):
        data = build_lnk(target=r"C:\test.exe", icon_location=r"C:\icon.exe")
        flags = struct.unpack_from("<I", data, 20)[0]
        assert flags & 0x40  # HasIconLocation

    def test_has_exp_string_flag(self):
        data = build_lnk(target=r"C:\test.exe", env_target_path=r"%WINDIR%\test.exe")
        flags = struct.unpack_from("<I", data, 20)[0]
        assert flags & 0x200  # HasExpString

    def test_has_exp_icon_flag(self):
        data = build_lnk(target=r"C:\test.exe", icon_env_path=r"%WINDIR%\icon.exe")
        flags = struct.unpack_from("<I", data, 20)[0]
        assert flags & 0x4000  # HasExpIcon

    def test_no_optional_flags_when_empty(self):
        data = build_lnk(target=r"C:\test.exe")
        flags = struct.unpack_from("<I", data, 20)[0]
        # IDList + LinkInfo + IsUnicode + DisableKnownFolderTracking (default)
        assert flags == 0x200083

    def test_disable_known_folder_tracking_off(self):
        data = build_lnk(target=r"C:\test.exe", disable_known_folder_tracking=False)
        flags = struct.unpack_from("<I", data, 20)[0]
        assert flags == 0x83


class TestHotkeyBytes:
    """Verify hotkey VK and modifier are packed correctly."""

    @pytest.mark.parametrize(
        "vk,mod",
        [
            (0x43, 0x02),  # Ctrl+C
            (0x41, 0x01),  # Shift+A
            (0x70, 0x04),  # Alt+F1
            (0x00, 0x00),  # No hotkey
        ],
    )
    def test_hotkey_encoding(self, vk, mod):
        data = build_lnk(target=r"C:\t.exe", hotkey_vk=vk, hotkey_mod=mod)
        assert data[64] == vk
        assert data[65] == mod


class TestShowCommand:
    """Verify show command is packed correctly."""

    @pytest.mark.parametrize(
        "cmd", [SW_SHOWNORMAL, SW_SHOWMAXIMIZED, SW_SHOWMINNOACTIVE]
    )
    def test_show_command_encoding(self, cmd):
        data = build_lnk(target=r"C:\t.exe", show_command=cmd)
        assert struct.unpack_from("<I", data, 60)[0] == cmd


class TestExtraDataBlocks:
    """Verify ExtraData blocks are present and correctly sized."""

    def test_env_var_block_present(self):
        from lnksmith.parser import parse_lnk

        data = build_lnk(target=r"C:\t.exe", env_target_path=r"%WINDIR%\t.exe")
        info = parse_lnk(data)
        sigs = [b.signature for b in info.extra_blocks]
        assert 0xA0000001 in sigs
        block = next(b for b in info.extra_blocks if b.signature == 0xA0000001)
        assert block.size == 788

    def test_icon_env_block_present(self):
        from lnksmith.parser import parse_lnk

        data = build_lnk(target=r"C:\t.exe", icon_env_path=r"%PF%\icon.exe")
        info = parse_lnk(data)
        sigs = [b.signature for b in info.extra_blocks]
        assert 0xA0000007 in sigs
        block = next(b for b in info.extra_blocks if b.signature == 0xA0000007)
        assert block.size == 788


class TestFileSize:
    """Verify file_size appears in header."""

    def test_file_size_in_header(self):
        data = build_lnk(target=r"C:\t.exe", file_size=201216)
        assert struct.unpack_from("<I", data, 52)[0] == 201216


class TestListTarget:
    """Verify list-style targets with 8.3 short names produce valid output."""

    def test_list_target_produces_valid_lnk(self, short_name_lnk_bytes):
        # Basic structural check
        assert struct.unpack_from("<I", short_name_lnk_bytes, 0)[0] == 0x4C
        assert short_name_lnk_bytes[-4:] == b"\x00\x00\x00\x00"


class TestWellKnownShortNames:
    """Verify _generate_short_name uses the well-known lookup table."""

    def test_program_files_lookup(self):
        from lnksmith.builder import _generate_short_name

        assert _generate_short_name("Program Files") == "PROGRA~1"

    def test_program_files_x86_lookup(self):
        from lnksmith.builder import _generate_short_name

        assert _generate_short_name("Program Files (x86)") == "PROGRA~2"

    def test_case_insensitive_lookup(self):
        from lnksmith.builder import _generate_short_name

        assert _generate_short_name("program files") == "PROGRA~1"
        assert _generate_short_name("PROGRAM FILES") == "PROGRA~1"

    def test_common_files_lookup(self):
        from lnksmith.builder import _generate_short_name

        assert _generate_short_name("Common Files") == "COMMON~1"

    def test_unknown_name_falls_back_to_generation(self):
        from lnksmith.builder import _generate_short_name

        # Not in the table, should use the VFAT algorithm
        result = _generate_short_name("Some Long Directory Name")
        assert result == "SOMELO~1"

    def test_simple_name_unchanged(self):
        from lnksmith.builder import _generate_short_name

        assert _generate_short_name("Windows") == "WINDOWS"
        assert _generate_short_name("cmd.exe") == "CMD.EXE"

    def test_string_target_uses_lookup(self):
        """Auto-derived short names for string targets use the lookup table."""
        from lnksmith.parser import parse_lnk

        data = build_lnk(target=r"C:\Program Files\test.exe")
        parse_lnk(data)  # verify round-trip parses without error
        # IDList should contain PROGRA~1 as the ANSI short name
        assert b"PROGRA~1" in data


# ---- MS-SHLLINK v10 feature tests ----


class TestTrackerBlock:
    """Verify TrackerDataBlock builder output."""

    def test_tracker_block_size(self, tracker_lnk_bytes):
        from lnksmith.parser import parse_lnk

        info = parse_lnk(tracker_lnk_bytes)
        block = next(b for b in info.extra_blocks if b.signature == 0xA0000003)
        assert block.size == 96

    def test_tracker_block_signature(self, tracker_lnk_bytes):
        from lnksmith.parser import parse_lnk

        info = parse_lnk(tracker_lnk_bytes)
        block = next(b for b in info.extra_blocks if b.signature == 0xA0000003)
        assert struct.unpack_from("<I", block.raw, 4)[0] == 0xA0000003


class TestKnownFolderBlock:
    """Verify KnownFolderDataBlock builder output."""

    def test_known_folder_block_size(self, known_folder_lnk_bytes):
        from lnksmith.parser import parse_lnk

        info = parse_lnk(known_folder_lnk_bytes)
        block = next(b for b in info.extra_blocks if b.signature == 0xA000000B)
        assert block.size == 28

    def test_known_folder_by_name(self):
        data = build_lnk(target=r"C:\t.exe", known_folder_id="Documents")
        from lnksmith.parser import parse_lnk

        info = parse_lnk(data)
        assert info.known_folder_name == "Documents"


class TestUNCLinkInfo:
    """Verify UNC LinkInfo builder output."""

    def test_unc_target_produces_valid_lnk(self, unc_lnk_bytes):
        assert struct.unpack_from("<I", unc_lnk_bytes, 0)[0] == 0x4C
        assert unc_lnk_bytes[-4:] == b"\x00\x00\x00\x00"

    def test_unc_sets_keeplocal_flag(self, unc_lnk_bytes):
        flags = struct.unpack_from("<I", unc_lnk_bytes, 20)[0]
        assert flags & 0x04000000  # KeepLocalIDListForUNCTarget


class TestVistaIdListBlock:
    """Verify VistaAndAboveIDListDataBlock builder output."""

    def test_vista_block_present(self, vista_idlist_lnk_bytes):
        from lnksmith.parser import parse_lnk

        info = parse_lnk(vista_idlist_lnk_bytes)
        sigs = [b.signature for b in info.extra_blocks]
        assert 0xA000000C in sigs


class TestPropertyStoreBlock:
    """Verify PropertyStoreDataBlock builder output."""

    def test_property_store_block_present(self, property_store_lnk_bytes):
        from lnksmith.parser import parse_lnk

        info = parse_lnk(property_store_lnk_bytes)
        sigs = [b.signature for b in info.extra_blocks]
        assert 0xA0000009 in sigs

    def test_property_store_block_signature(self, property_store_lnk_bytes):
        from lnksmith.parser import parse_lnk

        info = parse_lnk(property_store_lnk_bytes)
        block = next(b for b in info.extra_blocks if b.signature == 0xA0000009)
        assert struct.unpack_from("<I", block.raw, 4)[0] == 0xA0000009


class TestUnicodeLinkInfo:
    """Verify LinkInfo builder emits Unicode path offsets."""

    def test_linkinfo_header_size_0x24(self, simple_lnk_bytes):
        from lnksmith.parser import parse_lnk

        info = parse_lnk(simple_lnk_bytes)
        assert info.target_path == r"C:\Windows\notepad.exe"


# ---- v10.0 Gap Fix Tests ----


class TestStringDataLengthLimit:
    """GAP-1: v10.0 StringData 260-character limit enforcement."""

    def test_description_at_limit_succeeds(self):
        from lnksmith.parser import parse_lnk

        desc = "A" * 260
        data = build_lnk(target=r"C:\t.exe", description=desc)
        info = parse_lnk(data)
        assert info.description == desc

    def test_description_over_limit_raises(self):
        desc = "A" * 261
        with pytest.raises(ValueError, match="260-character limit"):
            build_lnk(target=r"C:\t.exe", description=desc)

    def test_relative_path_over_limit_raises(self):
        rp = "A" * 261
        with pytest.raises(ValueError, match="260-character limit"):
            build_lnk(target=r"C:\t.exe", relative_path=rp)

    def test_working_dir_over_limit_raises(self):
        wd = "A" * 261
        with pytest.raises(ValueError, match="260-character limit"):
            build_lnk(target=r"C:\t.exe", working_dir=wd)

    def test_icon_location_over_limit_raises(self):
        il = "A" * 261
        with pytest.raises(ValueError, match="260-character limit"):
            build_lnk(target=r"C:\t.exe", icon_location=il)

    def test_arguments_over_limit_succeeds(self):
        """COMMAND_LINE_ARGUMENTS is unbounded per spec."""
        from lnksmith.parser import parse_lnk

        args = "A" * 1000
        data = build_lnk(target=r"C:\t.exe", arguments=args)
        info = parse_lnk(data)
        assert info.arguments == args


class TestFileAttributesParam:
    """GAP-8: file_attributes parameter in builder."""

    def test_default_is_archive(self):
        data = build_lnk(target=r"C:\t.exe")
        attrs = struct.unpack_from("<I", data, 24)[0]
        assert attrs == 0x20

    def test_custom_attributes(self):
        data = build_lnk(target=r"C:\t.exe", file_attributes=0x22)
        attrs = struct.unpack_from("<I", data, 24)[0]
        assert attrs == 0x22

    def test_hidden_system(self):
        data = build_lnk(target=r"C:\t.exe", file_attributes=0x06)
        attrs = struct.unpack_from("<I", data, 24)[0]
        assert attrs == 0x06


class TestFileAttributesReservedBits:
    """Spec 2.1.2: FileAttributes bits 3 and 6 are reserved, MUST be zero."""

    def test_reserved_bit3_warns(self):
        import warnings

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            build_lnk(target=r"C:\t.exe", file_attributes=0x08)
        assert any("reserved bits" in str(x.message) for x in w)

    def test_reserved_bit6_warns(self):
        import warnings

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            build_lnk(target=r"C:\t.exe", file_attributes=0x40)
        assert any("reserved bits" in str(x.message) for x in w)

    def test_valid_bits_no_warning(self):
        import warnings

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            build_lnk(target=r"C:\t.exe", file_attributes=0x27)
        assert not any("reserved bits" in str(x.message) for x in w)


class TestHotkeyVkValidation:
    """Spec 2.1.3: HotKey VK codes restricted to normative list."""

    def test_nonspec_vk_warns(self):
        import warnings

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            build_lnk(target=r"C:\t.exe", hotkey_vk=0x08, hotkey_mod=0x02)
        assert any("normative VK code" in str(x.message) for x in w)

    def test_spec_valid_vk_no_warning(self):
        import warnings

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            build_lnk(target=r"C:\t.exe", hotkey_vk=0x43, hotkey_mod=0x02)
        assert not any("normative VK code" in str(x.message) for x in w)


class TestLinkFlagsParam:
    """GAP-7: Additional link_flags parameter in builder."""

    def test_extra_flags_merged(self):
        data = build_lnk(target=r"C:\t.exe", link_flags=0x00040000)
        flags = struct.unpack_from("<I", data, 20)[0]
        assert flags & 0x00040000  # ForceNoLinkTrack

    def test_auto_flags_preserved(self):
        data = build_lnk(target=r"C:\t.exe", description="test", link_flags=0x00040000)
        flags = struct.unpack_from("<I", data, 20)[0]
        assert flags & 0x04  # HasName (auto)
        assert flags & 0x00040000  # ForceNoLinkTrack (manual)


class TestDarwinDataBlockBuilder:
    """GAP-2: DarwinDataBlock builder."""

    def test_darwin_block_present(self):
        from lnksmith.parser import parse_lnk

        data = build_lnk(target=r"C:\t.exe", darwin_data="TestApp-1234")
        info = parse_lnk(data)
        sigs = [b.signature for b in info.extra_blocks]
        assert 0xA0000006 in sigs

    def test_darwin_block_size(self):
        from lnksmith.parser import parse_lnk

        data = build_lnk(target=r"C:\t.exe", darwin_data="TestApp-1234")
        info = parse_lnk(data)
        block = next(b for b in info.extra_blocks if b.signature == 0xA0000006)
        assert block.size == 788

    def test_darwin_sets_flag(self):
        data = build_lnk(target=r"C:\t.exe", darwin_data="TestApp")
        flags = struct.unpack_from("<I", data, 20)[0]
        assert flags & 0x00001000  # HasDarwinID


class TestConsoleFEDataBlockBuilder:
    """GAP-4: ConsoleFEDataBlock builder."""

    def test_console_fe_block_present(self):
        from lnksmith.parser import parse_lnk

        data = build_lnk(target=r"C:\t.exe", console_fe_codepage=65001)
        info = parse_lnk(data)
        sigs = [b.signature for b in info.extra_blocks]
        assert 0xA0000004 in sigs

    def test_console_fe_block_size(self):
        from lnksmith.parser import parse_lnk

        data = build_lnk(target=r"C:\t.exe", console_fe_codepage=65001)
        info = parse_lnk(data)
        block = next(b for b in info.extra_blocks if b.signature == 0xA0000004)
        assert block.size == 12


class TestShimDataBlockBuilder:
    """GAP-5: ShimDataBlock builder."""

    def test_shim_block_present(self):
        from lnksmith.parser import parse_lnk

        data = build_lnk(target=r"C:\t.exe", shim_layer_name="WinXPSP3")
        info = parse_lnk(data)
        sigs = [b.signature for b in info.extra_blocks]
        assert 0xA0000008 in sigs

    def test_shim_sets_flag(self):
        data = build_lnk(target=r"C:\t.exe", shim_layer_name="Win7RTM")
        flags = struct.unpack_from("<I", data, 20)[0]
        assert flags & 0x00020000  # RunWithShimLayer


class TestConsoleDataBlockBuilder:
    """GAP-3: ConsoleDataBlock builder."""

    def test_console_block_present(self):
        from lnksmith.parser import parse_lnk

        data = build_lnk(target=r"C:\t.exe", console_data={"window_size_x": 120})
        info = parse_lnk(data)
        sigs = [b.signature for b in info.extra_blocks]
        assert 0xA0000002 in sigs

    def test_console_block_size(self):
        from lnksmith.parser import parse_lnk

        data = build_lnk(target=r"C:\t.exe", console_data={})
        info = parse_lnk(data)
        block = next(b for b in info.extra_blocks if b.signature == 0xA0000002)
        assert block.size == 0xCC  # 204 bytes


class TestSpecialFolderDataBlockBuilder:
    """GAP-6: SpecialFolderDataBlock builder."""

    def test_special_folder_block_present(self):
        from lnksmith.parser import parse_lnk

        data = build_lnk(target=r"C:\t.exe", special_folder_id=0x25)
        info = parse_lnk(data)
        sigs = [b.signature for b in info.extra_blocks]
        assert 0xA0000005 in sigs

    def test_special_folder_block_size(self):
        from lnksmith.parser import parse_lnk

        data = build_lnk(target=r"C:\t.exe", special_folder_id=0x25)
        info = parse_lnk(data)
        block = next(b for b in info.extra_blocks if b.signature == 0xA0000005)
        assert block.size == 16


# ---- Red team enhancement tests ----


class TestArgumentPadding:
    """ZDI-CAN-25373: Whitespace padding hides args in Properties dialog."""

    def test_pad_args_prepends_spaces(self):
        from lnksmith.parser import parse_lnk

        data = build_lnk(
            target=r"C:\Windows\System32\cmd.exe",
            arguments="/c calc.exe",
            pad_args=300,
        )
        info = parse_lnk(data)
        assert info.arguments.startswith(" " * 300)
        assert info.arguments.endswith("/c calc.exe")
        assert len(info.arguments) == 300 + len("/c calc.exe")

    def test_pad_args_zero_no_change(self):
        from lnksmith.parser import parse_lnk

        data = build_lnk(target=r"C:\t.exe", arguments="--help", pad_args=0)
        info = parse_lnk(data)
        assert info.arguments == "--help"

    def test_pad_args_sets_has_arguments_flag(self):
        data = build_lnk(target=r"C:\t.exe", arguments="/c whoami", pad_args=500)
        flags = struct.unpack_from("<I", data, 20)[0]
        assert flags & 0x20  # HasArguments

    def test_pad_args_without_arguments(self):
        from lnksmith.parser import parse_lnk

        data = build_lnk(target=r"C:\t.exe", pad_args=100)
        info = parse_lnk(data)
        # pad_args on empty string = just spaces
        assert info.arguments == " " * 100


class TestBinaryPadding:
    """T1027.001: File bloating to bypass AV/sandbox scan limits."""

    def test_pad_size_inflates_file(self):
        baseline = build_lnk(target=r"C:\t.exe")
        padded = build_lnk(target=r"C:\t.exe", pad_size=1024)
        assert len(padded) == len(baseline) + 1024

    def test_pad_size_appends_null_bytes(self):
        data = build_lnk(target=r"C:\t.exe", pad_size=256)
        # The last 256 bytes should be null (before any append_data)
        assert data[-256:] == b"\x00" * 256

    def test_pad_size_zero_no_change(self):
        baseline = build_lnk(target=r"C:\t.exe")
        unpadded = build_lnk(target=r"C:\t.exe", pad_size=0)
        assert len(baseline) == len(unpadded)

    def test_padded_file_still_parseable(self):
        from lnksmith.parser import parse_lnk

        data = build_lnk(target=r"C:\Windows\notepad.exe", pad_size=4096)
        info = parse_lnk(data)
        assert info.target_path == r"C:\Windows\notepad.exe"


class TestPayloadAppend:
    """LNK/HTA polyglot: arbitrary data after terminal block."""

    def test_append_data_present(self):
        payload = b"<html><body>HTA content</body></html>"
        data = build_lnk(target=r"C:\t.exe", append_data=payload)
        assert data.endswith(payload)

    def test_append_data_after_padding(self):
        payload = b"PAYLOAD_MARKER"
        data = build_lnk(target=r"C:\t.exe", pad_size=100, append_data=payload)
        # Payload is at the very end, after padding
        assert data.endswith(payload)
        # Padding is before payload
        pad_start = len(data) - len(payload) - 100
        assert data[pad_start : pad_start + 100] == b"\x00" * 100

    def test_append_empty_no_size_change(self):
        baseline = build_lnk(target=r"C:\t.exe")
        with_empty = build_lnk(target=r"C:\t.exe", append_data=b"")
        assert len(baseline) == len(with_empty)

    def test_appended_file_still_parseable(self):
        from lnksmith.parser import parse_lnk

        payload = b"<script>alert(1)</script>" * 100
        data = build_lnk(target=r"C:\Windows\notepad.exe", append_data=payload)
        info = parse_lnk(data)
        assert info.target_path == r"C:\Windows\notepad.exe"


class TestStompMotW:
    """CVE-2024-38217: MotW bypass via malformed IDList paths."""

    def test_stomp_dot_appends_period(self):
        data = build_lnk(
            target=r"C:\Windows\System32\powershell.exe",
            stomp_motw="dot",
        )
        # The IDList should contain the dotted filename (UTF-16LE in BEEF0004)
        dotted_utf16 = "powershell.exe.".encode("utf-16-le")
        assert dotted_utf16 in data

    def test_stomp_dot_with_short_names(self):
        data = build_lnk(
            target=[
                "C",
                ("WINDOW~1", "Windows"),
                ("SYSTEM~1", "System32"),
                "cmd.exe",
            ],
            stomp_motw="dot",
        )
        # Both short and long names get the dot
        assert b"cmd.exe." in data

    def test_stomp_relative_minimal_idlist(self):
        data = build_lnk(
            target=r"C:\Windows\System32\cmd.exe",
            stomp_motw="relative",
        )
        # Should NOT contain root/drive items but should have the filename
        assert b"cmd.exe" in data

    def test_stomp_invalid_value_raises(self):
        with pytest.raises(ValueError, match="Invalid stomp_motw"):
            build_lnk(target=r"C:\t.exe", stomp_motw="invalid")

    def test_stomp_dot_still_has_linkinfo(self):
        from lnksmith.parser import parse_lnk

        data = build_lnk(
            target=r"C:\Windows\notepad.exe",
            stomp_motw="dot",
        )
        info = parse_lnk(data)
        # LinkInfo should still have the correct (non-stomped) path
        assert info.target_path == r"C:\Windows\notepad.exe"


# ---- Beukema LNK spoofing technique tests ----
# Reference: https://www.wietzebeukema.nl/blog/trust-me-im-a-shortcut


class TestSplitEnvVarBlock:
    """Beukema Variant 4: independent ANSI/Unicode env block fields."""

    def test_split_env_block_present(self):
        from lnksmith.parser import parse_lnk

        data = build_lnk(
            target=r"C:\t.exe",
            env_target_ansi=r"C:\Windows\System32\cmd.exe",
        )
        info = parse_lnk(data)
        sigs = [b.signature for b in info.extra_blocks]
        assert 0xA0000001 in sigs
        block = next(b for b in info.extra_blocks if b.signature == 0xA0000001)
        assert block.size == 788

    def test_ansi_only_populates_ansi_field(self):
        from lnksmith.parser import parse_lnk

        data = build_lnk(
            target=r"C:\t.exe",
            env_target_ansi=r"C:\Windows\System32\cmd.exe",
        )
        info = parse_lnk(data)
        assert info.env_target_ansi == r"C:\Windows\System32\cmd.exe"
        assert info.env_target_unicode == ""

    def test_unicode_only_populates_unicode_field(self):
        from lnksmith.parser import parse_lnk

        data = build_lnk(
            target=r"C:\t.exe",
            env_target_unicode=r"C:\Windows\System32\cmd.exe",
        )
        info = parse_lnk(data)
        assert info.env_target_ansi == ""
        assert info.env_target_unicode == r"C:\Windows\System32\cmd.exe"

    def test_both_fields_set_independently(self):
        from lnksmith.parser import parse_lnk

        data = build_lnk(
            target=r"C:\t.exe",
            env_target_ansi=r"C:\fake\path.exe",
            env_target_unicode=r"C:\real\target.exe",
        )
        info = parse_lnk(data)
        assert info.env_target_ansi == r"C:\fake\path.exe"
        assert info.env_target_unicode == r"C:\real\target.exe"

    def test_has_exp_string_flag_set(self):
        data = build_lnk(
            target=r"C:\t.exe",
            env_target_ansi=r"C:\Windows\System32\cmd.exe",
        )
        flags = struct.unpack_from("<I", data, 20)[0]
        assert flags & 0x200  # HasExpString

    def test_rejects_combined_with_env_target_path(self):
        with pytest.raises(ValueError, match="mutually exclusive"):
            build_lnk(
                target=r"C:\t.exe",
                env_target_path=r"%WINDIR%\t.exe",
                env_target_ansi=r"C:\t.exe",
            )


class TestNullEnvBlock:
    """Beukema Variant 1: all-zeros EnvironmentVariableDataBlock."""

    def test_null_env_block_present(self):
        from lnksmith.parser import parse_lnk

        data = build_lnk(target=r"C:\t.exe", null_env_block=True)
        info = parse_lnk(data)
        sigs = [b.signature for b in info.extra_blocks]
        assert 0xA0000001 in sigs
        block = next(b for b in info.extra_blocks if b.signature == 0xA0000001)
        assert block.size == 788

    def test_null_env_block_fields_empty(self):
        from lnksmith.parser import parse_lnk

        data = build_lnk(target=r"C:\t.exe", null_env_block=True)
        info = parse_lnk(data)
        assert info.env_target_ansi == ""
        assert info.env_target_unicode == ""

    def test_has_exp_string_flag_set(self):
        data = build_lnk(target=r"C:\t.exe", null_env_block=True)
        flags = struct.unpack_from("<I", data, 20)[0]
        assert flags & 0x200  # HasExpString

    def test_rejects_combined_with_env_target_path(self):
        with pytest.raises(ValueError, match="mutually exclusive"):
            build_lnk(
                target=r"C:\t.exe",
                null_env_block=True,
                env_target_path=r"%WINDIR%\t.exe",
            )

    def test_rejects_combined_with_split_env(self):
        with pytest.raises(ValueError, match="mutually exclusive"):
            build_lnk(
                target=r"C:\t.exe",
                null_env_block=True,
                env_target_ansi=r"C:\t.exe",
            )


class TestPadChar:
    """CVE-2025-9491: configurable padding character for argument hiding."""

    def test_lfcr_fill(self):
        from lnksmith.parser import parse_lnk

        data = build_lnk(
            target=r"C:\t.exe",
            arguments="/c calc.exe",
            pad_args=300,
            pad_char="\n\r",
        )
        info = parse_lnk(data)
        assert info.arguments.startswith("\n\r" * 150)
        assert info.arguments.endswith("/c calc.exe")

    def test_single_char_fill(self):
        from lnksmith.parser import parse_lnk

        data = build_lnk(
            target=r"C:\t.exe",
            arguments="--help",
            pad_args=50,
            pad_char="\t",
        )
        info = parse_lnk(data)
        assert info.arguments.startswith("\t" * 50)

    def test_multi_char_truncation(self):
        from lnksmith.parser import parse_lnk

        data = build_lnk(
            target=r"C:\t.exe",
            arguments="x",
            pad_args=7,
            pad_char="abc",
        )
        info = parse_lnk(data)
        assert info.arguments == "abcabcax"

    def test_empty_pad_char_raises(self):
        with pytest.raises(ValueError, match="pad_char must be non-empty"):
            build_lnk(target=r"C:\t.exe", pad_char="")

    def test_default_space_unchanged(self):
        from lnksmith.parser import parse_lnk

        data = build_lnk(
            target=r"C:\t.exe",
            arguments="--help",
            pad_args=10,
        )
        info = parse_lnk(data)
        assert info.arguments.startswith(" " * 10)


class TestForceAnsi:
    """Beukema Variant 4 combo: suppress IsUnicode, ANSI StringData."""

    def test_is_unicode_not_set(self):
        data = build_lnk(target=r"C:\t.exe", force_ansi=True)
        flags = struct.unpack_from("<I", data, 20)[0]
        assert not (flags & 0x80)  # IsUnicode must NOT be set

    def test_is_unicode_set_by_default(self):
        data = build_lnk(target=r"C:\t.exe")
        flags = struct.unpack_from("<I", data, 20)[0]
        assert flags & 0x80  # IsUnicode set by default

    def test_ansi_stringdata_encoding(self):
        from lnksmith.parser import parse_lnk

        data = build_lnk(
            target=r"C:\t.exe",
            arguments="/c whoami",
            force_ansi=True,
        )
        info = parse_lnk(data)
        assert info.arguments == "/c whoami"

    def test_variant4_combo(self):
        """Full Variant 4: fake IDList + real ANSI env target + force_ansi."""
        from lnksmith.parser import parse_lnk

        data = build_lnk(
            target=r"C:\Windows\notepad.exe",  # decoy (shown in IDList)
            env_target_ansi=r"C:\Windows\System32\cmd.exe",  # real target
            arguments="/c whoami",
            force_ansi=True,
        )
        info = parse_lnk(data)
        assert info.env_target_ansi == r"C:\Windows\System32\cmd.exe"
        assert info.env_target_unicode == ""
        assert info.arguments == "/c whoami"
        # HasExpString set, IsUnicode not set
        assert info.flags & 0x200
        assert not (info.flags & 0x80)
