"""Tests for lnksmith.builder."""

import struct

import pytest

from lnksmith._constants import LINK_CLSID, SW_MAXIMIZED, SW_MINIMIZED, SW_SHOWNORMAL
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
        # Only IDList + LinkInfo + IsUnicode
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

    @pytest.mark.parametrize("cmd", [SW_SHOWNORMAL, SW_MAXIMIZED, SW_MINIMIZED])
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
