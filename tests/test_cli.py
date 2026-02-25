"""Integration tests for the lnksmith CLI."""

import json
import subprocess
import sys


def run_cli(*args):
    """Run ``lnksmith`` as a subprocess and return CompletedProcess."""
    return subprocess.run(
        [sys.executable, "-m", "lnksmith", *args],
        capture_output=True,
        text=True,
        timeout=30,
    )


def _write_json(tmp_path, data, name="config.json"):
    """Write *data* as JSON to *tmp_path/name* and return the path string."""
    p = tmp_path / name
    p.write_text(json.dumps(data))
    return str(p)


class TestBuildSubcommand:
    """Test ``lnksmith build``."""

    def test_build_creates_file(self, tmp_path):
        out = tmp_path / "test.lnk"
        result = run_cli(
            "build",
            r"C:\Windows\notepad.exe",
            "-o",
            str(out),
        )
        assert result.returncode == 0
        assert out.exists()
        # Verify header magic
        data = out.read_bytes()
        assert len(data) >= 76
        assert data[0:4] == b"\x4c\x00\x00\x00"

    def test_build_with_all_options(self, tmp_path):
        out = tmp_path / "full.lnk"
        result = run_cli(
            "build",
            r"C:\Windows\notepad.exe",
            "-o",
            str(out),
            "--icon",
            r"C:\icon.exe",
            "--icon-env",
            r"%PF%\icon.exe",
            "--icon-index",
            "1",
            "--description",
            "My App",
            "--relative-path",
            r".\notepad.exe",
            "--working-dir",
            r"C:\Windows",
            "--arguments=--help",
            "--show",
            "maximized",
            "--file-size",
            "12345",
            "--hotkey",
            "CTRL+C",
        )
        assert result.returncode == 0
        assert out.exists()

    def test_build_missing_target(self):
        result = run_cli("build", "-o", "nope.lnk")
        assert result.returncode != 0

    def test_build_with_timestamps(self, tmp_path):
        out = tmp_path / "ts.lnk"
        result = run_cli(
            "build",
            r"C:\Windows\notepad.exe",
            "--creation-time",
            "2020-01-01T00:00:00",
            "--access-time",
            "2021-06-15T12:30:00",
            "--write-time",
            "132223104000000000",
            "-o",
            str(out),
        )
        assert result.returncode == 0
        assert out.exists()

    def test_build_with_volume_metadata(self, tmp_path):
        out = tmp_path / "vol.lnk"
        cfg = _write_json(
            tmp_path,
            {
                "volume_label": "SYSTEM",
                "drive_serial": 0xDEADBEEF,
                "drive_type": 2,
            },
        )
        result = run_cli(
            "build",
            r"C:\Windows\notepad.exe",
            "-o",
            str(out),
            "-j",
            cfg,
        )
        assert result.returncode == 0
        assert out.exists()

    def test_build_with_darwin(self, tmp_path):
        out = tmp_path / "darwin.lnk"
        cfg = _write_json(tmp_path, {"darwin_data": "MyAppProductCode"})
        result = run_cli(
            "build",
            r"C:\Windows\notepad.exe",
            "-o",
            str(out),
            "-j",
            cfg,
        )
        assert result.returncode == 0
        assert out.exists()

    def test_build_with_shim(self, tmp_path):
        out = tmp_path / "shim.lnk"
        cfg = _write_json(tmp_path, {"shim_layer_name": "WinXPSp3"})
        result = run_cli(
            "build",
            r"C:\Windows\notepad.exe",
            "-o",
            str(out),
            "-j",
            cfg,
        )
        assert result.returncode == 0
        assert out.exists()

    def test_build_with_special_folder(self, tmp_path):
        out = tmp_path / "sf.lnk"
        cfg = _write_json(
            tmp_path,
            {
                "special_folder_id": 0x25,
                "special_folder_offset": 0x00,
            },
        )
        result = run_cli(
            "build",
            r"C:\Windows\notepad.exe",
            "-o",
            str(out),
            "-j",
            cfg,
        )
        assert result.returncode == 0
        assert out.exists()

    def test_build_with_network_device(self, tmp_path):
        out = tmp_path / "net.lnk"
        cfg = _write_json(
            tmp_path,
            {
                "network_device_name": "Z:",
                "network_provider_type": 0x00020000,
            },
        )
        result = run_cli(
            "build",
            r"\\server\share\file.txt",
            "-o",
            str(out),
            "-j",
            cfg,
        )
        assert result.returncode == 0
        assert out.exists()


class TestParseSubcommand:
    """Test ``lnksmith parse``."""

    def test_parse_displays_output(self, tmp_path):
        # First build a LNK
        lnk_path = tmp_path / "test.lnk"
        run_cli("build", r"C:\Windows\notepad.exe", "-o", str(lnk_path))
        # Then parse it
        result = run_cli("parse", str(lnk_path))
        assert result.returncode == 0
        assert "notepad.exe" in result.stdout

    def test_parse_json_output(self, tmp_path):
        lnk_path = tmp_path / "test.lnk"
        run_cli("build", r"C:\Windows\notepad.exe", "-o", str(lnk_path))
        result = run_cli("parse", "--json", str(lnk_path))
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["target_path"] == r"C:\Windows\notepad.exe"

    def test_parse_multiple_files(self, tmp_path):
        lnk1 = tmp_path / "a.lnk"
        lnk2 = tmp_path / "b.lnk"
        run_cli("build", r"C:\a.exe", "-o", str(lnk1))
        run_cli("build", r"C:\b.exe", "-o", str(lnk2))
        result = run_cli("parse", str(lnk1), str(lnk2))
        assert result.returncode == 0
        assert "a.exe" in result.stdout
        assert "b.exe" in result.stdout


class TestNoCommand:
    """Test behavior with no subcommand."""

    def test_no_command_shows_help(self):
        result = run_cli()
        assert result.returncode != 0


# ---- Hotkey tests ----


class TestHotkey:
    """Test the combined --hotkey flag."""

    def test_hotkey_ctrl_c(self, tmp_path):
        out = tmp_path / "hk.lnk"
        result = run_cli(
            "build",
            r"C:\Windows\notepad.exe",
            "--hotkey",
            "CTRL+C",
            "-o",
            str(out),
        )
        assert result.returncode == 0
        result = run_cli("parse", "--json", str(out))
        data = json.loads(result.stdout)
        assert data["hotkey_vk"] == 0x43
        assert data["hotkey_mod"] == 0x02

    def test_hotkey_alt_shift_f5(self, tmp_path):
        out = tmp_path / "hk2.lnk"
        result = run_cli(
            "build",
            r"C:\Windows\notepad.exe",
            "--hotkey",
            "ALT+SHIFT+F5",
            "-o",
            str(out),
        )
        assert result.returncode == 0
        result = run_cli("parse", "--json", str(out))
        data = json.loads(result.stdout)
        assert data["hotkey_vk"] == 0x74
        assert data["hotkey_mod"] == 0x05  # ALT(0x04) | SHIFT(0x01)

    def test_hotkey_invalid_missing_modifier(self):
        result = run_cli("build", r"C:\t.exe", "--hotkey", "C")
        assert result.returncode != 0


# ---- --from-json tests ----


class TestFromJson:
    """Test the --from-json config file support."""

    def test_from_json_basic(self, tmp_path):
        out = tmp_path / "j.lnk"
        cfg = _write_json(
            tmp_path,
            {
                "description": "From JSON",
                "arguments": "--verbose",
                "tracker_machine_id": "HOST99",
            },
        )
        result = run_cli(
            "build",
            r"C:\Windows\notepad.exe",
            "-o",
            str(out),
            "-j",
            cfg,
        )
        assert result.returncode == 0
        result = run_cli("parse", "--json", str(out))
        data = json.loads(result.stdout)
        assert data["description"] == "From JSON"
        assert data["arguments"] == "--verbose"
        assert data["tracker_machine_id"] == "HOST99"

    def test_cli_overrides_json(self, tmp_path):
        out = tmp_path / "override.lnk"
        cfg = _write_json(
            tmp_path,
            {
                "description": "From JSON",
                "arguments": "--json-arg",
            },
        )
        result = run_cli(
            "build",
            r"C:\Windows\notepad.exe",
            "-o",
            str(out),
            "-j",
            cfg,
            "--description",
            "CLI Wins",
        )
        assert result.returncode == 0
        result = run_cli("parse", "--json", str(out))
        data = json.loads(result.stdout)
        assert data["description"] == "CLI Wins"
        # JSON-only field still applied
        assert data["arguments"] == "--json-arg"

    def test_from_json_with_property_stores(self, tmp_path):
        out = tmp_path / "ps.lnk"
        cfg = _write_json(
            tmp_path,
            {
                "property_stores": [
                    {
                        "format_id": "{B9B4B3FC-2B51-4A42-B5D8-324146AFCF25}",
                        "properties": [
                            {"id": 2, "type": 31, "value": "hello"},
                        ],
                    }
                ],
            },
        )
        result = run_cli(
            "build",
            r"C:\t.exe",
            "-o",
            str(out),
            "-j",
            cfg,
        )
        assert result.returncode == 0
        assert out.exists()


# ---- Auto-derive working dir tests ----


class TestAutoDeriveWorkingDir:
    """Test auto-derived working directory from target."""

    def test_auto_derive_local_path(self, tmp_path):
        out = tmp_path / "wd.lnk"
        run_cli(
            "build",
            r"C:\Windows\System32\notepad.exe",
            "-o",
            str(out),
        )
        result = run_cli("parse", "--json", str(out))
        data = json.loads(result.stdout)
        assert data["working_dir"] == r"C:\Windows\System32"

    def test_auto_derive_unc_path(self, tmp_path):
        out = tmp_path / "wd_unc.lnk"
        run_cli(
            "build",
            r"\\server\share\dir\file.txt",
            "-o",
            str(out),
        )
        result = run_cli("parse", "--json", str(out))
        data = json.loads(result.stdout)
        assert data["working_dir"] == r"\\server\share\dir"

    def test_explicit_working_dir_overrides(self, tmp_path):
        out = tmp_path / "wd_explicit.lnk"
        run_cli(
            "build",
            r"C:\Windows\notepad.exe",
            "--working-dir",
            r"C:\Users",
            "-o",
            str(out),
        )
        result = run_cli("parse", "--json", str(out))
        data = json.loads(result.stdout)
        assert data["working_dir"] == r"C:\Users"

    def test_empty_working_dir_disables_auto(self, tmp_path):
        out = tmp_path / "wd_empty.lnk"
        run_cli(
            "build",
            r"C:\Windows\notepad.exe",
            "--working-dir",
            "",
            "-o",
            str(out),
        )
        result = run_cli("parse", "--json", str(out))
        data = json.loads(result.stdout)
        assert data["working_dir"] == ""

    def test_json_working_dir_respected(self, tmp_path):
        out = tmp_path / "wd_json.lnk"
        cfg = _write_json(tmp_path, {"working_dir": r"C:\FromJSON"})
        run_cli(
            "build",
            r"C:\Windows\notepad.exe",
            "-o",
            str(out),
            "-j",
            cfg,
        )
        result = run_cli("parse", "--json", str(out))
        data = json.loads(result.stdout)
        assert data["working_dir"] == r"C:\FromJSON"


# ---- MS-SHLLINK v10 CLI tests ----


class TestBuildNewOptions:
    """Test new build subcommand options."""

    def test_build_with_tracker(self, tmp_path):
        out = tmp_path / "tracker.lnk"
        cfg = _write_json(tmp_path, {"tracker_machine_id": "MYHOST"})
        result = run_cli(
            "build",
            r"C:\Windows\notepad.exe",
            "-o",
            str(out),
            "-j",
            cfg,
        )
        assert result.returncode == 0
        assert out.exists()

    def test_build_with_known_folder(self, tmp_path):
        out = tmp_path / "kf.lnk"
        result = run_cli(
            "build",
            r"C:\Users\test\Desktop",
            "--known-folder",
            "Desktop",
            "-o",
            str(out),
        )
        assert result.returncode == 0
        assert out.exists()

    def test_build_unc_target(self, tmp_path):
        out = tmp_path / "unc.lnk"
        result = run_cli(
            "build",
            r"\\server\share\file.txt",
            "-o",
            str(out),
        )
        assert result.returncode == 0
        assert out.exists()

    def test_parse_unc_shows_network(self, tmp_path):
        lnk = tmp_path / "unc.lnk"
        run_cli("build", r"\\server\share\file.txt", "-o", str(lnk))
        result = run_cli("parse", str(lnk))
        assert result.returncode == 0
        assert r"\\server\share" in result.stdout

    def test_parse_tracker_shows_machine(self, tmp_path):
        lnk = tmp_path / "t.lnk"
        cfg = _write_json(tmp_path, {"tracker_machine_id": "HOST01"})
        run_cli(
            "build",
            r"C:\t.exe",
            "-o",
            str(lnk),
            "-j",
            cfg,
        )
        result = run_cli("parse", str(lnk))
        assert result.returncode == 0
        assert "HOST01" in result.stdout

    def test_parse_timestamps_roundtrip(self, tmp_path):
        lnk = tmp_path / "ts.lnk"
        run_cli(
            "build",
            r"C:\Windows\notepad.exe",
            "--creation-time",
            "2020-06-15T10:30:00",
            "-o",
            str(lnk),
        )
        result = run_cli("parse", "--json", str(lnk))
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert "2020-06-15" in data["creation_time"]

    def test_parse_volume_metadata_roundtrip(self, tmp_path):
        lnk = tmp_path / "vol.lnk"
        cfg = _write_json(tmp_path, {"volume_label": "TESTDISK"})
        run_cli(
            "build",
            r"C:\Windows\notepad.exe",
            "-o",
            str(lnk),
            "-j",
            cfg,
        )
        result = run_cli("parse", "--json", str(lnk))
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["volume_label"] == "TESTDISK"

    def test_parse_network_device_roundtrip(self, tmp_path):
        lnk = tmp_path / "net.lnk"
        cfg = _write_json(tmp_path, {"network_device_name": "Z:"})
        run_cli(
            "build",
            r"\\server\share\file.txt",
            "-o",
            str(lnk),
            "-j",
            cfg,
        )
        result = run_cli("parse", "--json", str(lnk))
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["device_name"] == "Z:"
