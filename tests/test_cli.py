"""Integration tests for the lnksmith CLI."""

import json
import subprocess
import sys


def run_cli(*args):
    """Run ``lnksmith`` as a subprocess and return CompletedProcess."""
    return subprocess.run(
        [sys.executable, "-m", "lnksmith.cli", *args],
        capture_output=True,
        text=True,
    )


class TestBuildSubcommand:
    """Test ``lnksmith build``."""

    def test_build_creates_file(self, tmp_path):
        out = tmp_path / "test.lnk"
        result = run_cli(
            "build",
            "--target",
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
            "--target",
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
            "--hotkey-vk",
            "0x43",
            "--hotkey-mod",
            "0x02",
        )
        assert result.returncode == 0
        assert out.exists()

    def test_build_missing_target(self):
        result = run_cli("build", "-o", "nope.lnk")
        assert result.returncode != 0


class TestParseSubcommand:
    """Test ``lnksmith parse``."""

    def test_parse_displays_output(self, tmp_path):
        # First build a LNK
        lnk_path = tmp_path / "test.lnk"
        run_cli("build", "--target", r"C:\Windows\notepad.exe", "-o", str(lnk_path))
        # Then parse it
        result = run_cli("parse", str(lnk_path))
        assert result.returncode == 0
        assert "notepad.exe" in result.stdout

    def test_parse_json_output(self, tmp_path):
        lnk_path = tmp_path / "test.lnk"
        run_cli("build", "--target", r"C:\Windows\notepad.exe", "-o", str(lnk_path))
        result = run_cli("parse", "--json", str(lnk_path))
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["target_path"] == r"C:\Windows\notepad.exe"

    def test_parse_multiple_files(self, tmp_path):
        lnk1 = tmp_path / "a.lnk"
        lnk2 = tmp_path / "b.lnk"
        run_cli("build", "--target", r"C:\a.exe", "-o", str(lnk1))
        run_cli("build", "--target", r"C:\b.exe", "-o", str(lnk2))
        result = run_cli("parse", str(lnk1), str(lnk2))
        assert result.returncode == 0
        assert "a.exe" in result.stdout
        assert "b.exe" in result.stdout


class TestNoCommand:
    """Test behavior with no subcommand."""

    def test_no_command_shows_help(self):
        result = run_cli()
        assert result.returncode != 0


# ---- MS-SHLLINK v10 CLI tests ----


class TestBuildNewOptions:
    """Test new build subcommand options."""

    def test_build_with_tracker(self, tmp_path):
        out = tmp_path / "tracker.lnk"
        result = run_cli(
            "build",
            "--target",
            r"C:\Windows\notepad.exe",
            "--tracker-machine-id",
            "MYHOST",
            "-o",
            str(out),
        )
        assert result.returncode == 0
        assert out.exists()

    def test_build_with_known_folder(self, tmp_path):
        out = tmp_path / "kf.lnk"
        result = run_cli(
            "build",
            "--target",
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
            "--target",
            r"\\server\share\file.txt",
            "-o",
            str(out),
        )
        assert result.returncode == 0
        assert out.exists()

    def test_parse_unc_shows_network(self, tmp_path):
        lnk = tmp_path / "unc.lnk"
        run_cli("build", "--target", r"\\server\share\file.txt", "-o", str(lnk))
        result = run_cli("parse", str(lnk))
        assert result.returncode == 0
        assert r"\\server\share" in result.stdout

    def test_parse_tracker_shows_machine(self, tmp_path):
        lnk = tmp_path / "t.lnk"
        run_cli(
            "build",
            "--target",
            r"C:\t.exe",
            "--tracker-machine-id",
            "HOST01",
            "-o",
            str(lnk),
        )
        result = run_cli("parse", str(lnk))
        assert result.returncode == 0
        assert "HOST01" in result.stdout

    def test_build_with_property_store_json(self, tmp_path):
        import json

        ps_file = tmp_path / "props.json"
        ps_data = [
            {
                "format_id": "{B9B4B3FC-2B51-4A42-B5D8-324146AFCF25}",
                "properties": [
                    {"id": 2, "type": 31, "value": "hello"},
                ],
            }
        ]
        ps_file.write_text(json.dumps(ps_data))

        out = tmp_path / "ps.lnk"
        result = run_cli(
            "build",
            "--target",
            r"C:\t.exe",
            "--property-store-json",
            str(ps_file),
            "-o",
            str(out),
        )
        assert result.returncode == 0
        assert out.exists()
