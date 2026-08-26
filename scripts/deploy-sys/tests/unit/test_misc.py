import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from types import SimpleNamespace

SOURCE = Path(__file__).resolve().parents[2] / "src"
sys.path.insert(0, str(SOURCE))

from misc import (  # noqa: E402
    REGISTRATION_PAYLOAD,
    _display_width,
    copy_source_files,
    create_registration,
    draw_banner,
    draw_table,
    git_source_files,
    release_registration,
    remove_workdir,
    run_quiet_command,
    should_remove_workdir,
)


class LocalRunner:
    def __init__(self) -> None:
        self.euid = os.geteuid()
        self.egid = os.getegid()

    def run(self, command, *, check=True, **_kwargs):
        path = Path(command[-1])
        if command[0] == "/usr/bin/mkdir":
            path.mkdir(mode=0o700)
        elif command[0] == "/usr/bin/chown":
            pass
        elif command[0] == "/usr/bin/rmdir":
            path.rmdir()
        else:
            raise AssertionError(command)
        return SimpleNamespace(returncode=0, stdout="")


class MiscTests(unittest.TestCase):
    def test_quiet_command_discards_success_and_retains_failure_output(self) -> None:
        success = StringIO()
        with redirect_stdout(success), redirect_stderr(success):
            run_quiet_command(
                (sys.executable, "-c", "print('successful child noise')"),
                cwd=Path.cwd(),
            )
        self.assertEqual(success.getvalue(), "")

        with self.assertRaises(subprocess.CalledProcessError) as raised:
            run_quiet_command(
                (
                    sys.executable,
                    "-c",
                    "import sys; print('child diagnostic'); sys.exit(7)",
                ),
                cwd=Path.cwd(),
            )
        self.assertEqual(raised.exception.returncode, 7)
        self.assertEqual(raised.exception.stdout, "child diagnostic\n")

    def test_clean_policy_truth_table(self) -> None:
        self.assertTrue(should_remove_workdir("always", succeeded=False))
        self.assertTrue(should_remove_workdir("always", succeeded=True))
        self.assertFalse(should_remove_workdir("except-fail", succeeded=False))
        self.assertTrue(should_remove_workdir("except-fail", succeeded=True))
        self.assertFalse(should_remove_workdir("none", succeeded=True))
        with self.assertRaises(ValueError):
            should_remove_workdir("sometimes", succeeded=True)

    def test_draw_table_contains_rows(self) -> None:
        table = draw_table((("result", "ok"), ("path", "/tmp/a")))
        self.assertIn("| result | ok", table)
        self.assertIn("| path", table)

    def test_draw_table_uses_terminal_width_for_chinese_labels(self) -> None:
        table = draw_table(
            (
                ("结果", "成功"),
                ("控制器 EUID", "1000"),
                ("data_path", "/etc/nvme-disk-mon"),
            )
        )
        lines = table.splitlines()
        self.assertEqual(lines[1], "| 结果        | 成功               |")
        self.assertEqual(lines[2], "| 控制器 EUID | 1000               |")
        self.assertEqual(lines[3], "| data_path   | /etc/nvme-disk-mon |")
        self.assertEqual(len({_display_width(line) for line in lines}), 1)

    def test_draw_banner_is_centered_and_exactly_38_columns(self) -> None:
        banner = draw_banner("NVMe-Disk-Mon Deploy System")
        lines = banner.splitlines()
        self.assertEqual(
            lines,
            [
                "**************************************",
                "*                                    *",
                "*    NVMe-Disk-Mon Deploy System     *",
                "*                                    *",
                "**************************************",
            ],
        )
        self.assertEqual({_display_width(line) for line in lines}, {38})

    def test_copy_and_remove_workdir_require_sentinel(self) -> None:
        original_cwd = Path.cwd()
        with tempfile.TemporaryDirectory(dir=original_cwd) as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "Cargo.toml").write_text("[package]\n", encoding="utf-8")
            workdir = root / "work"
            copy_source_files(source, workdir, (Path("Cargo.toml"),))
            self.assertEqual((workdir / "Cargo.toml").read_text(), "[package]\n")
            remove_workdir(workdir)
            self.assertFalse(workdir.exists())
        os.chdir(original_cwd)

    def test_registration_payload_is_private_and_released(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "registration"
            runner = LocalRunner()
            payload = create_registration(runner, {"pid": 1}, directory=directory)
            self.assertEqual(payload.name, REGISTRATION_PAYLOAD)
            self.assertEqual(payload.stat().st_mode & 0o777, 0o600)
            release_registration(runner, payload, directory=directory)
            self.assertFalse(directory.exists())

    def test_live_source_snapshot_includes_new_controller(self) -> None:
        project_root = Path(__file__).resolve().parents[4]
        files = git_source_files(project_root)
        self.assertIn(Path("scripts/deploy-sys/src/main.py"), files)
        self.assertIn(Path("docs/index.html"), files)
        self.assertNotIn(Path("packaging/templates/nvme-disk-mon.timer.template"), files)


if __name__ == "__main__":
    unittest.main()
