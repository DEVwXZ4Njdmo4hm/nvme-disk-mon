import os
import sys
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock

SOURCE = Path(__file__).resolve().parents[2] / "src"
sys.path.insert(0, str(SOURCE))

from privilege import SUDO_PREFIX, PrivilegeRunner  # noqa: E402


class PrivilegeRunnerTests(unittest.TestCase):
    def test_non_root_command_uses_exact_sudo_prefix(self) -> None:
        runner = PrivilegeRunner(euid=1000, egid=1000)
        self.assertEqual(
            runner.command(("/usr/bin/systemctl", "--system", "daemon-reload")),
            (*SUDO_PREFIX, "/usr/bin/systemctl", "--system", "daemon-reload"),
        )

    def test_root_command_skips_sudo(self) -> None:
        runner = PrivilegeRunner(euid=0, egid=0)
        self.assertEqual(
            runner.command(("/usr/bin/true",)),
            ("/usr/bin/true",),
        )

    def test_relative_and_unlisted_programs_are_rejected(self) -> None:
        runner = PrivilegeRunner(euid=os.geteuid(), egid=os.getegid())
        with self.assertRaises(ValueError):
            runner.command(("systemctl", "daemon-reload"))
        with self.assertRaises(ValueError):
            runner.command(("/bin/sh", "-c", "true"))

    @mock.patch("privilege.SUDO")
    @mock.patch("privilege.subprocess.run")
    def test_authorization_probe_is_fixed(self, run: mock.Mock, sudo: mock.Mock) -> None:
        sudo.is_file.return_value = True
        runner = PrivilegeRunner(euid=os.geteuid(), egid=os.getegid())
        if os.geteuid() == 0:
            runner.euid = 1000
            runner.egid = 1000
        with (
            mock.patch("privilege.os.geteuid", return_value=runner.euid),
            mock.patch("privilege.os.getegid", return_value=runner.egid),
        ):
            runner.authorize()
        run.assert_called_once_with(
            (*SUDO_PREFIX, "/usr/bin/true"),
            cwd=Path("/"),
            check=True,
        )

    def test_run_detects_controller_identity_change(self) -> None:
        runner = PrivilegeRunner(euid=123, egid=456)
        with (
            mock.patch("privilege.os.geteuid", return_value=124),
            mock.patch("privilege.os.getegid", return_value=456),
            self.assertRaises(PermissionError),
        ):
            runner.run(("/usr/bin/true",))

    @mock.patch("privilege.subprocess.run")
    def test_successful_root_command_is_not_echoed(self, run: mock.Mock) -> None:
        runner = PrivilegeRunner(euid=os.geteuid(), egid=os.getegid())
        output = StringIO()
        with redirect_stdout(output):
            runner.run(("/usr/bin/stat", "--format=%f", "--", "/usr"))

        self.assertEqual(output.getvalue(), "")
        run.assert_called_once_with(
            runner.command(("/usr/bin/stat", "--format=%f", "--", "/usr")),
            cwd=Path("/"),
            env=None,
            check=True,
            capture_output=False,
            text=True,
        )


if __name__ == "__main__":
    unittest.main()
