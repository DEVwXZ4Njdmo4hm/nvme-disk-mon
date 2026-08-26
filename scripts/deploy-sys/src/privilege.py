"""The deployment system's only entry point for root commands."""

import os
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path

SUDO = Path("/usr/bin/sudo")
SUDO_PREFIX = (str(SUDO), "-H", "-u", "root", "--")
ROOT_DIRECTORY = Path("/")

_ALLOWED_ROOT_PROGRAMS = frozenset(
    {
        Path("/usr/bin/chown"),
        Path("/usr/bin/find"),
        Path("/usr/bin/findmnt"),
        Path("/usr/bin/install"),
        Path("/usr/bin/mkdir"),
        Path("/usr/bin/rmdir"),
        Path("/usr/bin/sha256sum"),
        Path("/usr/bin/stat"),
        Path("/usr/bin/systemctl"),
        Path("/usr/bin/test"),
        Path("/usr/bin/true"),
        Path("/usr/local/bin/nvme-disk-mon"),
    }
)

type Command = Sequence[str | os.PathLike[str]]


class PrivilegeRunner:
    """Execute a small allowlist of absolute commands as root.

    The controller never changes identity.  A non-root controller receives a
    separate sudo policy decision for every invocation.
    """

    def __init__(self, *, euid: int | None = None, egid: int | None = None) -> None:
        self.euid = os.geteuid() if euid is None else euid
        self.egid = os.getegid() if egid is None else egid

    def _check_identity(self) -> None:
        if os.geteuid() != self.euid or os.getegid() != self.egid:
            raise PermissionError("部署控制器的 EUID/EGID 在执行期间发生变化")

    def command(self, command: Command) -> tuple[str, ...]:
        argv = tuple(str(argument) for argument in command)
        if not argv:
            raise ValueError("root 命令不能为空")
        program = Path(argv[0])
        if not program.is_absolute():
            raise ValueError(f"root 命令必须使用绝对路径：{program}")
        if program not in _ALLOWED_ROOT_PROGRAMS:
            raise ValueError(f"root 命令不在部署系统固定允许列表中：{program}")
        if self.euid == 0:
            return argv
        return (*SUDO_PREFIX, *argv)

    def authorize(self) -> None:
        """Ask the host policy to authorize one harmless root command."""
        self._check_identity()
        if self.euid == 0:
            return
        if not SUDO.is_file():
            raise FileNotFoundError(f"非 root 部署需要固定提权程序：{SUDO}")
        subprocess.run(
            (*SUDO_PREFIX, "/usr/bin/true"),
            cwd=ROOT_DIRECTORY,
            check=True,
        )
        self._check_identity()

    def run(
        self,
        command: Command,
        *,
        check: bool = True,
        capture_output: bool = False,
        text: bool = True,
        cwd: Path = ROOT_DIRECTORY,
        env: Mapping[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        self._check_identity()
        argv = self.command(command)
        result = subprocess.run(
            argv,
            cwd=cwd,
            env=None if env is None else dict(env),
            check=check,
            capture_output=capture_output,
            text=text,
        )
        self._check_identity()
        return result
