"""Small helpers shared by deployment stages."""

import json
import os
import shutil
import stat
import subprocess
import unicodedata
from collections.abc import Iterable, Mapping, Sequence
from contextlib import suppress
from pathlib import Path

from privilege import PrivilegeRunner

DEPLOY_SYSTEM_ROOT = Path(__file__).resolve().parent.parent
PROJECT_ROOT = DEPLOY_SYSTEM_ROOT.parent.parent

BIN_PATH = Path("/usr/local/bin/nvme-disk-mon")
LIB_PATH = Path("/usr/local/lib")
DATA_PATH = Path("/etc/nvme-disk-mon")
CONF_PATH = DATA_PATH / "ndm-cfg.toml"
STATS_PATH = DATA_PATH / "stats.db"
OAUTH_TOKEN_PATH = DATA_PATH / "oauth_token.json"
UNIT_DIRECTORY = Path("/usr/local/lib/systemd/system")
UNIT_PATH = UNIT_DIRECTORY / "nvme-disk-mon.service"
DOC_DIRECTORY_NAME = "nvme-disk-mon"

REGISTRATION_DIRECTORY = Path("/run/ndm-deploy-sys")
RUN_DIRECTORY = Path("/run")
REGISTRATION_PAYLOAD = ".payload"
MAX_REGISTRATION_BYTES = 16 * 1024

type Command = Sequence[str | os.PathLike[str]]


def run_quiet_command(command: Command, *, cwd: Path) -> None:
    """Discard successful child output and retain combined diagnostics on failure."""
    subprocess.run(
        tuple(str(argument) for argument in command),
        cwd=cwd,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def validate_run_directory(path: Path = RUN_DIRECTORY) -> None:
    metadata = path.stat(follow_symlinks=False)
    if not stat.S_ISDIR(metadata.st_mode) or path.is_symlink():
        raise NotADirectoryError(f"全局注册上级必须是实体目录：{path}")
    if metadata.st_uid != 0 or metadata.st_gid != 0:
        raise PermissionError(f"全局注册上级必须由 root:root 所有：{path}")
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        raise PermissionError(f"全局注册上级不能允许 group/other 写入：{path}")


def create_registration(
    runner: PrivilegeRunner,
    payload: Mapping[str, object],
    *,
    directory: Path = REGISTRATION_DIRECTORY,
) -> Path:
    """Create the fixed global registration directory and private payload."""
    if directory == REGISTRATION_DIRECTORY:
        validate_run_directory(directory.parent)
    runner.run(("/usr/bin/mkdir", "--mode=0700", "--", directory))
    try:
        runner.run(
            (
                "/usr/bin/chown",
                "--no-dereference",
                f"{runner.euid}:{runner.egid}",
                "--",
                directory,
            )
        )
        metadata = directory.stat(follow_symlinks=False)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or directory.is_symlink()
            or metadata.st_uid != runner.euid
            or metadata.st_gid != runner.egid
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise PermissionError(f"全局注册目录属性无效：{directory}")

        encoded = json.dumps(dict(payload), ensure_ascii=False, sort_keys=True).encode("utf-8")
        if len(encoded) + 1 > MAX_REGISTRATION_BYTES:
            raise ValueError("全局注册 payload 超过大小限制")
        payload_path = directory / REGISTRATION_PAYLOAD
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(payload_path, flags, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            output.write(encoded)
            output.write(b"\n")
            output.flush()
            os.fsync(output.fileno())
        payload_metadata = payload_path.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(payload_metadata.st_mode)
            or payload_metadata.st_uid != runner.euid
            or stat.S_IMODE(payload_metadata.st_mode) != 0o600
        ):
            raise PermissionError(f"全局注册 payload 属性无效：{payload_path}")
        return payload_path
    except BaseException:
        with suppress(BaseException):
            payload_path = directory / REGISTRATION_PAYLOAD
            payload_path.unlink(missing_ok=True)
        with suppress(BaseException):
            runner.run(("/usr/bin/rmdir", "--", directory), check=False)
        raise


def release_registration(
    runner: PrivilegeRunner,
    payload_path: Path | None,
    *,
    directory: Path = REGISTRATION_DIRECTORY,
) -> None:
    if payload_path is None:
        return
    if payload_path != directory / REGISTRATION_PAYLOAD:
        raise ValueError(f"拒绝释放未知注册 payload：{payload_path}")
    metadata = directory.stat(follow_symlinks=False)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or directory.is_symlink()
        or metadata.st_uid != runner.euid
        or metadata.st_gid != runner.egid
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise PermissionError(f"拒绝释放属性不符的全局注册目录：{directory}")
    payload_metadata = payload_path.stat(follow_symlinks=False)
    if (
        not stat.S_ISREG(payload_metadata.st_mode)
        or payload_metadata.st_uid != runner.euid
        or stat.S_IMODE(payload_metadata.st_mode) != 0o600
    ):
        raise PermissionError(f"拒绝删除属性不符的全局注册 payload：{payload_path}")
    payload_path.unlink()
    runner.run(("/usr/bin/rmdir", "--", directory))


def git_source_files(project_root: Path) -> tuple[Path, ...]:
    """Use Git's complete ignore semantics and exclude deleted tracked paths."""
    git = Path("/usr/bin/git")
    if not git.is_file():
        raise FileNotFoundError(f"源码快照需要固定 Git 程序：{git}")
    listed = subprocess.run(
        (
            str(git),
            "-C",
            str(project_root),
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ),
        check=True,
        capture_output=True,
    ).stdout
    deleted = frozenset(
        subprocess.run(
            (str(git), "-C", str(project_root), "ls-files", "-z", "--deleted"),
            check=True,
            capture_output=True,
        ).stdout.split(b"\0")
    )
    entries: list[Path] = []
    for raw_path in listed.split(b"\0"):
        if not raw_path or raw_path in deleted:
            continue
        relative = Path(os.fsdecode(raw_path))
        _validate_relative_path(relative)
        source = project_root / relative
        metadata = source.stat(follow_symlinks=False)
        if not stat.S_ISREG(metadata.st_mode) or source.is_symlink():
            raise ValueError(f"源码清单只允许实体普通文件：{relative}")
        entries.append(relative)
    required = {
        Path(".gitignore"),
        Path("Cargo.lock"),
        Path("Cargo.toml"),
        Path("deploy.py"),
        Path("scripts/build-script/src/main.py"),
        Path("scripts/deploy-sys/src/main.py"),
    }
    missing = required.difference(entries)
    if missing:
        names = ", ".join(str(item) for item in sorted(missing))
        raise FileNotFoundError(f"源码快照缺少部署必需文件：{names}")
    return tuple(sorted(set(entries)))


def _validate_relative_path(path: Path) -> None:
    if not path.parts or path.is_absolute() or ".." in path.parts or path.parts[0] == ".git":
        raise ValueError(f"源码路径越界：{path}")


def copy_source_files(project_root: Path, workdir: Path, files: Iterable[Path]) -> None:
    workdir.mkdir(mode=0o700, parents=False, exist_ok=False)
    try:
        for relative in files:
            _validate_relative_path(relative)
            source = project_root / relative
            metadata = source.stat(follow_symlinks=False)
            if not stat.S_ISREG(metadata.st_mode) or source.is_symlink():
                raise ValueError(f"源码文件属性在复制前发生变化：{relative}")
            destination = workdir / relative
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            shutil.copy2(source, destination, follow_symlinks=False)
        (workdir / ".ndm-deploy").mkdir(mode=0o700)
        actual = workdir.stat(follow_symlinks=False)
        if (
            not stat.S_ISDIR(actual.st_mode)
            or workdir.is_symlink()
            or actual.st_uid != os.geteuid()
            or actual.st_gid != os.getegid()
            or stat.S_IMODE(actual.st_mode) != 0o700
        ):
            raise PermissionError(f"工作目录属性无效：{workdir}")
    except BaseException:
        shutil.rmtree(workdir, ignore_errors=True)
        raise


def write_private_file(path: Path, contents: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            output.write(contents)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    path.chmod(0o600)


def should_remove_workdir(policy: str, *, succeeded: bool) -> bool:
    if policy == "always":
        return True
    if policy == "except-fail":
        return succeeded
    if policy == "none":
        return False
    raise ValueError(f"未知工作目录清理策略：{policy}")


def remove_workdir(workdir: Path) -> None:
    metadata = workdir.stat(follow_symlinks=False)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or workdir.is_symlink()
        or metadata.st_uid != os.geteuid()
        or metadata.st_gid != os.getegid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ValueError(f"拒绝清理非实体工作目录：{workdir}")
    resolved = workdir.resolve(strict=True)
    if resolved in {Path("/"), Path("/run"), Path("/tmp"), Path("/dev/shm")}:
        raise ValueError(f"拒绝清理宽泛目录：{resolved}")
    sentinel = resolved / ".ndm-deploy"
    if not sentinel.is_dir() or sentinel.is_symlink():
        raise ValueError(f"工作目录缺少部署哨兵：{sentinel}")
    os.chdir(resolved.parent)
    shutil.rmtree(resolved)


def draw_table(rows: Sequence[tuple[str, object]]) -> str:
    rendered = [(str(label), str(value)) for label, value in rows]
    label_width = max((_display_width(label) for label, _ in rendered), default=0)
    value_width = max((_display_width(value) for _, value in rendered), default=0)
    border = f"+-{'-' * label_width}-+-{'-' * value_width}-+"
    body = [border]
    body.extend(
        f"| {_pad_cell(label, label_width)} | {_pad_cell(value, value_width)} |"
        for label, value in rendered
    )
    body.append(border)
    return "\n".join(body)


def draw_banner(title: str, *, width: int = 38) -> str:
    inner_width = width - 2
    title_width = _display_width(title)
    if inner_width < title_width:
        raise ValueError("部署横幅宽度不足以容纳标题")
    remaining = inner_width - title_width
    left_padding = remaining // 2
    right_padding = remaining - left_padding
    border = "*" * width
    empty = f"*{' ' * inner_width}*"
    title_line = f"*{' ' * left_padding}{title}{' ' * right_padding}*"
    return "\n".join((border, empty, title_line, empty, border))


def _display_width(value: str) -> int:
    return sum(
        0
        if unicodedata.category(character) in {"Cf", "Mn", "Me"}
        else 2
        if unicodedata.east_asian_width(character) in {"F", "W"}
        else 1
        for character in value
    )


def _pad_cell(value: str, width: int) -> str:
    return value + " " * (width - _display_width(value))
