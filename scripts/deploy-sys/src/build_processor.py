"""Bind the validated configuration and invoke the isolated Release builder."""

import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path

from misc import run_quiet_command

_CHECKSUM_DECLARATION = re.compile(
    rb"pub\(crate\) const CONF_FILE_CHECKSUM: &str = match option_env!"
    rb"\(\"NDM_CONF_FILE_CHECKSUM\"\) \{\s*Some\(value\) => value,\s*None => \"\",\s*\};"
)


@dataclass(frozen=True, slots=True)
class BuildArtifacts:
    binary: Path
    documentation: Path | None
    config_checksum: str


def inject_config_checksum(workdir: Path, staged_config: Path, expected: bytes) -> str:
    """Verify the staged bytes and replace the sole reserved checksum declaration."""
    actual = staged_config.read_bytes()
    if actual != expected:
        raise ValueError("摘要注入前 WDIR 配置已偏离本地预检缓冲区")
    checksum = hashlib.sha256(actual).hexdigest()
    source_path = workdir / "src" / "config.rs"
    source = source_path.read_bytes()
    matches = tuple(_CHECKSUM_DECLARATION.finditer(source))
    if len(matches) != 1:
        raise ValueError("src/config.rs 中 CONF_FILE_CHECKSUM 预留声明应且仅应出现一次")
    replacement = f'pub(crate) const CONF_FILE_CHECKSUM: &str = "{checksum}";'.encode("ascii")
    rendered = _CHECKSUM_DECLARATION.sub(replacement, source, count=1)
    source_path.write_bytes(rendered)
    return checksum


def _require_file(path: Path, description: str) -> Path:
    if not path.is_file() or path.is_symlink():
        raise FileNotFoundError(f"缺少{description}：{path}")
    return path


def _require_executable(path: Path, description: str) -> Path:
    """Accept a venv executable symlink while requiring a live executable target."""
    if not path.is_file() or not os.access(path, os.X_OK):
        raise FileNotFoundError(f"缺少{description}：{path}")
    path.resolve(strict=True)
    return path


def build_release(
    workdir: Path,
    python: Path,
    *,
    enable_doc: bool,
    config_checksum: str,
) -> BuildArtifacts:
    resolved = workdir.resolve(strict=True)
    build_script = _require_file(
        resolved / "scripts" / "build-script" / "src" / "main.py",
        "构建脚本",
    )
    if not python.is_absolute():
        raise ValueError(f"构建用 Python 必须是绝对路径：{python}")
    _require_executable(python, "WDIR venv Python")
    if re.fullmatch(r"[0-9a-f]{64}", config_checksum) is None:
        raise ValueError("配置摘要必须是小写 SHA-256 十六进制值")

    build_dir = resolved / "build"
    if build_dir.exists() or build_dir.is_symlink():
        raise FileExistsError(f"部署构建目录已经存在：{build_dir}")
    build_dir.mkdir(mode=0o700)
    command = [
        str(python),
        str(build_script),
        "-S",
        str(resolved),
        "-B",
        str(build_dir),
        "-T",
        "Release",
    ]
    if enable_doc:
        command.append("--doc")
    run_quiet_command(command, cwd=resolved)

    target_dir = build_dir / "release"
    binary = _require_file(target_dir / "release" / "nvme-disk-mon", "Release 二进制")
    documentation = None
    if enable_doc:
        documentation = target_dir / "doc"
        if not documentation.is_dir() or documentation.is_symlink():
            raise FileNotFoundError(f"缺少 HTML 文档目标目录：{documentation}")
        _require_file(documentation / "index.html", "HTML 文档首页")
    return BuildArtifacts(
        binary=binary,
        documentation=documentation,
        config_checksum=config_checksum,
    )
