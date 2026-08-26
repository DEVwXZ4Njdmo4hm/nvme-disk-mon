"""Preflight checks for the NDM build script."""

import json
import os
import sys
import tomllib
from dataclasses import dataclass
from importlib.metadata import Distribution, PackageNotFoundError, distribution
from importlib.util import find_spec
from pathlib import Path

from misc import fetch_https


RUST_DISTRIBUTION_URL = "https://static.rust-lang.org/dist/channel-rust-stable.toml.sha256"
CRATES_IO_CONFIG_URL = "https://index.crates.io/config.json"
BUILD_SCRIPT_ROOT = Path(__file__).resolve().parent.parent
PYPROJECT_PATH = BUILD_SCRIPT_ROOT / "pyproject.toml"
PROJECT_ROOT = BUILD_SCRIPT_ROOT.parent.parent


@dataclass(frozen=True, slots=True)
class PreflightResult:
    source_dir: Path
    build_dir: Path


def check_runtime() -> None:
    """Require Python 3.14+ from the project virtual environment."""
    if sys.version_info < (3, 14):
        raise RuntimeError("构建脚本要求 Python 3.14 或更高版本")
    current_prefix = Path(sys.prefix).resolve()
    base_prefix = Path(sys.base_prefix).resolve()
    project_venvs = {(PROJECT_ROOT / name).resolve() for name in (".venv", "venv")}
    if current_prefix == base_prefix or current_prefix not in project_venvs:
        raise RuntimeError("构建脚本必须由仓库根目录的 .venv 或 venv 解释器运行")


def _recorded_certifi_origin(installed: Distribution) -> Path:
    """Resolve certifi's import entry from its installation record."""
    package_init = next(
        (
            item
            for item in installed.files or ()
            if item.parts == ("certifi", "__init__.py")
        ),
        None,
    )
    if package_init is None:
        raise ImportError("certifi 安装记录缺少 certifi/__init__.py")

    location = package_init.locate()
    if not isinstance(location, Path):
        raise ImportError("certifi 安装位置不是可验证的本地文件系统路径")
    return location.resolve()


def check_script_dependencies() -> None:
    """Check dependencies declared in the adjacent pyproject.toml."""
    required_version = required_certifi_version()
    try:
        installed = distribution("certifi")
    except PackageNotFoundError as exc:
        raise ModuleNotFoundError(
            "缺少构建脚本依赖 certifi；请先在项目级虚拟环境中安装 pyproject.toml 的依赖"
        ) from exc

    if installed.version != required_version:
        raise RuntimeError(
            f"certifi 版本不符合 pyproject.toml：需要 {required_version}，"
            f"当前为 {installed.version}"
        )

    spec = find_spec("certifi")
    if spec is None or spec.origin is None:
        raise ModuleNotFoundError("无法确定项目级虚拟环境中 certifi 的加载位置")

    actual_origin = Path(spec.origin).resolve()
    recorded_origin = _recorded_certifi_origin(installed)
    if actual_origin != recorded_origin:
        raise ImportError(
            f"certifi 加载位置与安装记录不一致：实际 {actual_origin}，"
            f"记录 {recorded_origin}"
        )


def required_certifi_version() -> str:
    """Read the exact certifi constraint from the authoritative pyproject."""
    with PYPROJECT_PATH.open("rb") as pyproject:
        document = tomllib.load(pyproject)
    project = document.get("project")
    if not isinstance(project, dict):
        raise ValueError("pyproject.toml 缺少 project 表")
    dependencies = project.get("dependencies", ())
    if not isinstance(dependencies, list):
        raise ValueError("pyproject.toml 的 project.dependencies 必须是数组")
    matches = [
        dependency.removeprefix("certifi==")
        for dependency in dependencies
        if isinstance(dependency, str) and dependency.startswith("certifi==")
    ]
    if len(matches) != 1 or not matches[0]:
        raise ValueError("pyproject.toml 必须且只能包含一个 certifi 精确版本约束")
    return matches[0]


def _has_access(path: Path, mode: int) -> bool:
    try:
        return os.access(path, mode, effective_ids=True)
    except NotImplementedError:
        return os.access(path, mode)


def validate_source_dir(path: Path) -> Path:
    """Validate only the source-directory contract, not Rust project contents."""
    resolved = path.expanduser().resolve(strict=True)
    if not resolved.is_dir():
        raise NotADirectoryError(f"源代码路径不是目录：{resolved}")
    if not _has_access(resolved, os.R_OK | os.X_OK):
        raise PermissionError(f"源代码目录需要当前用户具有 R、X 权限：{resolved}")
    return resolved


def validate_build_dir(path: Path) -> Path:
    """Require an existing, empty directory with R/W/X access."""
    resolved = path.expanduser().resolve(strict=True)
    if not resolved.is_dir():
        raise NotADirectoryError(f"构建路径不是目录：{resolved}")
    if not _has_access(resolved, os.R_OK | os.W_OK | os.X_OK):
        raise PermissionError(f"构建目录需要当前用户具有 R、W、X 权限：{resolved}")
    if next(resolved.iterdir(), None) is not None:
        raise ValueError(f"构建目录必须为空：{resolved}")
    return resolved


def check_network() -> None:
    """Verify access to the Rust stable distribution service."""
    payload = fetch_https(RUST_DISTRIBUTION_URL, max_bytes=4096)
    checksum_fields = payload.decode("ascii", errors="strict").strip().split(maxsplit=1)
    if not checksum_fields:
        raise ValueError("Rust stable 分发端点返回了空的 SHA-256 数据")
    checksum = checksum_fields[0]
    if len(checksum) != 64 or any(
        character not in "0123456789abcdef" for character in checksum.lower()
    ):
        raise ValueError("Rust stable 分发端点返回了无效的 SHA-256 数据")


def check_crates_io() -> None:
    """Verify the sparse crates.io index endpoint used by Cargo."""
    payload = fetch_https(CRATES_IO_CONFIG_URL, max_bytes=64 * 1024)
    try:
        config = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("crates.io sparse index 返回了无效 JSON") from exc

    if not isinstance(config, dict):
        raise ValueError("crates.io sparse index 配置必须是 JSON 对象")
    download_url = config.get("dl")
    if not isinstance(download_url, str) or not download_url.startswith("https://"):
        raise ValueError("crates.io sparse index 配置缺少有效的 HTTPS 下载地址")


def run_preflight(source_dir: Path, build_dir: Path) -> PreflightResult:
    """Run all local and network checks without writing to the build directory."""
    check_runtime()
    check_script_dependencies()
    source = validate_source_dir(source_dir)
    build = validate_build_dir(build_dir)
    check_network()
    check_crates_io()
    return PreflightResult(source_dir=source, build_dir=build)
