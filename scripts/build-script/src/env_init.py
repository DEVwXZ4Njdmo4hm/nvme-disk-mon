"""Create an isolated Rust toolchain and dependency environment."""

import hmac
import os
import platform
import re
from dataclasses import dataclass, field
from pathlib import Path

from misc import download_https, fetch_https, run_command
from preflight import PreflightResult


RUSTUP_DIST_ROOT = "https://static.rust-lang.org/rustup/dist"
_SHA256_PATTERN = re.compile(r"[0-9a-fA-F]{64}")

_RUST_ENV_KEYS = {
    "CARGO",
    "CARGO_BUILD_BUILD_DIR",
    "CARGO_BUILD_RUSTC",
    "CARGO_BUILD_RUSTC_WRAPPER",
    "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
    "CARGO_BUILD_RUSTFLAGS",
    "CARGO_BUILD_TARGET",
    "CARGO_BUILD_TARGET_DIR",
    "CARGO_ENCODED_RUSTFLAGS",
    "CARGO_ENCODED_RUSTDOCFLAGS",
    "CARGO_HOME",
    "CARGO_INCREMENTAL",
    "CARGO_NET_GIT_FETCH_WITH_CLI",
    "CARGO_NET_OFFLINE",
    "CARGO_TARGET_DIR",
    "RUSTC",
    "RUSTC_BOOTSTRAP",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "RUSTDOC",
    "RUSTDOCFLAGS",
    "RUSTFLAGS",
    "RUSTUP_DIST_SERVER",
    "RUSTUP_HOME",
    "RUSTUP_TOOLCHAIN",
    "RUSTUP_UPDATE_ROOT",
}


@dataclass(frozen=True, slots=True)
class BuildEnvironment:
    source_dir: Path
    build_dir: Path
    target: str
    rust_root: Path
    cargo_home: Path
    rustup_home: Path
    target_dir: Path
    temp_dir: Path
    process_env: dict[str, str] = field(repr=False)

    @property
    def cargo(self) -> Path:
        suffix = ".exe" if os.name == "nt" else ""
        return self.cargo_home / "bin" / f"cargo{suffix}"


def rustup_host_triple() -> str:
    """Map common native hosts to official rustup-init distribution tuples."""
    system = platform.system()
    machine = platform.machine().lower()

    architecture = {
        "amd64": "x86_64",
        "x86_64": "x86_64",
        "arm64": "aarch64",
        "aarch64": "aarch64",
    }.get(machine)
    if architecture is None:
        raise OSError(f"rustup-init 不支持当前 CPU 架构映射：{machine}")

    if system == "Linux":
        libc_name = platform.libc_ver()[0].lower()
        if "musl" in libc_name:
            libc = "musl"
        elif libc_name in {"glibc", "gnu libc"}:
            libc = "gnu"
        else:
            raise OSError(f"无法可靠识别当前 Linux C 库：{libc_name or 'unknown'}")
        return f"{architecture}-unknown-linux-{libc}"
    if system == "Darwin":
        return f"{architecture}-apple-darwin"
    if system == "Windows":
        return f"{architecture}-pc-windows-msvc"
    raise OSError(f"rustup-init 不支持当前操作系统映射：{system}")


def make_build_environment(preflight: PreflightResult, target: str) -> BuildEnvironment:
    """Create the BDIR-local directory layout and sanitized child environment."""
    if target not in {"Release", "Debug"}:
        raise ValueError(f"无效构建目标：{target}")
    if next(preflight.build_dir.iterdir(), None) is not None:
        raise ValueError(f"预检后构建目录已发生变化：{preflight.build_dir}")

    rust_root = preflight.build_dir / "rust"
    cargo_home = rust_root / "cargo"
    rustup_home = rust_root / "rustup"
    target_dir = preflight.build_dir / target.lower()
    temp_dir = rust_root / "tmp" / target.lower()

    rust_root.mkdir(mode=0o700, exist_ok=False)
    for directory in (rust_root / "bootstrap", cargo_home, rustup_home, target_dir):
        directory.mkdir(mode=0o700, exist_ok=False)
    temp_dir.parent.mkdir(mode=0o700, exist_ok=False)
    temp_dir.mkdir(mode=0o700, exist_ok=False)

    child_env = os.environ.copy()
    for key in tuple(child_env):
        if (
            key in _RUST_ENV_KEYS
            or key.startswith("CARGO_BUILD_")
            or key.startswith("CARGO_PROFILE_")
            or key.startswith("CARGO_TARGET_")
            or key.startswith("RUSTUP_")
        ):
            child_env.pop(key)

    old_path = child_env.get("PATH", "")
    cargo_bin = cargo_home / "bin"
    child_env.update(
        {
            "CARGO_HOME": str(cargo_home),
            "CARGO_NET_RETRY": "5",
            "CARGO_REGISTRIES_CRATES_IO_INDEX": "sparse+https://index.crates.io/",
            "CARGO_REGISTRIES_CRATES_IO_PROTOCOL": "sparse",
            "CARGO_TARGET_DIR": str(target_dir),
            "RUSTUP_HOME": str(rustup_home),
            "RUSTUP_MAX_RETRIES": "5",
            "RUSTUP_TOOLCHAIN": "stable",
            "TEMP": str(temp_dir),
            "TMP": str(temp_dir),
            "TMPDIR": str(temp_dir),
            "PATH": os.pathsep.join(part for part in (str(cargo_bin), old_path) if part),
        }
    )

    return BuildEnvironment(
        source_dir=preflight.source_dir,
        build_dir=preflight.build_dir,
        target=target,
        rust_root=rust_root,
        cargo_home=cargo_home,
        rustup_home=rustup_home,
        target_dir=target_dir,
        temp_dir=temp_dir,
        process_env=child_env,
    )


def download_rustup_init(environment: BuildEnvironment) -> tuple[Path, str]:
    """Download rustup-init from Rust infrastructure and verify its checksum."""
    host = rustup_host_triple()
    executable_name = "rustup-init.exe" if os.name == "nt" else "rustup-init"
    url = f"{RUSTUP_DIST_ROOT}/{host}/{executable_name}"
    checksum_payload = fetch_https(f"{url}.sha256", max_bytes=4096)
    checksum_fields = checksum_payload.decode("ascii", errors="strict").strip().split(maxsplit=1)
    if not checksum_fields:
        raise ValueError("rustup-init 校验文件为空")
    expected = checksum_fields[0]
    if _SHA256_PATTERN.fullmatch(expected) is None:
        raise ValueError("rustup-init 校验文件不包含有效 SHA-256")

    destination = environment.rust_root / "bootstrap" / executable_name
    actual = download_https(url, destination)
    if not hmac.compare_digest(actual.lower(), expected.lower()):
        destination.unlink(missing_ok=True)
        raise ValueError("rustup-init SHA-256 校验失败")
    if os.name != "nt":
        destination.chmod(0o700)
    return destination, host


def install_rust_toolchain(environment: BuildEnvironment, rustup_init: Path, host: str) -> None:
    """Install the stable Rust toolchain into the prepared BDIR environment."""
    run_command(
        (
            rustup_init,
            "-y",
            "--no-modify-path",
            "--profile",
            "minimal",
            "--default-host",
            host,
            "--default-toolchain",
            "stable",
        ),
        cwd=environment.build_dir,
        env=environment.process_env,
    )
    if not environment.cargo.is_file():
        raise FileNotFoundError(f"rustup 未生成预期 Cargo：{environment.cargo}")


def fetch_locked_dependencies(environment: BuildEnvironment) -> None:
    """Fetch every locked Cargo package into the isolated cache."""
    run_command(
        (
            environment.cargo,
            "fetch",
            "--locked",
            "--manifest-path",
            environment.source_dir / "Cargo.toml",
        ),
        cwd=environment.source_dir,
        env=environment.process_env,
    )
