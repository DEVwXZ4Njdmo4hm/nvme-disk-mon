"""Render and install explicit WDIR artifacts through fixed root commands."""

import hashlib
import stat
from dataclasses import dataclass
from pathlib import Path

from build_processor import BuildArtifacts
from misc import (
    BIN_PATH,
    CONF_PATH,
    DATA_PATH,
    DOC_DIRECTORY_NAME,
    STATS_FILES,
    UNIT_DIRECTORY,
    UNIT_PATH,
)
from preflight import LocalPreflight, PrivilegedPreflight
from privilege import PrivilegeRunner
from template_render import render_template_file, systemd_escape, systemd_exec_escape

SERVICE_UNIT = "nvme-disk-mon.service"


@dataclass(frozen=True, slots=True)
class InstallResult:
    binary: Path
    config: Path
    documentation: Path | None
    unit: Path | None


def render_systemd_unit(workdir: Path) -> Path:
    template = workdir / "packaging" / "templates" / "nvme-disk-mon.service.template"
    if not template.is_file() or template.is_symlink():
        raise FileNotFoundError(f"缺少 systemd service 模板：{template}")
    rendered_directory = workdir / ".ndm-deploy" / "rendered"
    rendered_directory.mkdir(mode=0o700, exist_ok=False)
    destination = rendered_directory / SERVICE_UNIT
    contexts: dict[str, object] = {
        "deploy_config": {
            "__implicit__": {
                "bin_path": systemd_exec_escape(str(BIN_PATH)),
                "data_path": systemd_escape(str(DATA_PATH)),
            }
        }
    }
    render_template_file(template, destination, contexts)
    destination.chmod(0o600)
    return destination


def quiesce_service(
    runner: PrivilegeRunner,
    local: LocalPreflight,
    privileged: PrivilegedPreflight,
) -> None:
    if local.config.install.systemd_integration and privileged.service_active:
        runner.run(("/usr/bin/systemctl", "--system", "stop", SERVICE_UNIT))


def _install_file(runner: PrivilegeRunner, source: Path, target: Path, mode: int) -> None:
    metadata = source.stat(follow_symlinks=False)
    if not stat.S_ISREG(metadata.st_mode) or source.is_symlink():
        raise ValueError(f"root 安装源必须是实体普通文件：{source}")
    runner.run(
        (
            "/usr/bin/install",
            "--owner=0",
            "--group=0",
            f"--mode={mode:04o}",
            "--",
            source,
            target,
        )
    )


def _install_documentation(
    runner: PrivilegeRunner,
    source: Path,
    parent: Path,
) -> Path:
    if not source.is_dir() or source.is_symlink():
        raise FileNotFoundError(f"HTML 文档目标目录不存在：{source}")
    destination = parent / DOC_DIRECTORY_NAME
    runner.run(
        (
            "/usr/bin/install",
            "--directory",
            "--owner=0",
            "--group=0",
            "--mode=0755",
            "--",
            destination,
        )
    )
    runner.run(
        (
            "/usr/bin/find",
            destination,
            "-depth",
            "-mindepth",
            "1",
            "-delete",
        )
    )
    for item in sorted(source.rglob("*")):
        relative = item.relative_to(source)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError(f"HTML 文档路径越界：{relative}")
        target = destination / relative
        metadata = item.stat(follow_symlinks=False)
        if stat.S_ISDIR(metadata.st_mode) and not item.is_symlink():
            runner.run(
                (
                    "/usr/bin/install",
                    "--directory",
                    "--owner=0",
                    "--group=0",
                    "--mode=0755",
                    "--",
                    target,
                )
            )
        elif stat.S_ISREG(metadata.st_mode) and not item.is_symlink():
            _install_file(runner, item, target, 0o644)
        else:
            raise ValueError(f"HTML 文档树包含不支持的文件类型：{item}")
    return destination


def install_release(
    runner: PrivilegeRunner,
    local: LocalPreflight,
    artifacts: BuildArtifacts,
    staged_config: Path,
    rendered_unit: Path | None,
) -> InstallResult:
    """Install the build while retaining the SQLite database files."""
    config_bytes = staged_config.read_bytes()
    if hashlib.sha256(config_bytes).hexdigest() != artifacts.config_checksum:
        raise ValueError("待安装配置与构建时注入的 SHA-256 不一致")

    runner.run(
        (
            "/usr/bin/install",
            "--directory",
            "--owner=0",
            "--group=0",
            "--mode=0700",
            "--",
            DATA_PATH,
        )
    )
    preserve_arguments: list[str | Path] = []
    for path in STATS_FILES:
        preserve_arguments.extend(("!", "-path", path))
    runner.run(
        (
            "/usr/bin/find",
            DATA_PATH,
            "-depth",
            "-mindepth",
            "1",
            *preserve_arguments,
            "-delete",
        )
    )
    _install_file(runner, artifacts.binary, BIN_PATH, 0o755)
    _install_file(runner, staged_config, CONF_PATH, 0o600)

    installed_hash = runner.run(
        ("/usr/bin/sha256sum", "--", CONF_PATH),
        capture_output=True,
    ).stdout.split(maxsplit=1)[0]
    if installed_hash != artifacts.config_checksum:
        raise OSError("安装后的 ndm-cfg.toml 与构建摘要不一致")

    documentation = None
    if local.config.deploy.enable_doc:
        if artifacts.documentation is None:
            raise FileNotFoundError("启用文档安装，但构建结果没有 HTML 文档目标")
        documentation = _install_documentation(
            runner,
            artifacts.documentation,
            local.config.install.doc_path,
        )

    unit = None
    if local.config.install.systemd_integration:
        if rendered_unit is None:
            raise FileNotFoundError("启用 systemd 集成，但没有渲染后的 service unit")
        runner.run(
            (
                "/usr/bin/install",
                "--directory",
                "--owner=0",
                "--group=0",
                "--mode=0755",
                "--",
                UNIT_DIRECTORY,
            )
        )
        _install_file(runner, rendered_unit, UNIT_PATH, 0o644)
        unit = UNIT_PATH
    return InstallResult(
        binary=BIN_PATH,
        config=CONF_PATH,
        documentation=documentation,
        unit=unit,
    )
