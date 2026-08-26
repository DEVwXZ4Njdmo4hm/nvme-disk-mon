"""Cargo build and documentation processing."""

import html
import stat
import tomllib
from pathlib import Path

from env_init import BuildEnvironment
from misc import run_command

DOCUMENT_SOURCE = Path("docs/index.html")
DOCUMENT_TARGET = Path("doc/index.html")
VERSION_PLACEHOLDER = "@NDM_VERSION@"
MAX_DOCUMENT_BYTES = 1024 * 1024


def _project_version(source_dir: Path) -> str:
    manifest = source_dir / "Cargo.toml"
    with manifest.open("rb") as source:
        document = tomllib.load(source)
    package = document.get("package")
    if not isinstance(package, dict):
        raise ValueError(f"Cargo.toml 缺少 package 表: {manifest}")
    version = package.get("version")
    if not isinstance(version, str) or not version:
        raise ValueError(f"Cargo.toml 缺少非空 package.version: {manifest}")
    return version


def render_html_documentation(environment: BuildEnvironment) -> Path:
    source = environment.source_dir / DOCUMENT_SOURCE
    metadata = source.stat(follow_symlinks=False)
    if not stat.S_ISREG(metadata.st_mode) or source.is_symlink():
        raise ValueError(f"HTML 文档源必须是实体普通文件: {source}")
    if metadata.st_size > MAX_DOCUMENT_BYTES:
        raise ValueError(f"HTML 文档源超过 {MAX_DOCUMENT_BYTES} 字节: {source}")
    template = source.read_text(encoding="utf-8", errors="strict")
    if template.count(VERSION_PLACEHOLDER) != 1:
        raise ValueError(f"HTML 文档源必须且只能包含一个 {VERSION_PLACEHOLDER}")

    output_root = environment.target_dir / DOCUMENT_TARGET.parent
    if not output_root.is_dir() or output_root.is_symlink():
        raise FileNotFoundError(f"Cargo 未生成预期文档目录: {output_root}")
    destination = environment.target_dir / DOCUMENT_TARGET
    if destination.is_symlink():
        raise ValueError(f"HTML 文档目标不能是符号链接: {destination}")
    rendered = template.replace(
        VERSION_PLACEHOLDER,
        html.escape(_project_version(environment.source_dir), quote=True),
    )
    destination.write_text(rendered, encoding="utf-8", newline="")
    return destination


def _common_arguments(environment: BuildEnvironment) -> tuple[str | Path, ...]:
    profile_arguments = ("--release",) if environment.target == "Release" else ()
    return (
        *profile_arguments,
        "--locked",
        "--offline",
        "--manifest-path",
        environment.source_dir / "Cargo.toml",
    )


def _require_document_source(environment: BuildEnvironment) -> None:
    document_source = environment.source_dir / DOCUMENT_SOURCE
    if not document_source.is_file() or document_source.is_symlink():
        raise FileNotFoundError(f"缺少 HTML 文档源: {document_source}")


def build_binary(environment: BuildEnvironment, *, require_documentation: bool) -> None:
    """Build the selected binary profile from the locked offline cache."""
    if require_documentation:
        _require_document_source(environment)

    run_command(
        (environment.cargo, "build", *_common_arguments(environment)),
        cwd=environment.source_dir,
        env=environment.process_env,
    )


def build_rustdoc(environment: BuildEnvironment) -> None:
    """Build only this package's Rust API documentation."""
    _require_document_source(environment)
    run_command(
        (environment.cargo, "doc", "--no-deps", *_common_arguments(environment)),
        cwd=environment.source_dir,
        env=environment.process_env,
    )


def build_project(environment: BuildEnvironment, *, build_doc: bool) -> None:
    """Build the binary and optional documentation through the public stage functions."""
    build_binary(environment, require_documentation=build_doc)
    if build_doc:
        build_rustdoc(environment)
        render_html_documentation(environment)
