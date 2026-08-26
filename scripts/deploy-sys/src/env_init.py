"""Prepare the controller-owned working source and Python environment."""

import sys
from pathlib import Path

from misc import copy_source_files, run_quiet_command


def prepare_source(project_root: Path, workdir: Path, source_files: tuple[Path, ...]) -> None:
    copy_source_files(project_root, workdir, source_files)


def _base_python_executable() -> Path:
    executable = getattr(sys, "_base_executable", None)
    if not isinstance(executable, str) or not executable:
        raise RuntimeError("无法确定项目 venv 对应的基础 CPython")
    path = Path(executable).resolve(strict=True)
    if not path.is_file():
        raise FileNotFoundError(f"基础 CPython 不是普通文件：{path}")
    return path


def create_working_venv(workdir: Path) -> Path:
    """Create WDIR/.venv without changing or re-entering controller identity."""
    resolved = workdir.resolve(strict=True)
    if not resolved.is_dir():
        raise NotADirectoryError(f"部署工作目录不是目录：{resolved}")
    venv_dir = resolved / ".venv"
    if venv_dir.exists() or venv_dir.is_symlink():
        raise FileExistsError(f"WDIR 已存在项目 venv：{venv_dir}")
    requirements = resolved / "requirements.txt"
    if not requirements.is_file() or requirements.is_symlink():
        raise FileNotFoundError(f"WDIR 缺少依赖锁定文件：{requirements}")

    run_quiet_command(
        (str(_base_python_executable()), "-m", "venv", str(venv_dir)),
        cwd=resolved,
    )
    python = venv_dir / "bin" / "python"
    if not python.is_file():
        raise FileNotFoundError(f"WDIR venv 未生成 Python：{python}")
    run_quiet_command(
        (
            str(python),
            "-m",
            "pip",
            "install",
            "--requirement",
            str(requirements),
        ),
        cwd=resolved,
    )
    return python
