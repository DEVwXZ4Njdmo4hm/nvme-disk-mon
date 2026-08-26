"""Command-line entry point for the NDM build script."""

import argparse
import shlex
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

sys.dont_write_bytecode = True

from build_processor import (  # noqa: E402
    build_binary,
    build_rustdoc,
    render_html_documentation,
)
from env_init import (  # noqa: E402
    download_rustup_init,
    fetch_locked_dependencies,
    install_rust_toolchain,
    make_build_environment,
)
from preflight import run_preflight  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="在隔离的项目构建目录中构建 NVMe-Disk-Mon",
        allow_abbrev=False,
        suggest_on_error=True,
    )
    parser.add_argument("-S", dest="source_dir", required=True, type=Path, metavar="DIR")
    parser.add_argument("-B", dest="build_dir", required=True, type=Path, metavar="DIR")
    parser.add_argument(
        "-T",
        dest="target",
        required=True,
        choices=("Release", "Debug"),
        metavar="{Release,Debug}",
    )
    parser.add_argument("--doc", action="store_true", help="同时构建 Rust 文档")
    parser.add_argument(
        "--init-only",
        action="store_true",
        help="仅初始化 Rust 环境并获取依赖",
    )
    return parser


def _subprocess_exit_code(returncode: int) -> int:
    if returncode < 0:
        return min(128 - returncode, 255)
    return returncode if 1 <= returncode <= 255 else 1


def _run_step[StepResult](
    position: int,
    total: int,
    description: str,
    action: Callable[[], StepResult],
) -> StepResult:
    print(f"[{position}/{total}] {description}...", end="", flush=True)
    try:
        result = action()
    except BaseException:
        print("FAILED!", flush=True)
        raise
    print("OK!", flush=True)
    return result


def _print_subprocess_output(error: subprocess.CalledProcessError) -> None:
    output = error.stdout if isinstance(error.stdout, str) else None
    if output:
        print(output, end="" if output.endswith("\n") else "\n", file=sys.stderr)


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    step_count = 5 if args.init_only else 8 if args.doc else 6
    try:
        preflight = _run_step(
            1,
            step_count,
            "执行预检",
            lambda: run_preflight(args.source_dir, args.build_dir),
        )
        environment = _run_step(
            2,
            step_count,
            "创建隔离 Rust 构建环境",
            lambda: make_build_environment(preflight, args.target),
        )
        rustup_init, host = _run_step(
            3,
            step_count,
            "下载并校验 rustup-init",
            lambda: download_rustup_init(environment),
        )
        _run_step(
            4,
            step_count,
            "安装 Rust stable 工具链",
            lambda: install_rust_toolchain(environment, rustup_init, host),
        )
        _run_step(
            5,
            step_count,
            "获取 Cargo 锁定依赖",
            lambda: fetch_locked_dependencies(environment),
        )

        if args.init_only:
            return 0

        _run_step(
            6,
            step_count,
            "编译程序",
            lambda: build_binary(environment, require_documentation=args.doc),
        )
        if args.doc:
            _run_step(7, step_count, "构建 Rustdoc", lambda: build_rustdoc(environment))
            _run_step(
                8,
                step_count,
                "渲染 HTML 命令文档",
                lambda: render_html_documentation(environment),
            )
        return 0
    except subprocess.CalledProcessError as exc:
        command = tuple(str(argument) for argument in exc.cmd)
        print(
            f"错误：外部命令以状态码 {exc.returncode} 失败：{shlex.join(command)}",
            file=sys.stderr,
        )
        _print_subprocess_output(exc)
        return _subprocess_exit_code(exc.returncode)
    except (ImportError, OSError, RuntimeError, ValueError) as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("错误：构建被用户中断", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
