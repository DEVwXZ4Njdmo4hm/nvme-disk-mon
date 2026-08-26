"""Identity-preserving controller for the declarative deployment workflow."""

import argparse
import os
import resource
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

sys.dont_write_bytecode = True

from build_processor import BuildArtifacts, build_release, inject_config_checksum  # noqa: E402
from env_init import create_working_venv, prepare_source  # noqa: E402
from install_processor import (  # noqa: E402
    InstallResult,
    install_release,
    quiesce_service,
    render_systemd_unit,
)
from misc import (  # noqa: E402
    BIN_PATH,
    DATA_PATH,
    PROJECT_ROOT,
    create_registration,
    draw_banner,
    draw_table,
    release_registration,
    remove_workdir,
    should_remove_workdir,
)
from oauth2_helper import run_mail_authentication  # noqa: E402
from post_install_processor import reload_and_verify_systemd, run_post_install  # noqa: E402
from preflight import (  # noqa: E402
    LocalPreflight,
    PrivilegedPreflight,
    run_local_preflight,
    run_privileged_preflight,
    stage_configs,
)
from privilege import PrivilegeRunner  # noqa: E402

DEPLOY_STEP_COUNT = 13
DEPLOY_BANNER_TITLE = "NVMe-Disk-Mon Deploy System"
ANSI_BOLD = "1"
ANSI_BOLD_RED = "1;31"
ANSI_BOLD_GREEN = "1;32"
ANSI_BOLD_YELLOW = "1;33"
ANSI_BOLD_CYAN = "1;36"
STATUS_STYLES = {
    "OK!": ANSI_BOLD_GREEN,
    "FAILED!": ANSI_BOLD_RED,
    "SKIPPED": ANSI_BOLD_YELLOW,
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="从源码声明式部署 NVMe-Disk-Mon",
        allow_abbrev=False,
    )
    parser.add_argument("deploy_config", type=Path, metavar="DEPLOY_CONFIG_PATH")
    return parser


def _secure_process() -> None:
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def _step_prefix(position: int, description: str) -> str:
    return f"[{position}/{DEPLOY_STEP_COUNT}] {description}..."


def _stdout_uses_color() -> bool:
    return sys.stdout.isatty()


def _style(value: str, ansi_code: str) -> str:
    if not _stdout_uses_color():
        return value
    return f"\033[{ansi_code}m{value}\033[0m"


def _styled_status(status: str) -> str:
    return _style(status, STATUS_STYLES[status])


def _run_step[StepResult](
    position: int,
    description: str,
    action: Callable[[], StepResult],
    *,
    passthrough: bool = False,
) -> StepResult:
    prefix = _step_prefix(position, description)
    print(prefix, end="\n" if passthrough else "", flush=True)
    try:
        result = action()
    except BaseException:
        status = _styled_status("FAILED!")
        print(f"{prefix}{status}" if passthrough else status, flush=True)
        raise
    status = _styled_status("OK!")
    print(f"{prefix}{status}" if passthrough else status, flush=True)
    return result


def _skip_step(position: int, description: str) -> None:
    print(f"{_step_prefix(position, description)}{_styled_status('SKIPPED')}", flush=True)


def _print_subprocess_output(error: subprocess.CalledProcessError) -> None:
    for output in (error.stdout, error.stderr):
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        if isinstance(output, str) and output:
            print(output, end="" if output.endswith("\n") else "\n", file=sys.stderr)


def _show_result(
    *,
    succeeded: bool,
    stage: str,
    local: LocalPreflight | None,
    installation: InstallResult | None,
    workdir_status: str,
) -> None:
    rows: list[tuple[str, object]] = [
        ("结果", "成功" if succeeded else "失败"),
        ("阶段", stage),
        ("控制器 EUID", os.geteuid()),
        ("安装模式", "root"),
        ("data_path", DATA_PATH),
        ("二进制", installation.binary if installation else BIN_PATH),
        (
            "systemd",
            "启用" if local and local.config.install.systemd_integration else "禁用",
        ),
        ("工作目录", workdir_status),
    ]
    print(flush=True)
    print(flush=True)
    print(_style("结果汇总：", ANSI_BOLD), flush=True)
    print(draw_table(rows), flush=True)


def _deploy(config_path: Path, project_root: Path) -> int:
    stage = "Local Preflight"
    local: LocalPreflight | None = None
    privileged: PrivilegedPreflight | None = None
    artifacts: BuildArtifacts | None = None
    installation: InstallResult | None = None
    registration: Path | None = None
    workdir: Path | None = None
    failure: BaseException | None = None
    succeeded = False
    workdir_status = "未创建"
    runner = PrivilegeRunner()

    print(_style(draw_banner(DEPLOY_BANNER_TITLE), ANSI_BOLD_CYAN), flush=True)
    print(flush=True)

    try:
        local = _run_step(
            1,
            "执行本地预检",
            lambda: run_local_preflight(config_path, project_root),
        )
        workdir = local.config.general.wdir
        workdir_status = f"保留：{workdir}"

        stage = "Privilege Authorization"
        _run_step(2, "获取 root 授权", runner.authorize, passthrough=True)

        stage = "Unit Registration"
        registration = _run_step(
            3,
            "注册全局部署单元",
            lambda: create_registration(
                runner,
                {
                    "controller_euid": runner.euid,
                    "controller_egid": runner.egid,
                    "pid": os.getpid(),
                    "wdir": str(workdir),
                },
            ),
        )

        stage = "Privileged Preflight"
        privileged = _run_step(
            4,
            "执行特权预检",
            lambda: run_privileged_preflight(runner, local),
        )

        stage = "Source Prepare"
        _run_step(
            5,
            "准备工作源码",
            lambda: prepare_source(project_root, workdir, local.source_files),
        )

        stage = "Config Staging"
        staged_config, working_python = _run_step(
            6,
            "暂存配置并创建 WDIR venv",
            lambda: (
                stage_configs(local, workdir),
                create_working_venv(workdir),
            ),
        )

        stage = "Implicit Data Generate and Source Building"
        artifacts, rendered_unit = _run_step(
            7,
            "注入配置校验和，并构建 Release",
            lambda: _build_artifacts(
                workdir,
                staged_config,
                working_python,
                local,
            ),
        )

        stage = "Service Quiesce"
        _run_step(
            8,
            "处理既有服务状态",
            lambda: quiesce_service(runner, local, privileged),
        )

        stage = "Install"
        installation = _run_step(
            9,
            "安装部署产物",
            lambda: install_release(
                runner,
                local,
                artifacts,
                staged_config,
                rendered_unit,
            ),
        )

        if local.config.install.systemd_integration:
            stage = "systemd Reload and Verify"
            _run_step(10, "重载并核验 systemd", lambda: reload_and_verify_systemd(runner))
        else:
            _skip_step(10, "重载并核验 systemd")

        stage = "Mail Auth"
        _run_step(
            11,
            "执行邮件认证",
            lambda: run_mail_authentication(runner, local.smtp_auth_method),
            passthrough=True,
        )

        stage = "Post-Install"
        _run_step(
            12,
            "执行部署后操作",
            lambda: run_post_install(runner, local, privileged),
            passthrough=True,
        )
        succeeded = True
        stage = "Clean"
    except KeyboardInterrupt as exc:
        failure = exc
        print(f"错误：{stage} 被用户中断", file=sys.stderr)
    except subprocess.CalledProcessError as exc:
        failure = exc
        print(f"错误：{stage}：{exc}", file=sys.stderr)
        _print_subprocess_output(exc)
    except Exception as exc:
        failure = exc
        print(f"错误：{stage}：{exc}", file=sys.stderr)
    finally:
        cleanup_errors: list[tuple[str, Exception]] = []
        cleanup_prefix = _step_prefix(13, "清理部署资源")
        print(cleanup_prefix, end="", flush=True)
        if workdir is not None and workdir.exists() and local is not None:
            try:
                if should_remove_workdir(local.config.post_install.clean, succeeded=succeeded):
                    remove_workdir(workdir)
                    workdir_status = "已清理"
            except Exception as exc:
                cleanup_errors.append(("Clean", exc))
                workdir_status = f"清理失败：{workdir}"
                if failure is None:
                    failure = exc
                    succeeded = False
                    stage = "Clean"
        try:
            release_registration(runner, registration)
        except Exception as exc:
            cleanup_errors.append(("无法释放全局部署注册", exc))
            if failure is None:
                failure = exc
                succeeded = False
                stage = "Clean"
        print(_styled_status("FAILED!" if cleanup_errors else "OK!"), flush=True)
        for description, error in cleanup_errors:
            print(f"错误：{description}：{error}", file=sys.stderr)

    _show_result(
        succeeded=succeeded,
        stage="Show" if succeeded else stage,
        local=local,
        installation=installation,
        workdir_status=workdir_status,
    )
    if isinstance(failure, KeyboardInterrupt):
        return 130
    return 0 if succeeded else 1


def _build_artifacts(
    workdir: Path,
    staged_config: Path,
    working_python: Path,
    local: LocalPreflight,
) -> tuple[BuildArtifacts, Path | None]:
    checksum = inject_config_checksum(workdir, staged_config, local.ndm_bytes)
    artifacts = build_release(
        workdir,
        working_python,
        enable_doc=local.config.deploy.enable_doc,
        config_checksum=checksum,
    )
    rendered_unit = (
        render_systemd_unit(workdir) if local.config.install.systemd_integration else None
    )
    return artifacts, rendered_unit


def main(argv: Sequence[str] | None = None) -> int:
    _secure_process()
    args = build_parser().parse_args(argv)
    project_root = Path(__file__).resolve().parents[3]
    if project_root != PROJECT_ROOT:
        raise RuntimeError("部署系统项目根目录解析不一致")
    return _deploy(args.deploy_config, project_root)


if __name__ == "__main__":
    raise SystemExit(main())
