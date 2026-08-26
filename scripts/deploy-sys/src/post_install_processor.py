"""Verify systemd integration and apply explicit post-install choices."""

from pathlib import Path

from misc import BIN_PATH, UNIT_PATH
from preflight import LocalPreflight, PrivilegedPreflight
from privilege import PrivilegeRunner

SERVICE_UNIT = "nvme-disk-mon.service"


def reload_and_verify_systemd(runner: PrivilegeRunner) -> None:
    runner.run(("/usr/bin/systemctl", "--system", "daemon-reload"))
    output = runner.run(
        (
            "/usr/bin/systemctl",
            "--system",
            "show",
            SERVICE_UNIT,
            "--property=LoadState",
            "--property=FragmentPath",
            "--property=DropInPaths",
        ),
        capture_output=True,
    ).stdout
    facts = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
    if facts.get("LoadState") != "loaded":
        raise RuntimeError(f"systemd 未成功加载固定 service：{facts.get('LoadState', '')}")
    if Path(facts.get("FragmentPath", "")) != UNIT_PATH:
        raise RuntimeError(f"systemd FragmentPath 不是固定 unit：{facts.get('FragmentPath', '')}")
    if facts.get("DropInPaths", "").strip():
        raise RuntimeError(f"systemd 加载了部署外 drop-in：{facts['DropInPaths']}")


def daemon_commands(action: str) -> tuple[tuple[str, ...], ...]:
    base = ("/usr/bin/systemctl", "--system")
    if action == "none":
        return ()
    if action == "start-only":
        return ((*base, "start", SERVICE_UNIT),)
    if action == "enable-only":
        return ((*base, "enable", SERVICE_UNIT),)
    if action == "enable-and-start":
        return ((*base, "enable", "--now", SERVICE_UNIT),)
    raise ValueError(f"未知 systemd daemon 策略：{action}")


def run_post_install(
    runner: PrivilegeRunner,
    local: LocalPreflight,
    privileged: PrivilegedPreflight,
) -> None:
    if local.config.post_install.send_test_mail:
        runner.run((str(BIN_PATH), "mail", "test-send"))
    if not local.config.install.systemd_integration:
        return
    for command in daemon_commands(local.config.post_install.daemon):
        runner.run(command)
    if privileged.service_active and local.config.post_install.daemon in {"none", "enable-only"}:
        print(
            "警告：部署前 nvme-disk-mon.service 正在运行，现已停止，而当前配置不会自动重新启动它。",
            flush=True,
        )
