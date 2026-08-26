import io
import subprocess
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

SOURCE = Path(__file__).resolve().parents[2] / "src"
sys.path.insert(0, str(SOURCE))

import main  # noqa: E402
from build_processor import BuildArtifacts  # noqa: E402
from install_processor import InstallResult  # noqa: E402
from preflight import (  # noqa: E402
    DeploymentConfig,
    DeploySection,
    GeneralSection,
    InstallSection,
    LocalPreflight,
    PostInstallSection,
    PrivilegedPreflight,
)


def local_preflight(*, systemd_integration: bool = True) -> LocalPreflight:
    config = DeploymentConfig(
        source_path=Path("/tmp/deploy.toml"),
        general=GeneralSection(1, Path("/tmp/ndm-test-missing-wdir")),
        deploy=DeploySection(Path("/tmp/ndm.toml"), False),
        install=InstallSection(Path("/usr/local/share/doc"), systemd_integration),
        post_install=PostInstallSection(False, "none", "none"),
    )
    return LocalPreflight(config, {}, {}, b"ndm", (), (), "PLAIN")


class FakeRunner:
    euid = 1000
    egid = 1000

    def __init__(self, events: list[str]) -> None:
        self.events = events

    def authorize(self) -> None:
        self.events.append("authorize")


class MainFlowTests(unittest.TestCase):
    def test_controller_runs_brief_stages_in_order(self) -> None:
        events: list[str] = []
        local = local_preflight()
        privileged = PrivilegedPreflight(False, ())
        artifacts = BuildArtifacts(Path("/tmp/binary"), None, "0" * 64)
        installation = InstallResult(
            Path("/usr/local/bin/nvme-disk-mon"),
            Path("/etc/nvme-disk-mon/ndm-cfg.toml"),
            None,
            Path("/usr/local/lib/systemd/system/nvme-disk-mon.service"),
        )

        def step(name: str, value=None):
            def run(*_args, **_kwargs):
                events.append(name)
                return value

            return run

        with (
            mock.patch("main.PrivilegeRunner", return_value=FakeRunner(events)),
            mock.patch("main.run_local_preflight", side_effect=step("local", local)),
            mock.patch("main.create_registration", side_effect=step("register", None)),
            mock.patch(
                "main.run_privileged_preflight",
                side_effect=step("privileged", privileged),
            ),
            mock.patch("main.prepare_source", side_effect=step("source")),
            mock.patch(
                "main.stage_configs",
                side_effect=step("stage-config", Path("/tmp/staged")),
            ),
            mock.patch(
                "main.create_working_venv",
                side_effect=step("venv", Path("/tmp/python")),
            ),
            mock.patch("main.inject_config_checksum", side_effect=step("inject", "0" * 64)),
            mock.patch("main.build_release", side_effect=step("build", artifacts)),
            mock.patch(
                "main.render_systemd_unit",
                side_effect=step("render", Path("/tmp/service")),
            ),
            mock.patch("main.quiesce_service", side_effect=step("quiesce")),
            mock.patch("main.install_release", side_effect=step("install", installation)),
            mock.patch("main.reload_and_verify_systemd", side_effect=step("reload")),
            mock.patch("main.run_mail_authentication", side_effect=step("mail-auth")),
            mock.patch("main.run_post_install", side_effect=step("post-install")),
            mock.patch("main.release_registration", side_effect=step("release")),
            redirect_stdout(output := io.StringIO()),
            redirect_stderr(io.StringIO()),
        ):
            status = main._deploy(Path("/tmp/deploy.toml"), Path("/repo"))

        self.assertEqual(status, 0)
        self.assertEqual(
            events,
            [
                "local",
                "authorize",
                "register",
                "privileged",
                "source",
                "stage-config",
                "venv",
                "inject",
                "build",
                "render",
                "quiesce",
                "install",
                "reload",
                "mail-auth",
                "post-install",
                "release",
            ],
        )
        progress = [line for line in output.getvalue().splitlines() if line.startswith("[")]
        self.assertEqual(
            progress,
            [
                "[1/13] 执行本地预检...OK!",
                "[2/13] 获取 root 授权...",
                "[2/13] 获取 root 授权...OK!",
                "[3/13] 注册全局部署单元...OK!",
                "[4/13] 执行特权预检...OK!",
                "[5/13] 准备工作源码...OK!",
                "[6/13] 暂存配置并创建 WDIR venv...OK!",
                "[7/13] 注入配置校验和，并构建 Release...OK!",
                "[8/13] 处理既有服务状态...OK!",
                "[9/13] 安装部署产物...OK!",
                "[10/13] 重载并核验 systemd...OK!",
                "[11/13] 执行邮件认证...",
                "[11/13] 执行邮件认证...OK!",
                "[12/13] 执行部署后操作...",
                "[12/13] 执行部署后操作...OK!",
                "[13/13] 清理部署资源...OK!",
            ],
        )
        rendered = output.getvalue()
        self.assertTrue(rendered.startswith(f"{main.draw_banner(main.DEPLOY_BANNER_TITLE)}\n\n"))
        self.assertIn("[13/13] 清理部署资源...OK!\n\n\n结果汇总：\n+", rendered)

    def test_terminal_styles_are_applied_only_to_status_text(self) -> None:
        with mock.patch("main._stdout_uses_color", return_value=True):
            self.assertEqual(main._styled_status("OK!"), "\033[1;32mOK!\033[0m")
            self.assertEqual(main._styled_status("FAILED!"), "\033[1;31mFAILED!\033[0m")
            self.assertEqual(main._styled_status("SKIPPED"), "\033[1;33mSKIPPED\033[0m")
            self.assertEqual(
                main._style("结果汇总：", main.ANSI_BOLD),
                "\033[1m结果汇总：\033[0m",
            )

        with mock.patch("main._stdout_uses_color", return_value=False):
            self.assertEqual(main._styled_status("OK!"), "OK!")

    def test_local_failure_never_requests_privilege(self) -> None:
        runner = mock.Mock()
        output = io.StringIO()
        with (
            mock.patch("main.PrivilegeRunner", return_value=runner),
            mock.patch("main.run_local_preflight", side_effect=ValueError("invalid")),
            redirect_stdout(output),
            redirect_stderr(io.StringIO()),
        ):
            status = main._deploy(Path("/tmp/deploy.toml"), Path("/repo"))
        self.assertEqual(status, 1)
        runner.authorize.assert_not_called()
        self.assertIn("[1/13] 执行本地预检...FAILED!", output.getvalue())
        self.assertIn("[13/13] 清理部署资源...OK!", output.getvalue())

    def test_disabled_systemd_stage_is_explicitly_skipped(self) -> None:
        events: list[str] = []
        local = local_preflight(systemd_integration=False)
        privileged = PrivilegedPreflight(False, ())
        artifacts = BuildArtifacts(Path("/tmp/binary"), None, "0" * 64)
        installation = InstallResult(
            Path("/usr/local/bin/nvme-disk-mon"),
            Path("/etc/nvme-disk-mon/ndm-cfg.toml"),
            None,
            None,
        )

        def step(name: str, value=None):
            def run(*_args, **_kwargs):
                events.append(name)
                return value

            return run

        output = io.StringIO()
        with (
            mock.patch("main.PrivilegeRunner", return_value=FakeRunner(events)),
            mock.patch("main.run_local_preflight", return_value=local),
            mock.patch("main.create_registration", return_value=None),
            mock.patch("main.run_privileged_preflight", return_value=privileged),
            mock.patch("main.prepare_source"),
            mock.patch("main.stage_configs", return_value=Path("/tmp/staged")),
            mock.patch("main.create_working_venv", return_value=Path("/tmp/python")),
            mock.patch("main.inject_config_checksum", return_value="0" * 64),
            mock.patch("main.build_release", return_value=artifacts),
            mock.patch("main.render_systemd_unit") as render,
            mock.patch("main.quiesce_service"),
            mock.patch("main.install_release", return_value=installation),
            mock.patch("main.reload_and_verify_systemd") as reload_systemd,
            mock.patch("main.run_mail_authentication"),
            mock.patch("main.run_post_install"),
            mock.patch("main.release_registration"),
            redirect_stdout(output),
            redirect_stderr(io.StringIO()),
        ):
            status = main._deploy(Path("/tmp/deploy.toml"), Path("/repo"))

        self.assertEqual(status, 0)
        self.assertIn("[10/13] 重载并核验 systemd...SKIPPED", output.getvalue())
        render.assert_not_called()
        reload_systemd.assert_not_called()

    def test_captured_child_diagnostics_are_replayed_after_stage_failure(self) -> None:
        runner = mock.Mock()
        output = io.StringIO()
        errors = io.StringIO()
        failure = subprocess.CalledProcessError(
            7,
            ("python", "-m", "pip"),
            output="pip diagnostic\n",
        )
        with (
            mock.patch("main.PrivilegeRunner", return_value=runner),
            mock.patch("main.run_local_preflight", side_effect=failure),
            redirect_stdout(output),
            redirect_stderr(errors),
        ):
            status = main._deploy(Path("/tmp/deploy.toml"), Path("/repo"))

        self.assertEqual(status, 1)
        self.assertIn("[1/13] 执行本地预检...FAILED!", output.getvalue())
        self.assertIn("pip diagnostic", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
