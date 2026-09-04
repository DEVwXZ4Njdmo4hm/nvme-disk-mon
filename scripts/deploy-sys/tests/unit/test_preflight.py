import copy
import json
import os
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

SOURCE = Path(__file__).resolve().parents[2] / "src"
sys.path.insert(0, str(SOURCE))

import preflight  # noqa: E402
from misc import (  # noqa: E402
    BIN_PATH,
    DATA_PATH,
    PROJECT_ROOT,
    STATS_FILES,
    STATS_PATH,
    STATS_SHM_PATH,
    STATS_WAL_PATH,
)
from preflight import (  # noqa: E402
    DeploymentConfig,
    DeploySection,
    GeneralSection,
    InstallSection,
    LocalPreflight,
    PostInstallSection,
    deployment_config,
    remapped_config_text,
    run_local_preflight,
    run_privileged_preflight,
)


def deployment_document(wdir: Path, ndm_cfg: Path) -> dict[str, object]:
    return {
        "general": {"schema_version": 1, "wdir": str(wdir)},
        "deploy": {"ndm_cfg": str(ndm_cfg), "enable_doc": False},
        "install": {"doc_path": "/usr/local/share/doc", "systemd_integration": False},
        "post-install": {"send_test_mail": True, "clean": "always", "daemon": "none"},
    }


class ReadOnlyRootRunner:
    euid = os.geteuid()
    egid = os.getegid()

    def __init__(
        self,
        *,
        device_readable: bool = True,
        state_files: frozenset[Path] = frozenset(),
        unsafe_state_file: Path | None = None,
    ) -> None:
        self.commands: list[tuple[str, ...]] = []
        self.device_readable = device_readable
        self.state_files = state_files
        self.unsafe_state_file = unsafe_state_file

    def run(self, command, *, check=True, capture_output=False, **_kwargs):
        command = tuple(str(argument) for argument in command)
        self.commands.append(command)
        program = command[0]
        if program == "/usr/bin/stat":
            path = Path(command[-1])
            if "--dereference" in command:
                return SimpleNamespace(returncode=0, stdout="61b0:0:0:660:1\n")
            if path == BIN_PATH:
                return SimpleNamespace(returncode=1, stdout="")
            if path in STATS_FILES:
                if path in self.state_files:
                    permissions = "640" if path == self.unsafe_state_file else "600"
                    return SimpleNamespace(
                        returncode=0,
                        stdout=f"8180:0:0:{permissions}:1\n",
                    )
                return SimpleNamespace(returncode=1, stdout="")
            if path == DATA_PATH:
                return SimpleNamespace(returncode=0, stdout="41c0:0:0:700:2\n")
            return SimpleNamespace(returncode=0, stdout="41ed:0:0:755:2\n")
        if program == "/usr/bin/findmnt":
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps({"filesystems": [{"target": "/"}]}),
            )
        if program == "/usr/bin/test":
            if command[1] == "-r" and command[-1].startswith("/dev/disk/by-id/"):
                return SimpleNamespace(
                    returncode=0 if self.device_readable else 1,
                    stdout="",
                )
            return SimpleNamespace(returncode=0, stdout="")
        raise AssertionError(command)


class PreflightTests(unittest.TestCase):
    def test_runtime_error_points_to_project_venv(self) -> None:
        with (
            mock.patch.object(preflight.platform, "system", return_value="Linux"),
            mock.patch.object(preflight.sys, "version_info", (3, 13, 9)),
            self.assertRaisesRegex(RuntimeError, r"\.venv/bin/python"),
        ):
            preflight.check_runtime(PROJECT_ROOT)

    def test_document_conversion_and_remap_use_current_contract(self) -> None:
        document = deployment_document(Path("/tmp/work"), Path("/tmp/ndm.toml"))
        config = deployment_config(Path("/tmp/deploy.toml"), document)
        self.assertEqual(config.deploy.ndm_cfg, Path("/tmp/ndm.toml"))
        text = remapped_config_text(config, Path("/tmp/work/.ndm-deploy/ndm-config.toml"))
        self.assertIn("send_test_mail = true", text)
        self.assertNotIn("deploy_user", text)
        self.assertNotIn("bin_path", text)

    def test_schema_rejects_old_deploy_user_contract(self) -> None:
        registry, schema, _ndm = preflight._schema_registry(PROJECT_ROOT)
        document = deployment_document(Path("/tmp/work"), Path("/tmp/ndm.toml"))
        document["deploy"]["deploy_user"] = "root"
        with self.assertRaisesRegex(ValueError, "不满足约束"):
            preflight._validate_schema(document, schema, registry, "部署配置")

    def test_ndm_schema_requires_auth_method_specific_credentials(self) -> None:
        registry, _deploy, schema = preflight._schema_registry(PROJECT_ROOT)
        oauth = tomllib.loads((PROJECT_ROOT / "packaging/config.example.toml").read_text())
        oauth["mail"]["oauth"].update(
            oauth_metadata_url="https://issuer.example/.well-known/openid-configuration",
            oauth_username="oauth-user@example.test",
            oauth_app_id="client-id",
            oauth_client_secret="client-secret",
        )
        preflight._validate_schema(oauth, schema, registry, "OAuth 配置")

        plain = copy.deepcopy(oauth)
        plain["mail"]["smtp_auth_method"] = "PLAIN"
        plain["mail"].pop("oauth")
        plain["mail"]["plain"] = {
            "plain_username": "plain-user@example.test",
            "plain_app_password": "app-password",
        }
        preflight._validate_schema(plain, schema, registry, "PLAIN 配置")

        oauth["mail"]["plain"] = plain["mail"]["plain"]
        with self.assertRaisesRegex(ValueError, "不满足约束"):
            preflight._validate_schema(oauth, schema, registry, "混合认证配置")

    def test_daemon_action_requires_systemd_integration(self) -> None:
        document = deployment_document(Path("/tmp/work"), Path("/tmp/ndm.toml"))
        document["post-install"]["daemon"] = "start-only"
        config = deployment_config(Path("/tmp/deploy.toml"), document)
        self.assertFalse(config.install.systemd_integration)
        self.assertEqual(config.post_install.daemon, "start-only")

    def test_ndm_semantics_select_auth_and_reject_nonfinite(self) -> None:
        document = {
            "writer_rank": {"rank_length": 1},
            "device": {"disk_list": []},
            "mail": {"smtp_auth_method": "XOAUTH2"},
        }
        self.assertEqual(preflight._validate_ndm_semantics(document), "XOAUTH2")
        document["device"] = {
            "disk_list": [{"detect_window_hr": 1, "w_delta_threshold_gib": float("nan")}]
        }
        with self.assertRaisesRegex(ValueError, "有限数"):
            preflight._validate_ndm_semantics(document)

    def test_local_preflight_reads_config_once_and_never_calls_sudo(self) -> None:
        with tempfile.TemporaryDirectory(dir=PROJECT_ROOT) as temporary:
            root = Path(temporary)
            ndm_path = root / "ndm.toml"
            ndm_text = (PROJECT_ROOT / "packaging/config.example.toml").read_text()
            ndm_text = (
                ndm_text.replace(
                    'oauth_username = ""',
                    'oauth_username = "oauth-user@example.test"',
                )
                .replace(
                    'oauth_app_id = ""',
                    'oauth_app_id = "client-id"',
                )
                .replace(
                    'oauth_client_secret = ""',
                    'oauth_client_secret = "client-secret"',
                )
                .replace(
                    'oauth_metadata_url = ""',
                    'oauth_metadata_url = "https://issuer.example/.well-known/openid-configuration"',
                )
            )
            ndm_path.write_text(ndm_text, encoding="utf-8")
            wdir = root / "work"
            deploy_path = root / "deploy.toml"
            deploy_path.write_text(
                "\n".join(
                    (
                        "[general]",
                        "schema_version = 1",
                        f'wdir = "{wdir}"',
                        "[deploy]",
                        f'ndm_cfg = "{ndm_path}"',
                        "enable_doc = false",
                        "[install]",
                        'doc_path = "/usr/local/share/doc"',
                        "systemd_integration = false",
                        "[post-install]",
                        "send_test_mail = false",
                        'clean = "always"',
                        'daemon = "none"',
                    )
                ),
                encoding="utf-8",
            )
            with (
                mock.patch("preflight.check_runtime"),
                mock.patch("preflight.check_dependencies"),
                mock.patch("preflight.git_source_files", return_value=(Path("Cargo.toml"),)),
                mock.patch("preflight.check_network") as network,
            ):
                result = run_local_preflight(deploy_path, PROJECT_ROOT, live_network=False)
            self.assertEqual(result.config.general.wdir, wdir)
            self.assertEqual(result.smtp_auth_method, "XOAUTH2")
            self.assertEqual(
                result.device_paths,
                (
                    Path("/dev/disk/by-id/disk_0_path"),
                    Path("/dev/disk/by-id/disk_1_path"),
                ),
            )
            network.assert_not_called()

    def test_privileged_preflight_can_run_without_systemd(self) -> None:
        config = DeploymentConfig(
            source_path=Path("/tmp/deploy.toml"),
            general=GeneralSection(1, Path("/tmp/work")),
            deploy=DeploySection(Path("/tmp/ndm.toml"), False),
            install=InstallSection(Path("/usr/local/share/doc"), False),
            post_install=PostInstallSection(False, "none", "none"),
        )
        device = Path("/dev/disk/by-id/nvme-SAMPLE_DISK")
        local = LocalPreflight(config, {}, {}, b"", (device,), (), "PLAIN")
        state_file_sets = (
            frozenset((STATS_PATH,)),
            frozenset((STATS_PATH, STATS_WAL_PATH)),
            frozenset(STATS_FILES),
        )
        for state_files in state_file_sets:
            with self.subTest(state_files=state_files):
                runner = ReadOnlyRootRunner(state_files=state_files)
                result = run_privileged_preflight(runner, local)
                self.assertFalse(result.service_active)
                self.assertEqual(result.mount_targets, (Path("/"),))
                self.assertIn(
                    (
                        "/usr/bin/stat",
                        "--dereference",
                        "--format=%f:%u:%g:%a:%h",
                        "--",
                        str(device),
                    ),
                    runner.commands,
                )
                self.assertIn(("/usr/bin/test", "-r", str(device)), runner.commands)
                for path in (STATS_PATH, STATS_WAL_PATH, STATS_SHM_PATH):
                    self.assertIn(
                        (
                            "/usr/bin/stat",
                            "--format=%f:%u:%g:%a:%h",
                            "--",
                            str(path),
                        ),
                        runner.commands,
                    )

    def test_privileged_preflight_rejects_group_accessible_sqlite_companion(self) -> None:
        config = DeploymentConfig(
            source_path=Path("/tmp/deploy.toml"),
            general=GeneralSection(1, Path("/tmp/work")),
            deploy=DeploySection(Path("/tmp/ndm.toml"), False),
            install=InstallSection(Path("/usr/local/share/doc"), False),
            post_install=PostInstallSection(False, "none", "none"),
        )
        device = Path("/dev/disk/by-id/nvme-SAMPLE_DISK")
        local = LocalPreflight(config, {}, {}, b"", (device,), (), "PLAIN")
        runner = ReadOnlyRootRunner(
            state_files=frozenset((STATS_PATH, STATS_WAL_PATH)),
            unsafe_state_file=STATS_WAL_PATH,
        )

        with self.assertRaisesRegex(PermissionError, "不能向 group/other 开放"):
            run_privileged_preflight(runner, local)

    def test_privileged_preflight_rejects_sqlite_companion_without_main_database(
        self,
    ) -> None:
        config = DeploymentConfig(
            source_path=Path("/tmp/deploy.toml"),
            general=GeneralSection(1, Path("/tmp/work")),
            deploy=DeploySection(Path("/tmp/ndm.toml"), False),
            install=InstallSection(Path("/usr/local/share/doc"), False),
            post_install=PostInstallSection(False, "none", "none"),
        )
        device = Path("/dev/disk/by-id/nvme-SAMPLE_DISK")
        local = LocalPreflight(config, {}, {}, b"", (device,), (), "PLAIN")
        for companion in (STATS_WAL_PATH, STATS_SHM_PATH):
            with self.subTest(companion=companion):
                runner = ReadOnlyRootRunner(state_files=frozenset((companion,)))
                with self.assertRaisesRegex(ValueError, "SQLite 伴随文件缺少主数据库"):
                    run_privileged_preflight(runner, local)

    def test_privileged_preflight_rejects_device_root_cannot_read(self) -> None:
        config = DeploymentConfig(
            source_path=Path("/tmp/deploy.toml"),
            general=GeneralSection(1, Path("/tmp/work")),
            deploy=DeploySection(Path("/tmp/ndm.toml"), False),
            install=InstallSection(Path("/usr/local/share/doc"), False),
            post_install=PostInstallSection(False, "none", "none"),
        )
        device = Path("/dev/disk/by-id/nvme-SAMPLE_DISK")
        local = LocalPreflight(config, {}, {}, b"", (device,), (), "PLAIN")
        runner = ReadOnlyRootRunner(device_readable=False)
        with self.assertRaisesRegex(PermissionError, "root 不能读取"):
            run_privileged_preflight(runner, local)
        self.assertFalse(
            any(command[-1] == str(BIN_PATH) for command in runner.commands),
            "设备预检失败后不应继续读取安装目标",
        )


if __name__ == "__main__":
    unittest.main()
