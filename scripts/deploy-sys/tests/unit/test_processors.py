import hashlib
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

SOURCE = Path(__file__).resolve().parents[2] / "src"
sys.path.insert(0, str(SOURCE))

from build_processor import BuildArtifacts  # noqa: E402
from install_processor import install_release  # noqa: E402
from misc import BIN_PATH, CONF_PATH, DATA_PATH, DOC_DIRECTORY_NAME, STATS_PATH  # noqa: E402
from oauth2_helper import authentication_commands  # noqa: E402
from post_install_processor import daemon_commands  # noqa: E402
from preflight import (  # noqa: E402
    DeploymentConfig,
    DeploySection,
    GeneralSection,
    InstallSection,
    LocalPreflight,
    PostInstallSection,
)


class RecordingRunner:
    euid = os.geteuid()
    egid = os.getegid()

    def __init__(self, digest: str) -> None:
        self.commands: list[tuple[str, ...]] = []
        self.digest = digest

    def run(self, command, **_kwargs):
        rendered = tuple(str(argument) for argument in command)
        self.commands.append(rendered)
        stdout = f"{self.digest}  {CONF_PATH}\n" if command[0] == "/usr/bin/sha256sum" else ""
        return SimpleNamespace(returncode=0, stdout=stdout)


def local_config(*, enable_doc: bool = False) -> LocalPreflight:
    config = DeploymentConfig(
        source_path=Path("/tmp/deploy.toml"),
        general=GeneralSection(1, Path("/tmp/work")),
        deploy=DeploySection(Path("/tmp/ndm.toml"), enable_doc),
        install=InstallSection(Path("/usr/local/share/doc"), False),
        post_install=PostInstallSection(False, "always", "none"),
    )
    return LocalPreflight(config, {}, {}, b"", (), (), "PLAIN")


class ProcessorTests(unittest.TestCase):
    def test_authentication_command_matrix(self) -> None:
        self.assertEqual(
            authentication_commands("PLAIN"),
            ((str(BIN_PATH), "mail", "validate"),),
        )
        self.assertEqual(
            authentication_commands("XOAUTH2"),
            (
                (str(BIN_PATH), "mail", "authorize"),
                (str(BIN_PATH), "mail", "validate"),
            ),
        )
        with self.assertRaises(ValueError):
            authentication_commands("LOGIN")

    def test_daemon_command_matrix_targets_service(self) -> None:
        self.assertEqual(daemon_commands("none"), ())
        self.assertIn("start", daemon_commands("start-only")[0])
        self.assertIn("enable", daemon_commands("enable-only")[0])
        self.assertIn("--now", daemon_commands("enable-and-start")[0])

    def test_install_preserves_only_stats_and_installs_fixed_targets(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "nvme-disk-mon"
            binary.write_bytes(b"binary")
            config = root / "ndm.toml"
            config.write_bytes(b"config")
            digest = hashlib.sha256(b"config").hexdigest()
            artifacts = BuildArtifacts(binary, None, digest)
            runner = RecordingRunner(digest)
            result = install_release(runner, local_config(), artifacts, config, None)
            self.assertEqual(result.binary, BIN_PATH)
            self.assertEqual(result.config, CONF_PATH)
            find_command = next(
                command for command in runner.commands if command[0] == "/usr/bin/find"
            )
            self.assertIn(str(DATA_PATH), find_command)
            self.assertIn(str(STATS_PATH), find_command)
            flattened = "\n".join(" ".join(command) for command in runner.commands)
            self.assertIn(str(BIN_PATH), flattened)
            self.assertIn(str(CONF_PATH), flattened)

    def test_installs_html_document_to_fixed_project_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "nvme-disk-mon"
            binary.write_bytes(b"binary")
            config = root / "ndm.toml"
            config.write_bytes(b"config")
            documentation = root / "doc"
            documentation.mkdir()
            manual = documentation / "index.html"
            manual.write_text("<!doctype html><h1>NVMe-Disk-Mon 1.0.0</h1>", encoding="utf-8")
            digest = hashlib.sha256(b"config").hexdigest()
            artifacts = BuildArtifacts(binary, documentation, digest)
            runner = RecordingRunner(digest)

            result = install_release(
                runner,
                local_config(enable_doc=True),
                artifacts,
                config,
                None,
            )

            destination = Path("/usr/local/share/doc") / DOC_DIRECTORY_NAME
            self.assertEqual(result.documentation, destination)
            cleanup_command = (
                "/usr/bin/find",
                str(destination),
                "-depth",
                "-mindepth",
                "1",
                "-delete",
            )
            install_command = (
                "/usr/bin/install",
                "--owner=0",
                "--group=0",
                "--mode=0644",
                "--",
                str(manual),
                str(destination / "index.html"),
            )
            self.assertIn(cleanup_command, runner.commands)
            self.assertIn(install_command, runner.commands)
            self.assertLess(
                runner.commands.index(cleanup_command),
                runner.commands.index(install_command),
            )


if __name__ == "__main__":
    unittest.main()
