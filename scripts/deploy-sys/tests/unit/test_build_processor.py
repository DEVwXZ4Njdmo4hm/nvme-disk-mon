import hashlib
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[2] / "src"
sys.path.insert(0, str(SOURCE))

from build_processor import build_release, inject_config_checksum  # noqa: E402

SENTINEL = """\
pub(crate) const CONF_FILE_CHECKSUM: &str = match option_env!("NDM_CONF_FILE_CHECKSUM") {
    Some(value) => value,
    None => "",
};
"""


class BuildProcessorTests(unittest.TestCase):
    def test_release_build_accepts_standard_venv_python_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workdir = Path(temporary)
            build_script = workdir / "scripts/build-script/src/main.py"
            build_script.parent.mkdir(parents=True)
            build_script.write_text("", encoding="utf-8")
            python = workdir / ".venv/bin/python"
            python.parent.mkdir(parents=True)
            python.symlink_to(Path(sys.executable).resolve())

            def create_artifact(*_args: object, **_kwargs: object) -> None:
                binary = workdir / "build/release/release/nvme-disk-mon"
                binary.parent.mkdir(parents=True)
                binary.write_bytes(b"binary")

            with patch("build_processor.run_quiet_command", side_effect=create_artifact) as run:
                artifacts = build_release(
                    workdir,
                    python,
                    enable_doc=False,
                    config_checksum="a" * 64,
                )

            self.assertEqual(artifacts.binary.read_bytes(), b"binary")
            self.assertEqual(run.call_args.args[0][0], str(python))

    def test_release_document_target_requires_html_homepage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workdir = Path(temporary)
            build_script = workdir / "scripts/build-script/src/main.py"
            build_script.parent.mkdir(parents=True)
            build_script.write_text("", encoding="utf-8")
            python = workdir / ".venv/bin/python"
            python.parent.mkdir(parents=True)
            python.symlink_to(Path(sys.executable).resolve())

            def create_artifact(*_args: object, **_kwargs: object) -> None:
                binary = workdir / "build/release/release/nvme-disk-mon"
                binary.parent.mkdir(parents=True)
                binary.write_bytes(b"binary")
                (workdir / "build/release/doc").mkdir()

            with (
                patch("build_processor.run_quiet_command", side_effect=create_artifact),
                self.assertRaisesRegex(FileNotFoundError, "HTML 文档首页"),
            ):
                build_release(
                    workdir,
                    python,
                    enable_doc=True,
                    config_checksum="a" * 64,
                )

    def test_injection_binds_exact_staged_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workdir = Path(temporary)
            (workdir / "src").mkdir()
            source = workdir / "src/config.rs"
            source.write_text(SENTINEL, encoding="utf-8")
            staged = workdir / "ndm.toml"
            payload = b"[general]\nschema_version = 1\n"
            staged.write_bytes(payload)
            digest = inject_config_checksum(workdir, staged, payload)
            self.assertEqual(digest, hashlib.sha256(payload).hexdigest())
            self.assertIn(f'CONF_FILE_CHECKSUM: &str = "{digest}"', source.read_text())
            self.assertNotIn("option_env!", source.read_text())

    def test_injection_rejects_changed_staging_copy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workdir = Path(temporary)
            (workdir / "src").mkdir()
            (workdir / "src/config.rs").write_text(SENTINEL, encoding="utf-8")
            staged = workdir / "ndm.toml"
            staged.write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "偏离"):
                inject_config_checksum(workdir, staged, b"expected")


if __name__ == "__main__":
    unittest.main()
