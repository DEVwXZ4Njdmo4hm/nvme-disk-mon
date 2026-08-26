import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

SRC_DIR = Path(__file__).resolve().parents[2] / "src"
sys.path.insert(0, str(SRC_DIR))

import build_processor  # noqa: E402
from env_init import BuildEnvironment  # noqa: E402


def environment(target: str, root: Path = Path("/workspace")) -> BuildEnvironment:
    return BuildEnvironment(
        source_dir=root / "source",
        build_dir=root / "build",
        target=target,
        rust_root=root / "build" / "rust",
        cargo_home=root / "build" / "rust" / "cargo",
        rustup_home=root / "build" / "rust" / "rustup",
        target_dir=root / "build" / target.lower(),
        temp_dir=root / "build" / "rust" / "tmp" / target.lower(),
        process_env={"CARGO_TARGET_DIR": str(root / "build" / target.lower())},
    )


def prepare_document_source(root: Path, *, version: str = "1.2.3") -> BuildEnvironment:
    source = root / "source"
    docs = source / "docs"
    docs.mkdir(parents=True)
    (source / "Cargo.toml").write_text(
        f'[package]\nname = "nvme-disk-mon"\nversion = "{version}"\n',
        encoding="utf-8",
    )
    (docs / "index.html").write_text(
        "<!doctype html><h1>NVMe-Disk-Mon @NDM_VERSION@</h1>\n",
        encoding="utf-8",
    )
    return environment("Release", root)


class BuildTests(unittest.TestCase):
    @patch.object(build_processor, "run_command")
    def test_debug_build_is_locked_and_offline(self, runner: Mock) -> None:
        build_environment = environment("Debug")

        build_processor.build_project(build_environment, build_doc=False)

        command = tuple(str(item) for item in runner.call_args.args[0])
        self.assertEqual(command[:2], (str(build_environment.cargo), "build"))
        self.assertIn("--locked", command)
        self.assertIn("--offline", command)
        self.assertNotIn("--release", command)
        self.assertEqual(runner.call_count, 1)
        self.assertEqual(runner.call_args.kwargs["cwd"], build_environment.source_dir)
        self.assertIs(runner.call_args.kwargs["env"], build_environment.process_env)
        manifest_index = command.index("--manifest-path") + 1
        self.assertEqual(command[manifest_index], str(build_environment.source_dir / "Cargo.toml"))

    @patch.object(build_processor, "run_command")
    def test_release_build_then_documentation(self, runner: Mock) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        build_environment = prepare_document_source(Path(temporary.name))

        def create_cargo_doc(command, **_kwargs):
            if command[1] == "doc":
                (build_environment.target_dir / "doc").mkdir(parents=True)

        runner.side_effect = create_cargo_doc

        build_processor.build_project(build_environment, build_doc=True)

        build_command = tuple(str(item) for item in runner.call_args_list[0].args[0])
        doc_command = tuple(str(item) for item in runner.call_args_list[1].args[0])
        self.assertEqual(build_command[1], "build")
        self.assertEqual(doc_command[1], "doc")
        self.assertIn("--release", build_command)
        self.assertIn("--release", doc_command)
        self.assertNotIn("--no-deps", build_command)
        self.assertIn("--no-deps", doc_command)
        self.assertIn("--locked", doc_command)
        self.assertIn("--offline", doc_command)
        self.assertNotIn("--open", doc_command)
        manual = build_environment.target_dir / "doc/index.html"
        self.assertEqual(
            manual.read_text(encoding="utf-8"),
            "<!doctype html><h1>NVMe-Disk-Mon 1.2.3</h1>\n",
        )
        self.assertEqual(runner.call_count, 2)
        for invocation in runner.call_args_list:
            self.assertEqual(invocation.kwargs["cwd"], build_environment.source_dir)
            self.assertIs(invocation.kwargs["env"], build_environment.process_env)
            command = tuple(str(item) for item in invocation.args[0])
            self.assertIn(str(build_environment.source_dir / "Cargo.toml"), command)

    @patch.object(build_processor, "run_command")
    def test_build_failure_prevents_documentation(self, runner: Mock) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        build_environment = prepare_document_source(Path(temporary.name))
        runner.side_effect = subprocess.CalledProcessError(101, ("cargo", "build"))

        with self.assertRaises(subprocess.CalledProcessError):
            build_processor.build_project(build_environment, build_doc=True)

        self.assertEqual(runner.call_count, 1)

    @patch.object(build_processor, "run_command")
    def test_missing_html_source_prevents_build(self, runner: Mock) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            build_environment = environment("Release", Path(temporary))
            with self.assertRaisesRegex(FileNotFoundError, "HTML 文档源"):
                build_processor.build_project(build_environment, build_doc=True)
        runner.assert_not_called()


if __name__ == "__main__":
    unittest.main()
