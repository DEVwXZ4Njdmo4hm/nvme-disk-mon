import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "src" / "main.py"
SOURCE_ROOT = SCRIPT.parents[3]


class CliSmokeTests(unittest.TestCase):
    def test_help_entry_point(self) -> None:
        result = subprocess.run(
            (sys.executable, str(SCRIPT), "--help"),
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("-S DIR", result.stdout)
        self.assertIn("-B DIR", result.stdout)
        self.assertIn("-T {Release,Debug}", result.stdout)
        self.assertIn("--doc", result.stdout)
        self.assertIn("--init-only", result.stdout)

    def test_missing_arguments_exit_with_usage_error(self) -> None:
        result = subprocess.run(
            (sys.executable, str(SCRIPT)),
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("usage:", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_nonempty_build_directory_fails_before_network_or_writes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            build = root / "build"
            marker = build / ".occupied"
            source.mkdir()
            build.mkdir()
            marker.write_text("unchanged", encoding="utf-8")

            result = subprocess.run(
                (
                    sys.executable,
                    str(SCRIPT),
                    "-S",
                    str(source),
                    "-B",
                    str(build),
                    "-T",
                    "Debug",
                ),
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(result.returncode, 1)
            self.assertIn("构建目录必须为空", result.stderr)
            self.assertEqual(marker.read_text(encoding="utf-8"), "unchanged")
            self.assertEqual(tuple(build.iterdir()), (marker,))
            self.assertNotIn("Traceback", result.stderr)

    def test_live_debug_build_and_documentation(self) -> None:
        build_root = SOURCE_ROOT / "build"
        created_build_root = not build_root.exists()
        build_root.mkdir(exist_ok=True)
        if created_build_root:
            self.addCleanup(build_root.rmdir)

        with tempfile.TemporaryDirectory(
            prefix="build-script-live-",
            dir=build_root,
        ) as temporary:
            build = Path(temporary)
            result = subprocess.run(
                (
                    sys.executable,
                    str(SCRIPT),
                    "-S",
                    str(SOURCE_ROOT),
                    "-B",
                    str(build),
                    "-T",
                    "Debug",
                    "--doc",
                ),
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                result.stdout.splitlines(),
                [
                    "[1/3] 执行预检...OK!",
                    "[2/3] 初始化隔离 Rust 环境并获取依赖...OK!",
                    "[3/3] 构建程序和文档...OK!",
                ],
            )
            self.assertTrue((build / "rust" / "cargo" / "bin" / "cargo").is_file())
            self.assertTrue((build / "debug" / "debug" / "nvme-disk-mon").is_file())
            self.assertTrue((build / "debug" / "doc" / "nvme_disk_mon" / "index.html").is_file())
            self.assertFalse((build / "debug" / "doc" / "heck").exists())
            manual = (build / "debug" / "doc" / "index.html").read_text(encoding="utf-8")
            self.assertTrue(manual.startswith("<!doctype html>"))
            self.assertIn("<h1>NVMe-Disk-Mon 1.0.0</h1>", manual)
            self.assertIn("mail test-send", manual)
            self.assertNotIn("@NDM_VERSION@", manual)

    def test_live_environment_initialization_only(self) -> None:
        build_root = SOURCE_ROOT / "build"
        created_build_root = not build_root.exists()
        build_root.mkdir(exist_ok=True)
        if created_build_root:
            self.addCleanup(build_root.rmdir)

        with tempfile.TemporaryDirectory(
            prefix="build-script-init-only-live-",
            dir=build_root,
        ) as temporary:
            build = Path(temporary)
            result = subprocess.run(
                (
                    sys.executable,
                    str(SCRIPT),
                    "-S",
                    str(SOURCE_ROOT),
                    "-B",
                    str(build),
                    "-T",
                    "Release",
                    "--doc",
                    "--init-only",
                ),
                capture_output=True,
                text=True,
                check=False,
            )

            target_dir = build / "release"
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                result.stdout.splitlines(),
                [
                    "[1/2] 执行预检...OK!",
                    "[2/2] 初始化隔离 Rust 环境并获取依赖...OK!",
                ],
            )
            self.assertNotIn("构建程序", result.stdout)
            self.assertTrue((build / "rust" / "cargo" / "bin" / "cargo").is_file())
            self.assertTrue(target_dir.is_dir())
            self.assertFalse((target_dir / "release" / "nvme-disk-mon").exists())
            self.assertFalse((target_dir / "doc" / "nvme_disk_mon" / "index.html").exists())

        self.assertFalse(build.exists())


if __name__ == "__main__":
    unittest.main()
