import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch


SRC_DIR = Path(__file__).resolve().parents[2] / "src"
sys.path.insert(0, str(SRC_DIR))

import preflight  # noqa: E402


class RuntimeTests(unittest.TestCase):
    def test_current_project_runtime_is_accepted(self) -> None:
        preflight.check_runtime()

    def test_runtime_does_not_require_jit(self) -> None:
        with (
            patch.dict(preflight.os.environ, {}, clear=True),
            patch.object(preflight.sys, "_jit", None, create=True),
        ):
            preflight.check_runtime()

    def test_non_project_venv_is_rejected(self) -> None:
        with (
            patch.object(preflight.sys, "prefix", "/external/.venv"),
            patch.object(preflight.sys, "base_prefix", "/python"),
            self.assertRaises(RuntimeError),
        ):
            preflight.check_runtime()

    def test_missing_dependency_is_rejected(self) -> None:
        with (
            patch.object(
                preflight,
                "distribution",
                side_effect=preflight.PackageNotFoundError("certifi"),
            ),
            self.assertRaises(ModuleNotFoundError),
        ):
            preflight.check_script_dependencies()

    def test_dependency_version_must_match_pyproject(self) -> None:
        installed = SimpleNamespace(version="0.0.0")
        with (
            patch.object(preflight, "distribution", return_value=installed),
            self.assertRaises(RuntimeError),
        ):
            preflight.check_script_dependencies()

    def test_module_cannot_shadow_certifi_distribution(self) -> None:
        recorded_origin = Path("/venv/site-packages/certifi/__init__.py")
        package_init = SimpleNamespace(
            parts=("certifi", "__init__.py"),
            locate=Mock(return_value=recorded_origin),
        )
        installed = SimpleNamespace(version="2026.7.22", files=[package_init])
        spec = SimpleNamespace(origin="/venv/site-packages/certifi.py")
        with (
            patch.object(preflight, "find_spec", return_value=spec),
            patch.object(preflight, "distribution", return_value=installed),
            patch.object(preflight, "required_certifi_version", return_value="2026.7.22"),
            self.assertRaises(ImportError),
        ):
            preflight.check_script_dependencies()

    def test_dependency_module_requires_a_known_origin(self) -> None:
        installed = SimpleNamespace(version="2026.7.22")
        for spec in (None, SimpleNamespace(origin=None)):
            with (
                self.subTest(spec=spec),
                patch.object(preflight, "find_spec", return_value=spec),
                patch.object(preflight, "distribution", return_value=installed),
                patch.object(
                    preflight,
                    "required_certifi_version",
                    return_value="2026.7.22",
                ),
                self.assertRaises(ModuleNotFoundError),
            ):
                preflight.check_script_dependencies()

    def test_dependency_origin_must_match_installation_record(self) -> None:
        origin = Path("/venv/site-packages/certifi/__init__.py")
        package_init = SimpleNamespace(
            parts=("certifi", "__init__.py"),
            locate=Mock(return_value=origin),
        )
        installed = SimpleNamespace(version="2026.7.22", files=[package_init])
        spec = SimpleNamespace(origin=str(origin))
        with (
            patch.object(preflight, "find_spec", return_value=spec),
            patch.object(preflight, "distribution", return_value=installed),
            patch.object(preflight, "required_certifi_version", return_value="2026.7.22"),
        ):
            preflight.check_script_dependencies()

    def test_dependency_record_must_contain_local_package_init(self) -> None:
        spec = SimpleNamespace(origin="/venv/site-packages/certifi/__init__.py")
        cases = (
            None,
            [],
            [
                SimpleNamespace(
                    parts=("certifi", "__init__.py"),
                    locate=Mock(return_value="/venv/site-packages/certifi/__init__.py"),
                )
            ],
        )
        for files in cases:
            installed = SimpleNamespace(version="2026.7.22", files=files)
            with (
                self.subTest(files=files),
                patch.object(preflight, "find_spec", return_value=spec),
                patch.object(preflight, "distribution", return_value=installed),
                patch.object(
                    preflight,
                    "required_certifi_version",
                    return_value="2026.7.22",
                ),
                self.assertRaises(ImportError),
            ):
                preflight.check_script_dependencies()

    def test_certifi_constraint_is_read_from_pyproject(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            pyproject = Path(temporary) / "pyproject.toml"
            pyproject.write_text(
                '[project]\ndependencies = ["certifi==2099.1.2"]\n',
                encoding="utf-8",
            )
            with patch.object(preflight, "PYPROJECT_PATH", pyproject):
                self.assertEqual(preflight.required_certifi_version(), "2099.1.2")


class DirectoryTests(unittest.TestCase):
    def test_source_requires_only_directory_and_rx_access(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            with patch.object(preflight, "_has_access", return_value=True) as access:
                result = preflight.validate_source_dir(source)

        self.assertEqual(result, source.resolve())
        access.assert_called_once_with(source.resolve(), os.R_OK | os.X_OK)

    def test_source_file_is_rejected(self) -> None:
        with tempfile.NamedTemporaryFile() as source, self.assertRaises(NotADirectoryError):
            preflight.validate_source_dir(Path(source.name))

    def test_source_without_access_is_rejected(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(preflight, "_has_access", return_value=False),
            self.assertRaises(PermissionError),
        ):
            preflight.validate_source_dir(Path(temporary))

    def test_build_directory_must_already_exist(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary) / "missing"
            with self.assertRaises(FileNotFoundError):
                preflight.validate_build_dir(missing)

        self.assertFalse(missing.exists())

    def test_empty_build_directory_is_accepted_without_writes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            build = Path(temporary)
            with patch.object(preflight, "_has_access", return_value=True):
                result = preflight.validate_build_dir(build)
            self.assertEqual(tuple(build.iterdir()), ())

        self.assertEqual(result, build.resolve())

    def test_hidden_entry_makes_build_directory_nonempty(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            build = Path(temporary)
            (build / ".hidden").touch()
            with (
                patch.object(preflight, "_has_access", return_value=True),
                self.assertRaises(ValueError),
            ):
                preflight.validate_build_dir(build)

    def test_build_directory_requires_rwx(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(preflight, "_has_access", return_value=False),
            self.assertRaises(PermissionError),
        ):
            preflight.validate_build_dir(Path(temporary))

    def test_access_check_falls_back_when_effective_ids_are_unsupported(self) -> None:
        with patch.object(
            preflight.os,
            "access",
            side_effect=(NotImplementedError, True),
        ) as access:
            self.assertTrue(preflight._has_access(Path("/build"), os.R_OK))

        self.assertEqual(access.call_count, 2)


class NetworkTests(unittest.TestCase):
    @patch.object(preflight, "fetch_https", return_value=("a" * 64).encode())
    def test_rust_distribution_checksum_is_accepted(self, fetch: Mock) -> None:
        preflight.check_network()

        fetch.assert_called_once_with(preflight.RUST_DISTRIBUTION_URL, max_bytes=4096)

    @patch.object(preflight, "fetch_https", return_value=b"not-a-checksum")
    def test_invalid_rust_distribution_response_is_rejected(self, _fetch: Mock) -> None:
        with self.assertRaises(ValueError):
            preflight.check_network()

    @patch.object(preflight, "fetch_https", return_value=b"   \n")
    def test_empty_rust_distribution_response_is_rejected(self, _fetch: Mock) -> None:
        with self.assertRaises(ValueError):
            preflight.check_network()

    @patch.object(
        preflight,
        "fetch_https",
        return_value=b'{"dl":"https://static.crates.io/crates","api":"https://crates.io"}',
    )
    def test_crates_io_sparse_config_is_accepted(self, fetch: Mock) -> None:
        preflight.check_crates_io()

        fetch.assert_called_once_with(preflight.CRATES_IO_CONFIG_URL, max_bytes=64 * 1024)

    @patch.object(preflight, "fetch_https", return_value=b'{"dl":"http://insecure"}')
    def test_invalid_crates_io_download_url_is_rejected(self, _fetch: Mock) -> None:
        with self.assertRaises(ValueError):
            preflight.check_crates_io()

    def test_preflight_checks_network_only_after_local_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"
            build = Path(temporary) / "build"
            source.mkdir()
            build.mkdir()
            (build / "occupied").touch()
            with (
                patch.object(preflight, "check_runtime"),
                patch.object(preflight, "check_script_dependencies"),
                patch.object(preflight, "check_network") as network,
                self.assertRaises(ValueError),
            ):
                preflight.run_preflight(source, build)

        network.assert_not_called()

    def test_successful_preflight_runs_every_check_in_order(self) -> None:
        events: list[str] = []
        source = Path("/source")
        build = Path("/build")

        def record(name: str, result=None):
            return lambda *_args: events.append(name) or result

        with (
            patch.object(preflight, "check_runtime", side_effect=record("runtime")),
            patch.object(
                preflight,
                "check_script_dependencies",
                side_effect=record("dependencies"),
            ),
            patch.object(
                preflight,
                "validate_source_dir",
                side_effect=record("source", source),
            ),
            patch.object(
                preflight,
                "validate_build_dir",
                side_effect=record("build", build),
            ),
            patch.object(preflight, "check_network", side_effect=record("network")),
            patch.object(preflight, "check_crates_io", side_effect=record("crates.io")),
        ):
            result = preflight.run_preflight(Path("source"), Path("build"))

        self.assertEqual(
            events,
            ["runtime", "dependencies", "source", "build", "network", "crates.io"],
        )
        self.assertEqual(result, preflight.PreflightResult(source, build))


if __name__ == "__main__":
    unittest.main()
