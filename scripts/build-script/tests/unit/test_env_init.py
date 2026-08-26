import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch


SRC_DIR = Path(__file__).resolve().parents[2] / "src"
sys.path.insert(0, str(SRC_DIR))

import env_init  # noqa: E402
from preflight import PreflightResult  # noqa: E402


class HostTripleTests(unittest.TestCase):
    def test_x86_64_linux_gnu(self) -> None:
        with (
            patch.object(env_init.platform, "system", return_value="Linux"),
            patch.object(env_init.platform, "machine", return_value="x86_64"),
            patch.object(env_init.platform, "libc_ver", return_value=("glibc", "2.39")),
        ):
            self.assertEqual(env_init.rustup_host_triple(), "x86_64-unknown-linux-gnu")

    def test_aarch64_macos(self) -> None:
        with (
            patch.object(env_init.platform, "system", return_value="Darwin"),
            patch.object(env_init.platform, "machine", return_value="arm64"),
        ):
            self.assertEqual(env_init.rustup_host_triple(), "aarch64-apple-darwin")

    def test_x86_64_windows_msvc(self) -> None:
        with (
            patch.object(env_init.platform, "system", return_value="Windows"),
            patch.object(env_init.platform, "machine", return_value="AMD64"),
        ):
            self.assertEqual(env_init.rustup_host_triple(), "x86_64-pc-windows-msvc")

    def test_unknown_architecture_fails_explicitly(self) -> None:
        with (
            patch.object(env_init.platform, "machine", return_value="mystery"),
            self.assertRaises(OSError),
        ):
            env_init.rustup_host_triple()

    def test_musl_linux_is_detected_explicitly(self) -> None:
        with (
            patch.object(env_init.platform, "system", return_value="Linux"),
            patch.object(env_init.platform, "machine", return_value="x86_64"),
            patch.object(env_init.platform, "libc_ver", return_value=("musl", "1.2.5")),
        ):
            self.assertEqual(env_init.rustup_host_triple(), "x86_64-unknown-linux-musl")

    def test_generic_libc_is_rejected(self) -> None:
        with (
            patch.object(env_init.platform, "system", return_value="Linux"),
            patch.object(env_init.platform, "machine", return_value="x86_64"),
            patch.object(env_init.platform, "libc_ver", return_value=("libc", "unknown")),
            self.assertRaises(OSError),
        ):
            env_init.rustup_host_triple()


class EnvironmentLayoutTests(unittest.TestCase):
    def test_layout_and_environment_are_confined_to_build_dir(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            build = root / "build"
            source.mkdir()
            build.mkdir()
            result = PreflightResult(source.resolve(), build.resolve())
            with patch.dict(
                env_init.os.environ,
                {
                    "CARGO_BUILD_RUSTC": "/host/rustc",
                    "CARGO_HOME": "/host/cargo",
                    "CARGO_INCREMENTAL": "1",
                    "CARGO_PROFILE_RELEASE_LTO": "false",
                    "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER": "/host/ld",
                    "PATH": "/bin",
                    "RUSTFLAGS": "host flags",
                    "RUSTUP_FORCE_ARG0": "rustup",
                },
                clear=True,
            ):
                environment = env_init.make_build_environment(result, "Debug")

            self.assertEqual(environment.rust_root, build / "rust")
            self.assertEqual(environment.cargo_home, build / "rust" / "cargo")
            self.assertEqual(environment.rustup_home, build / "rust" / "rustup")
            self.assertEqual(environment.target_dir, build / "debug")
            self.assertEqual(environment.process_env["CARGO_TARGET_DIR"], str(build / "debug"))
            self.assertEqual(
                environment.process_env["CARGO_REGISTRIES_CRATES_IO_INDEX"],
                "sparse+https://index.crates.io/",
            )
            self.assertEqual(environment.process_env["RUSTUP_TOOLCHAIN"], "stable")
            self.assertNotIn("RUSTFLAGS", environment.process_env)
            self.assertNotIn("CARGO_BUILD_RUSTC", environment.process_env)
            self.assertNotIn("CARGO_INCREMENTAL", environment.process_env)
            self.assertNotIn("CARGO_PROFILE_RELEASE_LTO", environment.process_env)
            self.assertNotIn(
                "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER",
                environment.process_env,
            )
            self.assertNotIn("RUSTUP_FORCE_ARG0", environment.process_env)
            self.assertEqual(
                environment.process_env["PATH"].split(env_init.os.pathsep)[0],
                str(build / "rust" / "cargo" / "bin"),
            )
            self.assertTrue(environment.temp_dir.is_dir())
            self.assertEqual(stat.S_IMODE(environment.rust_root.stat().st_mode), 0o700)

    def test_invalid_target_does_not_modify_build_dir(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            build = root / "build"
            source.mkdir()
            build.mkdir()
            result = PreflightResult(source, build)

            with self.assertRaises(ValueError):
                env_init.make_build_environment(result, "debug")

            self.assertEqual(tuple(build.iterdir()), ())

    def test_build_dir_change_after_preflight_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            build = root / "build"
            source.mkdir()
            build.mkdir()
            marker = build / "unexpected"
            marker.touch()

            with self.assertRaises(ValueError):
                env_init.make_build_environment(PreflightResult(source, build), "Debug")

            self.assertEqual(tuple(build.iterdir()), (marker,))


class RustupTests(unittest.TestCase):
    def make_environment(self, root: Path) -> env_init.BuildEnvironment:
        source = root / "source"
        build = root / "build"
        source.mkdir()
        build.mkdir()
        return env_init.make_build_environment(PreflightResult(source, build), "Release")

    def test_download_is_checksum_verified_and_executable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            environment = self.make_environment(Path(temporary))

            def fake_download(_url: str, destination: Path) -> str:
                destination.write_bytes(b"rustup")
                return "a" * 64

            with (
                patch.object(
                    env_init,
                    "rustup_host_triple",
                    return_value="x86_64-unknown-linux-gnu",
                ),
                patch.object(
                    env_init,
                    "fetch_https",
                    return_value=("a" * 64).encode(),
                ) as fetch,
                patch.object(
                    env_init,
                    "download_https",
                    side_effect=fake_download,
                ) as download,
            ):
                destination, host = env_init.download_rustup_init(environment)

            self.assertEqual(host, "x86_64-unknown-linux-gnu")
            self.assertTrue(destination.is_file())
            if env_init.os.name != "nt":
                self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o700)
            self.assertTrue(fetch.call_args.args[0].endswith("rustup-init.sha256"))
            self.assertEqual(download.call_args.args[1], destination)

    def test_checksum_mismatch_removes_download(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            environment = self.make_environment(Path(temporary))

            def fake_download(_url: str, destination: Path) -> str:
                destination.write_bytes(b"rustup")
                return "b" * 64

            with (
                patch.object(
                    env_init,
                    "rustup_host_triple",
                    return_value="x86_64-unknown-linux-gnu",
                ),
                patch.object(env_init, "fetch_https", return_value=("a" * 64).encode()),
                patch.object(env_init, "download_https", side_effect=fake_download),
                self.assertRaises(ValueError),
            ):
                env_init.download_rustup_init(environment)

            destination = environment.rust_root / "bootstrap" / "rustup-init"
            self.assertFalse(destination.exists())

    def test_empty_checksum_response_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            environment = self.make_environment(Path(temporary))
            with (
                patch.object(
                    env_init,
                    "rustup_host_triple",
                    return_value="x86_64-unknown-linux-gnu",
                ),
                patch.object(env_init, "fetch_https", return_value=b"\n"),
                patch.object(env_init, "download_https") as download,
                self.assertRaises(ValueError),
            ):
                env_init.download_rustup_init(environment)

            download.assert_not_called()


class InitializationTests(unittest.TestCase):
    def test_rustup_then_locked_fetch_use_local_cargo(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            build = root / "build"
            source.mkdir()
            build.mkdir()
            preflight = PreflightResult(source, build)
            environment = env_init.make_build_environment(preflight, "Debug")
            installer = environment.rust_root / "bootstrap" / "rustup-init"
            installer.write_bytes(b"rustup")

            invocations: list[tuple[tuple[str, ...], Path, dict[str, str]]] = []

            def fake_run(command, *, cwd, env) -> None:
                invocations.append((tuple(str(item) for item in command), cwd, env))
                if len(invocations) == 1:
                    environment.cargo.parent.mkdir(parents=True)
                    environment.cargo.write_bytes(b"cargo")

            with (
                patch.object(env_init, "make_build_environment", return_value=environment),
                patch.object(
                    env_init,
                    "download_rustup_init",
                    return_value=(installer, "x86_64-unknown-linux-gnu"),
                ),
                patch.object(env_init, "run_command", side_effect=fake_run),
            ):
                result = env_init.initialize_environment(preflight, "Debug")

            commands = [invocation[0] for invocation in invocations]
            self.assertIs(result, environment)
            self.assertEqual(commands[0][0], str(installer))
            self.assertIn("--default-toolchain", commands[0])
            self.assertIn("stable", commands[0])
            self.assertEqual(commands[1][0], str(environment.cargo))
            self.assertEqual(commands[1][1:3], ("fetch", "--locked"))
            self.assertIn(str(source / "Cargo.toml"), commands[1])
            self.assertEqual(invocations[0][1], build)
            self.assertEqual(invocations[1][1], source)
            self.assertIs(invocations[0][2], environment.process_env)
            self.assertIs(invocations[1][2], environment.process_env)

    def test_rustup_failure_prevents_fetch(self) -> None:
        environment = Mock()
        installer = Path("/build/rust/bootstrap/rustup-init")
        with (
            patch.object(env_init, "make_build_environment", return_value=environment),
            patch.object(
                env_init,
                "download_rustup_init",
                return_value=(installer, "x86_64-unknown-linux-gnu"),
            ),
            patch.object(
                env_init,
                "run_command",
                side_effect=subprocess.CalledProcessError(17, (str(installer), "-y")),
            ) as runner,
            self.assertRaises(subprocess.CalledProcessError),
        ):
            env_init.initialize_environment(Mock(), "Debug")

        self.assertEqual(runner.call_count, 1)


if __name__ == "__main__":
    unittest.main()
