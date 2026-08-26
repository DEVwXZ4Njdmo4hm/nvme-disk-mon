import subprocess
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

SRC_DIR = Path(__file__).resolve().parents[2] / "src"
sys.path.insert(0, str(SRC_DIR))

import main  # noqa: E402


class ArgumentParserTests(unittest.TestCase):
    def test_required_arguments_and_explicit_debug(self) -> None:
        args = main.build_parser().parse_args(["-S", "source", "-B", "build", "-T", "Debug"])

        self.assertEqual(args.source_dir, Path("source"))
        self.assertEqual(args.build_dir, Path("build"))
        self.assertEqual(args.target, "Debug")
        self.assertFalse(args.doc)
        self.assertFalse(args.init_only)

    def test_release_with_documentation(self) -> None:
        args = main.build_parser().parse_args(
            ["-S", "source", "-B", "build", "-T", "Release", "--doc"]
        )

        self.assertEqual(args.target, "Release")
        self.assertTrue(args.doc)
        self.assertFalse(args.init_only)

    def test_init_only_can_be_combined_with_documentation_flag(self) -> None:
        args = main.build_parser().parse_args(
            [
                "-S",
                "source",
                "-B",
                "build",
                "-T",
                "Release",
                "--doc",
                "--init-only",
            ]
        )

        self.assertTrue(args.doc)
        self.assertTrue(args.init_only)

    def test_init_only_flag(self) -> None:
        args = main.build_parser().parse_args(
            ["-S", "source", "-B", "build", "-T", "Debug", "--init-only"]
        )

        self.assertTrue(args.init_only)

    def test_target_is_case_sensitive(self) -> None:
        with redirect_stderr(StringIO()), self.assertRaises(SystemExit) as raised:
            main.build_parser().parse_args(["-S", "source", "-B", "build", "-T", "release"])

        self.assertEqual(raised.exception.code, 2)

    def test_each_short_option_is_required(self) -> None:
        arguments = {
            "-S": "source",
            "-B": "build",
            "-T": "Debug",
        }
        for omitted in arguments:
            argv = [item for pair in arguments.items() if pair[0] != omitted for item in pair]
            with self.subTest(omitted=omitted), redirect_stderr(StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    main.build_parser().parse_args(argv)
                self.assertEqual(raised.exception.code, 2)

    def test_doc_rejects_a_value(self) -> None:
        for doc_arguments in (("--doc=true",), ("--doc", "true")):
            with self.subTest(doc_arguments=doc_arguments), redirect_stderr(StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    main.build_parser().parse_args(
                        ["-S", "source", "-B", "build", "-T", "Debug", *doc_arguments]
                    )
                self.assertEqual(raised.exception.code, 2)

    def test_init_only_rejects_a_value(self) -> None:
        for init_arguments in (("--init-only=true",), ("--init-only", "true")):
            with self.subTest(init_arguments=init_arguments), redirect_stderr(StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    main.build_parser().parse_args(
                        ["-S", "source", "-B", "build", "-T", "Debug", *init_arguments]
                    )
                self.assertEqual(raised.exception.code, 2)

    def test_long_options_cannot_be_abbreviated(self) -> None:
        with redirect_stderr(StringIO()), self.assertRaises(SystemExit) as raised:
            main.build_parser().parse_args(["-S", "source", "-B", "build", "-T", "Debug", "--do"])

        self.assertEqual(raised.exception.code, 2)


class MainFlowTests(unittest.TestCase):
    @patch.object(main, "build_project")
    @patch.object(main, "initialize_environment")
    @patch.object(main, "run_preflight")
    def test_main_runs_stages_in_order(
        self,
        preflight: Mock,
        initialize: Mock,
        build: Mock,
    ) -> None:
        events: list[str] = []
        preflight.side_effect = lambda *_: events.append("preflight") or object()
        environment = SimpleNamespace(target_dir=Path("/build/debug"))
        initialize.side_effect = lambda *_: events.append("environment") or environment
        build.side_effect = lambda *_args, **_kwargs: events.append("build")

        output = StringIO()
        with redirect_stdout(output):
            result = main.main(["-S", "source", "-B", "build", "-T", "Debug", "--doc"])

        self.assertEqual(result, 0)
        self.assertEqual(events, ["preflight", "environment", "build"])
        build.assert_called_once_with(environment, build_doc=True)
        self.assertEqual(
            output.getvalue().splitlines(),
            [
                "[1/3] 执行预检...OK!",
                "[2/3] 初始化隔离 Rust 环境并获取依赖...OK!",
                "[3/3] 构建程序和文档...OK!",
            ],
        )

    @patch.object(main, "build_project")
    @patch.object(main, "initialize_environment")
    @patch.object(main, "run_preflight")
    def test_init_only_returns_after_environment_initialization(
        self,
        preflight: Mock,
        initialize: Mock,
        build: Mock,
    ) -> None:
        preflight_result = object()
        environment = SimpleNamespace(
            rust_root=Path("/build/rust"),
            target_dir=Path("/build/release"),
        )
        preflight.return_value = preflight_result
        initialize.return_value = environment

        output = StringIO()
        with redirect_stdout(output):
            result = main.main(
                [
                    "-S",
                    "source",
                    "-B",
                    "build",
                    "-T",
                    "Release",
                    "--doc",
                    "--init-only",
                ]
            )

        self.assertEqual(result, 0)
        preflight.assert_called_once_with(Path("source"), Path("build"))
        initialize.assert_called_once_with(preflight_result, "Release")
        build.assert_not_called()
        self.assertEqual(
            output.getvalue().splitlines(),
            [
                "[1/2] 执行预检...OK!",
                "[2/2] 初始化隔离 Rust 环境并获取依赖...OK!",
            ],
        )
        self.assertNotIn("构建程序", output.getvalue())

    @patch.object(main, "build_project")
    @patch.object(main, "initialize_environment")
    @patch.object(main, "run_preflight", side_effect=ValueError("bad preflight"))
    def test_preflight_failure_stops_flow(
        self,
        _preflight: Mock,
        initialize: Mock,
        build: Mock,
    ) -> None:
        output = StringIO()
        with redirect_stdout(output), redirect_stderr(StringIO()):
            result = main.main(["-S", "source", "-B", "build", "-T", "Debug"])

        self.assertEqual(result, 1)
        self.assertEqual(output.getvalue(), "[1/3] 执行预检...FAILED!\n")
        initialize.assert_not_called()
        build.assert_not_called()

    @patch.object(main, "initialize_environment")
    @patch.object(main, "run_preflight", return_value=object())
    def test_subprocess_exit_code_is_preserved(
        self,
        _preflight: Mock,
        initialize: Mock,
    ) -> None:
        initialize.side_effect = subprocess.CalledProcessError(
            101,
            ("cargo", "fetch"),
            output="cargo failed to fetch a dependency\n",
        )

        output = StringIO()
        errors = StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            result = main.main(["-S", "source", "-B", "build", "-T", "Debug"])

        self.assertEqual(result, 101)
        self.assertEqual(
            output.getvalue().splitlines(),
            [
                "[1/3] 执行预检...OK!",
                "[2/3] 初始化隔离 Rust 环境并获取依赖...FAILED!",
            ],
        )
        self.assertIn("cargo failed to fetch a dependency", errors.getvalue())

    def test_signal_exit_uses_posix_shell_convention(self) -> None:
        self.assertEqual(main._subprocess_exit_code(-9), 137)

    def test_entry_disables_local_bytecode_writes(self) -> None:
        self.assertTrue(main.sys.dont_write_bytecode)


if __name__ == "__main__":
    unittest.main()
