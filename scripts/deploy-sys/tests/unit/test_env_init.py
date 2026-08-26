import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[2] / "src"
sys.path.insert(0, str(SOURCE))

import env_init  # noqa: E402


class EnvironmentInitializationTests(unittest.TestCase):
    def test_working_venv_uses_quiet_controller_commands(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workdir = Path(temporary)
            (workdir / "requirements.txt").write_text("certifi==2026.7.22\n", encoding="utf-8")
            base_python = Path(sys.executable).resolve()

            def run(command, *, cwd: Path) -> None:
                self.assertEqual(cwd, workdir)
                if command[1:3] == ("-m", "venv"):
                    python = workdir / ".venv/bin/python"
                    python.parent.mkdir(parents=True)
                    python.symlink_to(base_python)

            with (
                patch.object(env_init, "_base_python_executable", return_value=base_python),
                patch.object(env_init, "run_quiet_command", side_effect=run) as quiet,
            ):
                python = env_init.create_working_venv(workdir)

            self.assertEqual(python, workdir / ".venv/bin/python")
            self.assertEqual(quiet.call_count, 2)
            pip_command = quiet.call_args_list[1].args[0]
            self.assertEqual(pip_command[:4], (str(python), "-m", "pip", "install"))
            self.assertIn(str(workdir / "requirements.txt"), pip_command)


if __name__ == "__main__":
    unittest.main()
