import subprocess
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[4]


class CliSmokeTests(unittest.TestCase):
    def test_root_entrypoint_help_needs_no_config_or_privilege(self) -> None:
        result = subprocess.run(
            (sys.executable, PROJECT_ROOT / "deploy.py", "--help"),
            cwd=PROJECT_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("DEPLOY_CONFIG_PATH", result.stdout)
        self.assertNotIn("sudo", result.stdout)


if __name__ == "__main__":
    unittest.main()
