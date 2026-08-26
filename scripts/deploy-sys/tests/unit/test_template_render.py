import sys
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[2] / "src"
sys.path.insert(0, str(SOURCE))

from template_render import render_template, systemd_exec_escape  # noqa: E402


class TemplateRenderTests(unittest.TestCase):
    def test_inline_and_block_placeholders(self) -> None:
        template = "Path=@ cfg.__.path @\n@@ cfg.__implicit__.lines @@\n"
        rendered = render_template(
            template,
            {"cfg": {"path": "/a", "__implicit__": {"lines": "A=1\nB=2"}}},
        )
        self.assertEqual(rendered, "Path=/a\nA=1\nB=2\n")

    def test_malformed_placeholder_fails_closed(self) -> None:
        with self.assertRaises(ValueError):
            render_template("@bad@\n", {})

    def test_systemd_exec_escape_covers_specifiers_and_expansion(self) -> None:
        self.assertEqual(systemd_exec_escape('/a/%n/$x"'), '/a/%%n/$$x\\"')


if __name__ == "__main__":
    unittest.main()
