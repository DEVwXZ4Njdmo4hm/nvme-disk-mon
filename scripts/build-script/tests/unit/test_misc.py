import hashlib
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import Mock, patch

SRC_DIR = Path(__file__).resolve().parents[2] / "src"
sys.path.insert(0, str(SRC_DIR))

import misc  # noqa: E402


class FakeResponse:
    def __init__(
        self,
        payload: bytes,
        status: int = 200,
        final_url: str = "https://example.test",
    ) -> None:
        self.payload = payload
        self.status = status
        self.final_url = final_url
        self.offset = 0

    def __enter__(self):
        return self

    def __exit__(self, *_args) -> None:
        return None

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            size = len(self.payload) - self.offset
        chunk = self.payload[self.offset : self.offset + size]
        self.offset += len(chunk)
        return chunk

    def geturl(self) -> str:
        return self.final_url


class HttpsTests(unittest.TestCase):
    def test_fetch_https_returns_bounded_payload(self) -> None:
        with (
            patch.object(misc, "tls_context"),
            patch.object(misc, "urlopen", return_value=FakeResponse(b"payload")),
        ):
            self.assertEqual(misc.fetch_https("https://example.test", max_bytes=7), b"payload")

    def test_fetch_https_rejects_oversize_payload(self) -> None:
        with (
            patch.object(misc, "tls_context"),
            patch.object(misc, "urlopen", return_value=FakeResponse(b"oversize")),
            self.assertRaises(ValueError),
        ):
            misc.fetch_https("https://example.test", max_bytes=4)

    def test_fetch_https_enforces_total_timeout(self) -> None:
        with (
            patch.object(misc, "tls_context"),
            patch.object(misc, "urlopen", return_value=FakeResponse(b"payload")),
            patch.object(misc.time, "monotonic", side_effect=(0.0, 31.0)),
            self.assertRaises(ConnectionError),
        ):
            misc.fetch_https("https://example.test", max_bytes=7, max_elapsed=30.0)

    def test_non_https_url_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            misc.fetch_https("http://example.test", max_bytes=4)

    def test_https_redirect_cannot_downgrade_protocol(self) -> None:
        response = FakeResponse(b"payload", final_url="http://example.test")
        with (
            patch.object(misc, "tls_context"),
            patch.object(misc, "urlopen", return_value=response),
            self.assertRaises(ConnectionError),
        ):
            misc.fetch_https("https://example.test", max_bytes=7)

    def test_download_is_streamed_and_hashed(self) -> None:
        payload = b"download payload"
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "download"
            with (
                patch.object(misc, "tls_context"),
                patch.object(misc, "urlopen", return_value=FakeResponse(payload)),
            ):
                digest = misc.download_https("https://example.test/file", destination)

            self.assertEqual(destination.read_bytes(), payload)
            self.assertEqual(digest, hashlib.sha256(payload).hexdigest())
            self.assertEqual(destination.stat().st_mode & 0o777, 0o600)

    def test_oversize_download_is_removed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "download"
            with (
                patch.object(misc, "tls_context"),
                patch.object(misc, "urlopen", return_value=FakeResponse(b"oversize")),
                self.assertRaises(ValueError),
            ):
                misc.download_https(
                    "https://example.test/file",
                    destination,
                    max_bytes=4,
                )

            self.assertFalse(destination.exists())
            self.assertFalse((Path(temporary) / ".download.part").exists())

    @patch.object(misc.subprocess, "run")
    def test_command_runner_never_uses_a_shell(self, run: Mock) -> None:
        run.return_value = misc.subprocess.CompletedProcess(
            ("cargo", "--version"),
            0,
            stdout="toolchain noise\n",
        )
        stdout = StringIO()
        stderr = StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            misc.run_command(("cargo", "--version"), cwd=Path("/tmp"), env={"PATH": "/bin"})

        run.assert_called_once_with(
            ("cargo", "--version"),
            cwd=Path("/tmp"),
            env={"PATH": "/bin"},
            check=True,
            stdout=misc.subprocess.PIPE,
            stderr=misc.subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
