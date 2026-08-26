"""Small shared helpers for the NDM build script."""

import hashlib
import os
import ssl
import subprocess
import time
from collections.abc import Mapping, Sequence
from importlib import import_module
from pathlib import Path
from urllib.request import Request, urlopen

USER_AGENT = "nvme-disk-mon-build-script/0.1"
DEFAULT_NETWORK_TIMEOUT = 15.0
DEFAULT_NETWORK_TOTAL_TIMEOUT = 30.0
DOWNLOAD_TIMEOUT = 120.0
DOWNLOAD_TOTAL_TIMEOUT = 300.0
MAX_DOWNLOAD_BYTES = 128 * 1024 * 1024

type Command = Sequence[str | Path]


def _require_https_response(response: object, requested_url: str) -> None:
    get_url = getattr(response, "geturl", None)
    final_url = get_url() if callable(get_url) else requested_url
    if not isinstance(final_url, str) or not final_url.startswith("https://"):
        raise ConnectionError(f"HTTPS 请求发生了不安全的协议降级：{requested_url} -> {final_url}")


def tls_context() -> ssl.SSLContext:
    """Create the HTTPS context declared by the script dependency set."""
    certifi = import_module("certifi")
    return ssl.create_default_context(cafile=certifi.where())


def fetch_https(
    url: str,
    *,
    max_bytes: int,
    timeout: float = DEFAULT_NETWORK_TIMEOUT,
    max_elapsed: float = DEFAULT_NETWORK_TOTAL_TIMEOUT,
) -> bytes:
    """Fetch a bounded HTTPS resource and reject unexpected responses."""
    if not url.startswith("https://"):
        raise ValueError(f"仅允许 HTTPS URL：{url}")
    if max_bytes < 1 or max_elapsed <= 0:
        raise ValueError("HTTPS 响应大小和时间限制必须为正数")

    request = Request(
        url,
        headers={
            "Accept": "application/json,text/plain,*/*",
            "Connection": "close",
            "User-Agent": USER_AGENT,
        },
    )
    started = time.monotonic()
    try:
        with urlopen(request, context=tls_context(), timeout=timeout) as response:
            _require_https_response(response, url)
            status = getattr(response, "status", 200)
            if status != 200:
                raise ConnectionError(f"HTTPS 请求返回状态码 {status}：{url}")
            read_chunk = getattr(response, "read1", response.read)
            payload = bytearray()
            while True:
                if time.monotonic() - started > max_elapsed:
                    raise TimeoutError(f"HTTPS 请求超过 {max_elapsed:g} 秒总时限：{url}")
                chunk = read_chunk(min(16 * 1024, max_bytes + 1 - len(payload)))
                if not chunk:
                    break
                payload.extend(chunk)
                if len(payload) > max_bytes:
                    raise ValueError(f"HTTPS 响应超过 {max_bytes} 字节限制：{url}")
                if time.monotonic() - started > max_elapsed:
                    raise TimeoutError(f"HTTPS 请求超过 {max_elapsed:g} 秒总时限：{url}")
    except OSError as exc:
        raise ConnectionError(f"无法访问 {url}：{exc}") from exc

    return bytes(payload)


def download_https(
    url: str,
    destination: Path,
    *,
    timeout: float = DOWNLOAD_TIMEOUT,
    max_elapsed: float = DOWNLOAD_TOTAL_TIMEOUT,
    max_bytes: int = MAX_DOWNLOAD_BYTES,
) -> str:
    """Stream an HTTPS download to a new file and return its SHA-256 digest."""
    if not url.startswith("https://"):
        raise ValueError(f"仅允许 HTTPS URL：{url}")
    if max_elapsed <= 0 or max_bytes < 1:
        raise ValueError("下载时间和大小限制必须为正数")

    partial = destination.with_name(f".{destination.name}.part")
    request = Request(
        url,
        headers={
            "Accept": "application/octet-stream",
            "Connection": "close",
            "User-Agent": USER_AGENT,
        },
    )
    digest = hashlib.sha256()
    downloaded = 0
    started = time.monotonic()

    try:
        with urlopen(request, context=tls_context(), timeout=timeout) as response:
            _require_https_response(response, url)
            status = getattr(response, "status", 200)
            if status != 200:
                raise ConnectionError(f"HTTPS 请求返回状态码 {status}：{url}")
            read_chunk = getattr(response, "read1", response.read)
            file_descriptor = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(file_descriptor, "wb") as output:
                while True:
                    if time.monotonic() - started > max_elapsed:
                        raise TimeoutError(f"下载超过 {max_elapsed:g} 秒总时限：{url}")
                    chunk = read_chunk(64 * 1024)
                    if not chunk:
                        break
                    downloaded += len(chunk)
                    if downloaded > max_bytes:
                        raise ValueError(f"下载内容超过 {max_bytes} 字节限制：{url}")
                    if time.monotonic() - started > max_elapsed:
                        raise TimeoutError(f"下载超过 {max_elapsed:g} 秒总时限：{url}")
                    output.write(chunk)
                    digest.update(chunk)
        partial.replace(destination)
    except OSError as exc:
        partial.unlink(missing_ok=True)
        raise ConnectionError(f"无法下载 {url}：{exc}") from exc
    except BaseException:
        partial.unlink(missing_ok=True)
        raise

    streamed_digest = digest.hexdigest()
    with destination.open("rb") as downloaded_file:
        stored_digest = hashlib.file_digest(downloaded_file, "sha256").hexdigest()
    if stored_digest != streamed_digest:
        destination.unlink(missing_ok=True)
        raise OSError(f"下载文件写入后的 SHA-256 发生变化：{destination}")
    return stored_digest


def run_command(
    command: Command,
    *,
    cwd: Path,
    env: Mapping[str, str],
) -> None:
    """Run one external command without a shell, retaining output only on failure."""
    argv = tuple(str(argument) for argument in command)
    subprocess.run(
        argv,
        cwd=cwd,
        env=dict(env),
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
