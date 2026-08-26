"""Local and privileged preflight checks for declarative deployment."""

import importlib.metadata
import importlib.util
import json
import math
import os
import platform
import ssl
import stat
import sys
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

from jsonschema import Draft202012Validator
from misc import (
    BIN_PATH,
    CONF_PATH,
    DATA_PATH,
    PROJECT_ROOT,
    STATS_PATH,
    UNIT_DIRECTORY,
    UNIT_PATH,
    git_source_files,
    write_private_file,
)
from privilege import PrivilegeRunner
from referencing import Registry, Resource

MAX_CONFIG_BYTES = 4 * 1024 * 1024
RUST_DISTRIBUTION_URL = "https://static.rust-lang.org/dist/channel-rust-stable.toml.sha256"
CRATES_IO_CONFIG_URL = "https://index.crates.io/config.json"
PYPI_PROJECTS = ("certifi", "jsonschema", "referencing")
SERVICE_UNIT = "nvme-disk-mon.service"


@dataclass(frozen=True, slots=True)
class GeneralSection:
    schema_version: int
    wdir: Path


@dataclass(frozen=True, slots=True)
class DeploySection:
    ndm_cfg: Path
    enable_doc: bool


@dataclass(frozen=True, slots=True)
class InstallSection:
    doc_path: Path
    systemd_integration: bool


@dataclass(frozen=True, slots=True)
class PostInstallSection:
    send_test_mail: bool
    clean: str
    daemon: str


@dataclass(frozen=True, slots=True)
class DeploymentConfig:
    source_path: Path
    general: GeneralSection
    deploy: DeploySection
    install: InstallSection
    post_install: PostInstallSection


@dataclass(frozen=True, slots=True)
class LocalPreflight:
    config: DeploymentConfig
    deploy_document: Mapping[str, object]
    ndm_document: Mapping[str, object]
    ndm_bytes: bytes
    device_paths: tuple[Path, ...]
    source_files: tuple[Path, ...]
    smtp_auth_method: str


@dataclass(frozen=True, slots=True)
class PrivilegedPreflight:
    service_active: bool
    mount_targets: tuple[Path, ...]


@dataclass(frozen=True, slots=True)
class RootStat:
    mode: int
    uid: int
    gid: int
    permissions: int
    links: int


def _read_bounded(path: Path, *, allow_symlink: bool = False) -> bytes:
    metadata = path.stat() if allow_symlink else path.stat(follow_symlinks=False)
    if not stat.S_ISREG(metadata.st_mode) or (not allow_symlink and path.is_symlink()):
        raise ValueError(f"配置路径必须是实体普通文件：{path}")
    if metadata.st_size > MAX_CONFIG_BYTES:
        raise ValueError(f"配置文件超过 {MAX_CONFIG_BYTES} 字节：{path}")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if not allow_symlink:
        flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb", closefd=True) as source:
        contents = source.read(MAX_CONFIG_BYTES + 1)
    if len(contents) > MAX_CONFIG_BYTES:
        raise ValueError(f"配置文件超过 {MAX_CONFIG_BYTES} 字节：{path}")
    return contents


def _parse_toml(path: Path, contents: bytes) -> Mapping[str, object]:
    try:
        document = tomllib.loads(contents.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ValueError(f"配置文件不是有效的 UTF-8 TOML：{path}：{exc}") from exc
    if not isinstance(document, dict):
        raise ValueError(f"TOML 顶层必须是 table：{path}")
    return document


def _load_json(path: Path) -> Mapping[str, Any]:
    try:
        with path.open("rb") as source:
            document = json.load(source)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"约束文件不是有效 JSON：{path}：{exc}") from exc
    if not isinstance(document, dict):
        raise ValueError(f"约束文件顶层必须是对象：{path}")
    return document


def _schema_registry(project_root: Path) -> tuple[Registry, Mapping[str, Any], Mapping[str, Any]]:
    packaging = project_root / "packaging"
    common = _load_json(packaging / "config-common.types.schema.json")
    deploy = _load_json(packaging / "deploy-config.constraints.schema.json")
    ndm = _load_json(packaging / "ndm-config.constraints.schema.json")
    for schema in (common, deploy, ndm):
        Draft202012Validator.check_schema(schema)
        identifier = schema.get("$id")
        if not isinstance(identifier, str) or not identifier:
            raise ValueError("约束文件缺少非空 $id")
    registry = Registry().with_resources(
        (str(schema["$id"]), Resource.from_contents(schema)) for schema in (common, deploy, ndm)
    )
    return registry, deploy, ndm


def _validate_schema(
    document: Mapping[str, object],
    schema: Mapping[str, Any],
    registry: Registry,
    label: str,
) -> None:
    validator = Draft202012Validator(schema, registry=registry)
    errors = sorted(
        validator.iter_errors(document),
        key=lambda item: tuple(str(part) for part in item.absolute_path),
    )
    if errors:
        details = []
        for error in errors[:8]:
            path = ".".join(str(part) for part in error.absolute_path) or "<root>"
            details.append(f"{path}: {error.message}")
        if len(errors) > 8:
            details.append(f"另有 {len(errors) - 8} 项错误")
        raise ValueError(f"{label}不满足约束：{'；'.join(details)}")


def _as_table(document: Mapping[str, object], key: str) -> Mapping[str, object]:
    value = document.get(key)
    if not isinstance(value, dict):
        raise ValueError(f"配置 section {key} 必须是 table")
    return value


def _as_path(table: Mapping[str, object], key: str) -> Path:
    value = table.get(key)
    if not isinstance(value, str):
        raise ValueError(f"配置项 {key} 必须是字符串路径")
    return Path(value)


def deployment_config(path: Path, document: Mapping[str, object]) -> DeploymentConfig:
    general = _as_table(document, "general")
    deploy = _as_table(document, "deploy")
    install = _as_table(document, "install")
    post_install = _as_table(document, "post-install")
    return DeploymentConfig(
        source_path=path,
        general=GeneralSection(
            schema_version=int(general["schema_version"]),
            wdir=_as_path(general, "wdir"),
        ),
        deploy=DeploySection(
            ndm_cfg=_as_path(deploy, "ndm_cfg"),
            enable_doc=bool(deploy["enable_doc"]),
        ),
        install=InstallSection(
            doc_path=_as_path(install, "doc_path"),
            systemd_integration=bool(install["systemd_integration"]),
        ),
        post_install=PostInstallSection(
            send_test_mail=bool(post_install["send_test_mail"]),
            clean=str(post_install["clean"]),
            daemon=str(post_install["daemon"]),
        ),
    )


def check_runtime(project_root: Path) -> None:
    if platform.system() != "Linux":
        raise OSError("部署系统只支持 Linux")
    if sys.version_info < (3, 14):  # noqa: UP036 - the brief requires a runtime guard
        raise RuntimeError(
            "部署系统要求项目 .venv/venv 中的 Python 3.14 或更高版本；"
            "请从仓库根目录使用 .venv/bin/python 启动"
        )
    current_prefix = Path(sys.prefix).resolve()
    if current_prefix == Path(sys.base_prefix).resolve():
        raise RuntimeError("部署系统必须由项目级虚拟环境运行")
    allowed = {(project_root / name).resolve() for name in (".venv", "venv")}
    if current_prefix not in allowed:
        raise RuntimeError("部署系统必须由当前源码树的 .venv 或 venv 解释器运行")
    jit = getattr(sys, "_jit", None)
    if jit is None or not jit.is_available() or not jit.is_enabled():
        print("提示：当前 Python JIT 未启用，部署继续执行", file=sys.stderr)


def check_dependencies(project_root: Path) -> None:
    pyproject_path = project_root / "scripts" / "deploy-sys" / "pyproject.toml"
    with pyproject_path.open("rb") as source:
        pyproject = tomllib.load(source)
    project = pyproject.get("project")
    if not isinstance(project, dict) or not isinstance(project.get("dependencies"), list):
        raise ValueError(f"部署系统 pyproject 缺少 dependencies：{pyproject_path}")
    prefix = Path(sys.prefix).resolve()
    for requirement in project["dependencies"]:
        if not isinstance(requirement, str) or requirement.count("==") != 1:
            raise ValueError(f"部署依赖必须使用单一精确版本：{requirement!r}")
        name, expected = requirement.split("==", 1)
        try:
            distribution = importlib.metadata.distribution(name)
        except importlib.metadata.PackageNotFoundError as exc:
            raise ModuleNotFoundError(f"项目 venv 缺少部署依赖：{name}") from exc
        actual = distribution.version
        if actual != expected:
            raise RuntimeError(f"部署依赖 {name} 需要 {expected}，当前为 {actual}")
        origin = Path(distribution.locate_file("")).resolve()
        if not origin.is_relative_to(prefix):
            raise RuntimeError(f"部署依赖 {name} 未从当前项目 venv 导入：{origin}")
        if importlib.util.find_spec(name.replace("-", "_")) is None:
            raise ModuleNotFoundError(f"项目 venv 无法导入部署依赖：{name}")


def _has_access(path: Path, mode: int, *, follow_symlinks: bool = False) -> bool:
    return os.access(path, mode, effective_ids=True, follow_symlinks=follow_symlinks)


def _require_executable_filesystem(path: Path) -> None:
    noexec = getattr(os, "ST_NOEXEC", None)
    if noexec is None:
        raise RuntimeError("当前 Linux Python 未提供 ST_NOEXEC，无法验证 WDIR 文件系统")
    if os.statvfs(path).f_flag & noexec:
        raise PermissionError(f"工作目录所在文件系统禁止执行文件：{path}")


def _validate_workdir(workdir: Path) -> None:
    if not workdir.is_absolute():
        raise ValueError(f"general.wdir 必须是绝对路径：{workdir}")
    normalized = Path(os.path.normpath(str(workdir)))
    if normalized != workdir or workdir.resolve(strict=False) != workdir:
        raise ValueError(f"general.wdir 必须是无符号链接的规范路径：{workdir}")
    if workdir.exists() or workdir.is_symlink():
        raise FileExistsError(f"general.wdir 必须尚不存在：{workdir}")
    parent = workdir.parent
    metadata = parent.stat(follow_symlinks=False)
    if not stat.S_ISDIR(metadata.st_mode) or parent.is_symlink():
        raise NotADirectoryError(f"WDIR 直接上级必须是实体目录：{parent}")
    if parent.resolve(strict=True) != parent:
        raise ValueError(f"WDIR 直接上级不能经过符号链接：{parent}")
    if metadata.st_uid not in {0, os.geteuid()}:
        raise PermissionError(f"WDIR 上级必须由 root 或控制器所有：{parent}")
    if not _has_access(parent, os.R_OK | os.W_OK | os.X_OK):
        raise PermissionError(f"控制器对 WDIR 上级需要 R、W、X 权限：{parent}")
    permissions = stat.S_IMODE(metadata.st_mode)
    if permissions & 0o022 and not permissions & stat.S_ISVTX:
        raise PermissionError(f"可由其他 UID 写入的 WDIR 上级必须设置 sticky bit：{parent}")
    _require_executable_filesystem(parent)


def _validated_device_paths(document: Mapping[str, object]) -> tuple[Path, ...]:
    devices = _as_table(document, "device").get("disk_list")
    if not isinstance(devices, list):
        raise ValueError("device.disk_list 必须是数组")
    seen_paths: set[str] = set()
    paths: list[Path] = []
    for index, entry in enumerate(devices):
        if not isinstance(entry, dict):
            raise ValueError(f"device.disk_list[{index}] 必须是 table")
        raw_path = entry.get("path")
        if not isinstance(raw_path, str):
            raise ValueError(f"device.disk_list[{index}].path 必须是路径")
        if raw_path in seen_paths:
            raise ValueError(f"device.disk_list 中存在重复 path：{raw_path}")
        seen_paths.add(raw_path)
        device = Path(raw_path)
        if device.parts[:4] != ("/", "dev", "disk", "by-id") or len(device.parts) != 5:
            raise ValueError(f"监视设备必须是 /dev/disk/by-id 下的直接路径：{device}")
        paths.append(device)
    return tuple(paths)


def _validate_ndm_semantics(document: Mapping[str, object]) -> str:
    def walk(value: object, path: str) -> None:
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError(f"配置数值必须为有限数：{path}")
        if isinstance(value, dict):
            for key, child in value.items():
                walk(child, f"{path}.{key}" if path else str(key))
        elif isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, f"{path}[{index}]")

    walk(document, "")
    writer_rank = _as_table(document, "writer_rank")
    rank_length = writer_rank.get("rank_length")
    if isinstance(rank_length, int) and rank_length > (1 << 63) - 1:
        raise ValueError("writer_rank.rank_length 必须可表示为 SQLite INTEGER")
    devices = _as_table(document, "device").get("disk_list")
    if isinstance(devices, list):
        for index, entry in enumerate(devices):
            if not isinstance(entry, dict):
                continue
            hours = entry.get("detect_window_hr")
            if isinstance(hours, int) and hours > min((1 << 64) - 1, ((1 << 32) - 1) // 60):
                raise ValueError(f"device.disk_list[{index}].detect_window_hr 超出运行时可表示范围")
    method = _as_table(document, "mail").get("smtp_auth_method")
    if method not in {"PLAIN", "XOAUTH2", "OAUTHBEARER"}:
        raise ValueError("mail.smtp_auth_method 无效")
    recipients = _as_table(document, "mail").get("send_to")
    if isinstance(recipients, list):
        canonical = [str(recipient).casefold() for recipient in recipients]
        if len(canonical) != len(set(canonical)):
            raise ValueError("mail.send_to 包含大小写归一后重复的邮箱地址")
    return str(method)


def _fetch_endpoint(url: str, *, max_bytes: int) -> bytes:
    import certifi

    request = Request(
        url,
        headers={"Connection": "close", "User-Agent": "nvme-disk-mon-deploy-system/0.2"},
    )
    context = ssl.create_default_context(cafile=certifi.where())
    with urlopen(request, context=context, timeout=15) as response:
        final_url = response.geturl()
        if not isinstance(final_url, str) or not final_url.startswith("https://"):
            raise ConnectionError(f"HTTPS 端点发生协议降级：{url}")
        if getattr(response, "status", 200) != 200:
            raise ConnectionError(f"HTTPS 端点返回状态 {response.status}：{url}")
        contents = response.read(max_bytes + 1)
    if len(contents) > max_bytes:
        raise ValueError(f"预检端点响应过大：{url}")
    return contents


def check_network() -> None:
    checksum = _fetch_endpoint(RUST_DISTRIBUTION_URL, max_bytes=4096).split(maxsplit=1)[0]
    if len(checksum) != 64 or any(byte not in b"0123456789abcdefABCDEF" for byte in checksum):
        raise ValueError("Rust stable 分发端点返回无效 SHA-256")
    crates = json.loads(_fetch_endpoint(CRATES_IO_CONFIG_URL, max_bytes=64 * 1024))
    if not isinstance(crates, dict) or not str(crates.get("dl", "")).startswith("https://"):
        raise ValueError("crates.io sparse index 配置无效")
    for project in PYPI_PROJECTS:
        response = _fetch_endpoint(
            f"https://pypi.org/simple/{project}/",
            max_bytes=4 * 1024 * 1024,
        )
        if project.encode("ascii") not in response.lower():
            raise ValueError(f"PyPI {project} 索引响应无效")


def run_local_preflight(
    config_path: Path,
    project_root: Path = PROJECT_ROOT,
    *,
    live_network: bool = True,
) -> LocalPreflight:
    """Validate all caller-visible facts without sudo or target mutations."""
    check_runtime(project_root)
    check_dependencies(project_root)
    resolved_config = config_path.expanduser().resolve(strict=True)
    if resolved_config.suffix.lower() != ".toml":
        raise ValueError(f"部署配置必须使用 .toml 后缀：{resolved_config}")
    deploy_bytes = _read_bounded(resolved_config, allow_symlink=True)
    deploy_document = _parse_toml(resolved_config, deploy_bytes)
    registry, deploy_schema, ndm_schema = _schema_registry(project_root)
    _validate_schema(deploy_document, deploy_schema, registry, "部署配置")
    config = deployment_config(resolved_config, deploy_document)
    if not config.install.systemd_integration and config.post_install.daemon != "none":
        raise ValueError("install.systemd_integration=false 时 post-install.daemon 必须为 none")
    _validate_workdir(config.general.wdir)

    ndm_path = config.deploy.ndm_cfg
    if not ndm_path.is_absolute():
        raise ValueError(f"deploy.ndm_cfg 必须是绝对路径：{ndm_path}")
    if not _has_access(ndm_path, os.R_OK):
        raise PermissionError(f"控制器不能读取 deploy.ndm_cfg：{ndm_path}")
    ndm_bytes = _read_bounded(ndm_path)
    ndm_document = _parse_toml(ndm_path, ndm_bytes)
    _validate_schema(ndm_document, ndm_schema, registry, "NDM 配置")
    smtp_auth_method = _validate_ndm_semantics(ndm_document)
    device_paths = _validated_device_paths(ndm_document)

    source_files = git_source_files(project_root)
    if config.deploy.enable_doc and Path("docs/index.html") not in source_files:
        raise FileNotFoundError("启用文档构建时源码快照必须包含 docs/index.html")
    if live_network:
        check_network()
    return LocalPreflight(
        config=config,
        deploy_document=deploy_document,
        ndm_document=ndm_document,
        ndm_bytes=ndm_bytes,
        device_paths=device_paths,
        source_files=source_files,
        smtp_auth_method=smtp_auth_method,
    )


def _root_stat(
    runner: PrivilegeRunner,
    path: Path,
    *,
    dereference: bool = False,
) -> RootStat | None:
    command = ["/usr/bin/stat"]
    if dereference:
        command.append("--dereference")
    command.extend(("--format=%f:%u:%g:%a:%h", "--", str(path)))
    result = runner.run(
        tuple(command),
        check=False,
        capture_output=True,
    )
    if result.returncode == 1:
        return None
    if result.returncode != 0:
        raise OSError(f"root stat 失败：{path}（状态 {result.returncode}）")
    fields = result.stdout.strip().split(":")
    if len(fields) != 5:
        raise ValueError(f"root stat 返回格式无效：{path}")
    return RootStat(
        mode=int(fields[0], 16),
        uid=int(fields[1]),
        gid=int(fields[2]),
        permissions=int(fields[3], 8),
        links=int(fields[4]),
    )


def _validate_ndm_devices(runner: PrivilegeRunner, device_paths: tuple[Path, ...]) -> None:
    for device in device_paths:
        metadata = _root_stat(runner, device, dereference=True)
        if metadata is None or not stat.S_ISBLK(metadata.mode):
            raise ValueError(f"监视设备路径解析后必须是块设备：{device}")
        readable = runner.run(
            ("/usr/bin/test", "-r", str(device)),
            check=False,
            capture_output=True,
        )
        if readable.returncode != 0:
            raise PermissionError(f"root 不能读取监视设备：{device}")


def _trusted_root_directory(runner: PrivilegeRunner, path: Path, *, writable: bool) -> None:
    if not path.is_absolute() or Path(os.path.normpath(str(path))) != path:
        raise ValueError(f"root 目录必须是规范绝对路径：{path}")
    ancestors = [path]
    ancestors.extend(path.parents)
    for current in reversed(ancestors):
        metadata = _root_stat(runner, current)
        if metadata is None or not stat.S_ISDIR(metadata.mode):
            raise NotADirectoryError(f"root 目标路径必须经过实体目录：{current}")
        if metadata.uid != 0 or metadata.gid != 0:
            raise PermissionError(f"root 目标路径必须由 root:root 所有：{current}")
        if metadata.permissions & 0o022:
            raise PermissionError(f"root 目标路径不能允许 group/other 写入：{current}")
    conditions = ["-d", "-r", "-x"]
    if writable:
        conditions.append("-w")
    for condition in conditions:
        result = runner.run(
            ("/usr/bin/test", condition, str(path)),
            check=False,
            capture_output=True,
        )
        if result.returncode != 0:
            raise PermissionError(f"root 目标目录不满足 {condition}：{path}")


def _trusted_existing_file(runner: PrivilegeRunner, path: Path) -> None:
    metadata = _root_stat(runner, path)
    if metadata is None:
        return
    if not stat.S_ISREG(metadata.mode) or metadata.links != 1:
        raise ValueError(f"已有安装文件必须是单链接实体普通文件：{path}")
    if metadata.uid != 0 or metadata.gid != 0:
        raise PermissionError(f"已有安装文件必须由 root:root 所有：{path}")
    if metadata.permissions & 0o022:
        raise PermissionError(f"已有安装文件不能允许 group/other 写入：{path}")


def _mount_targets(runner: PrivilegeRunner) -> tuple[Path, ...]:
    result = runner.run(
        ("/usr/bin/findmnt", "--json", "--output", "TARGET"),
        capture_output=True,
    )
    document = json.loads(result.stdout)
    roots = document.get("filesystems") if isinstance(document, dict) else None
    if not isinstance(roots, list):
        raise ValueError("findmnt 未返回 filesystems 数组")
    output: list[Path] = []

    def visit(nodes: list[object]) -> None:
        for node in nodes:
            if not isinstance(node, dict) or not isinstance(node.get("target"), str):
                raise ValueError("findmnt 返回无效挂载项")
            output.append(Path(os.path.normpath(node["target"])))
            children = node.get("children", [])
            if not isinstance(children, list):
                raise ValueError("findmnt children 字段无效")
            visit(children)

    visit(roots)
    return tuple(output)


def _reject_mount_boundary(target: Path, mounts: tuple[Path, ...]) -> None:
    for mount in mounts:
        if mount == target or mount.is_relative_to(target):
            raise PermissionError(f"递归安装/清理目标不能是挂载点或包含子挂载：{target} -> {mount}")


def _systemd_facts(runner: PrivilegeRunner) -> bool:
    runner.run(
        ("/usr/bin/systemctl", "--system", "show", "--property=Version", "--value"),
        capture_output=True,
    )
    unit_paths = runner.run(
        ("/usr/bin/systemctl", "--system", "show", "--property=UnitPath", "--value"),
        capture_output=True,
    ).stdout.split()
    if str(UNIT_DIRECTORY) not in unit_paths:
        raise RuntimeError(f"运行中的 systemd manager 未搜索固定 unit 目录：{UNIT_DIRECTORY}")

    for shadow in (
        Path("/etc/systemd/system") / SERVICE_UNIT,
        Path("/run/systemd/system") / SERVICE_UNIT,
    ):
        if _root_stat(runner, shadow) is not None:
            raise RuntimeError(f"固定 unit 被更高优先级文件或 mask 遮蔽：{shadow}")

    search_roots = tuple(
        path
        for path in (
            Path("/etc/systemd/system"),
            Path("/run/systemd/system"),
            Path("/usr/local/lib/systemd/system"),
            Path("/usr/lib/systemd/system"),
        )
        if (metadata := _root_stat(runner, path)) is not None and stat.S_ISDIR(metadata.mode)
    )
    dropins = (
        runner.run(
            (
                "/usr/bin/find",
                *search_roots,
                "-path",
                "*/nvme-disk-mon.service.d/*.conf",
                "-print",
            ),
            capture_output=True,
        ).stdout.splitlines()
        if search_roots
        else []
    )
    if dropins:
        raise RuntimeError(f"检测到部署外 systemd drop-in：{', '.join(dropins)}")

    result = runner.run(
        (
            "/usr/bin/systemctl",
            "--system",
            "show",
            SERVICE_UNIT,
            "--property=LoadState",
            "--property=FragmentPath",
            "--property=DropInPaths",
            "--property=ActiveState",
        ),
        check=False,
        capture_output=True,
    )
    facts = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    if facts.get("LoadState") == "masked":
        raise RuntimeError(f"systemd unit 已被 mask：{SERVICE_UNIT}")
    fragment = facts.get("FragmentPath", "")
    if fragment and Path(fragment) != UNIT_PATH:
        raise RuntimeError(f"systemd 当前加载了部署外 unit：{fragment}")
    if facts.get("DropInPaths", "").strip():
        raise RuntimeError(f"systemd 当前加载了部署外 drop-in：{facts['DropInPaths']}")
    return facts.get("ActiveState") in {"active", "activating", "reloading"}


def run_privileged_preflight(
    runner: PrivilegeRunner,
    local: LocalPreflight,
) -> PrivilegedPreflight:
    """Read root-only host facts after registration and before WDIR creation."""
    _validate_ndm_devices(runner, local.device_paths)
    _trusted_root_directory(runner, BIN_PATH.parent, writable=True)
    _trusted_root_directory(runner, Path("/etc"), writable=True)
    _trusted_root_directory(runner, Path("/usr/local/lib"), writable=True)
    _trusted_existing_file(runner, BIN_PATH)
    if local.config.deploy.enable_doc:
        _trusted_root_directory(runner, local.config.install.doc_path, writable=True)
        doc_target = local.config.install.doc_path / "nvme-disk-mon"
        if _root_stat(runner, doc_target) is not None:
            _trusted_root_directory(runner, doc_target, writable=True)

    data_metadata = _root_stat(runner, DATA_PATH)
    if data_metadata is not None:
        _trusted_root_directory(runner, DATA_PATH, writable=True)
        if not stat.S_ISDIR(data_metadata.mode):
            raise NotADirectoryError(f"固定 data_path 必须是实体目录：{DATA_PATH}")
        if data_metadata.uid != 0 or data_metadata.gid != 0:
            raise PermissionError(f"固定 data_path 必须由 root:root 所有：{DATA_PATH}")
        if data_metadata.permissions & 0o077:
            raise PermissionError(f"固定 data_path 不能向 group/other 开放：{DATA_PATH}")
    stats_metadata = _root_stat(runner, STATS_PATH)
    if stats_metadata is not None:
        if not stat.S_ISREG(stats_metadata.mode) or stats_metadata.links != 1:
            raise ValueError(f"已有 stats.db 必须是单链接普通文件：{STATS_PATH}")
        if stats_metadata.uid != 0 or stats_metadata.gid != 0:
            raise PermissionError(f"已有 stats.db 必须由 root:root 所有：{STATS_PATH}")
        if stats_metadata.permissions & 0o077:
            raise PermissionError(f"已有 stats.db 不能向 group/other 开放：{STATS_PATH}")

    mounts = _mount_targets(runner)
    _reject_mount_boundary(DATA_PATH, mounts)
    if local.config.deploy.enable_doc:
        _reject_mount_boundary(
            local.config.install.doc_path / "nvme-disk-mon",
            mounts,
        )
    for file_target in (BIN_PATH, CONF_PATH, UNIT_PATH):
        if file_target in mounts:
            raise PermissionError(f"安装文件目标不能是挂载点：{file_target}")

    service_active = False
    if local.config.install.systemd_integration:
        if _root_stat(runner, UNIT_DIRECTORY) is None:
            _trusted_root_directory(runner, UNIT_DIRECTORY.parent, writable=True)
        else:
            _trusted_root_directory(runner, UNIT_DIRECTORY, writable=True)
        _trusted_existing_file(runner, UNIT_PATH)
        service_active = _systemd_facts(runner)
    return PrivilegedPreflight(service_active=service_active, mount_targets=mounts)


def _toml_string(value: Path | str) -> str:
    return json.dumps(str(value), ensure_ascii=True)


def remapped_config_text(config: DeploymentConfig, ndm_config: Path) -> str:
    return "\n".join(
        (
            "[general]",
            f"schema_version = {config.general.schema_version}",
            f"wdir = {_toml_string(config.general.wdir)}",
            "",
            "[deploy]",
            f"ndm_cfg = {_toml_string(ndm_config)}",
            f"enable_doc = {str(config.deploy.enable_doc).lower()}",
            "",
            "[install]",
            f"doc_path = {_toml_string(config.install.doc_path)}",
            f"systemd_integration = {str(config.install.systemd_integration).lower()}",
            "",
            "[post-install]",
            f"send_test_mail = {str(config.post_install.send_test_mail).lower()}",
            f"clean = {_toml_string(config.post_install.clean)}",
            f"daemon = {_toml_string(config.post_install.daemon)}",
            "",
        )
    )


def stage_configs(local: LocalPreflight, workdir: Path) -> Path:
    metadata = workdir / ".ndm-deploy"
    ndm_destination = metadata / "ndm-config.toml"
    original_deploy = metadata / "deploy-input.toml"
    remapped_deploy = metadata / "deploy.toml"
    write_private_file(ndm_destination, local.ndm_bytes)
    write_private_file(original_deploy, _read_bounded(local.config.source_path, allow_symlink=True))
    write_private_file(
        remapped_deploy,
        remapped_config_text(local.config, ndm_destination).encode("utf-8"),
    )
    if ndm_destination.read_bytes() != local.ndm_bytes:
        raise OSError("WDIR 中的 NDM 配置与本地预检缓冲区不一致")
    return ndm_destination
