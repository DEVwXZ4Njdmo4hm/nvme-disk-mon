# nvme-disk-mon

`nvme-disk-mon` 是一个以 Rust 编写的长期运行服务。它持续核验 NVMe 设备身份与
SMART 写入计数，记录 SQLite 历史，统计 cgroup 写入者，并在写入量越过配置阈值时通过
SMTP 发送告警。

程序支持多块 NVMe 设备。每块设备使用 `/dev/disk/by-id` 下的稳定路径和预期序列号共同
识别；设备路径解析出的块设备、namespace 编号和序列号不一致时，监视任务失败关闭。

## 项目环境

Python 工具只允许从仓库根目录的 `.venv` 或 `venv` 运行，最低版本为 Python 3.14。安装
锁定依赖：

```bash
.venv/bin/python -m pip install -r requirements.txt
```

Rust 构建使用项目级构建脚本。构建目录必须预先创建、为空且对调用者可读写执行：

```bash
mkdir -m 0700 build/local-debug
.venv/bin/python scripts/build-script/src/main.py \
  -S "$PWD" \
  -B "$PWD/build/local-debug" \
  -T Debug
```

脚本在 `-B` 指定的目录内下载并校验 `rustup-init`，安装隔离的 stable 工具链，以
`--locked` 获取依赖，再用 `--locked --offline` 构建。使用 `--doc` 同时以
`cargo doc --no-deps` 生成当前项目的 Rustdoc，并把 [HTML5 命令参考](docs/index.html)
渲染为文档目标的 `index.html`；`--init-only` 只初始化工具链和依赖。

## NDM 配置

[配置示例](packaging/config.example.toml)和
[约束文件](packaging/ndm-config.constraints.schema.json)描述当前 schema version 1。
配置包含：

- `general.schema_version`；
- `device.host` 和至少一项 `device.disk_list`；
- `writer_rank.rank_length`；
- SMTP 主机、端口、TLS、认证方式、认证字段、发件人与收件人；
- `XOAUTH2` 或 `OAUTHBEARER` 使用的 OAuth metadata URL、scope 与可选授权参数。

部署系统在构建前完成 schema、语义与文件系统预检。NDM 运行时从固定路径
`/etc/nvme-disk-mon/ndm-cfg.toml` 读取一次原始字节，先核对构建时内嵌的 SHA-256，再完成
运行所需的 UTF-8、TOML 解析和类型构造。安装后直接修改配置会导致摘要不一致；配置变更
需要重新部署。

固定运行时路径为：

| 名称 | 路径 |
| --- | --- |
| 二进制 | `/usr/local/bin/nvme-disk-mon` |
| 数据目录 | `/etc/nvme-disk-mon/` |
| NDM 配置 | `/etc/nvme-disk-mon/ndm-cfg.toml` |
| 状态数据库 | `/etc/nvme-disk-mon/stats.db` |
| OAuth token cache | `/etc/nvme-disk-mon/oauth_token.json` |

daemon 的数据库写者在启动时执行一次 WAL checkpoint。SQLite 会将 WAL 中已经提交但尚未
写回主数据库的页写回 `stats.db` 并清空 WAL；checkpoint 受阻或失败时，daemon 启动失败。

## 命令行

不带子命令时，程序以前台 daemon 方式运行。其它命令为：

```text
nvme-disk-mon help
nvme-disk-mon version
nvme-disk-mon stats
nvme-disk-mon mail authorize
nvme-disk-mon mail validate
nvme-disk-mon mail test-send
```

`mail authorize` 只用于 `XOAUTH2` 和 `OAUTHBEARER`；`mail validate` 建立新的已认证
SMTP 会话；`mail test-send` 提交一封测试邮件。所有读取配置的命令都执行同一份摘要合同。

## 声明式部署系统

部署合同以 [deploy-system-brief.md](deploy-system-brief.md) 为准。仓库根入口为
[deploy.py](deploy.py)，实现位于 [`scripts/deploy-sys`](scripts/deploy-sys)。调用时只接受
一个现存 TOML 文件：

```bash
.venv/bin/python deploy.py /absolute/path/to/deploy.toml
```

`sudo python deploy.py ...`可能选择root环境中的旧版主机解释器。通常应由普通用户执行上述
命令，让控制器在本地预检后自行请求固定sudo授权；确需以EUID 0启动时，应显式传入项目
venv解释器的绝对路径。

`--help` 只显示用法。控制器保持启动时 EUID，不因调用者是否为 root 改变安装模式。非
root 控制器在本地预检完成后，先运行固定授权探针：

```text
/usr/bin/sudo -H -u root -- /usr/bin/true
```

每个后续 root 动作仍使用自己的固定绝对命令和同一 sudo 前缀。部署器不执行 shell，
不请求保留调用者环境，不生成 sudoers、PAM 或 SELinux 配置，也不提供其它提权机制。

部署配置 schema version 1 的字段为：

```toml
[general]
schema_version = 1
wdir = "/absolute/nonexistent/wdir"

[deploy]
ndm_cfg = "/absolute/path/to/ndm-config.toml"
enable_doc = true

[install]
doc_path = "/usr/local/share/doc"
systemd_integration = true

[post-install]
send_test_mail = true
clean = "always"
daemon = "none"
```

完整示例和 schema 分别位于
[packaging/deploy.example.toml](packaging/deploy.example.toml) 与
[packaging/deploy-config.constraints.schema.json](packaging/deploy-config.constraints.schema.json)。
`clean` 可选 `none`、`except-fail`、`always`；启用 systemd 集成时，`daemon` 可选
`none`、`start-only`、`enable-only`、`enable-and-start`。

部署过程先完成所有调用者可见的配置、设备路径形式、源码、网络与 WDIR 预检，再请求
root 授权。设备节点是否解析为块设备及 root 可读性在授权后由固定的只读命令检查。固定
`/run/ndm-deploy-sys` 目录提供跨调用 UID 的全局互斥。取得注册后，部署器只用固定只读
root 命令检查安装目录、挂载边界、已有 `stats.db` 及其 WAL/SHM 伴随文件和 systemd
manager；这些检查完成前不会创建 WDIR 或修改持久化目标。

源码选择遵循 Git 和根 `.gitignore`，并排除工作树中已经删除的 tracked 文件。控制器创建
mode `0700` 的 WDIR，暂存两份配置，创建 WDIR 项目 venv，确认 NDM 配置仍与本地预检的
原始字节相同，把 SHA-256 写入 WDIR 的 `CONF_FILE_CHECKSUM`，然后调用项目构建脚本执行
固定 Release 构建。Python 控制流始终留在原控制器进程中，WDIR venv 和构建脚本也不会
作为 sudo 目标执行。

安装阶段保留旧数据目录中的 `stats.db`、`stats.db-wal` 和 `stats.db-shm`，由 daemon
下次启动时完成 WAL 恢复；其余文件按当前部署重新生成。二进制、配置、HTML 命令参考、
Rustdoc 和可选 unit 都从明确的 WDIR 产物通过逐条 root 命令安装；文档
首页固定为 `doc_path/nvme-disk-mon/index.html`。每次文档安装先清空这个项目专属目录，旧版
依赖 crate 页面不会残留。启用 systemd 时，
[service 模板](packaging/templates/nvme-disk-mon.service.template)渲染到
`/usr/local/lib/systemd/system/nvme-disk-mon.service`；部署器执行 `daemon-reload`，再核对
manager 的 `FragmentPath` 和 `DropInPaths`。

邮件认证由已安装的 NDM 执行。`XOAUTH2` 与 `OAUTHBEARER` 依次执行 `mail authorize`、
`mail validate`；`PLAIN` 只执行 `mail validate`。随后按配置执行可选的
`mail test-send` 与 service enable/start 动作。正常退出和已捕获的失败路径都会尝试释放
全局注册；WDIR 是否删除只由 `post-install.clean` 决定。

## 测试

部署系统和构建脚本测试：

```bash
.venv/bin/python -m unittest discover -s scripts/deploy-sys/tests -v
.venv/bin/python -m unittest discover -s scripts/build-script/tests -v
```

Rust 检查应使用仓库的项目级 Rust 环境：

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked --offline -- -D warnings
cargo test --all-targets --locked --offline
```

生产安装、交互式 OAuth、真实 NVMe、systemd start/enable 和 SMTP 投递会修改目标主机或依赖
外部服务，应在专用目标环境中单独验收。
