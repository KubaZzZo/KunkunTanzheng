# Server Probe

## 中文

Server Probe 是一个面向最多 50 台 Linux 服务器的自托管监控 MVP。每个 Agent 每 30 秒通过出站 HTTPS 上报一次，中心服务将原始采样数据存入 SQLite，并提供中文监控界面。界面显示 CPU、内存、根目录磁盘、网络流量速率，以及最近 24 小时的流量累计值。

系统的公网入口经过严格限制：只有 Caddy 发布 TCP 443。Probe Server 和 SQLite 数据库仅存在于 Compose 私有网络中。系统不提供远程命令、Agent 入站监听器、公开状态页或多用户账户。

### 构建与测试

仓库固定使用 Go 1.25.13。在本工作站上，请使用 `D:\CodeTools\Go\go\bin\go.exe` 并设置 `GOTOOLCHAIN=go1.25.13`；Go 命令会将固定工具链下载到本地缓存中。

```powershell
$env:GOTOOLCHAIN = 'go1.25.13'
& 'D:\CodeTools\Go\go\bin\go.exe' test ./...
& 'D:\CodeTools\Go\go\bin\go.exe' vet ./...
```

在可信构建主机上，为目标架构构建 Linux Agent：

```powershell
$env:GOOS = 'linux'
$env:GOARCH = 'amd64'
& 'D:\CodeTools\Go\go\bin\go.exe' build -trimpath -ldflags='-s -w' -o probe-agent ./cmd/probe-agent
```

ARM64 主机请使用 `GOARCH=arm64`。

### 部署中心服务

为三个不同的域名创建 DNS `A` 或 `AAAA` 记录，并全部指向运行 Compose 的主机：

- `monitor.tanzhen.zhuoruan.xyz`
- `ingest.tanzhen.zhuoruan.xyz`
- `enroll.tanzhen.zhuoruan.xyz`

在 Cloudflare 中创建三个指向 Compose 主机的 DNS 记录。监控地址为 `https://monitor.tanzhen.zhuoruan.xyz`；`tanzhen.zhuoruan.xyz` 可以作为区域根域名或跳转目标。三个服务域名必须保持不同，因为 ingest 域名要求 Agent mTLS，而 enroll 域名故意保持公开。

主机防火墙只允许入站 TCP 443。不要发布 8080 端口或数据库卷。准备一个归属于非 root 容器 UID 的私有备份目录：

```sh
sudo install -d -m 0700 -o 65532 -g 65532 /srv/server-probe/backups
```

在 `docker-compose.yml` 同目录创建 `.env`：

```dotenv
PROBE_MONITOR_HOST=monitor.tanzhen.zhuoruan.xyz
PROBE_INGEST_HOST=ingest.tanzhen.zhuoruan.xyz
PROBE_ENROLL_HOST=enroll.tanzhen.zhuoruan.xyz
PROBE_BACKUP_HOST_DIRECTORY=/srv/server-probe/backups
```

启动服务：

```sh
docker compose up -d --build
docker compose logs -f probe-server
```

首次启动时，`probe-data`、`agent-ca-private` 和 `agent-ca-public` 命名卷会从镜像目录初始化，并使用 UID/GID `65532`。SQLite 数据库和 Agent CA 私钥分别隔离在前两个卷中；只有公开 CA 证书会复制到 `agent-ca-public` 供 Caddy 使用。Caddy 会等待该证书准备好后再启动 mTLS 监听器。

监控界面没有内置登录功能。公开访问前，请使用 Cloudflare Access、IP 允许列表或私有网络限制 `monitor.tanzhen.zhuoruan.xyz`；否则节点创建、禁用和删除操作不需要认证。

### 注册 Agent

在监控界面创建服务器，并严格按照页面中仅显示一次的一次性命令操作。命令包含节点 ID、上报地址、注册地址和有效期十分钟的注册码。

使用 systemd 部署时，将二进制文件安装到 `/usr/local/bin/probe-agent`，将 `deploy/systemd/probe-agent.service` 复制到 `/etc/systemd/system/`，并根据界面显示的环境变量创建 `/etc/probe-agent/probe-agent.env`：

```dotenv
PROBE_NODE_ID=node-id-from-the-ui
PROBE_ENDPOINT=https://ingest.tanzhen.zhuoruan.xyz/v1/reports
PROBE_ENROLL_ENDPOINT=https://enroll.tanzhen.zhuoruan.xyz/v1/enroll
PROBE_ENROLL_CODE=one-time-code-from-the-ui
```

启用专用服务账户并启动 Agent：

```sh
sudo useradd --system --home /var/lib/probe-agent --shell /usr/sbin/nologin probe-agent
sudo install -d -m 0700 -o probe-agent -g probe-agent /etc/probe-agent
sudo chmod 0600 /etc/probe-agent/probe-agent.env
sudo systemctl daemon-reload
sudo systemctl enable --now probe-agent
```

注册成功后，从环境文件中删除 `PROBE_ENROLL_CODE` 和 `PROBE_ENROLL_ENDPOINT`。凭据存放在 `/var/lib/probe-agent` 下，目录权限为 `0700`，文件权限为 `0600`。Agent 在 30 天客户端证书进入最后 7 天时自动续期；凭据过期或被吊销后将停止上报。

### 备份与恢复

服务器每天向 `PROBE_BACKUP_HOST_DIRECTORY` 写入一次在线 SQLite 备份，并保留最近 7 个文件。请保持该目录私有，并使用组织现有的备份系统将文件复制到其他主机。

恢复时，只停止 `probe-server`，在 `probe-data` 卷中将 `probe.db` 替换为选定的 `probe-YYYY-MM-DD.db` 备份，同时删除对应的 `probe.db-wal` 和 `probe.db-shm` 文件，然后重新启动 `probe-server`。保持 Caddy 运行。服务恢复后，在监控界面确认最新上报时间。

## English

Server Probe is a self-hosted monitoring MVP for up to 50 Linux servers. Each Agent sends an outbound HTTPS report every 30 seconds; the central service stores raw samples in SQLite and exposes a Chinese monitoring UI. The UI shows CPU, memory, root disk, network traffic rates, and accumulated traffic for the last 24 hours.

The public surface is deliberately limited: only Caddy publishes TCP 443. The Probe Server and SQLite database are private to the Compose network. There are no remote commands, inbound Agent listeners, public status pages, or multi-user accounts.

### Build and test

The repository is locked to Go 1.25.13. On this workstation, use `D:\CodeTools\Go\go\bin\go.exe` with `GOTOOLCHAIN=go1.25.13`; the Go command downloads that fixed toolchain once into its local cache.

```powershell
$env:GOTOOLCHAIN = 'go1.25.13'
& 'D:\CodeTools\Go\go\bin\go.exe' test ./...
& 'D:\CodeTools\Go\go\bin\go.exe' vet ./...
```

Build a Linux Agent for the target architecture from a trusted build host:

```powershell
$env:GOOS = 'linux'
$env:GOARCH = 'amd64'
& 'D:\CodeTools\Go\go\bin\go.exe' build -trimpath -ldflags='-s -w' -o probe-agent ./cmd/probe-agent
```

Use `GOARCH=arm64` for ARM64 hosts.

### Deploy the central service

Create DNS `A` or `AAAA` records for three distinct names, all pointing at the Compose host:

- `monitor.tanzhen.zhuoruan.xyz`
- `ingest.tanzhen.zhuoruan.xyz`
- `enroll.tanzhen.zhuoruan.xyz`

Create three Cloudflare DNS records pointing to the Compose host. The monitor URL is `https://monitor.tanzhen.zhuoruan.xyz`; `tanzhen.zhuoruan.xyz` can remain the zone apex or redirect target. Keep the three service hostnames distinct because the ingest hostname requires Agent mTLS while enrollment is intentionally public.

Allow only inbound TCP 443 at the host firewall. Do not publish port 8080 or the database volume. Prepare a private host backup directory owned by the non-root container UID:

```sh
sudo install -d -m 0700 -o 65532 -g 65532 /srv/server-probe/backups
```

Create `.env` next to `docker-compose.yml`:

```dotenv
PROBE_MONITOR_HOST=monitor.tanzhen.zhuoruan.xyz
PROBE_INGEST_HOST=ingest.tanzhen.zhuoruan.xyz
PROBE_ENROLL_HOST=enroll.tanzhen.zhuoruan.xyz
PROBE_BACKUP_HOST_DIRECTORY=/srv/server-probe/backups
```

Start the service:

```sh
docker compose up -d --build
docker compose logs -f probe-server
```

Fresh `probe-data`, `agent-ca-private`, and `agent-ca-public` named volumes are initialized from image directories owned by UID/GID `65532`. SQLite and the Agent CA private key are isolated in the first two volumes; only the public CA certificate is copied into `agent-ca-public` for Caddy. Caddy waits for that certificate before starting its mTLS listener.

The monitor UI has no built-in login. Restrict `monitor.tanzhen.zhuoruan.xyz` with Cloudflare Access, an IP allowlist, or a private network before exposing it publicly; node creation, disablement, and removal are otherwise unauthenticated.

### Enroll an Agent

In the monitor UI, create a server and use the one-time command displayed exactly once. It includes the node ID, the report endpoint, enrollment endpoint, and a ten-minute enrollment code.

For systemd deployment, install the binary at `/usr/local/bin/probe-agent`, copy `deploy/systemd/probe-agent.service` to `/etc/systemd/system/`, and create `/etc/probe-agent/probe-agent.env` with the environment values shown by the UI:

```dotenv
PROBE_NODE_ID=node-id-from-the-ui
PROBE_ENDPOINT=https://ingest.tanzhen.zhuoruan.xyz/v1/reports
PROBE_ENROLL_ENDPOINT=https://enroll.tanzhen.zhuoruan.xyz/v1/enroll
PROBE_ENROLL_CODE=one-time-code-from-the-ui
```

Enable the dedicated service account and start it:

```sh
sudo useradd --system --home /var/lib/probe-agent --shell /usr/sbin/nologin probe-agent
sudo install -d -m 0700 -o probe-agent -g probe-agent /etc/probe-agent
sudo chmod 0600 /etc/probe-agent/probe-agent.env
sudo systemctl daemon-reload
sudo systemctl enable --now probe-agent
```

After a successful registration, remove `PROBE_ENROLL_CODE` and `PROBE_ENROLL_ENDPOINT` from the environment file. Credentials live under `/var/lib/probe-agent` with `0700` directory and `0600` file permissions. The Agent renews its 30-day client certificate when it enters the final seven days and stops reporting after an expired or revoked credential.

### Backups and restore

The server writes an online SQLite backup once per day to `PROBE_BACKUP_HOST_DIRECTORY` and retains the latest seven files. Keep that directory private and copy it off-host using the organisation's backup system.

To restore, stop only `probe-server`, replace `probe.db` in the `probe-data` volume with a chosen `probe-YYYY-MM-DD.db` backup, remove the corresponding `probe.db-wal` and `probe.db-shm` files, then start `probe-server` again. Leave Caddy running. Verify the latest report times in the monitor UI after the service returns.
