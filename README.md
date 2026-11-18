# sing-box-deploy

一个面向 Linux 服务器的 sing-box 部署与管理脚本。脚本提供中文交互菜单，可从官方软件源安装稳定版 sing-box，生成 **VLESS Reality + Hysteria2 + AnyTLS + TUIC** 四组入站，并将流量按 **Google / YouTube、AI、其他** 分流到三组上游代理（每组可独立选择 SOCKS5 或 HTTPS）。

同时提供配置编辑、待应用配置、事务回滚、防火墙归属管理、端口跳跃、备份恢复、内核更新和卸载等日常运维功能。

> 源码入口是 `sing-box-deploy.sh`，Python 逻辑位于 `lib/sb_deploy/`；可打包生成独立发布脚本。测试使用隔离环境，不会修改本机真实部署。

---

## 功能特性

- **交互菜单**：分组菜单、彩色状态提示、运行概览卡片、待应用修改提醒。
- **官方源安装**：通过 sing-box 官方 APT / DNF 软件源安装稳定版，不手动覆盖可执行文件。
- **四种协议**：
  - VLESS Reality（TCP）
  - Hysteria2（UDP，Salamander 混淆，自签证书）
  - AnyTLS（TCP，自签证书）
  - TUIC（UDP / QUIC，自签证书）
- **三组独立代理出口（SOCKS5 / HTTPS）**：
  - Google / YouTube → `google-socks`
  - 其余 AI 流量 → `ai-socks`
  - 其他公网流量 → `other-socks`
- **配置编辑**：支持逐字段编辑、完整 JSON 编辑、逐项开关和字段移除。
- **待应用配置**：修改先进入 `deployment/pending`，确认后执行 `apply` 才生效。
- **事务与回滚**：失败时恢复配置、证书、客户端资料和原服务状态。
- **防火墙归属管理**：只添加和删除本脚本记录的放行规则，不清理管理员自己的规则。
- **端口跳跃**：为 Hysteria2 生成独立 systemd + UDP 重定向服务。
- **备份与恢复**：带清单和 SHA-256 校验的私有备份包。
- **客户端资料**：生成分享链接、sing-box outbound JSON、Clash / Mihomo proxies YAML 和证书指纹。
- **日志隐私**：sing-box 日志级别默认 `warn`，避免记录访问域名；可用 `LOG_LEVEL` 或 `set-log-level` 调整。
- **握手目标回退**：Reality 默认握手域名不可用时，自动尝试备选域名，并校验 TLS 1.3、h2 和证书。
- **安全默认值**：凭据随机生成，配置和客户端目录默认仅 root 可读；错误输入不会写入运行配置。

---

## 系统要求

- Linux + systemd
- root 权限（`sudo`）
- 支持以下包管理器之一：
  - `apt-get`：Debian、Ubuntu 等
  - `dnf5` / `dnf`：Fedora、RHEL 兼容发行版
- sing-box **1.14 或更高版本**
- 需要联网访问：
  - sing-box 官方软件源与 GPG 密钥
  - GitHub 规则集下载地址
  - Reality 握手目标（默认 `la.mirrors.clouvider.net:443`，不可用时自动尝试备选域名）
  - 公网 IP 探测源（`api.ipify.org`、`icanhazip.com`、`ifconfig.me`、`checkip.amazonaws.com`，未指定 `SERVER_IP` 时使用）
- 安装时会自动安装依赖：`curl`、`ca-certificates`、`openssl`、`python3`、`iproute2` / `iproute`、`diffutils`（提供更新校验使用的 `cmp`）

> 脚本不会自动安装或接管 UFW / firewalld；检测到已启用的管理工具时才会添加本脚本拥有的规则。
> 开启端口跳跃但系统没有 nftables / iptables 时，脚本会通过系统包管理器安装 nftables。

---

## 快速开始

### 1. 获取脚本

```bash
git clone https://github.com/eurekaevan/sb-deploy.git sb-deploy
cd sb-deploy
chmod +x sing-box-deploy.sh
```

源码版需同时保留 `sing-box-deploy.sh` 和 `lib/`。需要单文件复制到服务器时，先在源码目录打包：

```bash
python3 -B scripts/build_release.py --output dist/sing-box-deploy.sh
```

将生成的 `dist/sing-box-deploy.sh` 单独复制到服务器即可运行，不需要安装 Python 第三方依赖。打包保留源码顶部的默认参数；修改默认值后需重新打包。以下命令可用于源码版，也可用于生成的发布脚本。

### 2. 进入管理菜单

```bash
sudo bash sing-box-deploy.sh
```

不带参数或使用 `menu` 会进入中文管理菜单；在非交互环境中运行 `menu` 会显示帮助而不是等待输入。

菜单和状态输出会在终端中使用颜色强调状态与风险；重定向、`TERM=dumb` 或设置 `NO_COLOR` 时自动切换为纯文本，便于日志和脚本处理。

### 3. 安装

在菜单中选择「安装」，或非交互执行：

```bash
sudo env \
  AI_SOCKS_HOST=ai-upstream.example AI_SOCKS_PORT=1080 \
  AI_SOCKS_USER=ai-user AI_SOCKS_PASS='ai-pass' \
  GOOGLE_SOCKS_HOST=google-upstream.example GOOGLE_SOCKS_PORT=1080 \
  GOOGLE_SOCKS_USER=google-user GOOGLE_SOCKS_PASS='google-pass' \
  OTHER_SOCKS_HOST=other-upstream.example OTHER_SOCKS_PORT=1080 \
  OTHER_SOCKS_USER=other-user OTHER_SOCKS_PASS='other-pass' \
  SERVER_IP=203.0.113.10 \
  bash sing-box-deploy.sh install
```

上面仅演示非交互参数形式。生产环境不建议把真实密码直接写在命令行中，可改用下方的 `0600` 环境文件方式，避免密码进入 shell 历史和进程参数。

也可以交互安装，脚本会提示端口、代理协议和连接参数。安装前会确认：

- `/etc/sing-box/config.json` 必须不存在
- `sing-box.service` 不得处于运行状态
- 部署目录和 `sb-manager` 不得已存在
- 目标端口未被占用
- 代理上游认证和 CONNECT 可用，HTTPS 同时校验 TLS 证书
- Reality 握手目标 TLS 1.3、h2 与证书校验通过；显式指定 `REALITY_DOMAIN` 时只检查该域名，否则按默认及备选列表依次尝试

安装完成后会自动安装快捷命令：

```bash
sudo sb-manager
```

`sb-manager` 实际执行的是 `/var/lib/sing-box/deployment/manager.sh`。安装或更新快捷命令时会自动打包，因此已安装入口不依赖原仓库目录，现有事务回滚也覆盖打包失败。

---

## 安装后的目录

| 路径 | 说明 |
| --- | --- |
| `/etc/sing-box/config.json` | 当前生效的服务端配置 |
| `/var/lib/sing-box/deployment/` | 部署数据目录（权限 0700） |
| `/var/lib/sing-box/deployment/tls/` | 托管证书与私钥 |
| `/var/lib/sing-box/deployment/rules/` | AI / Google / YouTube 规则集 |
| `/var/lib/sing-box/deployment/client/` | 按需生成的客户端资料 |
| `/var/lib/sing-box/deployment/pending/` | 待应用修改（未生效） |
| `/var/lib/sing-box/deployment/hopping.json` | Hysteria2 端口跳跃状态 |
| `/var/lib/sing-box/deployment/firewall-owned.json` | 本脚本拥有的防火墙规则记录 |
| `/usr/local/bin/sb-manager` | 快捷管理入口 |
| `/etc/systemd/system/sing-box-hopping.service` | 端口跳跃服务（启用时生成） |
| `/var/backups/sing-box-deploy/` | 默认备份目录 |
| `/usr/bin/sing-box` | 官方软件包安装的内核 |

> `client/` 目录是可删除、可重新生成的导出结果，不参与读取服务端配置。`config.json` 才是节点配置的依据。

---

## 默认端口

| 协议 | 传输 | 默认端口 |
| --- | --- | --- |
| VLESS Reality | TCP | `443` |
| Hysteria2 | UDP | `443` |
| AnyTLS | TCP | `8443` |
| TUIC | UDP | `10443` |

端口约束：

- AnyTLS 与 VLESS 不能使用相同 TCP 端口
- TUIC 与 Hysteria2 不能使用相同 UDP 端口
- 端口范围：`1–65535`

---

## 配置修改流程

除安装和恢复外，协议、端口、代理出口、凭据和跳跃设置的修改都会先写入待应用区：

```text
修改 → deployment/pending → 校验 → apply → 更新服务 / 防火墙 / 跳跃规则
```

常用命令：

```bash
# 应用待应用修改并重启服务
sudo bash sing-box-deploy.sh apply

# 丢弃待应用修改
sudo DISCARD_CONFIRM=YES bash sing-box-deploy.sh discard-pending

# 查看运行状态、真实版本、已确认运行配置和待应用配置
sudo bash sing-box-deploy.sh summary
```

说明：

- `apply` 会先校验配置；失败会自动回滚并保留待应用修改。
- 如果已应用配置在暂存后被其他操作修改，`apply` 会拒绝覆盖。
- 存在待应用修改时，恢复、卸载等破坏性操作会被拒绝。
- 安装后建议先执行 `show` 查看节点资料，再导入客户端。

### 逐字段编辑

```bash
# 修改字段（值必须是合法 JSON）
sudo bash sing-box-deploy.sh edit-field vless /tls/handshake_timeout '"15s"'

# 布尔开关
sudo bash sing-box-deploy.sh edit-field tuic /zero_rtt_handshake true

# 移除字段
sudo bash sing-box-deploy.sh edit-field tuic /heartbeat :remove

# 使用编辑器完整编辑入站 JSON
sudo bash sing-box-deploy.sh edit-protocol vless

# 指定编辑器
sudo VISUAL=vim bash sing-box-deploy.sh edit-protocol vless
```

字段路径使用 JSON Pointer（例如 `/tls/reality/handshake/server_port`）。完整编辑默认使用 `nano`，可通过 `VISUAL` / `EDITOR` 覆盖。

---

## 常用命令

### 服务与状态

```bash
sudo bash sing-box-deploy.sh status
sudo bash sing-box-deploy.sh logs
sudo bash sing-box-deploy.sh check
sudo bash sing-box-deploy.sh start
sudo bash sing-box-deploy.sh stop
sudo bash sing-box-deploy.sh restart
```

- `status`：服务状态、监听检查、配置校验、跳跃服务检查
- `check`：配置、SOCKS5 / HTTPS 上游和可检查的 TLS 项目
- `logs`：最近 80 行服务日志

### 节点资料

```bash
# 查看节点参数、分享链接、JSON 和 Clash/Mihomo YAML
sudo bash sing-box-deploy.sh show

# 查看 outbound JSON
sudo bash sing-box-deploy.sh show-json

# 查看 Clash/Mihomo proxies YAML
sudo bash sing-box-deploy.sh show-yaml

# 导出客户端资料到 deployment/client
sudo bash sing-box-deploy.sh export

# 可选导出 proxies.yaml
sudo bash sing-box-deploy.sh export-yaml
```

`export` 会生成：

- `<协议>.outbound.json`
- `nodes.txt`（分享链接）
- `node-info.txt`（完整说明）
- 证书文件与证书 SHA-256 指纹

YAML 使用证书指纹校验（`skip-cert-verify: false`）；JSON 内嵌证书。自签证书仍需客户端信任，或使用指纹校验。

### 修改端口 / SNI / 凭据

```bash
# 修改端口（未指定的端口保留当前值）
sudo VLESS_PORT=8443 bash sing-box-deploy.sh set-ports

# 修改 SNI
sudo NEW_REALITY_DOMAIN=www.example.com \
  NEW_HY2_SNI=www.example.com \
  NEW_ANYTLS_SNI=www.example.com \
  bash sing-box-deploy.sh set-sni

# 修改凭据
sudo NEW_UUID=... NEW_HY2_PASS=... bash sing-box-deploy.sh set-credentials

# 重新生成某个协议（保留端口和 SNI）
sudo bash sing-box-deploy.sh regenerate vless

# 轮换全部凭据（旧节点会失效）
sudo bash sing-box-deploy.sh rotate-credentials
```

显式修改 `NEW_REALITY_DOMAIN` 时，脚本只检查该域名的 TLS 1.3、h2 和证书；通过后保存到待应用配置，执行 `apply` 才生效。不指定时，安装会从默认域名和备选域名中自动选择第一个可用的握手目标。

`REALITY_DOMAIN` 的默认候选按顺序为：`la.mirrors.clouvider.net`、`www.microsoft.com`、`www.apple.com`、`www.cloudflare.com`、`www.amazon.com`。全部不可用时会明确失败，此时可用 `REALITY_DOMAIN` 指定其他同时支持 TLS 1.3 和 h2 的域名。

### 日志级别

```bash
# 暂存为 warn（默认，不记录访问域名），执行 apply 后生效
sudo bash sing-box-deploy.sh set-log-level warn

# 排查问题时临时使用 debug 或 info
sudo bash sing-box-deploy.sh set-log-level debug
```

环境变量 `LOG_LEVEL` 控制新生成配置的日志级别，默认 `warn`。`info` / `debug` 可能记录目标域名，排障完成后建议恢复为 `warn`。

### 代理出口（SOCKS5 / HTTPS）

```bash
# 修改单组：交互选择 socks5 或 https，回车保留当前协议和参数
sudo bash sing-box-deploy.sh set-ai-proxy
sudo bash sing-box-deploy.sh set-google-proxy
sudo bash sing-box-deploy.sh set-other-proxy

# 同时修改三组
sudo bash sing-box-deploy.sh configure-proxies

# 开关三组出口的 TCP Fast Open（SOCKS5、HTTPS 均支持）
sudo SOCKS_TFO=false bash sing-box-deploy.sh set-tfo
```

每组独立选择协议，允许混用。`set-ai-socks` / `set-google-socks` / `set-other-socks` / `configure-socks` 继续作为兼容命令；旧 `*_SOCKS_HOST/PORT/USER/PASS` 参数也继续有效。

例如，将 AI 出口暂存为 HTTPS，其他两组保持当前配置：

```bash
sudo AI_PROXY_PROTOCOL=https \
  AI_PROXY_HOST=proxy.example.com AI_PROXY_PORT=443 \
  AI_PROXY_SNI=proxy.example.com \
  bash sing-box-deploy.sh set-ai-proxy
sudo bash sing-box-deploy.sh apply
```

示例沿用当前认证信息；交互输入隐藏密码，也可在私密环境文件中填写 `AI_PROXY_USER` / `AI_PROXY_PASS`。HTTPS 支持 Basic 认证；用户名和密码均为空时不发送认证，交互输入 `:clear` 可清除当前认证。普通回车保留现有值。

HTTPS 使用 sing-box 的 [`http` 出站与 TLS](https://sing-box.sagernet.org/configuration/outbound/http/)，默认启用证书和主机名校验。SNI 默认取代理地址，可通过 `*_PROXY_SNI` 独立设置；原有 HTTPS TLS 设置保留。提供的是 TCP CONNECT 代理能力，不提供 SOCKS5 UDP 转发。连接检查覆盖 TLS、SNI、认证与 CONNECT；非默认 HTTP/2/3、自定义 CONNECT 路径/请求头或尚不能准确模拟的高级 TLS 配置会明确提示需要手动核实，避免误报通过。

默认路由顺序：

1. Google / YouTube → `google-socks`
2. AI → `ai-socks`
3. 其他流量 → `other-socks`

这些旧标签继续保留，切换协议不会改变分流引用；状态页按实际出站类型显示 SOCKS5 或 HTTPS。Google 规则优先于 AI，避免 Gemini 等同时命中两组规则时走错出口。所有出口修改仍仅暂存，需手动 `apply`，失败按原事务机制回滚。

### 添加可选协议

升级旧部署或后补协议：

```bash
sudo ANYTLS_PORT=10443 NEW_ANYTLS_SNI=www.example.com \
  bash sing-box-deploy.sh add-anytls

sudo TUIC_PORT=11443 NEW_TUIC_SNI=www.example.com \
  bash sing-box-deploy.sh add-tuic
```

修改后会进入待应用区，执行 `apply` 才生效。

### Hysteria2 端口跳跃

```bash
# 开启 UDP 跳跃
sudo HY2_HOP_PORTS='20000:20100,30000' \
  HY2_HOP_INTERVAL=30s \
  bash sing-box-deploy.sh set-hopping

# 关闭跳跃
sudo bash sing-box-deploy.sh disable-hopping
```

- `HY2_HOP_EXCLUDE` 默认为 `auto`，自动排除本机已占用的 UDP 端口。
- 设置为 `none` 表示不自动排除。
- 跳跃由独立 systemd 服务通过 nftables / iptables UDP 重定向实现。
- 云安全组必须单独放行所有跳跃端口。
- 跳跃服务只转发发往本机的 UDP 流量。

### 防火墙

```bash
sudo bash sing-box-deploy.sh firewall-status
sudo bash sing-box-deploy.sh firewall-details
sudo bash sing-box-deploy.sh firewall-auto true
sudo bash sing-box-deploy.sh firewall-auto false
sudo FIREWALL_CONFIRM=YES bash sing-box-deploy.sh firewall-enable ufw
sudo FIREWALL_CONFIRM=YES bash sing-box-deploy.sh firewall-disable ufw
```

- 脚本自动放行只管理自己记录的端口，不会删除无归属的旧规则。
- UFW / firewalld 规则会持久化。
- 裸 nftables / iptables 规则仅在当前运行时生效。
- 云防火墙 / 安全组需要单独配置。

### 备份与恢复

```bash
# 备份到默认目录
sudo bash sing-box-deploy.sh backup

# 指定备份路径
sudo bash sing-box-deploy.sh backup /root/sb-20260101.tar.gz

# 恢复
sudo bash sing-box-deploy.sh restore /root/sb-20260101.tar.gz
```

备份包包含：

- `config.json`
- 证书和私钥
- 规则集
- 跳跃配置
- 内核版本与服务启停状态清单
- 每个文件的 SHA-256 校验值

不包含：

- 待应用修改
- 可重新生成的 `client/` 导出资料
- 缓存文件

> 备份包含节点密码和私钥，请存放在 root 专属目录并妥善保管。备份路径不能覆盖部署目录、配置目录、`sb-manager` 入口或跳跃服务文件。

### 更新内核

```bash
sudo bash sing-box-deploy.sh update
```

更新流程会先下载当前版本的回滚包，再通过官方源升级。更新后确认：

- 软件包已安装
- 版本可读取
- 配置校验通过
- 配置未被软件包脚本改写
- 原服务启停状态保持

任一步失败会恢复原版本和原配置。

### 卸载

```bash
sudo UNINSTALL_CONFIRM=YES bash sing-box-deploy.sh uninstall
```

卸载前会自动备份，然后移除：

- sing-box 软件包
- `/etc/sing-box/config.json`
- `/var/lib/sing-box/deployment`
- `sb-manager`
- 跳跃服务文件
- 本脚本拥有的防火墙规则

保留：

- 备份文件
- 共享软件源和签名密钥
- 依赖包
- 无法确认归属的旧防火墙规则

---

## 环境变量

脚本顶部的 `DEFAULT_*` 变量是首次安装默认值；环境变量优先于源码默认值，交互输入又可覆盖两者。普通修改默认沿用当前配置中未选择修改的值。

### 安装与连接

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `AI_SOCKS_HOST` / `PORT` / `USER` / `PASS` | 无 | AI 流量代理地址、端口、认证（旧参数名保留） |
| `GOOGLE_SOCKS_HOST` / `PORT` / `USER` / `PASS` | 无 | Google / YouTube 代理地址、端口、认证（旧参数名保留） |
| `OTHER_SOCKS_HOST` / `PORT` / `USER` / `PASS` | 无 | 其他流量代理地址、端口、认证（旧参数名保留） |
| `AI_PROXY_PROTOCOL` / `GOOGLE_PROXY_PROTOCOL` / `OTHER_PROXY_PROTOCOL` | 新安装 `socks5`，修改沿用当前协议 | 每组可设 `socks5` 或 `https`；源码对应 `DEFAULT_*_PROXY_PROTOCOL` |
| `AI_PROXY_HOST` / `PORT` / `USER` / `PASS` | 沿用当前值 | AI 组通用参数；优先于同名 `AI_SOCKS_*` 旧参数 |
| `GOOGLE_PROXY_HOST` / `PORT` / `USER` / `PASS` | 沿用当前值 | Google / YouTube 组通用参数 |
| `OTHER_PROXY_HOST` / `PORT` / `USER` / `PASS` | 沿用当前值 | 其他流量组通用参数 |
| `AI_PROXY_SNI` / `GOOGLE_PROXY_SNI` / `OTHER_PROXY_SNI` | 原有 SNI，否则代理地址 | HTTPS SNI；源码对应 `DEFAULT_*_PROXY_SNI`，显式空值重置为代理地址 |
| `SERVER_IP` | 自动探测公网 IPv4 | 客户端导出地址，不写回服务端配置 |
| `VLESS_PORT` | `443` | VLESS Reality TCP 端口 |
| `HY2_PORT` | `443` | Hysteria2 UDP 端口 |
| `ANYTLS_PORT` | `8443` | AnyTLS TCP 端口 |
| `TUIC_PORT` | `10443` | TUIC UDP 端口 |
| `REALITY_DOMAIN` | 自动选择（优先 `la.mirrors.clouvider.net`） | 显式设置时固定该 Reality 握手域名并校验 TLS 1.3 + h2；留空则失败后自动尝试备选域名 |
| `LOG_LEVEL` | `warn` | sing-box 日志级别：`trace` / `debug` / `info` / `warn` / `error` / `fatal` / `panic`；`warn` 不记录访问域名 |
| `SOCKS_TFO` | `true` | 三组 SOCKS5 / HTTPS 出站的 TCP Fast Open |
| `HY2_BBR_PROFILE` | `standard` | `standard` / `conservative` / `aggressive` |
| `HY2_HOP_PORTS` | 空（关闭） | 跳跃端口，例如 `20000:20100,30000` |
| `HY2_HOP_INTERVAL` | `30s` | 跳跃间隔 |
| `HY2_HOP_EXCLUDE` | `auto` | 自动排除已占用 UDP 端口，或 `none` |

### 修改命令专用

| 变量 | 说明 |
| --- | --- |
| `NEW_REALITY_DOMAIN` | 修改 Reality SNI / 握手域名 |
| `NEW_HY2_SNI` | 修改 Hysteria2 SNI |
| `NEW_ANYTLS_SNI` | 修改 AnyTLS SNI |
| `NEW_TUIC_SNI` | 修改 TUIC SNI |
| `NEW_UUID` | 修改 VLESS UUID |
| `NEW_HY2_PASS` | 修改 Hysteria2 密码 |
| `NEW_HY2_OBFS_PASS` | 修改 Salamander 混淆密码 |
| `NEW_ANYTLS_PASS` | 修改 AnyTLS 密码 |
| `NEW_TUIC_UUID` | 修改 TUIC UUID |
| `NEW_TUIC_PASS` | 修改 TUIC 密码 |
| `BACKUP_FILE` | `backup` / `restore` 的默认文件路径 |
| `DISCARD_CONFIRM=YES` | 非交互丢弃待应用修改 |
| `UNINSTALL_CONFIRM=YES` | 非交互卸载 |
| `FIREWALL_CONFIRM=YES` | 非交互系统防火墙开关 |
| `VISUAL` / `EDITOR` | 完整编辑使用的编辑器，默认 `nano` |

> 建议在 root shell 中使用权限为 `0600` 的环境文件加载凭据，避免密码进入 shell 历史或进程参数。

示例：

```bash
sudo -i
umask 077
cat >/root/sb-install.env <<'EOF'
AI_SOCKS_HOST=...
AI_SOCKS_PORT=1080
AI_SOCKS_USER=...
AI_SOCKS_PASS=...
EOF
set -a
. /root/sb-install.env
set +a
bash /root/sb-deploy/sing-box-deploy.sh install
```

---

## 客户端资料与证书

- VLESS Reality 使用 Reality 公钥、Short ID 和 SNI。
- Hysteria2 使用认证密码、Salamander 混淆密码、证书指纹和可选跳跃端口。
- AnyTLS 使用密码、SNI 和证书指纹。
- TUIC 使用 UUID、密码、SNI、拥塞控制和证书指纹。
- 默认生成自签证书；客户端必须信任证书，或使用 YAML 中的 SHA-256 指纹校验。
- 分享链接本身不携带证书，导入后仍需确认客户端证书设置。
- 通配监听地址无法直接确定公网地址；导出时可自动探测，或用 `SERVER_IP` 指定。

自签证书默认有效期为 825 天，可在源码顶部调整 `DEFAULT_CERT_VALID_DAYS`，或用 `CERT_VALID_DAYS` 覆盖。`status`、`summary` 和主菜单显示实际配置中每张证书的剩余天数与到期时间；默认剩余 30 天内标黄，过期或无法读取时标红。预警阈值由 `DEFAULT_CERT_WARN_DAYS` / `CERT_WARN_DAYS` 设置。Reality 不使用此证书到期检查。

续期托管自签证书：

```bash
sudo sb-manager renew-certs  # 仅暂存；保留私钥、SNI、SAN 和其他证书扩展
sudo sb-manager apply        # 手动应用并重启；失败时回滚
sudo sb-manager show-yaml    # 获取更新后的客户端资料
```

续期会改变证书 SHA-256 指纹，继续使用原有证书校验策略；**应用后必须重新导出并导入客户端节点**。多协议共用一张证书时仅续期一次；续期失败会恢复之前的待应用内容。

自有证书可通过“修改协议配置”设置 `tls.certificate_path` / `tls.key_path`，也支持内嵌 PEM。外部、内嵌、备份导入的外部证书及 CA 签发证书不会被 `renew-certs` 覆盖。ACME 证书应由原工具续期，本脚本未新增 ACME 自动签发；使用动态证书配置时会提示无法离线确认到期时间。

---

## 故障排查

### 服务异常

```bash
sudo sb-manager status
sudo sb-manager logs
sudo journalctl -u sing-box.service -n 100 --no-pager
```

### 端口被占用

```bash
ss -lntup
```

在菜单中修改端口时，脚本会先显示当前占用情况。UDP 和 TCP 分别判断，本机未占用不代表云安全组已放行。

### 配置校验失败

```bash
sudo bash sing-box-deploy.sh status
sudo /usr/bin/sing-box check -C /etc/sing-box
```

`apply` 失败会自动回滚。待应用修改会保留，修复后可再次执行 `apply`。

### 客户端资料导出失败

如果 `deployment/client/EXPORT-ERROR.txt` 存在，说明服务端配置可能有效，但客户端资料无法完整生成。此时：

1. 查看错误文件；
2. 使用 `show-json` / `show` 手动复制配置；
3. 服务端配置和运行服务不受影响。

### 无法确定公网 IPv4

脚本会先读取 `ip route get 1.1.1.1` 的本机出口地址，再依次尝试 `api.ipify.org`、`icanhazip.com`、`ifconfig.me/ip`、`checkip.amazonaws.com`，并过滤私网、回环等非公网地址。全部失败时手动指定：

```bash
sudo SERVER_IP=203.0.113.10 bash sing-box-deploy.sh export
```

`SERVER_IP` 只影响客户端导出，不写回服务端配置。

### Reality 握手域名不可用

安装时会校验握手域名的 TLS 1.3、h2 和证书。默认域名失败后会自动尝试 README 中列出的备选域名；如果全部失败，选择一个网络可达、同时支持 TLS 1.3 和 h2 的第三方域名：

```bash
sudo REALITY_DOMAIN=www.example.com bash sing-box-deploy.sh install
```

显式指定的域名不会自动回退到其他候选，失败时安装会停止。已有部署修改域名使用 `set-sni`，并需执行 `apply`。

### 防火墙放行后仍不可达

请依次检查：

1. 本机防火墙规则
2. 云平台安全组
3. 运营商或上游网络限制
4. 客户端证书 / SNI / 密钥配置
5. 实际监听端口与服务状态

---

## 测试

开发检查与分组测试：

```bash
python3 -m pip install -r requirements-dev.txt
bash -n sing-box-deploy.sh
shellcheck sing-box-deploy.sh
ruff check .
python3 -B tests/run_tests.py --group fast  # 直接导入 Python 模块、本地 TLS 代理、发布包契约及发行版检测
python3 -B tests/run_tests.py --group slow  # 临时目录中的系统生命周期回归
python3 -B tests/run_tests.py --group all   # 两组合并；可追加 -v
```

快组不依赖伪 systemd 或伪防火墙，验证配置编辑、SSH/UFW 解析、跳跃规划及独立发布包行为。慢组保留原有事务、失败回滚、安装、更新、卸载等测试，使用伪 systemd、软件包管理器和防火墙工具，不会修改本机真实部署。

CI 对 PR 运行静态检查和 Debian 12 / Fedora 43 快组；推送到 main/master 或手动执行时，在两个发行版增加慢组。静态检查同时覆盖源码及生成的单文件发布脚本。APT/DNF 测试验证命令契约与回滚路径，容器运行不代表已经验证真实官方软件源安装或 systemd 服务管理。

每日及手动 nightly 使用固定版本、固定 SHA-256 的官方 sing-box 运行下方真实跳跃测试；缺少 namespace 权限时明确失败，不跳过。

运行真实 Hysteria2 端口跳跃集成测试（需要真实 sing-box 内核和 Linux namespace 支持）：

```bash
python3 tests/hopping_integration.py --sing-box /usr/bin/sing-box
```

依赖：Linux user namespace、`iproute2`、`nftables`、`iptables`、`curl`、`nsenter`。测试明确移除单元测试夹具的伪防火墙和伪 `ss`，在新建的网络 namespace 内执行真实工具。

---

## 安全说明

- 脚本以 root 运行，会修改系统软件包、systemd 服务、配置和防火墙规则。
- 配置、私钥和备份均包含敏感信息，请限制为 root 可读。
- 不要把真实密码提交到 Git、命令历史、公开日志或截图中。
- sing-box 日志默认使用 `warn`，避免记录访问域名；只有在排障时才临时提高日志级别。
- 开启系统防火墙前，务必确认 SSH 已放行，避免把自己锁在服务器外。
- 云安全组需要单独放行节点端口和全部跳跃端口。
- 修改 SNI、凭据和协议前，先确认客户端可重新导入配置。
- 生产环境使用前，请先在测试服务器验证网络、防火墙和客户端兼容性。

---

## 项目结构

```text
.
├── README.md
├── sing-box-deploy.sh          # Bash 管理界面、事务、systemd 与包管理
├── lib/
│   ├── runner.py              # 保留 stdin/argv 的模块调用入口
│   └── sb_deploy/
│       ├── __init__.py        # Python 包入口
│       ├── configuration.py   # 配置生成、代理出口编辑、TLS 路径与字段修改
│       ├── nodes.py           # 协议配置、动态菜单及客户端导出
│       ├── certificates.py    # 到期检测与托管自签续期
│       ├── firewall.py        # 防火墙状态、SSH 保护及规则归属
│       ├── hopping.py         # 跳跃端口规划与 NAT 生命周期
│       ├── network.py         # 地址检查与连接探测
│       ├── backup.py          # 私密归档、校验及恢复
│       └── bundle.py          # 源码与独立发布包共用的打包逻辑
├── scripts/build_release.py   # 生成 dist/sing-box-deploy.sh；不提交生成文件
├── tests/
│   ├── run_tests.py           # fast / slow / all 分组入口
│   ├── test_modules.py        # 模块直接单测与发布包契约（快组）
│   ├── test_https_proxy.py    # 本地真实 TLS 代理与认证探测（快组）
│   ├── test_deploy.py         # 隔离系统生命周期回归（慢组）
│   └── hopping_integration.py # 真实 Hysteria2 跳跃测试（network namespace）
├── .github/workflows/
│   ├── ci.yml                # 静态检查与 Debian/Fedora 测试
│   └── nightly.yml           # 固定真实内核的每日网络集成
├── requirements-dev.txt       # 固定开发检查工具；服务器无需安装
├── ruff.toml                 # Python 静态检查规则
├── .shellcheckrc              # 有意的暂存子进程作用域说明
└── .gitignore                # 排除缓存与生成的发布包
```

---

## 相关链接

- sing-box 官方文档：<https://sing-box.sagernet.org/>
- sing-box 安装文档：<https://sing-box.sagernet.org/installation/package-manager/>
- AI 规则集：<https://github.com/DustinWin/ruleset_geodata>
- Google / YouTube 规则集：<https://github.com/MetaCubeX/meta-rules-dat>
