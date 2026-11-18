#!/usr/bin/env bash
# sing-box deployment with config-driven inbound editing and owned firewall management.
# Google/YouTube, remaining AI and other public traffic use independent SOCKS5/HTTPS proxies.
# Installs stable sing-box from the official APT/DNF repository; uses packaged systemd unit.
# Tested syntactically on Linux; run as root on a systemd server with apt-get or dnf.
set -Eeuo pipefail
umask 077

# Editable defaults. Environment variables override these; interactive input can override both.
# Keep credentials in single quotes (escape any literal single quote); protect this file if populated.
# shellcheck disable=SC2034 # Read through indirect variable names in read_socks_profile.
DEFAULT_AI_SOCKS_HOST=''
# shellcheck disable=SC2034 # Read through indirect variable names in read_socks_profile.
DEFAULT_AI_SOCKS_PORT=''
# shellcheck disable=SC2034 # Read through indirect variable names in read_socks_profile.
DEFAULT_AI_SOCKS_USER=''
# shellcheck disable=SC2034 # Read through indirect variable names in read_socks_profile.
DEFAULT_AI_SOCKS_PASS=''
# shellcheck disable=SC2034 # Selected dynamically for each proxy group.
DEFAULT_AI_PROXY_PROTOCOL='socks5'
# shellcheck disable=SC2034 # Optional HTTPS SNI; empty uses the proxy host.
DEFAULT_AI_PROXY_SNI=''
# shellcheck disable=SC2034 # Read through indirect variable names in read_socks_profile.
DEFAULT_GOOGLE_SOCKS_HOST=''
# shellcheck disable=SC2034 # Read through indirect variable names in read_socks_profile.
DEFAULT_GOOGLE_SOCKS_PORT=''
# shellcheck disable=SC2034 # Read through indirect variable names in read_socks_profile.
DEFAULT_GOOGLE_SOCKS_USER=''
# shellcheck disable=SC2034 # Read through indirect variable names in read_socks_profile.
DEFAULT_GOOGLE_SOCKS_PASS=''
# shellcheck disable=SC2034 # Selected dynamically for each proxy group.
DEFAULT_GOOGLE_PROXY_PROTOCOL='socks5'
# shellcheck disable=SC2034 # Optional HTTPS SNI; empty uses the proxy host.
DEFAULT_GOOGLE_PROXY_SNI=''
# shellcheck disable=SC2034 # Read through indirect variable names in read_socks_profile.
DEFAULT_OTHER_SOCKS_HOST=''
# shellcheck disable=SC2034 # Read through indirect variable names in read_socks_profile.
DEFAULT_OTHER_SOCKS_PORT=''
# shellcheck disable=SC2034 # Read through indirect variable names in read_socks_profile.
DEFAULT_OTHER_SOCKS_USER=''
# shellcheck disable=SC2034 # Read through indirect variable names in read_socks_profile.
DEFAULT_OTHER_SOCKS_PASS=''
# shellcheck disable=SC2034 # Selected dynamically for each proxy group.
DEFAULT_OTHER_PROXY_PROTOCOL='socks5'
# shellcheck disable=SC2034 # Optional HTTPS SNI; empty uses the proxy host.
DEFAULT_OTHER_PROXY_SNI=''
DEFAULT_FIREWALL_AUTO='true' # Manage only this script's owned port permits.
DEFAULT_SOCKS_TFO='true' # Applies to all three proxy outbounds.
DEFAULT_VLESS_PORT='443'
DEFAULT_HY2_PORT='443'
DEFAULT_TUIC_PORT='10443'
DEFAULT_TLS_HANDSHAKE_TIMEOUT='10s'
DEFAULT_CERT_VALID_DAYS='825'
DEFAULT_CERT_WARN_DAYS='30'
DEFAULT_ANYTLS_PORT='8443' # Separate TCP port for the default installation.
DEFAULT_HY2_HOP_PORTS='' # Empty disables hopping; e.g. 20000:20100,30000.
DEFAULT_HY2_HOP_INTERVAL='30s'
DEFAULT_HY2_BBR_PROFILE='standard'
DEFAULT_SERVER_IP='' # Empty: detect the public IPv4 automatically.
DEFAULT_LOG_LEVEL='warn' # sing-box log level; warn avoids logging visited domains by default.
DEFAULT_REALITY_DOMAIN='la.mirrors.clouvider.net'
DEFAULT_REALITY_FALLBACK_DOMAINS=(
  'www.microsoft.com'
  'www.apple.com'
  'www.cloudflare.com'
  'www.amazon.com'
)

# Environment overrides and explicit requests; ordinary edits load current config values.
LOG_LEVEL="${LOG_LEVEL-$DEFAULT_LOG_LEVEL}"
CERT_VALID_DAYS="${CERT_VALID_DAYS-$DEFAULT_CERT_VALID_DAYS}"
CERT_WARN_DAYS="${CERT_WARN_DAYS-$DEFAULT_CERT_WARN_DAYS}"
REQUEST_SOCKS_TFO="${SOCKS_TFO-}"
SOCKS_TFO="${SOCKS_TFO-$DEFAULT_SOCKS_TFO}"
HY2_BBR_PROFILE_REQUEST="${HY2_BBR_PROFILE-}"
HY2_BBR_PROFILE="${HY2_BBR_PROFILE-$DEFAULT_HY2_BBR_PROFILE}"
HY2_HOP_PORTS_REQUEST="${HY2_HOP_PORTS-}"
HY2_HOP_INTERVAL_REQUEST="${HY2_HOP_INTERVAL-}"
HY2_HOP_PORTS="${HY2_HOP_PORTS-$DEFAULT_HY2_HOP_PORTS}"
HY2_HOP_INTERVAL="${HY2_HOP_INTERVAL-$DEFAULT_HY2_HOP_INTERVAL}"
VLESS_PORT_REQUEST="${VLESS_PORT-}"
HY2_PORT_REQUEST="${HY2_PORT-}"
ANYTLS_PORT_REQUEST="${ANYTLS_PORT-}"
TUIC_PORT_REQUEST="${TUIC_PORT-}"
VLESS_PORT="${VLESS_PORT-$DEFAULT_VLESS_PORT}"
HY2_PORT="${HY2_PORT-$DEFAULT_HY2_PORT}"
ANYTLS_PORT="${ANYTLS_PORT-$DEFAULT_ANYTLS_PORT}"
TUIC_PORT="${TUIC_PORT-$DEFAULT_TUIC_PORT}"
SERVER_IP="${SERVER_IP-$DEFAULT_SERVER_IP}"
# An explicit REALITY_DOMAIN pins that target; otherwise installation tries the default and fallbacks.
REALITY_DOMAIN_REQUEST="${REALITY_DOMAIN-}"
REALITY_DOMAIN="${REALITY_DOMAIN:-$DEFAULT_REALITY_DOMAIN}"

# Installation paths and rule sources.
SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
PYTHON_ROOT="${SCRIPT_PATH%/*}/lib"
MANAGER="/usr/local/bin/sb-manager"
APP="/var/lib/sing-box/deployment"
BIN="/usr/bin/sing-box"
CONFIG="/etc/sing-box/config.json"
UNIT="sing-box.service"
HOP_UNIT="sing-box-hopping.service"
HOP_UNIT_FILE="/etc/systemd/system/sing-box-hopping.service"
BACKUP_DIR="/var/backups/sing-box-deploy"
AI_URL="https://github.com/DustinWin/ruleset_geodata/releases/download/sing-box-ruleset/ai.srs"
GOOGLE_URL="https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/google.srs"
YOUTUBE_URL="https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/youtube.srs"
# Per-operation transaction state.
TEMP=""
TRANSACTION=""
WAS_ACTIVE=0
WAS_ENABLED=0
ROLLBACK_PATHS=()
ROLLBACK_EXISTS=()
FW_UNDO=()
FW_NFT=0
FW_RESTORE=""
HOP_TRANSACTION=0
HOP_WAS_ACTIVE=0
HOP_WAS_ENABLED=0
PACKAGE_ROLLBACK=0
CLIENT_EXPORT_FAILED=0
OLD_PACKAGE=""
OLD_PACKAGE_ID=""
FW_MARK="sing-box-deploy-$BASHPID"
FW_SSH_MARK='sing-box-deploy SSH safeguard'

# BEGIN PYTHON RUNNER
python_module() {
  python3 -B "$PYTHON_ROOT/runner.py" "$@"
}
# END PYTHON RUNNER

# Color only terminal output; redirected output and NO_COLOR remain plain text.
ui() {
  local kind="$1" text="$2" tail="${3:-}" color='' reset=''
  if [[ -t 1 && "${TERM:-dumb}" != dumb && ! ${NO_COLOR+x} ]]; then
    reset=$'\033[0m'
    case "$kind" in
      title) color=$'\033[1;36m' ;;
      section) color=$'\033[1;35m' ;;
      item) color=$'\033[36m' ;;
      info) color=$'\033[0;37m' ;;
      muted) color=$'\033[2;37m' ;;
      success) color=$'\033[1;32m' ;;
      warning) color=$'\033[1;33m' ;;
      error) color=$'\033[1;31m' ;;
      *) color=$'\033[0;37m' ;;
    esac
  fi
  printf '%s%s%s%s\n' "$color" "$text" "$reset" "$tail"
}

# A light visual separator used between UI sections.
ui_rule() {
  local width="${1:-46}" glyph="${2:-─}" indent="${3:-}" line
  printf -v line '%*s' "$width" ''
  line="${line// /$glyph}"
  ui muted "${indent}${line}"
}

menu_choices() {
  local line text indent number rest
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" == '@@GROUP@@'* ]]; then
      printf '\n'
      ui section "  ── ${line#@@GROUP@@} ──"
    elif [[ "$line" == *卸载* || "$line" == *关闭系统防火墙* ]]; then
      indent="${line%%[![:space:]]*}"
      text="${line#"$indent"}"
      printf '%s' "$indent"; ui error "$text"
    elif [[ "$line" == *应用配置并重启* || "$line" == *'· 开启'* ]]; then
      indent="${line%%[![:space:]]*}"
      text="${line#"$indent"}"
      printf '%s' "$indent"; ui success "$text"
    elif [[ "$line" == *重新生成* || "$line" == *含访问凭据* || "$line" == *需确认* || "$line" == *待应用* ]]; then
      indent="${line%%[![:space:]]*}"
      text="${line#"$indent"}"
      printf '%s' "$indent"; ui warning "$text"
    elif [[ "$line" =~ ^[[:space:]]*0\.[[:space:]] ]]; then
      text="${line#"${line%%[![:space:]]*}"}"
      ui muted "  $text"
    elif [[ "$line" =~ ^([[:space:]]*)([0-9]+\.)([[:space:]]+)(.*)$ ]]; then
      indent="${BASH_REMATCH[1]}"
      number="${BASH_REMATCH[2]}"
      rest="${BASH_REMATCH[4]}"
      # Keep the numbered prefix plain in redirected output and color only the number in a terminal.
      ui item "${indent}${number}" " ${rest}"
    elif [[ -n "$line" ]]; then ui title "$line"
    else printf '\n'; fi
  done < <(printf '%s' "$1")
}

log() { printf '\n' >&2; ui info "[sing-box-deploy] $*" >&2; }
success() { printf '\n' >&2; ui success "[成功] $*" >&2; }
warn() { printf '\n' >&2; ui warning "[提示] $*" >&2; }
die() { printf '\n' >&2; ui error "[ERROR] $*" >&2; exit 1; }
[[ "$SOCKS_TFO" == true || "$SOCKS_TFO" == false ]] || die 'SOCKS_TFO must be true or false.'
[[ "$CERT_VALID_DAYS" =~ ^[1-9][0-9]*$ ]] || die 'CERT_VALID_DAYS 必须是正整数。'
[[ "$CERT_WARN_DAYS" =~ ^[0-9]+$ ]] || die 'CERT_WARN_DAYS 必须是非负整数。'
[[ "$HY2_BBR_PROFILE" == standard || "$HY2_BBR_PROFILE" == conservative || "$HY2_BBR_PROFILE" == aggressive ]] || die 'HY2_BBR_PROFILE 必须是 standard、conservative 或 aggressive。'
case "$LOG_LEVEL" in
  trace|debug|info|warn|error|fatal|panic) ;;
  *) die 'LOG_LEVEL 必须是 trace、debug、info、warn、error、fatal 或 panic。' ;;
esac
# Snapshot before the first mutation; keep backups if restoration itself fails.
begin_transaction() {
  local mode="$1" path index=0
  [[ ${STAGING:-0} != 1 ]] || mode=files
  shift
  [[ -z "$TRANSACTION" ]] || die "已有未完成的配置操作。"
  [[ -n "$TEMP" ]] || TEMP="$(mktemp -d)"
  if [[ "$mode" != files ]]; then
    if systemctl is-active --quiet "$UNIT"; then WAS_ACTIVE=1; fi
    local enabled
    enabled="$(systemctl is-enabled "$UNIT" 2>/dev/null || true)"
    case "$enabled" in
      enabled) WAS_ENABLED=1 ;;
      enabled-runtime) die 'Runtime-only service enablement is unsupported; configure persistent service state first.' ;;
      masked|masked-runtime) die "${UNIT} is masked; unmask it explicitly before configuring." ;;
    esac
  fi
  for path in "$@"; do
    [[ ! -L "$path" ]] || die "Refusing to modify symlinked deployment path: $path"
    ROLLBACK_PATHS+=("$path")
    if [[ -e "$path" ]]; then
      cp -a -- "$path" "$TEMP/$index"
      if [[ "$mode" == uninstall && "$path" == "$APP" ]]; then
        rm -f "$TEMP/$index/cache.db"
      fi
      ROLLBACK_EXISTS+=(1)
    else
      ROLLBACK_EXISTS+=(0)
    fi
    index=$((index + 1))
  done
  TRANSACTION="$mode"
}

cleanup() {
  local rc=$? failed=0 index path
  trap - EXIT INT TERM
  set +e
  if [[ ${STAGING:-0} == 1 ]]; then
    if [[ -n "$TEMP" ]]; then rm -rf -- "$TEMP"; fi
    exit "$rc"
  fi
  if [[ -n "$TRANSACTION" ]]; then
    log 'Operation failed; restoring firewall, configuration and service state.'
    rollback_firewall || failed=1
    if (( HOP_TRANSACTION )); then
      if [[ -f "$APP/hopping.json" ]]; then hopping_runtime stop || failed=1; fi
      if [[ -f "$HOP_UNIT_FILE" ]]; then
        systemctl stop "$HOP_UNIT" || failed=1
        systemctl disable "$HOP_UNIT" || failed=1
      fi
    fi
    if [[ "$TRANSACTION" != files ]] && systemctl cat "$UNIT" >/dev/null 2>&1; then
      systemctl stop "$UNIT" || failed=1
    fi
    if (( PACKAGE_ROLLBACK )); then
      restore_package || failed=1
      systemctl stop "$UNIT" || failed=1
    fi
    for index in "${!ROLLBACK_PATHS[@]}"; do
      path="${ROLLBACK_PATHS[$index]}"
      if rm -rf -- "$path"; then
        if [[ ${ROLLBACK_EXISTS[$index]} == 1 ]]; then
          cp -a -- "$TEMP/$index" "$path" || failed=1
        fi
      else
        failed=1
      fi
    done
    if (( HOP_TRANSACTION )); then
      systemctl daemon-reload || failed=1
      if (( HOP_WAS_ENABLED )); then systemctl enable "$HOP_UNIT" || failed=1; fi
      if (( HOP_WAS_ACTIVE )); then systemctl start "$HOP_UNIT" && systemctl is-active --quiet "$HOP_UNIT" || failed=1; fi
    fi
    if [[ "$TRANSACTION" != files ]] && systemctl cat "$UNIT" >/dev/null 2>&1; then
      if (( WAS_ENABLED )); then systemctl enable "$UNIT" || failed=1
      else systemctl disable "$UNIT" || failed=1; fi
    fi
    if [[ "$TRANSACTION" != files ]] && (( WAS_ACTIVE )); then
      systemctl restart "$UNIT" && sleep 2 && systemctl is-active --quiet "$UNIT" || failed=1
    fi
    if (( failed )); then
      ui error "ERROR: Rollback incomplete. Backups retained at $TEMP; inspect ${UNIT} manually." >&2
      rc=1
    else
      warn 'Rollback completed. Installed packages/dependencies are retained.'
    fi
  fi
  if (( ! failed )) && [[ -n "$TEMP" ]]; then rm -rf -- "$TEMP"; fi
  exit "$rc"
}
trap cleanup EXIT
trap 'ui error "[ERROR] Command failed at line $LINENO (exit $?)." >&2' ERR
trap 'exit 130' INT
trap 'exit 143' TERM

# Command help and installation prerequisites.
usage() {
  cat <<'EOF'
用法：以 root 身份运行 bash sing-box-deploy.sh [命令]
  不带参数 / menu       进入中文管理菜单（非交互运行时显示帮助）
  install              安装 VLESS Reality + Hysteria2 + AnyTLS + TUIC 及三组代理
  apply                应用全部待应用修改并重启服务（失败自动回滚，保留待应用修改）
  discard-pending      丢弃待应用修改；非交互需 DISCARD_CONFIRM=YES
  summary              显示真实服务/版本、已确认运行配置及待应用配置
  firewall-status / firewall-details  查看防火墙状态及规则详情
  firewall-auto true|false  开关脚本自动放行（保留现有规则，下次 apply 生效）
  firewall-enable / firewall-disable [ufw|firewalld]  系统开关，需明确 YES 确认
    启用前检测并预先放行实际 SSH 端口；无法确认或核实放行规则时拒绝启用。
  set-ports            修改端口，默认保留当前值；可传 VLESS_PORT、HY2_PORT、ANYTLS_PORT、TUIC_PORT
  add-anytls           为旧部署添加 AnyTLS；可传 ANYTLS_PORT、NEW_ANYTLS_SNI、NEW_ANYTLS_PASS
  add-tuic             暂存生成 TUIC（独立 UUID/密码/证书），可传 TUIC_PORT、NEW_TUIC_SNI
  edit-field 标签 /字段路径 [JSON值|:remove]  逐项编辑或移除字段，保存后需 apply
  disable-hopping      暂存关闭 HY2 跳跃规则，保存后需 apply
  edit-protocol [标签] [JSON文件]  完整编辑现有入站所有字段；默认 nano，VISUAL / EDITOR 可覆盖
  set-protocol-defaults 更新已有协议的 TLS 10s、HY2 ignore_client_bandwidth 及 TUIC 默认参数
  set-log-level [级别] 暂存 sing-box 日志级别；默认 warn，避免记录访问域名，应用后生效
  renew-certs          暂存续期托管自签证书；保留私钥/SNI/SAN，指纹改变，手动 apply 后重导客户端
  SERVER_IP=公网地址    可覆盖客户端导出地址；不写回服务端配置
  export-yaml          可选导出 Clash/Mihomo proxies.yaml；普通生成/导出只在结果中显示 YAML
  set-hy2-bbr          设置 HY2 BBR 档位，默认 standard；可传 HY2_BBR_PROFILE；保存后需 apply
  set-hopping          HY2 端口跳跃，支持 HY2_HOP_PORTS、HY2_HOP_EXCLUDE、HY2_HOP_INTERVAL
  update               通过官方软件源更新 sing-box，先取得当前版本回滚包
  backup [文件路径]    私密配置备份（默认 /var/backups/sing-box-deploy）
  restore [备份路径]   校验后恢复配置、凭据、证书和跳跃设置；不替换内核
  uninstall            备份后卸载；非交互需 UNINSTALL_CONFIRM=YES
  set-sni              修改 SNI；非交互使用 NEW_REALITY_DOMAIN、NEW_HY2_SNI、NEW_ANYTLS_SNI
  set-credentials      修改凭据；可传 NEW_UUID、NEW_HY2_PASS、NEW_HY2_OBFS_PASS、NEW_ANYTLS_PASS
  rotate-credentials   重新生成全部节点凭据，旧节点将失效
  regenerate [协议]    单独重新生成 vless / hysteria2 / anytls / tuic 的凭据及托管证书；保留端口和 SNI
  set-tfo              开关三组代理 TFO；非交互传 SOCKS_TFO=true/false
  set-ai-proxy / set-google-proxy / set-other-proxy   修改单组 SOCKS5 / HTTPS；旧 *-socks 命令兼容
  configure-proxies    修改三组代理；默认沿用已安装配置（configure-socks 兼容）
  *_PROXY_PROTOCOL=socks5|https  分组协议；*_PROXY_HOST/PORT/USER/PASS；*_PROXY_SNI 为 HTTPS SNI
  源码 DEFAULT_{AI,GOOGLE,OTHER}_PROXY_PROTOCOL/SNI 可设置首次安装默认值；HTTPS 默认校验证书。
  show / show-json / show-yaml   查看节点参数、分享链接、JSON 或 Clash/Mihomo proxies（含密码）
  export               导出到 /var/lib/sing-box/deployment/client
  start / stop / restart / status / logs / check    服务和连接检查
  setup-manager        安装或更新快捷管理命令 sb-manager

终端使用颜色强调状态与风险；重定向、TERM=dumb 或 NO_COLOR 时输出纯文本。
源码顶部 DEFAULT_* 是首次安装默认值，环境变量优先，交互输入可覆盖。
证书默认有效期 CERT_VALID_DAYS=825；CERT_WARN_DAYS=30 天内在状态/概览中预警。
自有证书可用 tls.certificate_path / tls.key_path 或内嵌 PEM；续期命令不会改写外部/内嵌/ACME 证书。
端口、TFO 等默认值读取源码顶部 DEFAULT_* 与环境变量；普通修改沿用当前值并保留未选择的凭据。
协议、代理出口和跳跃设置的修改仅保存到待应用区，执行 apply 才更新服务、防火墙和跳跃规则。
config.json 是节点配置依据；client 目录仅为可删除、可重新生成的导出结果，不参与读取服务端设置。
普通 show/export 从已保存配置即时生成资料；通配监听地址无法直接确定公网地址，显式导出时可探测或用 SERVER_IP 指定。
待应用修改及其导出结果位于 deployment/pending，应用前不要导入。
安装支持三组 *_PROXY_* 通用参数；兼容 AI_SOCKS_*、GOOGLE_SOCKS_*、OTHER_SOCKS_*；支持 SERVER_IP。
LOG_LEVEL 默认 warn，避免记录访问域名；REALITY_DOMAIN 可固定握手域名，留空自动尝试备选列表。
请勿把密码放入命令参数或公开日志；填写凭据后的源码也应妥善保护。
UFW/firewalld 放行规则持久化；裸 nftables/iptables 仅当前运行时生效。
跳跃规则会通过独立 systemd 服务持久化，只转发发往本机的 UDP 流量。
云安全组需单独开放跳跃端口。旧部署无归属记录的旧端口规则不会自动删除。
操作失败恢复配置、节点资料和服务状态；软件包及依赖保留。

EOF
}

need_root() { [[ ${EUID:-$(id -u)} -eq 0 ]] || die 'Please run as root (sudo bash ...).'; }
check_os() {
  [[ -r /etc/os-release ]] || die 'Cannot identify Linux distribution.'
  [[ -d /run/systemd/system ]] || die 'A Linux distribution using systemd is required.'
  if command -v apt-get >/dev/null 2>&1; then
    PKG=apt
  elif command -v dnf5 >/dev/null 2>&1; then
    PKG=dnf5
  elif command -v dnf >/dev/null 2>&1; then
    PKG=dnf4
  else
    die 'Supported installation paths: apt-get (Debian/Ubuntu) or DNF (Fedora/RHEL-compatible).'
  fi
}

install_deps() {
  if [[ $PKG == apt ]]; then
    DEBIAN_FRONTEND=noninteractive apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends curl ca-certificates openssl python3 iproute2 diffutils
  elif [[ $PKG == dnf5 ]]; then
    dnf5 install -y curl ca-certificates openssl python3 iproute diffutils
  else
    dnf install -y curl ca-certificates openssl python3 iproute diffutils
  fi
}

# Official installation documented at https://sing-box.sagernet.org/installation/package-manager/
# Repository-managed stable packages; never download or overwrite the executable manually.
install_sing_box_official() {
  log 'Installing sing-box stable via official repository'
  if [[ $PKG == apt ]]; then
    install -d -m 0755 /etc/apt/keyrings
    curl -fsSL --retry 2 --connect-timeout 10 --max-time 90 https://sing-box.app/gpg.key -o /etc/apt/keyrings/sagernet.asc
    chmod 0644 /etc/apt/keyrings/sagernet.asc
    cat > /etc/apt/sources.list.d/sagernet.sources <<'EOF'
Types: deb
URIs: https://deb.sagernet.org/
Suites: *
Components: *
Enabled: yes
Signed-By: /etc/apt/keyrings/sagernet.asc
EOF
    DEBIAN_FRONTEND=noninteractive apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y sing-box
  elif [[ $PKG == dnf5 ]]; then
    curl -fsSL --retry 2 --connect-timeout 10 --max-time 90 https://sing-box.app/sing-box.repo -o /etc/yum.repos.d/sing-box.repo
    dnf5 install -y sing-box
  else
    curl -fsSL --retry 2 --connect-timeout 10 --max-time 90 https://sing-box.app/sing-box.repo -o /etc/yum.repos.d/sing-box.repo
    dnf install -y sing-box
  fi
  [[ -x "$BIN" ]] || die "Installed sing-box binary not found: $BIN"
  systemctl cat "$UNIT" >/dev/null 2>&1 || die "Official package does not provide ${UNIT}"
  "$BIN" version
  # Features used by this script require sing-box 1.14 or newer.
  local ver major minor
  ver="$("$BIN" version | sed -n '1s/.*version //p')"
  major="${ver%%.*}"
  minor="${ver#*.}"; minor="${minor%%.*}"
  [[ $major =~ ^[0-9]+$ && $minor =~ ^[0-9]+$ ]] || die "Cannot parse sing-box version: ${ver}"
  (( major > 1 || (major == 1 && minor >= 14) )) || die "sing-box >= 1.14 is required (installed: ${ver})"
}

# Protocol inputs, credentials, certificates and initial configuration.
show_occupied_ports() {
  OCCUPIED_PORTS=''
  local count=0
  printf '\n' >&2
  ui title '  ╭─ 当前已占用端口 · TCP / UDP ──────────────' >&2
  if ! command -v ss >/dev/null; then
    warn '无法读取占用情况：未安装 ss，请安装 iproute2 / iproute 后再核实端口。'
    return 0
  fi
  OCCUPIED_PORTS="$(ss -H -lntup)" || { warn '读取端口失败，请先检查系统网络工具。'; return 1; }
  if [[ -n "$OCCUPIED_PORTS" ]]; then
    count="$(printf '%s\n' "$OCCUPIED_PORTS" | grep -c '[^[:space:]]' || true)"
    ui muted "  │  共 ${count:-0} 条监听记录" >&2
    printf '  %s\n' "$OCCUPIED_PORTS" >&2
  else
    ui muted '  │  当前没有监听端口' >&2
  fi
  ui muted '  ╰─ TCP 与 UDP 分别判断；本机占用情况不代表云安全组已放行。' >&2
} >&2

read_ports() {
  show_occupied_ports
  local name value answer
  local -a names=("$@")
  if (( ${#names[@]} == 0 )); then names=(VLESS_PORT HY2_PORT ANYTLS_PORT TUIC_PORT); fi
  for name in "${names[@]}"; do
    [[ ( "$name" != ANYTLS_PORT && "$name" != TUIC_PORT ) || -n "${!name}" ]] || continue
    value="${!name}"
    if [[ -t 0 ]]; then
      read -r -p "${name} 监听端口 [$value]：" answer
      value="${answer:-$value}"
    fi
    # shellcheck disable=SC2015 # Both validation conditions must succeed; otherwise fail.
    [[ "$value" =~ ^[0-9]{1,5}$ ]] && ((10#$value >= 1 && 10#$value <= 65535)) || die "Invalid ${name} (1-65535)."
    printf -v "$name" '%s' "$((10#$value))"
  done
  [[ ${STAGING:-0} == 1 || -z "$ANYTLS_PORT" || "$ANYTLS_PORT" != "$VLESS_PORT" ]] || die 'AnyTLS 与 VLESS 不能使用相同 TCP 端口。'
  [[ ${STAGING:-0} == 1 || -z "$TUIC_PORT" || "$TUIC_PORT" != "$HY2_PORT" ]] || die 'TUIC 与 Hysteria2 不能使用相同 UDP 端口。'
}

# Each group selects SOCKS5 or HTTPS; legacy variable names remain compatible.
read_socks_profile() {
  show_occupied_ports
  local profile="$1" label prefix generic key fallback host port user pass answer protocol sni tls='{}' http='{}'
  label="${profile^}"
  prefix="${profile^^}_SOCKS"
  generic="${profile^^}_PROXY"
  local -a current=()
  if [[ -f "$CONFIG" ]]; then
    mapfile -d '' -t current < <(node_config proxy "$profile")
    [[ ${#current[@]} == 9 && "${current[8]}" == READY ]] || die '无法读取当前代理出口配置。'
    # shellcheck disable=SC2034 # Read through indirect variable names below.
    local DEFAULT_HOST="${current[0]}" DEFAULT_PORT="${current[1]}" DEFAULT_USER="${current[2]}" DEFAULT_PASS="${current[3]}"
    if [[ -n "${current[4]}" ]]; then
      for key in HOST PORT USER PASS; do
        fallback="DEFAULT_$key"
        printf -v "DEFAULT_${prefix}_$key" '%s' "${!fallback}"
      done
    fi
    tls="${current[6]}"; http="${current[7]}"
  fi
  key="${prefix}_HOST"; fallback="DEFAULT_${key}"; host="${!key-${!fallback}}"
  key="${prefix}_PORT"; fallback="DEFAULT_${key}"; port="${!key-${!fallback}}"
  key="${prefix}_USER"; fallback="DEFAULT_${key}"; user="${!key-${!fallback}}"
  key="${prefix}_PASS"; fallback="DEFAULT_${key}"; pass="${!key-${!fallback}}"
  key="${generic}_HOST"; host="${!key-$host}"
  key="${generic}_PORT"; port="${!key-$port}"
  key="${generic}_USER"; user="${!key-$user}"
  key="${generic}_PASS"; pass="${!key-$pass}"
  key="${generic}_PROTOCOL"; fallback="DEFAULT_$key"; protocol="${!key-${current[4]:-${!fallback}}}"
  key="${generic}_SNI"; fallback="DEFAULT_$key"; sni="${!fallback}"
  if [[ -n "${current[4]:-}" ]]; then sni="${current[5]}"; fi
  sni="${!key-$sni}"
  if [[ -t 0 ]]; then
    read -r -p "${label} 出口协议 socks5 / https [$protocol]：" answer
    protocol="${answer:-$protocol}"
  fi
  protocol="${protocol,,}"
  [[ "$protocol" == socks5 || "$protocol" == https ]] || die '出口协议必须是 socks5 或 https。'
  if [[ -t 0 ]]; then
    read -r -p "${label} ${protocol^^} 地址${host:+ [$host]}：" answer
    host="${answer:-$host}"
    read -r -p "${label} ${protocol^^} 端口${port:+ [$port]}：" answer
    port="${answer:-$port}"
    read -r -p "${label} 用户名${user:+ [$user]}（HTTPS 可留空，:clear 清除认证）：" answer
    if [[ "$protocol" == https && "$answer" == :clear ]]; then user=''; pass=''
    else user="${answer:-$user}"; fi
    read -r -s -p "${label} 密码（隐藏输入，回车保留当前值）：" answer
    printf '\n' >&2
    pass="${answer:-$pass}"
    if [[ "$protocol" == https ]]; then
      read -r -p "${label} HTTPS SNI [${sni:-$host}]：" answer
      sni="${answer:-$sni}"
    fi
  fi
  [[ -n "$host" && "$host" =~ ^[a-zA-Z0-9.:-]+$ ]] || die "Invalid ${label} proxy host."
  # shellcheck disable=SC2015 # Both validation conditions must succeed; otherwise fail.
  [[ "$port" =~ ^[0-9]{1,5}$ ]] && ((10#$port >= 1 && 10#$port <= 65535)) || die "Invalid ${label} proxy port (1-65535)."
  if [[ "$protocol" == socks5 ]]; then
    [[ -n "$user" && -n "$pass" ]] || die "${label} SOCKS username/password cannot be empty."
    tls='{}'; http='{}'
  else
    [[ "$user" != *:* ]] || die 'HTTPS Basic 认证用户名不能包含冒号。'
    [[ -z "$sni" || "$sni" =~ ^[a-zA-Z0-9.:-]+$ ]] || die 'HTTPS SNI 必须是域名或 IP 地址。'
  fi
  export "${prefix}_HOST=$host" "${prefix}_PORT=$((10#$port))" "${prefix}_USER=$user" "${prefix}_PASS=$pass"
  export "${generic}_PROTOCOL=$protocol" "${generic}_SNI=${sni:-$host}" "${generic}_TLS=$tls" "${generic}_HTTP=$http"
}

# Check proxy authentication and CONNECT without placing credentials in argv/logs.
check_socks() {
  local key="${1^^}_PROXY_PROTOCOL"
  log "Checking $1 ${!key:-socks5} authentication and outbound connectivity"
  SOCKS_PROFILE="$1" python_module network check_proxy
}

forget_socks() {
  local group
  for group in AI GOOGLE OTHER; do
    unset "${group}_SOCKS_PASS" "${group}_SOCKS_USER" "${group}_PROXY_PASS" "${group}_PROXY_USER"
  done
}

public_ipv4_candidate_is_global() {
  local candidate="$1"
  [[ "$candidate" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
  SERVER_IP="$candidate" python_module network public_ipv4 >/dev/null 2>&1
}

# Try the local egress address first, then independent HTTPS echo services.
detect_public_ipv4() {
  local candidate source
  local -a sources=(
    'https://api.ipify.org'
    'https://icanhazip.com'
    'https://ifconfig.me/ip'
    'https://checkip.amazonaws.com'
  )
  if command -v ip >/dev/null 2>&1; then
    candidate="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i=1; i<NF; i++) if ($i == "src") {print $(i+1); exit}}')" || candidate=''
    if [[ -n "$candidate" ]] && public_ipv4_candidate_is_global "$candidate"; then
      printf '%s\n' "$candidate"
      return 0
    fi
  fi
  for source in "${sources[@]}"; do
    candidate="$(curl -4fsSL --connect-timeout 5 --max-time 12 "$source" 2>/dev/null | tr -d '[:space:]' || true)"
    if [[ -n "$candidate" ]] && public_ipv4_candidate_is_global "$candidate"; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

public_ipv4() {
  SERVER_IP="${SERVER_IP:-}"
  if [[ -n "$SERVER_IP" ]]; then
    export SERVER_IP
    python_module network public_ipv4
  else
    SERVER_IP="$(detect_public_ipv4)" || SERVER_IP=''
    [[ -n "$SERVER_IP" ]] || die 'Cannot detect a public IPv4 from the local route or the configured HTTP sources; set SERVER_IP=<your server public IP> and retry.'
    export SERVER_IP
  fi
  log "Detected public IPv4: $SERVER_IP"
}

reality_target_supported() {
  local domain="$1" output
  output="$(timeout 12 openssl s_client -connect "${domain}:443" \
    -servername "$domain" -tls1_3 -alpn h2 -verify_hostname "$domain" \
    -verify_return_error </dev/null 2>&1)" || return 1
  grep -qi 'Verify return code: 0 (ok)' <<< "$output" || return 1
  grep -qi 'ALPN protocol: h2' <<< "$output"
}

check_reality_target() {
  local requested="${1:-${REALITY_DOMAIN_REQUEST:-}}" domain
  local -a candidates=()
  local seen=' '
  if [[ -n "$requested" ]]; then
    candidates=("$requested")
  else
    candidates=("$DEFAULT_REALITY_DOMAIN" "${DEFAULT_REALITY_FALLBACK_DOMAINS[@]}")
  fi
  for domain in "${candidates[@]}"; do
    [[ -n "$domain" ]] || continue
    [[ "$seen" != *" $domain "* ]] || continue
    seen+="$domain "
    log "Testing third-party Reality handshake target ${domain}:443 (TLS 1.3 + h2)"
    if reality_target_supported "$domain"; then
      REALITY_DOMAIN="$domain"
      export REALITY_DOMAIN
      log "Reality handshake target verified: ${domain}:443"
      return 0
    fi
    warn "Reality handshake target ${domain}:443 failed TLS 1.3, h2 or certificate validation; trying the next candidate."
  done
  die "No usable Reality handshake target among: ${candidates[*]}. Set REALITY_DOMAIN to a domain that supports TLS 1.3 and h2."
}

download_rules() {
  mkdir -p "$APP/rules"
  local name url
  local -a entries=("$@")
  if (( ${#entries[@]} == 0 )); then entries=(ai google youtube); fi
  for name in "${entries[@]}"; do
    case "$name" in
      ai) url="$AI_URL" ;; google) url="$GOOGLE_URL" ;; youtube) url="$YOUTUBE_URL" ;;
    esac
    log "Downloading ${name}.srs"
    curl -fLSs --retry 2 --connect-timeout 10 --max-time 90 \
      "$url" -o "$TEMP/$name.srs" || die "Failed to download ${name}.srs"
    [[ $(wc -c < "$TEMP/$name.srs") -gt 100 ]] || die "${name}.srs is too small."
    # Header of sing-box .srs binary format is ASCII 'SRS' plus a version byte.
    [[ "$(head -c 3 "$TEMP/$name.srs")" == SRS ]] || die "${name}.srs is not a sing-box binary ruleset."
    install -m 0644 "$TEMP/$name.srs" "$APP/rules/$name.srs"
  done
}

new_credentials() {
  local protocol="${1:-all}" kp
  if [[ "$protocol" == all || "$protocol" == vless ]]; then
    UUID="$(cat /proc/sys/kernel/random/uuid)"
    kp="$("$BIN" generate reality-keypair)"
    REALITY_PRIVATE="$(sed -n 's/^PrivateKey: *//p' <<< "$kp" | head -n 1)"
    REALITY_PUBLIC="$(sed -n 's/^PublicKey: *//p' <<< "$kp" | head -n 1)"
    [[ -n "$REALITY_PRIVATE" && -n "$REALITY_PUBLIC" ]] || die 'Failed to parse sing-box reality-keypair output.'
    SHORT_ID="$(openssl rand -hex 8)"
    export UUID REALITY_PRIVATE REALITY_PUBLIC SHORT_ID
  fi
  if [[ "$protocol" == all || "$protocol" == hysteria2 ]]; then
    HY2_PASS="$(openssl rand -hex 24)"
    HY2_OBFS_PASS="$(openssl rand -hex 24)"
    export HY2_PASS HY2_OBFS_PASS
  fi
  if [[ "$protocol" == all || "$protocol" == anytls ]]; then
    ANYTLS_PASS="$(openssl rand -base64 32)"
    export ANYTLS_PASS
  fi
  if [[ "$protocol" == all || "$protocol" == tuic ]]; then
    TUIC_UUID="$(cat /proc/sys/kernel/random/uuid)"
    TUIC_PASS="$(openssl rand -base64 32)"
    export TUIC_UUID TUIC_PASS
  fi
}

certificate_status() {
  export CONFIG CERT_WARN_DAYS
  local index result=0 level
  local -a records=()
  mapfile -d '' -t records < <(python_module certificates status)
  if (( ${#records[@]} < 1 || (${#records[@]}-1)%2 != 0 )) || [[ "${records[-1]}" != READY ]]; then
    ui error '证书到期检查未完整执行，请检查 Python 和配置文件。' >&2
    return 1
  fi
  for ((index=0; index<${#records[@]}-1; index+=2)); do
    level="${records[index]}"
    case "$level" in
      error) result=1 ;;
      info|success|warning) ;;
      *) ui error '证书到期检查返回了无效状态。' >&2; return 1 ;;
    esac
    ui "$level" "${records[index+1]}"
  done
  return "$result"
}

make_hy2_certificate() { make_tls_certificate hy2 "${HY2_SNI:-$REALITY_DOMAIN}"; }

make_tls_certificate() {
  local name="$1" sni="$2" san
  [[ ! -L "$APP/tls/$name.crt" && ! -L "$APP/tls/$name.key" ]] || die '证书或私钥是符号链接，请先确认外部证书管理方式。'
  san="$(python_module certificates san "$sni")"
  log "正在生成 $name 自签证书：$sni"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -sha256 \
    -days "$CERT_VALID_DAYS" -nodes \
    -keyout "$APP/tls/$name.key" -out "$APP/tls/$name.crt" \
    -subj "/CN=${sni}" -addext "subjectAltName=${san}" >/dev/null
  if [[ "$san" == IP:* ]]; then
    openssl verify -CAfile "$APP/tls/$name.crt" -verify_ip "$sni" "$APP/tls/$name.crt"
  else
    openssl verify -CAfile "$APP/tls/$name.crt" -verify_hostname "$sni" "$APP/tls/$name.crt"
  fi
  chmod 0600 "$APP/tls/$name.key"
  chmod 0644 "$APP/tls/$name.crt"
}

# Renew only managed self-signed material in the pending tree; never replace external files.
renew_certificates() {
  [[ ${STAGING:-0} == 1 ]] || die '证书续期必须通过 renew-certs 暂存，再手动应用。'
  local renewed
  renewed="$(python_module certificates renew "$CONFIG" "$APP/tls" "$CERT_VALID_DAYS")" || return "$?"
  if [[ "$renewed" == 0 ]]; then
    log '没有可续期的托管自签证书；自有证书和 ACME 证书应由原管理方式续期。'
    return 0
  fi
  check_configuration
  export_client_files
  success "已暂存 $renewed 张自签证书的续期。"
  warn '证书指纹已经改变，指纹校验策略保持不变。手动应用后必须重新导出并导入客户端节点。'
}

write_jsons() {
  export APP CONFIG REALITY_DOMAIN LOG_LEVEL AI_URL GOOGLE_URL YOUTUBE_URL VLESS_PORT HY2_PORT ANYTLS_PORT ANYTLS_SNI ANYTLS_PASS HY2_BBR_PROFILE SOCKS_TFO TUIC_PORT TUIC_UUID TUIC_PASS TUIC_SNI DEFAULT_TLS_HANDSHAKE_TIMEOUT
  python_module configuration generate
  check_configuration || die 'sing-box check failed. Service was not started.'
  node_config export
}

configuration_listeners() {
  python_module configuration listeners "${1:-$CONFIG}"
}

check_listeners() {
  local listeners network port label output
  listeners="$(configuration_listeners)"
  while read -r network port label; do
    [[ -n "$port" ]] || continue
    if [[ "$network" == udp ]]; then output="$(ss -H -lunp "( sport = :$port )")"
    else output="$(ss -H -ltnp "( sport = :$port )")"; fi
    [[ "$output" == *'"sing-box"'* ]] || die "服务未监听 $label $network/$port。"
  done <<< "$listeners"
}

start_official_unit() {
  # Official package unit reads /etc/sing-box/*.json with -C; keep only config.json there.
  systemctl daemon-reload
  systemctl restart "$UNIT"
  sleep 2
  systemctl is-active --quiet "$UNIT" || {
    journalctl -u "$UNIT" -n 40 --no-pager >&2 || true
    die "${UNIT} failed to start"
  }
  check_listeners
  systemctl enable "$UNIT"
  record_runtime_state
}

# Firewall management and ownership.
# Add rules through the active manager; only journal additions made by this run.
open_firewall() {
  [[ ${STAGING:-0} != 1 ]] || return 0
  local automatic
  automatic="$(firewall_auto)" || return
  if [[ "$automatic" == false ]]; then
    warn '自动放行端口已关闭；现有规则保持不变，请自行确认端口可达。'
    return 0
  fi
  local ufw_active=0 firewalld_active=0 output rc entry zone zones mode port proto rules chains family table chain
  local -a endpoints=() desired=("${VLESS_NETWORK:-tcp}/$VLESS_PORT" "udp/$HY2_PORT") previous=()
  [[ -z "$ANYTLS_PORT" ]] || desired+=("tcp/$ANYTLS_PORT")
  [[ -z "$TUIC_PORT" ]] || desired+=("udp/$TUIC_PORT")
  [[ -z "${1:-}" ]] || previous+=("${5:-tcp}/$1")
  [[ -z "${2:-}" ]] || previous+=("udp/$2")
  [[ -z "${3:-}" ]] || previous+=("tcp/$3")
  [[ -z "${4:-}" ]] || previous+=("udp/$4")
  # Explicitly enabling automation also reconciles ports changed while it was disabled.
  [[ ! -f "$APP/firewall-settings.json" ]] || previous=()
  local configured network label
  if [[ -f "$CONFIG" ]]; then
    configured="$(configuration_listeners)"
    desired=()
    while read -r network port label; do
      [[ -z "$port" ]] || desired+=("$network/$port")
    done <<< "$configured"
  fi
  local candidate known
  local -A scheduled=()
  for candidate in "${desired[@]}"; do
    [[ ! ${scheduled[$candidate]+present} ]] || continue
    scheduled[$candidate]=1
    known=0
    for entry in "${previous[@]}"; do [[ "$entry" != "$candidate" ]] || known=1; done
    (( known )) || endpoints+=("${candidate#*/}/${candidate%/*}")
  done
  (( ${#endpoints[@]} )) || return 0
  if command -v ufw >/dev/null; then
    output="$(LC_ALL=C ufw status)"
    case "$output" in
      *'Status: active'*) ufw_active=1 ;;
      *'Status: inactive'*) ;;
      *) die 'Cannot determine UFW state.' ;;
    esac
  fi
  if command -v firewall-cmd >/dev/null; then
    if output="$(LC_ALL=C firewall-cmd --state 2>&1)"; then
      [[ "$output" == running ]] || die "Unexpected firewalld state: $output"
      firewalld_active=1
    else
      rc=$?
      [[ $rc == 252 && "$output" == *'not running'* ]] || die "Cannot determine firewalld state: $output"
    fi
  fi
  (( ufw_active + firewalld_active < 2 )) || die 'UFW and firewalld are both active; use one firewall manager before installing.'
  if (( ufw_active )); then
    rules="$(LC_ALL=C ufw status numbered)"
    output="$(python_module firewall ufw_missing "${endpoints[@]}" <<< "$rules")"
    while IFS= read -r entry; do
      [[ -n "$entry" ]] || continue
      FW_UNDO+=("ufw $entry")
      printf '%s\n' "${FW_UNDO[@]}" > "$TEMP/firewall.undo"
      port="${entry%/*}"; proto="${entry#*/}"
      output="$(LC_ALL=C ufw insert 1 allow proto "$proto" from 0.0.0.0/0 to 0.0.0.0/0 port "$port" comment "$FW_MARK")"
      [[ "$output" != *Skipping* ]] || die "UFW skipped inserting $entry due to an existing matching rule; inspect its policy."
    done <<< "$output"
    log 'UFW: requested ports allowed (persistent).'
    return
  fi
  if (( firewalld_active )); then
    # Include source-bound/interface-bound zones and the fallback default zone.
    output="$(firewall-cmd --get-active-zones)"
    zones="$(awk '/^[^[:space:]]/ {print $1}' <<< "$output")"
    zones+=$'\n'"$(firewall-cmd --get-default-zone)"
    zones="$(sort -u <<< "$zones")"
    while IFS= read -r zone; do
      [[ -n "$zone" ]] || continue
      for entry in "${endpoints[@]}"; do
        for mode in runtime permanent; do
          local -a args=("--zone=$zone")
          [[ "$mode" != permanent ]] || args+=(--permanent)
          if firewall-cmd "${args[@]}" "--query-port=$entry" >/dev/null; then
            continue
          else
            rc=$?
            [[ $rc == 1 ]] || die "Cannot query firewalld $mode $zone $entry (exit $rc)."
          fi
          FW_UNDO+=("firewalld $mode $zone $entry")
          printf '%s\n' "${FW_UNDO[@]}" > "$TEMP/firewall.undo"
          firewall-cmd "${args[@]}" "--add-port=$entry"
          firewall-cmd "${args[@]}" "--query-port=$entry" >/dev/null
        done
      done
    done <<< "$zones"
    log 'firewalld: requested ports allowed in active/default zones (runtime and permanent; no global reload).'
    return
  fi
  if command -v nft >/dev/null; then
    rules="$(nft -j list ruleset)"
    chains="$(python_module firewall nft_chains <<< "$rules")"
    if [[ -n "$chains" ]]; then
      printf '%s\n' "$FW_MARK" > "$TEMP/nft.marker"
      FW_NFT=1
      while read -r family table chain; do
        for entry in "${endpoints[@]}"; do
          port="${entry%/*}"; proto="${entry#*/}"
          nft insert rule "$family" "$table" "$chain" meta nfproto ipv4 "$proto" dport "$port" accept comment "\"$FW_MARK\""
        done
      done <<< "$chains"
      warn 'WARNING: Native nftables ports opened for this runtime only; persist them using your existing firewall loader before reboot.'
    fi
  fi
  if command -v iptables >/dev/null; then
    # nft-backed iptables uses the same rules already handled above.
    output="$(iptables --version)"
    if (( FW_NFT )) && [[ "$output" == *nf_tables* ]]; then return; fi
    rules="$(iptables -w -S INPUT)"
    if grep -Eq '^-P INPUT DROP$|^-A INPUT ' <<< "$rules"; then
      for entry in "${endpoints[@]}"; do
        port="${entry%/*}"; proto="${entry#*/}"
        FW_UNDO+=("iptables $proto $port")
        printf '%s\n' "${FW_UNDO[@]}" > "$TEMP/firewall.undo"
        iptables -w -I INPUT 1 -p "$proto" --dport "$port" -m comment --comment "$FW_MARK" -j ACCEPT
      done
      warn 'WARNING: Native iptables ports opened for this runtime only; persist them using your existing firewall loader before reboot.'
      return
    fi
  fi
  (( FW_NFT )) || log 'No active supported host input firewall detected; no firewall was enabled.'
}

rollback_firewall() {
  local index entry backend mode zone port proto rules handles family table chain handle rc failed=0
  if (( FW_NFT )); then
    if rules="$(nft -j list ruleset)"; then
      if handles="$(FW_MARK="$FW_MARK" python_module firewall nft_handles <<< "$rules")"; then
        while read -r family table chain handle; do
          [[ -n "$handle" ]] || continue
          nft delete rule "$family" "$table" "$chain" handle "$handle" || failed=1
        done <<< "$handles"
      else
        failed=1
      fi
    else
      failed=1
    fi
  fi
  for ((index=${#FW_UNDO[@]}-1; index>=0; index--)); do
    entry="${FW_UNDO[$index]}"
    read -r backend mode zone port <<< "$entry"
    case "$backend" in
      ufw)
        port="${mode%/*}"; proto="${mode#*/}"
        ufw --force delete allow proto "$proto" from 0.0.0.0/0 to 0.0.0.0/0 port "$port" comment "$FW_MARK" || failed=1 ;;
      firewalld)
        local -a args=("--zone=$zone")
        [[ "$mode" != permanent ]] || args+=(--permanent)
        if firewall-cmd "${args[@]}" "--query-port=$port" >/dev/null; then
          firewall-cmd "${args[@]}" "--remove-port=$port" || failed=1
        else
          rc=$?; [[ $rc == 1 ]] || failed=1
        fi ;;
      iptables)
        proto="$mode"; port="$zone"
        local -a rule=(INPUT -p "$proto" --dport "$port" -m comment --comment "$FW_MARK" -j ACCEPT)
        if iptables -w -C "${rule[@]}"; then
          iptables -w -D "${rule[@]}" || failed=1
        else
          rc=$?; [[ $rc == 1 ]] || failed=1
        fi ;;
    esac
  done
  if [[ -n "$FW_RESTORE" && -f "$FW_RESTORE" ]]; then
    update_firewall_ownership restore || failed=1
  fi
  return "$failed"
}

# This preference changes future port management, never existing rules or the service.
firewall_auto() {
  python_module firewall automatic "$APP/firewall-settings.json" "$DEFAULT_FIREWALL_AUTO" "${1:-}" "$CONFIG"
}

set_firewall_auto() {
  need_root
  local value="${1:-}" current answer
  current="$(firewall_auto)"
  if [[ -z "$value" && -t 0 ]]; then
    ui info "当前自动放行端口：$current；关闭后保留现有规则。"
    read -r -p '1 开启，2 关闭，0 返回：' answer
    case "$answer" in 1) value=true ;; 2) value=false ;; 0) return 0 ;; *) die '无效选择。' ;; esac
  fi
  [[ "$value" == true || "$value" == false ]] || die '用法：firewall-auto true|false。'
  firewall_auto "$value" >/dev/null
  success "自动放行端口：$value。设置立即保存，现有规则不变；下次应用配置时生效。"
}

firewall_status() {
  need_root
  local automatic
  automatic="$(firewall_auto)"
  printf '\n'
  ui title '  ╭─ 防火墙状态 ──────────────────────────────'
  ui info "  │  脚本自动放行端口：$automatic"
  python_module firewall status "${1:-summary}" "$APP/firewall-owned.json" | sed 's/^/  │  /'
  ui muted '  ╰─ 云安全组不在本机防火墙状态内，请在云平台单独核对。'
}

# Only actual listeners can justify enabling a firewall; never assume TCP/22.
ssh_listening_ports() {
  local sockets effective=''
  command -v ss >/dev/null || die '无法检测 SSH：未安装 ss，拒绝启用系统防火墙。'
  sockets="$(ss -H -ltnp)" || die '无法读取 TCP 监听信息，拒绝启用系统防火墙。'
  if command -v sshd >/dev/null; then
    if ! effective="$(sshd -T 2>/dev/null)"; then
      warn '无法读取 sshd 有效配置；仅使用可确认的实际 SSH 监听。'
      effective=''
    fi
  fi
  SSH_LISTENERS="$sockets" SSH_EFFECTIVE_CONFIG="$effective" python_module firewall ssh_listeners
}

# SSH permits are deliberately not node-owned rules: uninstall/port edits must retain them.
firewall_allow_ssh() {
  local backend="$1" listeners="$2" family port ipv6=0 zone zones mode command_name
  local -a ports=() zone_list=() modes=() args=()
  local -A seen=()
  while read -r family port; do
    [[ "$family" != 6 ]] || ipv6=1
    [[ ! ${seen[$port]+present} ]] || continue
    seen[$port]=1;ports+=("$port")
  done <<< "$listeners"
  (( ${#ports[@]} )) || die '缺少已确认的 SSH 端口，拒绝启用系统防火墙。'
  if [[ "$backend" == ufw ]]; then
    if (( ipv6 )); then
      if ! python_module firewall ufw_ipv6 /etc/default/ufw
      then die 'UFW IPv6 检查未通过，系统防火墙保持不变。'; fi
    fi
    for port in "${ports[@]}"; do
      ufw insert 1 allow "$port/tcp" comment "$FW_SSH_MARK" || die 'SSH 放行规则写入失败，拒绝启用 UFW。'
    done
    # show added normalizes order; inspect the persisted per-family input chains instead.
    if ! python_module firewall ufw_ssh_rules /etc/ufw/user.rules /etc/ufw/user6.rules "$ipv6" "${ports[@]}"
    then die 'UFW SSH 放行规则检查未通过，拒绝启用。'; fi
  else
    local state rc
    if state="$(LC_ALL=C firewall-cmd --state 2>&1)"; then
      [[ "$state" == running ]] || die '无法识别 firewalld 状态，拒绝启用。'
      modes=(runtime permanent)
    else
      rc=$?
      [[ "$rc" == 252 && "$state" == *'not running'* ]] || die "无法读取 firewalld 状态：$state"
      command -v firewall-offline-cmd >/dev/null || die '缺少 firewall-offline-cmd，无法在启用前保护 SSH，拒绝启用。'
      modes=(offline)
    fi
    for mode in "${modes[@]}"; do
      command_name=firewall-cmd;args=()
      if [[ "$mode" == offline ]]; then command_name=firewall-offline-cmd
      elif [[ "$mode" == permanent ]]; then args+=(--permanent); fi
      zones="$("$command_name" "${args[@]}" --get-zones)" || die '无法读取 firewalld 区域，拒绝启用。'
      read -r -a zone_list <<< "${zones//$'\n'/ }"
      (( ${#zone_list[@]} )) || die '未找到 firewalld 区域，拒绝启用。'
      for zone in "${zone_list[@]}"; do
        [[ "$zone" =~ ^[a-zA-Z0-9_.-]+$ ]] || die 'firewalld 区域名称无效，拒绝启用。'
        for port in "${ports[@]}"; do
          "$command_name" "${args[@]}" "--zone=$zone" "--add-port=$port/tcp" || die 'SSH 放行规则写入失败，拒绝启用 firewalld。'
          "$command_name" "${args[@]}" "--zone=$zone" "--query-port=$port/tcp" >/dev/null || die '无法核实 SSH 放行规则，拒绝启用 firewalld。'
        done
      done
    done
    "$command_name" --check-config || die 'firewalld 持久配置检查失败，拒绝启用。'
  fi
  # A formerly node-owned permit may now also protect SSH; transfer it out of node cleanup.
  if ! python_module firewall release_ssh_ownership "$APP/firewall-owned.json" "$backend" "${ports[@]}"
  then die '无法将 SSH 保护规则与节点清理分离，拒绝启用。'; fi
  success 'SSH TCP 端口已预先放行并核实；保护规则将保留，不参与节点端口清理。'
}

firewall_system() {
  need_root
  local operation="${1:-}" backend="${2:-}" answer="${FIREWALL_CONFIRM:-}" choice output rc
  local -a managers=()
  local ssh_listeners='' ssh_family ssh_port
  [[ "$operation" == enable || "$operation" == disable ]] || die '系统防火墙操作必须是 enable 或 disable。'
  if command -v ufw >/dev/null; then managers+=(ufw); fi
  if command -v firewall-cmd >/dev/null; then managers+=(firewalld); fi
  (( ${#managers[@]} )) || die '仅支持 UFW/firewalld 系统开关；裸 nftables/iptables 请自行管理，脚本不会清空规则。'
  if [[ -z "$backend" ]]; then
    if (( ${#managers[@]} == 1 )); then backend="${managers[0]}"
    elif [[ -t 0 ]]; then
      for choice in "${!managers[@]}"; do ui item " $((choice+1)). ${managers[choice]}"; done
      ui item ' 0. 返回'
      read -r -p '选择系统防火墙：' choice
      [[ "$choice" != 0 ]] || return 0
      # shellcheck disable=SC2015 # Both validation conditions must succeed; otherwise fail.
      [[ "$choice" =~ ^[0-9]$ ]] && ((choice>=1 && choice<=${#managers[@]})) || die '无效选择。'
      backend="${managers[choice-1]}"
    else die '检测到多个管理工具，请指定 ufw 或 firewalld。'; fi
  fi
  case "$backend" in
    ufw) command -v ufw >/dev/null || die 'UFW 未安装。' ;;
    firewalld) command -v firewall-cmd >/dev/null || die 'firewalld 未安装。' ;;
    *) die '系统开关仅支持 ufw 或 firewalld。' ;;
  esac
  if [[ "$operation" == enable ]]; then
    if [[ "$backend" == ufw ]] && command -v firewall-cmd >/dev/null; then
      if output="$(LC_ALL=C firewall-cmd --state 2>&1)"; then
        die 'firewalld 已运行，请先关闭它后再启用 UFW。'
      else rc=$?; [[ "$rc" == 252 && "$output" == *'not running'* ]] || die "无法读取 firewalld 状态：$output"; fi
    elif [[ "$backend" == firewalld ]] && command -v ufw >/dev/null; then
      output="$(LC_ALL=C ufw status)"
      [[ "$output" != *'Status: active'* ]] || die 'UFW 已运行，请先关闭它后再启用 firewalld。'
      [[ "$output" == *'Status: inactive'* ]] || die '无法读取 UFW 状态。'
    fi
  fi
  if [[ "$operation" == enable ]]; then
    ssh_listeners="$(ssh_listening_ports)" || die 'SSH 检测未通过，系统防火墙保持不变。'
    ui title '已确认的 SSH 监听端口：'
    while read -r ssh_family ssh_port; do ui info "  IPv$ssh_family · TCP/$ssh_port"; done <<< "$ssh_listeners"
    if [[ "$backend" == firewalld ]]; then
      ui info '将预先在全部现有 firewalld 区域放行这些 SSH 端口，包含持久配置。'
    fi
  fi
  ui warning "$operation $backend 会立即修改整台服务器的防火墙及其持久状态。启用前会核实 SSH 保护；关闭会影响整机防护。"
  if [[ -t 0 ]]; then read -r -p '确认此系统操作？输入 YES：' answer; fi
  [[ "$answer" == YES ]] || die '未明确确认，系统防火墙保持不变；非交互操作需 FIREWALL_CONFIRM=YES。'
  if [[ "$operation" == enable ]]; then firewall_allow_ssh "$backend" "$ssh_listeners"; fi
  if [[ "$backend" == ufw ]]; then
    ufw --force "$operation"
    output="$(LC_ALL=C ufw status)"
    if [[ "$operation" == enable ]]; then [[ "$output" == *'Status: active'* ]] || die 'UFW 未成功开启。'
    else [[ "$output" == *'Status: inactive'* ]] || die 'UFW 未成功关闭。'; fi
  else
    systemctl "$operation" --now firewalld.service
    if output="$(LC_ALL=C firewall-cmd --state 2>&1)"; then
      [[ "$operation" == enable && "$output" == running ]] || die 'firewalld 未成功关闭。'
    else
      rc=$?; [[ "$operation" == disable && "$rc" == 252 && "$output" == *'not running'* ]] || die "firewalld 状态确认失败：$output"
    fi
  fi
  success "$backend 系统防火墙已执行 $operation；脚本自动放行开关未改变。"
}

firewall_hints() {
  [[ -f "$CONFIG" ]] || return 0
  local listeners proto port label endpoint port_summary=''
  local -A seen=()
  listeners="$(configuration_listeners)" || return 1
  while read -r proto port label; do
    [[ -n "$port" ]] || continue
    endpoint="${proto^^}/$port"
    [[ ! ${seen[$endpoint]+present} ]] || continue
    seen[$endpoint]=1
    port_summary+="${port_summary:+、}$endpoint"
  done <<< "$listeners"
  if [[ -n "$port_summary" ]]; then
    log "配置中的监听端口：$port_summary；请在云防火墙/安全组确认放行，公网可达性需客户端验证。"
  else
    log '当前配置没有 TCP/UDP 监听端口。'
  fi
}

# Installation, staged edits and manual application.
fresh_install() {
  need_root
  check_os
  [[ ! -e "$CONFIG" && ! -L "$CONFIG" ]] || die "$CONFIG exists. Refusing to overwrite any installed configuration."
  if systemctl is-active --quiet "$UNIT" 2>/dev/null; then
    die "${UNIT} already active; refusing to overwrite running service."
  fi
  [[ ! -e "$APP" && ! -L "$APP" ]] || die "$APP already exists; inspect the previous deployment before installing."
  [[ ! -e "$MANAGER" && ! -L "$MANAGER" ]] || die "$MANAGER 已存在，请先确认管理命令归属。"
  ANYTLS_PORT="${ANYTLS_PORT:-$DEFAULT_ANYTLS_PORT}"
  TUIC_PORT="${TUIC_PORT:-$DEFAULT_TUIC_PORT}"
  read_ports
  read_socks_profile ai
  read_socks_profile google
  read_socks_profile other
  if [[ -t 0 ]]; then
    printf '\n安装摘要：VLESS TCP/%s，Hysteria2 UDP/%s，AnyTLS TCP/%s，TUIC UDP/%s\n' "$VLESS_PORT" "$HY2_PORT" "$ANYTLS_PORT" "$TUIC_PORT"
    printf 'AI → %s %s:%s\nGoogle/YouTube → %s %s:%s\n其他 → %s %s:%s\n' "${AI_PROXY_PROTOCOL^^}" "$AI_SOCKS_HOST" "$AI_SOCKS_PORT" "${GOOGLE_PROXY_PROTOCOL^^}" "$GOOGLE_SOCKS_HOST" "$GOOGLE_SOCKS_PORT" "${OTHER_PROXY_PROTOCOL^^}" "$OTHER_SOCKS_HOST" "$OTHER_SOCKS_PORT"
    local confirm
    read -r -p '回车开始安装，输入 0 取消：' confirm
    [[ "$confirm" != 0 ]] || return 0
  fi
  install_deps
  if [[ -t 0 || -n "$HY2_HOP_PORTS" ]]; then prepare_hopping; fi
  check_socks ai
  check_socks google
  check_socks other
  local tcp udp
  tcp="$(ss -H -ltn "( sport = :$VLESS_PORT )")"
  udp="$(ss -H -lun "( sport = :$HY2_PORT )")"
  local anytls
  anytls="$(ss -H -ltn "( sport = :$ANYTLS_PORT )")"
  local tuic
  tuic="$(ss -H -lun "( sport = :$TUIC_PORT )")"
  if [[ -n "$tcp" || -n "$udp" || -n "$anytls" || -n "$tuic" ]]; then
    die "TCP/$VLESS_PORT, UDP/$HY2_PORT, TCP/$ANYTLS_PORT or UDP/$TUIC_PORT is already occupied; inspect ss -lntup."
  fi
  public_ipv4
  check_reality_target
  if [[ $PKG == apt ]]; then
    begin_transaction install /etc/sing-box "$APP" "$MANAGER" "$HOP_UNIT_FILE" /etc/apt/keyrings/sagernet.asc /etc/apt/sources.list.d/sagernet.sources
  else
    begin_transaction install /etc/sing-box "$APP" "$MANAGER" "$HOP_UNIT_FILE" /etc/yum.repos.d/sing-box.repo
  fi
  install_sing_box_official
  # The official package may create a default config.json. Only replace it
  # because we verified no such file existed BEFORE installing the package.
  install -d -m 0755 /etc/sing-box
  local other_configs
  other_configs="$(find /etc/sing-box -maxdepth 1 -type f -name '*.json' ! -name 'config.json' -print)"
  [[ -z "$other_configs" ]] || die "Other JSON config files found in /etc/sing-box; refusing to merge duplicates: $other_configs"
  mkdir -p "$APP/rules" "$APP/tls" "$APP/client"
  chmod 0700 "$APP" "$APP/tls" "$APP/client"
  download_rules ai google youtube
  new_credentials
  HY2_SNI="$REALITY_DOMAIN"
  make_hy2_certificate
  ANYTLS_SNI="$REALITY_DOMAIN"
  make_tls_certificate anytls "$ANYTLS_SNI"
  TUIC_SNI="$REALITY_DOMAIN"
  make_tls_certificate tuic "$TUIC_SNI"
  export AI_URL GOOGLE_URL YOUTUBE_URL
  write_jsons
  install_manager
  if [[ -f "$TEMP/hopping-plan.json" ]]; then
    snapshot_hopping
    apply_hopping_plan
    node_config export
  fi
  start_official_unit
  open_firewall
  update_firewall_ownership
  forget_socks
  unset REALITY_PRIVATE HY2_PASS HY2_OBFS_PASS ANYTLS_PASS TUIC_PASS
  firewall_hints
  success "INSTALL OK: ${UNIT} on TCP/$VLESS_PORT (Reality), UDP/$HY2_PORT (HY2) TCP/$ANYTLS_PORT (AnyTLS) and UDP/$TUIC_PORT (TUIC)."
  log "Client outbound objects (root only): ${APP}/client/*.json"
  show_node_details
  TRANSACTION=""
  log 'Verify cloud firewall and actual client connectivity.'
}

# Proxy updates share one transaction; staged edits leave the running service untouched.
set_socks_profile() {
  need_root
  [[ -f "$CONFIG" && -x "$BIN" ]] || die '需要现有 config.json 和可执行的 sing-box 内核。'
  local profile
  for profile in "$@"; do
    read_socks_profile "$profile"
    check_socks "$profile"
  done
  check_configuration
  begin_transaction update "$CONFIG" "$APP/client"
  export CONFIG APP SOCKS_TFO REQUEST_SOCKS_TFO
  python_module configuration set_socks "$@"
  forget_socks
  check_configuration
  if [[ ${STAGING:-0} != 1 ]]; then
    systemctl restart "$UNIT"
    sleep 2
    if ! systemctl is-active --quiet "$UNIT"; then
      journalctl -u "$UNIT" -n 40 --no-pager >&2 || true
      die 'Service failed after configuration update.'
    fi
  fi
  export_client_files
  if [[ ! -f "$APP/client/EXPORT-ERROR.txt" ]]; then show_node_details; fi
  TRANSACTION=""
  if [[ ${STAGING:-0} != 1 ]]; then log 'Configuration updated, checked and service restarted.'; fi
}

show_node_details() {
  need_root
  [[ ${CLIENT_EXPORT_FAILED:-0} != 1 ]] || return 0
  node_config show
}

# Validate the file being staged, or the complete directory used by the installed unit.
check_configuration() {
  if [[ ${STAGING:-0} == 1 ]]; then "$BIN" check -c "$CONFIG"
  else "$BIN" check -C /etc/sing-box; fi
}

relocate_tls_paths() {
  python_module configuration relocate_tls "$1" "$2" "$3"
}

pending_fingerprint() {
  python_module configuration fingerprint "$1"
}

stage_changes() {
  need_root
  [[ -f "$CONFIG" ]] || die "配置文件不存在：$CONFIG"
  local pending="$APP/pending" name existed=0 before
  [[ ! -d "$pending" ]] || existed=1
  begin_transaction files "$pending"
  if [[ ! -d "$pending" ]]; then
    install -d -m 0700 "$pending"
    for name in tls client; do
      [[ ! -L "$APP/$name" ]] || die '拒绝暂存符号链接目录。'
      if [[ -d "$APP/$name" ]]; then cp -a "$APP/$name" "$pending/$name"; else install -d -m 0700 "$pending/$name"; fi
    done
    sha256sum "$CONFIG" | cut -d ' ' -f1 > "$pending/base.sha256"
    cp -a "$CONFIG" "$pending/config.json"
    if [[ -f "$APP/hopping.json" ]]; then cp -a "$APP/hopping.json" "$pending/hopping.json"; fi
    relocate_tls_paths "$pending/config.json" "$APP" "$pending"
  fi
  before="$(pending_fingerprint "$pending")"
  ui warning '正在编辑待应用配置；保存不会重载服务、证书、防火墙或跳跃规则。'
  (
    LIVE_APP="$APP"
    APP="$pending" CONFIG="$pending/config.json" STAGING=1
    TEMP='' TRANSACTION='' ROLLBACK_PATHS=() ROLLBACK_EXISTS=()
    trap cleanup EXIT
    "$@"
    if [[ -f "$APP/hopping.json" ]]; then hopping_runtime validate; fi
  )
  if [[ "$(pending_fingerprint "$pending")" == "$before" ]]; then
    if (( ! existed )); then rm -rf -- "$pending"; fi
    TRANSACTION=''
    log '本次设置没有变化；已有待应用修改保持不变。'
    return 0
  fi
  TRANSACTION=''
  success '待应用配置已保存并校验。请执行 apply（应用配置并重启）后再导入新节点。'
}

require_no_pending() {
  [[ ! -d "$APP/pending" ]] || die '存在待应用配置，请先 apply 或 discard-pending，再执行此操作。'
}

apply_changes() {
  need_root
  show_occupied_ports
  local pending="$APP/pending" name staged=0 answer
  [[ -f "$CONFIG" ]] || die '请先安装节点。'
  if [[ -f "$pending/config.json" ]]; then
    staged=1
    [[ -f "$pending/base.sha256" ]] || die '待应用配置缺少原配置校验信息，请先丢弃后重新编辑。'
    [[ "$(sha256sum "$CONFIG" | cut -d ' ' -f1)" == "$(cat "$pending/base.sha256")" ]] || die '已应用配置在暂存后被其他操作修改，拒绝覆盖；请先导出并丢弃待应用修改。'
    (APP="$pending" CONFIG="$pending/config.json" STAGING=1; check_configuration)
  else
    check_configuration
  fi
  if [[ -t 0 ]]; then
    ui title '确认即将应用的配置文件'
    if (( staged )); then
      printf '%s\n' "$pending/config.json"
      (APP="$pending" CONFIG="$pending/config.json"; node_config summary)
    else
      printf '%s\n' "$CONFIG"
      node_config summary
    fi
    read -r -p '确认应用并重启 sing-box 和已启用的脚本跳跃服务？输入 YES：' answer
    [[ "$answer" == YES ]] || return 0
  fi
  local FW_PREVIOUS_ENDPOINTS
  FW_PREVIOUS_ENDPOINTS="$(configuration_listeners)"
  begin_transaction update "$CONFIG" "$APP/tls" "$APP/client" "$APP/hopping.json" "$APP/firewall-owned.json" "$APP/manager.sh" "$MANAGER" "$HOP_UNIT_FILE" "$APP/runtime-state.json"
  snapshot_hopping
  if (( staged )); then
    if [[ -f "$pending/hopping.json" ]]; then cp "$pending/hopping.json" "$TEMP/hopping-plan.json"; fi
    for name in tls client; do rm -rf "${APP:?}/$name"; cp -a "$pending/$name" "$APP/$name"; done
    install -m 0600 "$pending/config.json" "$CONFIG"
    relocate_tls_paths "$CONFIG" "$pending" "$APP"
  elif [[ -f "$APP/hopping.json" ]]; then
    cp "$APP/hopping.json" "$TEMP/hopping-plan.json"
  fi
  check_configuration
  install_manager
  if [[ -f "$TEMP/hopping-plan.json" ]]; then apply_hopping_plan; fi
  open_firewall
  restart_checked
  update_firewall_ownership
  export_client_files
  record_runtime_state
  if [[ ! -f "$APP/client/EXPORT-ERROR.txt" ]]; then show_node_details; fi
  TRANSACTION=''
  if (( staged )); then rm -rf -- "$pending"; fi
  success '配置已校验，sing-box 和已启用的跳跃服务已重启，管理入口及运行状态已刷新。'
}

discard_pending() {
  need_root
  [[ -d "$APP/pending" ]] || die '没有待应用配置。'
  local answer="${DISCARD_CONFIRM:-}"
  if [[ -t 0 ]]; then read -r -p '丢弃全部待应用修改？输入 YES：' answer; fi
  [[ "$answer" == YES ]] || die '未确认，已保留待应用配置。'
  rm -rf -- "$APP/pending"
  success '已丢弃待应用修改，运行配置未改变。'
}

record_runtime_state() {
  local identity version
  if ! identity="$(systemctl show "$UNIT" -p InvocationID --value)" || [[ -z "$identity" ]]; then
    warn '无法取得服务进程标识，暂不能确认运行配置快照。'
    return 0
  fi
  version="$("$BIN" version | sed -n '1s/.*version //p')"
  node_config record-runtime "$identity" "${version:-未知}"
}

show_dashboard() {
  need_root
  local identity='' snapshot='' version='' pid='' active=0 pending=0 line
  if systemctl is-active --quiet "$UNIT"; then active=1; fi
  [[ ! -f "$APP/pending/config.json" ]] || pending=1
  printf '\n'
  if (( pending )); then
    ui title '  ╭─ 运行概况 ────────────────────── 有未应用修改'
  else
    ui title '  ╭─ 运行概况 ────────────────────────────────'
  fi
  if (( active )) && identity="$(systemctl show "$UNIT" -p InvocationID --value)" && [[ -n "$identity" ]] && snapshot="$(node_config running-summary "$identity")"; then
    ui success "  │  ● ${snapshot%%$'\n'*}"
    while IFS= read -r line; do
      ui info "  │  $line"
    done <<< "${snapshot#*$'\n'}"
  else
    if (( active )) && pid="$(systemctl show "$UNIT" -p MainPID --value)" && [[ "$pid" =~ ^[1-9][0-9]*$ && -x "/proc/$pid/exe" ]]; then
      version="$("/proc/$pid/exe" version | sed -n '1s/.*version //p')"
      ui success "  │  ● 服务：运行中    版本：${version:-未知}"
    else
      if [[ -x "$BIN" ]]; then version="$("$BIN" version | sed -n '1s/.*version //p')"; fi
      if (( active )); then ui success "  │  ● 服务：运行中    已安装版本：${version:-未知}"
      else ui warning "  │  ○ 服务：已停止或异常    已安装版本：${version:-未安装}"; fi
    fi
    if [[ -f "$CONFIG" ]]; then
      if (( active )); then
        ui warning '  │  运行配置未确认；以下为已保存的配置文件（通过本工具启动或应用后可确认）。'
      else
        ui muted '  │  已保存配置：'
      fi
      node_config summary | while IFS= read -r line; do ui info "  │  $line"; done
    else
      ui warning '  │  尚未安装节点。'
    fi
  fi
  ui muted '  ╰─ 修改配置后需执行“应用配置并重启”才会生效。'
  if [[ -f "$CONFIG" ]]; then
    ui section '  已保存配置的证书'
    if ! certificate_status; then ui warning '证书已过期或无法读取，请检查证书文件；托管自签证书可用 renew-certs 续期。'; fi
  fi
  if (( pending )); then
    printf '\n'
    ui warning '待应用配置（尚未生效）：'
    (CONFIG="$APP/pending/config.json"; APP="$APP/pending"; node_config summary) | while IFS= read -r line; do
      ui warning "  · $line"
    done
    (
      CONFIG="$APP/pending/config.json"; APP="$APP/pending"
      ui section '  待应用配置的证书'
      if ! certificate_status; then ui warning '待应用证书已过期或无法读取，请先修正再应用。'; fi
    )
    ui warning '执行 apply 应用并重启；执行 discard-pending 丢弃修改。'
  fi
}

menu_config() {
  (
    if [[ -f "$APP/pending/config.json" ]]; then APP="$APP/pending"; CONFIG="$APP/config.json"; fi
    node_config "$@"
  )
}

edit_inbound_field() {
  local selected="$1" pointer="$2" value="${3-}" input
  [[ -n "$TEMP" ]] || TEMP="$(mktemp -d)"
  node_config extract-inbound "$selected" > "$TEMP/field-original.json"
  if (( $# < 3 )); then
    [[ -t 0 ]] || die '请提供 JSON 值或 :remove。'
    show_occupied_ports
    ui info '输入 JSON 值（隐藏输入）；字符串需双引号，true/false 为开关；:remove 移除字段，:cancel 取消。'
    read -r -s -p "${pointer}：" value || return 0
    printf '\n' >&2
    [[ "$value" != :cancel ]] || return 0
  fi
  input="$TEMP/field-edited.json"
  FIELD_VALUE="$value" python_module configuration edit_field "$TEMP/field-original.json" "$input" "$pointer"
  edit_protocol "$selected" "$input"
}

# Complete inbound JSON editing is validated by the installed core, not a field whitelist.
edit_protocol() {
  need_root
  local selected="${1:-}" input="${2:-}" choice index result
  local -a options=() editor=() certificate=()
  if [[ -z "$selected" && -t 0 ]]; then
    mapfile -d '' -t options < <(node_config editable-protocols)
    ui title '选择要修改的现有协议'
    for ((index=0; index<${#options[@]}; index+=2)); do ui item " $((index/2+1)). ${options[index+1]}"; done
    ui item ' 0. 返回'
    read -r -p '请选择：' choice || return 0
    [[ "$choice" != 0 ]] || return 0
    # shellcheck disable=SC2015 # Both validation conditions must succeed; otherwise fail.
    [[ "$choice" =~ ^[0-9]{1,3}$ ]] && ((10#$choice>=1 && 10#$choice<=${#options[@]}/2)) || die '无效选择。'
    selected="${options[(10#$choice-1)*2]}"
  fi
  [[ -n "$selected" ]] || die '用法：edit-protocol 协议标签 配置JSON文件。'
  [[ -n "$TEMP" ]] || TEMP="$(mktemp -d)"
  show_occupied_ports
  node_config extract-inbound "$selected" > "$TEMP/original-inbound.json"
  cp "$TEMP/original-inbound.json" "$TEMP/inbound.json"
  if [[ -z "$input" ]]; then
    [[ -t 0 ]] || die '非交互编辑请提供完整入站 JSON 文件。'
    read -r -a editor <<< "${VISUAL:-${EDITOR:-nano}}"
    command -v "${editor[0]}" >/dev/null || die "编辑器 ${editor[0]} 未安装，请先安装该编辑器、设置 VISUAL / EDITOR 或提供 JSON 文件。"
    "${editor[@]}" "$TEMP/inbound.json"
    input="$TEMP/inbound.json"
  fi
  [[ -f "$input" ]] || die '入站 JSON 文件不存在。'
  result="$(node_config replace-inbound "$selected" "$input")"
  [[ "$result" != unchanged ]] || { log '设置没有变化。'; return 0; }
  check_configuration
  mapfile -d '' -t certificate < <(node_config managed-sni-change "$TEMP/original-inbound.json")
  if (( ${#certificate[@]} == 2 )); then
    make_tls_certificate "${certificate[0]}" "${certificate[1]}"
    check_configuration
  fi
  if [[ -f "$APP/hopping.json" ]]; then hopping_runtime validate; fi
  export_client_files
  if [[ ! -f "$APP/client/EXPORT-ERROR.txt" ]]; then show_node_details; fi
}

update_protocol_defaults() {
  node_config defaults
  check_configuration
  export_client_files
  success 'TLS 10s、HY2 带宽协商及默认参数已保存到待应用配置。'
}

update_log_level() {
  local level="${1:-${LOG_LEVEL:-$DEFAULT_LOG_LEVEL}}" answer
  if [[ -t 0 && $# == 0 ]]; then
    read -r -p "sing-box 日志级别 trace/debug/info/warn/error/fatal/panic [${level}]：" answer
    level="${answer:-$level}"
  fi
  case "$level" in
    trace|debug|info|warn|error|fatal|panic) ;;
    *) die 'LOG_LEVEL 必须是 trace、debug、info、warn、error、fatal 或 panic。' ;;
  esac
  node_config log-level "$level"
  check_configuration
  success "日志级别已保存为 ${level}；执行 apply 后生效。"
}

export_client_files() {
  local rc report
  CLIENT_EXPORT_FAILED=0
  [[ -n "$TEMP" ]] || TEMP="$(mktemp -d)"
  report="$TEMP/client-export-error"
  if ! install -d -m 0700 "$APP/client"; then
    CLIENT_EXPORT_FAILED=1
    warn '无法创建可选的客户端导出目录；配置保存不受影响，请手动导出。'
    return 0
  fi
  if CLIENT_EXPORT_OPTIONAL=1 node_config export "${1:-}" 2>"$report"; then
    if ! rm -f "$APP/client/EXPORT-ERROR.txt"; then warn '旧的导出错误记录未能删除；请查看目录权限。'; fi
    return 0
  else rc=$?; fi
  CLIENT_EXPORT_FAILED=1
  cat "$report" >&2
  if ! install -m 0600 "$report" "$APP/client/EXPORT-ERROR.txt"; then
    warn '无法保存客户端导出错误记录；请保留上方诊断。'
  fi
  if [[ "$rc" == 3 ]]; then
    if ! { node_config summary; cat "$report"; } > "$APP/client/node-info.txt"; then
      warn '无法保存可选的节点说明；配置保存不受影响。'
    fi
    warn '服务端配置有效，该组合需手动配置客户端；可选资料未完整导出。'
  else
    warn "客户端资料导出失败（退出码 $rc）；配置保存不受影响，请检查上方原因并手动导出。"
  fi
}

# Shared config reader/writer and derived client exports; client files are never inputs.
node_config() {
  case "${1:-}" in
    show|json|yaml|export|export-yaml)
      if [[ -z "${SERVER_IP:-}" && "${CLIENT_EXPORT_OPTIONAL:-0}" != 1 ]]; then
        if command -v ip >/dev/null 2>&1 || command -v curl >/dev/null 2>&1; then
          SERVER_IP="$(detect_public_ipv4)" || SERVER_IP=''
        fi
      fi ;;
  esac
  export APP CONFIG DEFAULT_HY2_HOP_INTERVAL DEFAULT_TLS_HANDSHAKE_TIMEOUT LIVE_APP SERVER_IP
  python_module nodes run "$@"
}

load_node_settings() {
  local -a settings=()
  local index
  mapfile -d '' -t settings < <(node_config load)
  [[ ${#settings[@]} == 37 && "${settings[36]}" == READY ]] || die '无法读取已有节点配置。'
  for ((index=0; index<36; index+=2)); do
    printf -v "${settings[index]}" '%s' "${settings[index+1]}"
    export "${settings[index]}"
  done
}

restart_checked() {
  [[ ${STAGING:-0} != 1 ]] || return 0
  systemctl daemon-reload
  systemctl restart "$UNIT"
  sleep 2
  if ! systemctl is-active --quiet "$UNIT"; then
    journalctl -u "$UNIT" -n 40 --no-pager >&2 || true
    die '服务启动失败，正在恢复原配置。'
  fi
  check_listeners
  record_runtime_state
}

set_node() {
  local mode="$1" answer requested_vless="${VLESS_PORT_REQUEST:-}" requested_hy2="${HY2_PORT_REQUEST:-}" requested_anytls="${ANYTLS_PORT_REQUEST:-}" requested_tuic="${TUIC_PORT_REQUEST:-}"
  need_root
  [[ -f "$CONFIG" && -x "$BIN" ]] || die '请先安装。'
  load_node_settings
  local old_vless="$VLESS_PORT" old_hy2="$HY2_PORT" old_reality="$REALITY_DOMAIN" old_sni="$HY2_SNI" old_anytls="$ANYTLS_PORT" old_anytls_sni="$ANYTLS_SNI" old_tuic="$TUIC_PORT" old_tuic_sni="$TUIC_SNI" old_vnet="$VLESS_NETWORK"
  if [[ "$mode" == regenerate ]]; then
    local protocol="${2:-}"
    if [[ -z "$protocol" && -t 0 ]]; then
      local -a protocols=()
      local index
      mapfile -d '' -t protocols < <(node_config protocols)
      (( ${#protocols[@]} > 0 && ${#protocols[@]} % 2 == 0 )) || die '没有可重新生成的协议。'
      ui warning '重新生成指定协议配置（端口和 SNI 保持不变）'
      for ((index=0; index<${#protocols[@]}; index+=2)); do ui item " $((index/2+1)). ${protocols[index+1]}"; done
      ui item ' 0. 返回'
      read -r -p '请选择：' answer || return 0
      [[ "$answer" != 0 ]] || return 0
      # shellcheck disable=SC2015 # Both validation conditions must succeed; otherwise fail.
      [[ "$answer" =~ ^[0-9]{1,2}$ ]] && ((10#$answer>=1 && 10#$answer<=${#protocols[@]}/2)) || die '无效选择。'
      protocol="${protocols[(10#$answer-1)*2]}"
    fi
    case "$protocol" in
      vless|hysteria2) ;;
      tuic) [[ -n "$TUIC_PORT" ]] || die '尚未安装 TUIC。' ;;
      anytls) [[ -n "$ANYTLS_PORT" ]] || die '尚未安装 AnyTLS，请先添加该协议。' ;;
      *) die '请指定协议：regenerate vless|hysteria2|anytls|tuic。' ;;
    esac
    if [[ -t 0 ]]; then
      ui warning "将重新生成 $protocol 的连接凭据；选中 HY2/AnyTLS 时同时换新证书。该协议旧节点将失效。"
      read -r -p '输入 YES 继续：' answer
      [[ "$answer" == YES ]] || return 0
    fi
    new_credentials "$protocol"
    mode="regenerate-$protocol"
  fi
  case "$mode" in
    regenerate-vless|regenerate-hysteria2|regenerate-anytls|regenerate-tuic) ;;
    add-tuic)
      [[ -z "$TUIC_PORT" ]] || die 'TUIC 已存在，请修改现有协议。'
      TUIC_PORT="${requested_tuic:-$DEFAULT_TUIC_PORT}"
      TUIC_SNI="${NEW_TUIC_SNI:-$REALITY_DOMAIN}"
      new_credentials tuic
      read_ports TUIC_PORT
      if [[ -t 0 ]]; then read -r -p "TUIC SNI [$TUIC_SNI]：" answer; TUIC_SNI="${answer:-$TUIC_SNI}"; fi ;;
    add-anytls)
      [[ -z "$ANYTLS_PORT" ]] || die 'AnyTLS 已存在，请使用修改端口、SNI 或凭据功能。'
      ANYTLS_PORT="${requested_anytls:-$DEFAULT_ANYTLS_PORT}"
      ANYTLS_SNI="${NEW_ANYTLS_SNI:-$REALITY_DOMAIN}"
      ANYTLS_PASS="${NEW_ANYTLS_PASS-$(openssl rand -base64 32)}"
      read_ports ANYTLS_PORT
      if [[ -t 0 ]]; then
        read -r -p "AnyTLS SNI [$ANYTLS_SNI]：" answer; ANYTLS_SNI="${answer:-$ANYTLS_SNI}"
      fi
      local occupied
      if [[ ${STAGING:-0} == 1 ]]; then
        occupied="$(ss -H -ltnp "( sport = :$ANYTLS_PORT )")"
        [[ -z "$occupied" || "$occupied" == *'"sing-box"'* ]] || die "TCP/$ANYTLS_PORT 已被占用。"
      else
        occupied="$(ss -H -ltn "( sport = :$ANYTLS_PORT )")"
        [[ -z "$occupied" ]] || die "TCP/$ANYTLS_PORT 已被占用。"
      fi ;;
    ports)
      VLESS_PORT="${requested_vless:-$VLESS_PORT}"; HY2_PORT="${requested_hy2:-$HY2_PORT}"
      if [[ -n "$ANYTLS_PORT" ]]; then ANYTLS_PORT="${requested_anytls:-$ANYTLS_PORT}"; fi
      if [[ -n "$TUIC_PORT" ]]; then TUIC_PORT="${requested_tuic:-$TUIC_PORT}"; fi
      read_ports
      local occupied
      if [[ "$VLESS_PORT" != "$old_vless" ]]; then
        if [[ ${STAGING:-0} == 1 ]]; then
          occupied="$(ss -H -ltnp "( sport = :$VLESS_PORT )")"
          [[ -z "$occupied" || "$occupied" == *'"sing-box"'* ]] || die "TCP/$VLESS_PORT 已被占用。"
        else
          occupied="$(ss -H -ltn "( sport = :$VLESS_PORT )")"
          [[ -z "$occupied" ]] || die "TCP/$VLESS_PORT 已被占用。"
        fi
      fi
      if [[ "$HY2_PORT" != "$old_hy2" ]]; then
        if [[ ${STAGING:-0} == 1 ]]; then
          occupied="$(ss -H -lunp "( sport = :$HY2_PORT )")"
          [[ -z "$occupied" || "$occupied" == *'"sing-box"'* ]] || die "UDP/$HY2_PORT 已被占用。"
        else
          occupied="$(ss -H -lun "( sport = :$HY2_PORT )")"
          [[ -z "$occupied" ]] || die "UDP/$HY2_PORT 已被占用。"
        fi
      fi
      if [[ -n "$ANYTLS_PORT" && "$ANYTLS_PORT" != "$old_anytls" ]]; then
        if [[ ${STAGING:-0} == 1 ]]; then
          occupied="$(ss -H -ltnp "( sport = :$ANYTLS_PORT )")"
          [[ -z "$occupied" || "$occupied" == *'"sing-box"'* ]] || die "TCP/$ANYTLS_PORT 已被占用。"
        else
          occupied="$(ss -H -ltn "( sport = :$ANYTLS_PORT )")"
          [[ -z "$occupied" ]] || die "TCP/$ANYTLS_PORT 已被占用。"
        fi
      fi ;;
    sni)
      REALITY_DOMAIN="${NEW_REALITY_DOMAIN:-$REALITY_DOMAIN}"; HY2_SNI="${NEW_HY2_SNI:-$HY2_SNI}"
      if [[ -n "$TUIC_PORT" ]]; then TUIC_SNI="${NEW_TUIC_SNI:-$TUIC_SNI}"; fi
      if [[ -n "$ANYTLS_PORT" ]]; then ANYTLS_SNI="${NEW_ANYTLS_SNI:-$ANYTLS_SNI}"; fi
      if [[ -t 0 ]]; then
        read -r -p "Reality SNI/握手域名 [$REALITY_DOMAIN]：" answer; REALITY_DOMAIN="${answer:-$REALITY_DOMAIN}"
        read -r -p "Hysteria2 SNI [$HY2_SNI]：" answer; HY2_SNI="${answer:-$HY2_SNI}"
        if [[ -n "$TUIC_PORT" ]]; then read -r -p "TUIC SNI [$TUIC_SNI]：" answer; TUIC_SNI="${answer:-$TUIC_SNI}"; fi
        if [[ -n "$ANYTLS_PORT" ]]; then
          read -r -p "AnyTLS SNI [$ANYTLS_SNI]：" answer; ANYTLS_SNI="${answer:-$ANYTLS_SNI}"
        fi
      fi ;;
    credentials)
      UUID="${NEW_UUID:-$UUID}"; HY2_PASS="${NEW_HY2_PASS:-$HY2_PASS}"; HY2_OBFS_PASS="${NEW_HY2_OBFS_PASS:-$HY2_OBFS_PASS}"
      if [[ -n "$TUIC_PORT" ]]; then TUIC_UUID="${NEW_TUIC_UUID:-$TUIC_UUID}"; TUIC_PASS="${NEW_TUIC_PASS-$TUIC_PASS}"; fi
      if [[ -n "$ANYTLS_PORT" ]]; then ANYTLS_PASS="${NEW_ANYTLS_PASS-$ANYTLS_PASS}"; fi
      if [[ -t 0 ]]; then
        read -r -p "VLESS UUID [$UUID]：" answer; UUID="${answer:-$UUID}"
        if [[ -n "$TUIC_PORT" ]]; then
          read -r -p "TUIC UUID [$TUIC_UUID]：" answer; TUIC_UUID="${answer:-$TUIC_UUID}"
          read -r -s -p 'TUIC 密码（回车保留）：' answer; printf '\n'; TUIC_PASS="${answer:-$TUIC_PASS}"
        fi
        read -r -s -p 'HY2 认证密码（回车保留）：' answer; printf '\n'; HY2_PASS="${answer:-$HY2_PASS}"
        read -r -s -p 'Salamander 混淆密码（回车保留）：' answer; printf '\n'; HY2_OBFS_PASS="${answer:-$HY2_OBFS_PASS}"
        if [[ -n "$ANYTLS_PORT" ]]; then
          read -r -s -p 'AnyTLS 密码（回车保留）：' answer; printf '\n'; ANYTLS_PASS="${answer:-$ANYTLS_PASS}"
        fi
      fi ;;
    rotate)
      if [[ -t 0 ]]; then
        read -r -p '将更换全部 UUID、Reality 密钥、Short ID、HY2 和 AnyTLS 密码，旧节点将失效。输入 YES 继续：' answer
        [[ "$answer" == YES ]] || return 0
      fi
      new_credentials ;;
    bbr)
      HY2_BBR_PROFILE="${HY2_BBR_PROFILE_REQUEST:-${HY2_BBR_CURRENT:-$DEFAULT_HY2_BBR_PROFILE}}"
      if [[ -t 0 ]]; then
        read -r -p "HY2 BBR 档位：standard / conservative / aggressive [$HY2_BBR_PROFILE]：" answer
        HY2_BBR_PROFILE="${answer:-$HY2_BBR_PROFILE}"
      fi ;;
    tfo)
      if [[ -t 0 ]]; then
        read -r -p '三组代理的 TFO：1 开启，2 关闭，0 返回：' answer
        case "$answer" in 1) SOCKS_TFO=true ;; 2) SOCKS_TFO=false ;; 0) return 0 ;; *) die '无效选择。' ;; esac
      fi ;;
    *) die '未知节点修改操作。' ;;
  esac
  export VLESS_PORT HY2_PORT ANYTLS_PORT ANYTLS_SNI ANYTLS_PASS REALITY_DOMAIN HY2_SNI UUID HY2_PASS HY2_OBFS_PASS HY2_BBR_PROFILE SOCKS_TFO TUIC_PORT TUIC_SNI TUIC_UUID TUIC_PASS
  local validation
  validation="$(node_config validate "$mode")"
  if [[ "$validation" == unchanged ]]; then log '设置没有变化，已保留现有配置。'; return 0; fi
  check_configuration
  begin_transaction update "$CONFIG" "$APP/client" "$APP/tls" "$APP/firewall-owned.json" "$APP/hopping.json" "$HOP_UNIT_FILE"
  if [[ "$mode" == sni ]]; then
    [[ "$REALITY_DOMAIN" == "$old_reality" ]] || check_reality_target "$REALITY_DOMAIN"
    [[ "$HY2_SNI" == "$old_sni" ]] || make_hy2_certificate
    if [[ -n "$ANYTLS_PORT" && "$ANYTLS_SNI" != "$old_anytls_sni" ]]; then make_tls_certificate anytls "$ANYTLS_SNI"; fi
    if [[ -n "$TUIC_PORT" && "$TUIC_SNI" != "$old_tuic_sni" ]]; then make_tls_certificate tuic "$TUIC_SNI"; fi
  elif [[ "$mode" == add-tuic || "$mode" == regenerate-tuic ]]; then
    make_tls_certificate tuic "$TUIC_SNI"
  elif [[ "$mode" == regenerate-hysteria2 ]]; then
    make_hy2_certificate
  elif [[ "$mode" == add-anytls || "$mode" == regenerate-anytls ]]; then
    make_tls_certificate anytls "$ANYTLS_SNI"
  fi
  if [[ "$mode" == ports && -f "$APP/hopping.json" ]]; then
    snapshot_hopping
    python_module hopping set_base_port "$APP/hopping.json" "$TEMP/hopping-plan.json" "$HY2_PORT"
    apply_hopping_plan
  fi
  node_config update "$mode"
  check_configuration
  export_client_files "$mode"
  if [[ "$mode" == ports || "$mode" == add-anytls || "$mode" == add-tuic ]]; then open_firewall "$old_vless" "$old_hy2" "$old_anytls" "$old_tuic" "$old_vnet"; fi
  restart_checked
  if [[ "$mode" == ports || "$mode" == add-anytls || "$mode" == add-tuic ]]; then
    update_firewall_ownership "$old_vless" "$old_hy2" "$old_anytls" "$old_tuic" "$old_vnet"
  fi
  if [[ ! -f "$APP/client/EXPORT-ERROR.txt" ]]; then show_node_details; fi
  TRANSACTION=""
  forget_socks
  unset REALITY_PRIVATE HY2_PASS HY2_OBFS_PASS ANYTLS_PASS TUIC_PASS
  if [[ ${STAGING:-0} != 1 ]]; then success '配置、客户端资料和服务已同步更新。请重新导入有变化的节点。'; fi
}

export_nodes() {
  need_root
  [[ -f "$CONFIG" ]] || die '请先安装。'
  begin_transaction files "$APP/client"
  node_config export
  show_node_details
  TRANSACTION=""
  success "节点文件已导出到 $APP/client，包含 JSON、分享链接和证书；YAML 文件请使用 export-yaml 单独导出。"
}

# Persist ownership so later port edits never remove an administrator's permits.
update_firewall_ownership() {
  [[ ${STAGING:-0} != 1 ]] || return 0
  if [[ "${1:-}" != restore && "${1:-}" != remove-all ]]; then
    local automatic
    automatic="$(firewall_auto)" || return
    [[ "$automatic" == true ]] || return 0
  fi
  FW_RESTORE="$TEMP/firewall-restore.json"
  FW_CONFIG_ENDPOINTS=''
  if [[ "${1:-}" != restore && "${1:-}" != remove-all && -f "$CONFIG" ]]; then
    FW_CONFIG_ENDPOINTS="$(configuration_listeners)"
  fi
  export FW_CONFIG_ENDPOINTS FW_PREVIOUS_ENDPOINTS="${FW_PREVIOUS_ENDPOINTS-}"
  export APP TEMP FW_MARK FW_SSH_MARK FW_NFT FW_RESTORE VLESS_PORT HY2_PORT ANYTLS_PORT TUIC_PORT VLESS_NETWORK
  python_module firewall ownership "$@"
}


# Service status, manager entry point and connectivity checks.
status_cmd() {
  need_root
  local result=0 state='' reload='' rc running=0 endpoints proto port label output hopping_enabled hop_state
  printf '\n'
  ui title '  ╭─ 服务状态 ────────────────────────────────'
  if ! state="$(systemctl show "$UNIT" --property=ActiveState --value)"; then
    ui error '无法查询 sing-box 服务状态，请检查 systemd 或服务文件。' >&2
    result=1
  fi
  ui muted '  ├─ systemd 详情'
  if systemctl status "$UNIT" --no-pager -l --lines=0; then :
  else
    rc=$?
    if [[ "$rc" != 3 ]]; then ui error "服务详情查询失败（退出码 $rc）。" >&2; result=1; fi
  fi
  case "$state" in
    active|reloading|refreshing) running=1; ui success '  ├─ 服务：运行中' ;;
    inactive) ui info '  ├─ 服务：已停止；可通过服务管理启动。' ;;
    activating|deactivating) ui warning "  ├─ 服务正在切换状态：$state，请稍后查看。" ;;
    failed) ui error '  ├─ 服务：启动或运行失败，请通过“查看日志”检查原因。' >&2; result=1 ;;
    *) ui error "  ├─ 无法确认服务状态：${state:-未知}。" >&2; result=1 ;;
  esac
  if reload="$(systemctl show "$UNIT" --property=NeedDaemonReload --value)"; then
    case "$reload" in
      yes) ui warning '  ├─ 服务文件已变化，systemd 尚未重新加载；手动启动、重启或应用配置时会先重新加载。' ;;
      no) ;;
      *) ui error '  ├─ 无法确认服务文件是否需要重新加载。' >&2; result=1 ;;
    esac
  else ui error '  ├─ 无法查询服务文件的重新加载状态。' >&2; result=1; fi
  if [[ -f "$CONFIG" ]]; then
    ui muted '  ├─ 当前配置'
    node_config summary || result=1
    endpoints="$(configuration_listeners)" || result=1
    ui muted '  ├─ 监听检查'
    while read -r proto port label; do
      [[ -n "$port" ]] || continue
      printf '\n'
      ui title "  ── ${label} ${proto^^} ${port} ──"
      if [[ "$proto" == udp ]]; then
        if ! output="$(ss -H -lunp "( sport = :$port )")"; then
          ui error "无法查询 UDP/$port 的监听情况。" >&2; result=1; continue
        fi
      else
        if ! output="$(ss -H -ltnp "( sport = :$port )")"; then
          ui error "无法查询 TCP/$port 的监听情况。" >&2; result=1; continue
        fi
      fi
      if [[ -n "$output" ]]; then printf '  %s\n' "$output"
      else ui info '  当前没有监听。'; fi
      if (( running )) && [[ "$output" != *'"sing-box"'* ]]; then
        ui error "服务运行中，但未发现 $label ${proto^^}/$port 的 sing-box 监听。" >&2
        result=1
      fi
    done <<< "$endpoints"
  fi
  printf '\n'
  if [[ -f "$CONFIG" ]]; then
    ui muted '  ├─ 证书有效期'
    certificate_status || result=1
  fi
  ui muted '  ├─ 配置校验'
  if [[ -x "$BIN" && -f "$CONFIG" ]]; then
    if check_configuration; then ui success '  │  配置校验通过。'
    else ui error '  │  配置校验失败，请检查上方具体错误。' >&2; result=1; fi
  else
    ui error '  │  sing-box 内核或配置文件不存在。' >&2
    result=1
  fi
  if [[ -f "$APP/hopping.json" ]]; then
    if hopping_enabled="$(python_module hopping enabled "$APP/hopping.json")"; then
      if [[ "$hopping_enabled" == yes ]]; then
        ui muted '  ├─ 端口跳跃'
        if ! hop_state="$(systemctl show "$HOP_UNIT" --property=ActiveState --value)"; then
          ui error '无法查询端口跳跃服务状态。' >&2; result=1
        fi
        if systemctl status "$HOP_UNIT" --no-pager -l --lines=0; then :
        else
          rc=$?
          if [[ "$rc" != 3 ]]; then
            ui error "端口跳跃服务查询失败（退出码 $rc）。" >&2
            result=1
          fi
        fi
        if [[ "$hop_state" == failed || -z "$hop_state" ]]; then
          ui error '端口跳跃服务异常，请查看服务日志。' >&2; result=1
        elif (( running )) && [[ "$hop_state" != active ]]; then
          ui error 'sing-box 已运行，但端口跳跃服务未运行。' >&2; result=1
        fi
      fi
    else ui error '无法读取端口跳跃设置。' >&2; result=1; fi
  fi
  firewall_hints || result=1
  if (( result == 0 )); then
    ui success '  ╰─ 状态检查完成，未发现异常。'
  else
    ui warning '  ╰─ 状态检查完成，发现需要处理的异常。'
  fi
  return "$result"
}

install_manager() {
  [[ ${STAGING:-0} != 1 ]] || return 0
  [[ ! -L "$MANAGER" ]] || die '管理入口是符号链接，拒绝覆盖。'
  if [[ -e "$MANAGER" ]]; then
    grep -qxF '# sing-box-deploy 管理入口' "$MANAGER" || die '该管理命令不属于本脚本，拒绝覆盖。'
  fi
  [[ -f "$SCRIPT_PATH" ]] || die '请先把脚本保存为文件，再运行安装。'
  install -d -m 0700 "$APP"
  install -d -m 0755 "$(dirname "$MANAGER")"
  if [[ "$SCRIPT_PATH" != "$APP/manager.sh" ]]; then
    python_module bundle build "$SCRIPT_PATH" "$TEMP/manager.sh"
    install -m 0700 "$TEMP/manager.sh" "$APP/manager.sh"
  fi
  printf '#!/usr/bin/env bash\n# sing-box-deploy 管理入口\nexec bash %q "$@"\n' "$APP/manager.sh" > "$MANAGER"
  chmod 0700 "$MANAGER"
  log '快捷管理命令已安装：sb-manager'
}

setup_manager() {
  need_root
  [[ -f "$CONFIG" ]] || die "配置文件不存在：$CONFIG"
  begin_transaction files "$APP/manager.sh" "$MANAGER"
  install_manager
  TRANSACTION=""
}

service_cmd() {
  need_root
  case "$1" in
    restart) require_no_pending; check_configuration; restart_checked ;;
    start)
      require_no_pending
      if ! systemctl is-active --quiet "$UNIT"; then
        check_configuration
        systemctl daemon-reload
        systemctl start "$UNIT"
        systemctl is-active --quiet "$UNIT"
        record_runtime_state
      fi ;;
    stop) systemctl stop "$UNIT" ;;
  esac
  log "服务操作完成：$1"
}

check_connections() {
  need_root
  [[ -f "$CONFIG" && -x "$BIN" ]] || die '请指定有效配置文件及已安装的 sing-box 内核。'
  printf '\n' >&2
  ui title '  ╭─ 连接检查 ────────────────────────────────' >&2
  "$BIN" check -c "$CONFIG"
  local index
  local -a probes=()
  mapfile -d '' -t probes < <(python_module network connection_probes "$CONFIG")
  (( ${#probes[@]} >= 1 && (${#probes[@]}-1)%5 == 0 )) && [[ "${probes[-1]}" == READY ]] || die '无法完成当前配置的连接检查。'
  if (( ${#probes[@]} > 1 )); then
    ui muted '  ── SOCKS5 连通性（HTTPS 已在配置扫描时检查） ──' >&2
  fi
  for ((index=0; index<${#probes[@]}-1; index+=5)); do
    log "检查 SOCKS5 出口：${probes[index]}"
    export PROBE_SOCKS_HOST="${probes[index+1]}" PROBE_SOCKS_PORT="${probes[index+2]}" PROBE_SOCKS_USER="${probes[index+3]}" PROBE_SOCKS_PASS="${probes[index+4]}"
    check_socks probe
    unset PROBE_SOCKS_HOST PROBE_SOCKS_PORT PROBE_SOCKS_USER PROBE_SOCKS_PASS
  done
  log '当前配置、已配置 SOCKS5 / HTTPS 及可检查的 TLS 项目检查通过；公网节点连通性仍需客户端验证。'
  ui success '  ╰─ 检查完成，未发现异常。' >&2
}

menu_action() {
  local refresh=0
  # A separate process preserves errexit and transaction traps inside every operation.
  if bash "$SCRIPT_PATH" "$@"; then
    ui success '操作完成。'
    [[ "${1:-}" != apply ]] || refresh=1
  else
    local rc=$?
    if [[ "${1:-}" == status ]]; then
      ui warning "状态检查完成，发现异常（退出码 $rc），请查看上方具体提示。" >&2
    else
      ui error "操作未完成（退出码 $rc），请查看上方错误；有备份时请保留。" >&2
    fi
  fi
  [[ -f "$SCRIPT_PATH" ]] || exit 0
  local answer
  read -r -p '  按回车返回菜单…' answer || return 0
  if (( refresh )); then exec bash "$SCRIPT_PATH" menu; fi
}

# Configuration-driven menus.
# Labels and actions share one list; menu groups use @group and are never numbered.
run_menu() {
  local title="$1" header="$2" choice action index text count provider='' width number padding
  shift 2
  local -a entries=("$@") actions=()
  if (( ${#entries[@]} == 1 )) && [[ "${entries[0]}" == @* ]]; then provider="${entries[0]#@}"; fi
  while true; do
    if [[ -n "$provider" ]]; then mapfile -d '' -t entries < <("$provider"); fi
    count=0
    for ((index=0; index<${#entries[@]}; index+=2)); do
      if [[ "${entries[index+1]}" != '@group' ]]; then count=$((count+1)); fi
    done
    width=${#count}
    actions=()
    text=''
    number=0
    for ((index=0; index<${#entries[@]}; index+=2)); do
      if [[ "${entries[index+1]}" == '@group' ]]; then
        text+="@@GROUP@@${entries[index]}"$'\n'
        continue
      fi
      number=$((number+1))
      printf -v padding '%*d' "$width" "$number"
      text+=" ${padding}. ${entries[index]}"$'\n'
      actions+=("${entries[index+1]}")
    done
    text+=' 0. 返回 / 退出'
    printf '\n'
    ui title "  ╭─ $title"
    ui info  '  │  选择编号操作 · 0 返回 / 退出'
    ui muted '  ╰──────────────────────────────────────────────'
    if [[ -n "$header" ]]; then
      if ! bash "$SCRIPT_PATH" "$header"; then ui warning '配置摘要读取失败，请查看状态和日志。'; fi
      ui muted '  ── 操作菜单 ──'
    fi
    printf '\n'
    menu_choices "$text"
    ui_rule 46 '─' '  '
    read -r -p '  请选择编号：' choice || return 0
    [[ "$choice" != 0 ]] || return 0
    if [[ ! "$choice" =~ ^[0-9]+$ ]] || (( ${#choice}>${#count} || 10#$choice<1 || 10#$choice>count )); then
      ui warning '  无效选择，请输入菜单中的编号。'
      continue
    fi
    action="${actions[10#$choice-1]}"
    case "$action" in
      inbound:*) protocol_submenu "${action#inbound:}" ;;
      group:*) protocol_fields_menu "$ACTIVE_INBOUND" "${action#group:}" ;;
      switch:*) protocol_switch_menu "$ACTIVE_INBOUND" "${action#switch:}" ;;
      value:*) menu_action edit-field "$ACTIVE_INBOUND" "$ACTIVE_FIELD" "${action#value:}"; return 0 ;;
      field:*) menu_action edit-field "$ACTIVE_INBOUND" "${action#field:}" ;;
      remove:*) menu_action edit-field "$ACTIVE_INBOUND" "${action#remove:}" :remove; return 0 ;;
      edit-current) menu_action edit-protocol "$ACTIVE_INBOUND" ;;
      add-field) add_inbound_field "$ACTIVE_INBOUND" ;;
      hopping) menu_action set-hopping "$ACTIVE_INBOUND" ;;
      disable-hopping) menu_action disable-hopping "$ACTIVE_INBOUND" ;;
      @*) "${action#@}" ;;
      *) menu_action "$action" ;;
    esac
  done
}

protocol_entries() { menu_config menu-inbounds; }
protocol_field_entries() { menu_config menu-fields "$ACTIVE_INBOUND" "$ACTIVE_FIELD"; }
protocol_action_entries() { menu_config menu-inbound "$ACTIVE_INBOUND"; }

protocol_menu() {
  run_menu '修改现有协议 · 按配置中的入站分组' protocol-edit-header @protocol_entries
}

protocol_submenu() {
  local ACTIVE_INBOUND="$1" title
  title="$(menu_config inbound-label "$ACTIVE_INBOUND")"
  run_menu "$title · 协议配置" protocol-edit-header @protocol_action_entries
}

protocol_fields_menu() {
  local ACTIVE_INBOUND="$1" ACTIVE_FIELD="$2" title
  title="$(menu_config inbound-label "$ACTIVE_INBOUND")"
  run_menu "$title${ACTIVE_FIELD} · 配置字段" '' @protocol_field_entries
}

protocol_switch_menu() {
  local ACTIVE_INBOUND="$1" ACTIVE_FIELD="$2" title
  title="$(menu_config inbound-label "$ACTIVE_INBOUND")"
  run_menu "$title${ACTIVE_FIELD} · 开关" '' \
    '开启 · true' value:true \
    '关闭 · false' value:false \
    '移除字段 · 使用内核默认值' value::remove
}

protocol_edit_header() {
  if [[ -f "$APP/pending/config.json" ]]; then ui warning '编辑来源：待应用配置 · 保存后仍需手动应用'
  else ui info '编辑来源：已保存配置 · 修改将写入待应用区'; fi
}

add_inbound_field() {
  local selected="$1" pointer
  read -r -p '字段 JSON Pointer（例如 /tls/handshake_timeout，0 返回）：' pointer || return 0
  [[ "$pointer" != 0 ]] || return 0
  menu_action edit-field "$selected" "$pointer"
}

protocol_creation_entries() {
  local -a supported=('anytls' 'AnyTLS' 'add-anytls' 'tuic' 'TUIC' 'add-tuic')
  local index installed=''
  if [[ -f "$CONFIG" ]]; then installed="$(menu_config inbound-types)"; fi
  for ((index=0; index<${#supported[@]}; index+=3)); do
    if [[ $'\n'"$installed"$'\n' != *$'\n'"${supported[index]}"$'\n'* ]]; then
      printf '%s\0%s\0' "生成 ${supported[index+1]} 入站" "${supported[index+2]}"
    fi
  done
  printf '%s\0%s\0' \
    '重新生成指定协议配置' regenerate \
    '重新生成全部节点凭据（旧节点失效）' rotate-credentials \
    '更新已有协议为当前脚本默认参数' set-protocol-defaults
}

protocol_creation_menu() {
  run_menu '生成 / 重新生成协议' '' @protocol_creation_entries
}

firewall_menu() {
  run_menu '防火墙 · 状态与开关' firewall-status \
    '脚本自动放行端口' @group \
    '查看状态和完整规则详情' firewall-details \
    '开启脚本自动放行端口（现有规则不变）' firewall-auto-on \
    '关闭脚本自动放行端口（保留现有规则）' firewall-auto-off \
    '系统防火墙（需确认）' @group \
    '开启系统防火墙（需确认）' firewall-enable \
    '关闭系统防火墙（需确认）' firewall-disable
}

socks_menu() {
  run_menu '代理出口（SOCKS5 / HTTPS）' '' \
    'AI' set-ai-proxy \
    'Google / YouTube' set-google-proxy \
    '其他流量' set-other-proxy \
    '共享设置' @group \
    '同时修改三组' configure-proxies \
    '三组代理的 TFO 开关' set-tfo
}

export_menu() {
  run_menu '节点资料（含访问凭据）' '' \
    '查看已应用的连接参数和分享链接' show \
    '导出已应用节点到资料目录' export \
    '查看已应用的 Clash/Mihomo proxies YAML' show-yaml \
    '可选导出已应用的 proxies.yaml 文件' export-yaml
}

service_menu() {
  run_menu '服务管理' '' \
    '启动服务' start \
    '停止服务' stop \
    '重启服务（重新加载配置）' restart
}

# Port hopping is UDP REDIRECT into the same QUIC listener, never separate inbounds.
prepare_hopping() {
  [[ -n "$TEMP" ]] || TEMP="$(mktemp -d)"
  local spec_input exclusion_input interval_input
  local occupied exclusion="${HY2_HOP_EXCLUDE:-auto}" spec="${HY2_HOP_PORTS:-}" interval="${HY2_HOP_INTERVAL:-$DEFAULT_HY2_HOP_INTERVAL}" backend
  show_occupied_ports
  occupied="$OCCUPIED_PORTS"
  printf '%s\n' "$occupied" > "$TEMP/occupied.txt"
  if [[ -t 0 ]]; then
    read -r -p "HY2 跳跃端口/区间，逗号分隔，0 关闭 [${spec:-关闭}]：" spec_input
    spec="${spec_input:-$spec}"
    if [[ -n "$spec" && "$spec" != 0 ]]; then
      read -r -p "排除端口/区间，回车自动排除 UDP 冲突；none 不排除 [$exclusion]：" exclusion_input
      exclusion="${exclusion_input:-$exclusion}"
      read -r -p "跳跃间隔 [$interval]：" interval_input
      interval="${interval_input:-$interval}"
    fi
  fi
  if command -v nft >/dev/null; then backend=nft
  elif command -v iptables >/dev/null; then backend=iptables
  elif [[ -z "$spec" || "$spec" == 0 ]]; then backend=nft
  else
    check_os
    if [[ $PKG == apt ]]; then apt-get update; DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends nftables
    elif [[ $PKG == dnf5 ]]; then dnf5 install -y nftables
    else dnf install -y nftables; fi
    backend=nft
  fi
  HOP_SPEC="$spec" HOP_EXCLUDE="$exclusion" HOP_INTERVAL="$interval" HOP_BACKEND="$backend" HY2_PORT="$HY2_PORT" python_module hopping prepare "$TEMP"
}

snapshot_hopping() {
  [[ ${STAGING:-0} != 1 ]] || return 0
  if [[ -f "$HOP_UNIT_FILE" ]]; then
    grep -qxF 'Description=sing-box owned HY2 port hopping' "$HOP_UNIT_FILE" || die '同名跳跃服务不属于本脚本，拒绝覆盖。'
  elif systemctl cat "$HOP_UNIT" >/dev/null 2>&1; then
    die '存在无法确认归属的同名跳跃服务。'
  fi
  HOP_TRANSACTION=1
  if systemctl is-active --quiet "$HOP_UNIT"; then HOP_WAS_ACTIVE=1; fi
  if systemctl is-enabled --quiet "$HOP_UNIT"; then HOP_WAS_ENABLED=1; fi
}

apply_hopping_plan() {
  local enabled
  enabled="$(python_module hopping plan_enabled "$TEMP/hopping-plan.json")"
  if [[ ${STAGING:-0} == 1 ]]; then
    if [[ -f "$APP/hopping.json" || "$enabled" == yes ]]; then
      install -m 0600 "$TEMP/hopping-plan.json" "$APP/hopping.json"
    fi
    return 0
  fi
  # Stop with the old metadata before replacing the redirect target.
  if [[ -f "$APP/hopping.json" ]]; then
    hopping_runtime stop
  fi
  systemctl stop "$HOP_UNIT" 2>/dev/null || {
    [[ ! -f "$HOP_UNIT_FILE" ]] || die '无法停止端口跳跃服务。'
  }
  install -m 0600 "$TEMP/hopping-plan.json" "$APP/hopping.json"
  if [[ "$enabled" == yes ]]; then
    install -d -m 0755 "$(dirname "$HOP_UNIT_FILE")"
    printf '[Unit]\nDescription=sing-box owned HY2 port hopping\nBefore=sing-box.service\nAfter=network-pre.target\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/bin/bash %s hopping-runtime start\nExecStop=/bin/bash %s hopping-runtime stop\n\n[Install]\nWantedBy=multi-user.target\n' "$APP/manager.sh" "$APP/manager.sh" > "$HOP_UNIT_FILE"
    chmod 0644 "$HOP_UNIT_FILE"
    systemctl daemon-reload
    systemctl enable "$HOP_UNIT"
    systemctl restart "$HOP_UNIT"
    systemctl is-active --quiet "$HOP_UNIT" || die '端口跳跃规则未能启动。'
  else
    if [[ -f "$HOP_UNIT_FILE" ]]; then systemctl disable "$HOP_UNIT"; rm -f "$HOP_UNIT_FILE"; fi
    systemctl daemon-reload
  fi
}

hopping_runtime() {
  need_root
  python_module hopping runtime "${2:-$APP/hopping.json}" "$1" "${3:-$CONFIG}"
}

set_hopping() {
  need_root
  [[ -f "$CONFIG" ]] || die '请先安装。'
  local requested="${HY2_HOP_PORTS_REQUEST:-}" interval="${HY2_HOP_INTERVAL_REQUEST:-}"
  load_node_settings
  if [[ -n "${1:-}" ]]; then
    HY2_PORT="$(node_config hopping-port "$1")"
    ui info "本次端口跳跃目标：$1 · UDP/$HY2_PORT；单个跳跃服务同时管理一个 HY2 入站。"
  fi
  HY2_HOP_PORTS="${requested:-$HY2_HOP_PORTS}"; HY2_HOP_INTERVAL="${interval:-$HY2_HOP_INTERVAL}"
  prepare_hopping
  hopping_runtime validate "$TEMP/hopping-plan.json"
  check_configuration
  begin_transaction update "$APP/client" "$APP/hopping.json" "$APP/manager.sh" "$MANAGER" "$HOP_UNIT_FILE"
  snapshot_hopping
  install_manager
  apply_hopping_plan
  export_client_files
  restart_checked
  if [[ ! -f "$APP/client/EXPORT-ERROR.txt" ]]; then show_node_details; fi
  TRANSACTION=""
  if [[ ${STAGING:-0} != 1 ]]; then success '端口跳跃已更新；请重新导入客户端配置，并在云安全组开放上面列出的 UDP 跳跃端口。'; fi
}

# Kernel package lifecycle and portable configuration backups.
package_is_installed() {
  local status rc
  if [[ $PKG == apt ]]; then
    if status="$(dpkg-query -W -f='${db:Status-Status}' sing-box 2>/dev/null)"; then
      [[ "$status" == installed ]]
    else
      rc=$?; [[ $rc == 1 ]] && return 1; return 2
    fi
  else
    if rpm -q sing-box >/dev/null 2>&1; then return 0
    else rc=$?; [[ $rc == 1 ]] && return 1; return 2; fi
  fi
}

package_id() {
  if [[ $PKG == apt ]]; then
    dpkg-query -W -f='sing-box|${Version}|${Architecture}' sing-box
  else
    rpm -q --qf '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}' sing-box
  fi
}

prepare_package_rollback() {
  package_is_installed || die '无法确认 sing-box 软件包已完整安装。'
  OLD_PACKAGE_ID="$(package_id)"
  install -d -m 0700 "$TEMP/download" "$TEMP/package-rollback"
  if [[ $PKG == apt ]]; then
    local version="${OLD_PACKAGE_ID#*|}"; version="${version%%|*}"
    (cd "$TEMP/download"; apt-get download "sing-box=$version") || die '无法取得当前版本的回滚安装包，尚未更新/卸载。'
  else
    local manager=dnf
    [[ $PKG != dnf5 ]] || manager=dnf5
    if ! "$manager" download --help >/dev/null 2>&1; then
      if [[ $PKG == dnf5 ]]; then "$manager" install -y dnf5-plugins
      else "$manager" install -y dnf-plugins-core; fi
    fi
    if [[ $PKG == dnf5 ]]; then
      "$manager" download --destdir "$TEMP/download" "$OLD_PACKAGE_ID"
    else
      "$manager" download --downloaddir "$TEMP/download" "$OLD_PACKAGE_ID"
    fi
  fi
  local candidate identity count=0
  for candidate in "$TEMP/download/"*; do
    [[ -f "$candidate" ]] || continue
    if [[ $PKG == apt ]]; then
      # shellcheck disable=SC2016 # dpkg-deb expands these format placeholders, not Bash.
      identity="$(dpkg-deb -W --showformat='${Package}|${Version}|${Architecture}' "$candidate")"
    else
      identity="$(rpm -qp --qf '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}' "$candidate")"
    fi
    [[ "$identity" == "$OLD_PACKAGE_ID" ]] || continue
    count=$((count+1))
    OLD_PACKAGE="$TEMP/package-rollback/$(basename "$candidate")"
    cp -p "$candidate" "$OLD_PACKAGE"
  done
  [[ $count == 1 ]] || die '未取得唯一且版本/架构匹配的回滚包；操作已停止。'
}

restore_package() {
  local current manager=dnf
  current="$(package_id 2>/dev/null)" || current=missing
  [[ -f "$OLD_PACKAGE" ]] || { log '缺少原版本安装包，无法自动恢复内核。'; return 1; }
  if [[ $PKG == apt ]]; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y --reinstall --allow-downgrades --no-remove -o Dpkg::Options::=--force-confold "$OLD_PACKAGE" || return 1
  else
    [[ $PKG != dnf5 ]] || manager=dnf5
    if [[ "$current" == missing ]]; then
      "$manager" install -y "$OLD_PACKAGE" || return 1
    elif [[ "$current" == "$OLD_PACKAGE_ID" ]]; then
      "$manager" reinstall -y "$OLD_PACKAGE" || return 1
    else
      "$manager" downgrade -y "$OLD_PACKAGE" || return 1
    fi
  fi
  package_is_installed || return 1
  current="$(package_id)" || return 1
  [[ "$current" == "$OLD_PACKAGE_ID" ]] || { log '恢复后软件包版本不匹配。'; return 1; }
}

kernel_update() {
  need_root
  command -v cmp >/dev/null || die '缺少 cmp；请先安装 diffutils，再更新 sing-box 内核。'
  check_os
  [[ -x "$BIN" && -f "$CONFIG" ]] || die '请先安装。'
  check_configuration
  begin_transaction update /etc/sing-box "$APP/client" "$APP/tls" "$APP/rules"
  prepare_package_rollback
  systemctl stop "$UNIT"
  rm -f "$APP/cache.db"
  if [[ $PKG == apt ]]; then
    apt-get update
    PACKAGE_ROLLBACK=1
    DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade --no-remove -o Dpkg::Options::=--force-confold sing-box
  elif [[ $PKG == dnf5 ]]; then
    PACKAGE_ROLLBACK=1
    dnf5 upgrade -y sing-box
  else
    PACKAGE_ROLLBACK=1
    dnf upgrade -y sing-box
  fi
  systemctl daemon-reload
  "$BIN" version
  check_configuration
  # Package scripts must not silently replace node credentials or configuration.
  cmp -s "$CONFIG" "$TEMP/0/config.json" || die '软件包更新改动了配置，正在恢复原版本。'
  if (( WAS_ACTIVE )); then restart_checked; else systemctl stop "$UNIT"; fi
  if (( WAS_ENABLED )); then systemctl enable "$UNIT"; else systemctl disable "$UNIT"; fi
  PACKAGE_ROLLBACK=0
  TRANSACTION=""
  success 'sing-box 内核更新完成，节点凭据、证书和原服务启停状态已保留；运行缓存已重建。'
}

backup_archive() {
  export APP CONFIG BACKUP_DIR MANAGER HOP_UNIT_FILE
  python_module backup archive "$@"
}
backup_cmd() {
  need_root
  if [[ -d "$APP/pending" ]]; then warn '本次备份仅包含已应用配置，待应用修改未纳入备份。'; fi
  [[ -f "$CONFIG" ]] || die '没有可备份的节点配置。'
  local target="${1:-${BACKUP_FILE:-}}" version
  if [[ -x "$BIN" ]] && version="$("$BIN" version 2>/dev/null)" && [[ -n "$version" ]]; then
    BACKUP_KERNEL_VERSION="${version%%$'\n'*}"
  else
    BACKUP_KERNEL_VERSION=unknown
    log '无法读取内核版本，将继续备份配置资料。'
  fi
  BACKUP_SERVICE_ACTIVE=no; BACKUP_SERVICE_ENABLED=no
  if systemctl is-active --quiet "$UNIT"; then BACKUP_SERVICE_ACTIVE=yes; fi
  if systemctl is-enabled --quiet "$UNIT"; then BACKUP_SERVICE_ENABLED=yes; fi
  export BACKUP_KERNEL_VERSION BACKUP_SERVICE_ACTIVE BACKUP_SERVICE_ENABLED
  LAST_BACKUP="$(backup_archive create "$target")"
  success "备份完成：$LAST_BACKUP（包含节点密码和私钥，请妥善保管）。"
}

restore_backup() {
  need_root
  show_occupied_ports
  require_no_pending
  [[ -x "$BIN" ]] || die '请先安装兼容的 sing-box 内核，再恢复配置。'
  local FW_PREVIOUS_ENDPOINTS=''
  local source="${1:-${BACKUP_FILE:-}}" answer
  if [[ -z "$source" && -t 0 ]]; then
    printf '\n已有备份：\n'; ls -1 "$BACKUP_DIR/"*.tar.gz 2>/dev/null || true
    read -r -p '要恢复的备份完整路径：' source
  fi
  [[ -f "$source" ]] || die '请指定有效备份文件。'
  TEMP="$(mktemp -d)"
  backup_archive extract "$source" "$TEMP/restored"
  if [[ -f "$TEMP/restored/hopping.json" ]]; then hopping_runtime validate "$TEMP/restored/hopping.json" "$TEMP/restored/config.json"; fi
  if [[ -t 0 ]]; then
    read -r -p '恢复会覆盖当前节点凭据及证书，旧客户端配置可能失效。输入 YES 继续：' answer
    [[ "$answer" == YES ]] || return 0
  fi
  if [[ -f "$CONFIG" ]]; then
    if ! FW_PREVIOUS_ENDPOINTS="$(configuration_listeners)"; then
      FW_PREVIOUS_ENDPOINTS=''
      log '当前配置已损坏，旧防火墙规则将保留。'
    fi
  fi
  local -a restore_paths=("$APP/rules" "$APP/tls" "$APP/client" "$APP/hopping.json" "$APP/firewall-owned.json" "$APP/manager.sh")
  if [[ ! -e "$APP" && ! -L "$APP" ]]; then restore_paths=("$APP"); fi
  local restore_active restore_enabled states
  states="$(python_module backup service_state "$TEMP/restored/manifest.json")"
  read -r restore_active restore_enabled <<< "$states"
  begin_transaction update "$CONFIG" "${restore_paths[@]}" "$MANAGER" "$HOP_UNIT_FILE"
  snapshot_hopping
  if [[ -f "$APP/hopping.json" ]]; then hopping_runtime stop; fi
  if [[ -f "$HOP_UNIT_FILE" ]]; then systemctl stop "$HOP_UNIT"; fi
  systemctl stop "$UNIT"
  install -d -m 0755 "$(dirname "$CONFIG")"
  install -d -m 0700 "$APP"
  install -m 0600 "$TEMP/restored/config.json" "$CONFIG"
  local name
  for name in rules tls client; do
    rm -rf "${APP:?}/$name"
    if [[ -d "$TEMP/restored/$name" ]]; then cp -a "$TEMP/restored/$name" "$APP/$name"; else install -d -m 0700 "$APP/$name"; fi
  done
  # Old rules were already stopped using their original metadata above.
  rm -f "$APP/hopping.json"
  install_manager
  if [[ -f "$TEMP/restored/hopping.json" ]]; then
    cp "$TEMP/restored/hopping.json" "$TEMP/hopping-plan.json"
    apply_hopping_plan
  elif [[ -f "$HOP_UNIT_FILE" ]]; then
    systemctl disable "$HOP_UNIT"
    rm -f "$HOP_UNIT_FILE"
    systemctl daemon-reload
  fi
  export_client_files
  check_configuration
  rm -f "$APP/cache.db"
  open_firewall
  if [[ "$restore_active" == yes ]]; then restart_checked; else systemctl stop "$UNIT"; fi
  if [[ "$restore_enabled" == yes ]]; then systemctl enable "$UNIT"; else systemctl disable "$UNIT"; fi
  update_firewall_ownership
  if [[ ! -f "$APP/client/EXPORT-ERROR.txt" ]]; then show_node_details; fi
  TRANSACTION=""
  success '配置备份已恢复，服务启停和开机启动状态按备份恢复；内核版本未改变。请重新导入节点资料。'
}

uninstall_cmd() {
  need_root
  require_no_pending
  check_os
  [[ -f "$CONFIG" ]] || die '没有可卸载的配置。'
  if [[ -e "$MANAGER" ]]; then
    # shellcheck disable=SC2015 # Both validation conditions must succeed; otherwise fail.
    [[ ! -L "$MANAGER" ]] && grep -qxF '# sing-box-deploy 管理入口' "$MANAGER" || die '管理入口不属于本脚本，拒绝删除。'
  fi
  backup_cmd
  local answer="${UNINSTALL_CONFIRM:-}"
  if [[ -t 0 ]]; then
    printf '\n将移除 sing-box 软件包、节点配置、管理入口及本脚本拥有的防火墙规则。\n备份、共享软件源和依赖会保留。\n'
    read -r -p '确认卸载请输入 YES：' answer
  fi
  [[ "$answer" == YES ]] || die '未确认卸载，已保留现有部署。'
  begin_transaction uninstall "$CONFIG" "$APP" "$MANAGER" "$HOP_UNIT_FILE"
  prepare_package_rollback
  snapshot_hopping
  if [[ -f "$APP/hopping.json" ]]; then hopping_runtime stop; fi
  if [[ -f "$HOP_UNIT_FILE" ]]; then systemctl disable --now "$HOP_UNIT"; fi
  systemctl stop "$UNIT"
  systemctl disable "$UNIT"
  if [[ -f "$APP/firewall-owned.json" ]]; then update_firewall_ownership remove-all; fi
  if [[ $PKG == apt ]]; then
    local simulation
    simulation="$(LC_ALL=C apt-get -s --no-auto-remove remove sing-box)"
    if awk '$1=="Remv" && $2!="sing-box" && $2!~/^sing-box:/ {bad=1} END {exit !bad}' <<< "$simulation"; then die '卸载会移除其他软件包，已停止。'; fi
    PACKAGE_ROLLBACK=1
    DEBIAN_FRONTEND=noninteractive apt-get remove -y --no-auto-remove sing-box
  else
    rpm -e --test sing-box
    PACKAGE_ROLLBACK=1
    if [[ $PKG == dnf5 ]]; then dnf5 remove -y --setopt=clean_requirements_on_remove=False sing-box
    else dnf remove -y --setopt=clean_requirements_on_remove=False sing-box; fi
  fi
  local removed_status
  if package_is_installed; then die '软件包仍然安装，已停止清理并恢复原部署。'
  else removed_status=$?; [[ $removed_status == 1 ]] || die '无法确认软件包卸载状态。'; fi
  rm -f "$CONFIG" "$MANAGER" "$HOP_UNIT_FILE"
  rm -rf "$APP"
  systemctl daemon-reload
  PACKAGE_ROLLBACK=0
  TRANSACTION=""
  success "卸载完成。备份保留在 $LAST_BACKUP；共享软件源、签名密钥、依赖及无法确认归属的旧防火墙规则已保留。"
}

# Main menu and command dispatch.
main_menu() {
  need_root
  [[ -t 0 ]] || { usage; return 0; }
  run_menu 'sing-box 管理工具' summary \
    '节点与协议' @group \
    '安装' install \
    '修改协议配置' @protocol_menu \
    '修改代理出口（SOCKS5 / HTTPS）' @socks_menu \
    '查看 / 导出节点' @export_menu \
    '服务与监控' @group \
    '启动 / 停止 / 重启服务' @service_menu \
    '查看状态' status \
    '查看日志' logs \
    '检查连接' check \
    '维护与工具' @group \
    '安装 / 更新快捷命令 sb-manager' setup-manager \
    '更新 sing-box 内核' update \
    '手动备份已应用配置' backup \
    '恢复配置备份' restore \
    '卸载' uninstall \
    '变更管理' @group \
    '应用配置并重启' apply \
    '丢弃待应用修改' discard-pending \
    '高级操作' @group \
    '生成 / 重新生成协议' @protocol_creation_menu \
    '防火墙状态 / 详情 / 开关' @firewall_menu \
    '续期托管自签证书（应用后重导客户端）' renew-certs \
    '日志级别（默认 warn，保护访问隐私）' set-log-level
}

case "${1:-menu}" in
  menu) main_menu ;;
  firewall-status) firewall_status ;;
  firewall-details) firewall_status details ;;
  firewall-auto) set_firewall_auto "${2:-}" ;;
  firewall-auto-on) set_firewall_auto true ;;
  firewall-auto-off) set_firewall_auto false ;;
  firewall-enable) firewall_system enable "${2:-}" ;;
  firewall-disable) firewall_system disable "${2:-}" ;;
  install) fresh_install ;;
  set-ports) stage_changes set_node ports ;;
  set-hopping) stage_changes set_hopping "${2:-}" ;;
  set-hy2-bbr) stage_changes set_node bbr ;;
  update) kernel_update ;;
  backup) backup_cmd "${2:-}" ;;
  restore) restore_backup "${2:-}" ;;
  uninstall) uninstall_cmd ;;
  hopping-runtime) hopping_runtime "${2:-validate}" ;;
  set-sni) stage_changes set_node sni ;;
  set-credentials) stage_changes set_node credentials ;;
  rotate-credentials) stage_changes set_node rotate ;;
  regenerate) stage_changes set_node regenerate "${2:-}" ;;
  set-tfo) stage_changes set_node tfo ;;
  export) export_nodes ;;
  show-json) need_root; node_config json ;;
  show-yaml) need_root; node_config yaml ;;
  export-yaml) need_root; node_config export-yaml; success "已导出 $APP/client/proxies.yaml" ;;
  add-anytls) stage_changes set_node add-anytls ;;
  add-tuic) stage_changes set_node add-tuic ;;
  edit-protocol) stage_changes edit_protocol "${2:-}" "${3:-}" ;;
  edit-field) if (( $# >= 4 )); then stage_changes edit_inbound_field "$2" "$3" "$4"; else stage_changes edit_inbound_field "${2:-}" "${3:-}"; fi ;;
  disable-hopping) HY2_HOP_PORTS_REQUEST=0; stage_changes set_hopping "${2:-}" ;;
  set-protocol-defaults) stage_changes update_protocol_defaults ;;
  set-log-level) if (( $# >= 2 )); then stage_changes update_log_level "$2"; else stage_changes update_log_level; fi ;;
  renew-certs) stage_changes renew_certificates ;;
  summary) show_dashboard ;;
  protocol-edit-header) protocol_edit_header ;;
  apply) apply_changes ;;
  discard-pending) discard_pending ;;
  setup-manager) setup_manager ;;
  start|stop|restart) service_cmd "$1" ;;
  logs) need_root; journalctl -u "$UNIT" -n 80 --no-pager ;;
  check) check_connections ;;
  set-ai-proxy|set-ai-socks|set-socks) stage_changes set_socks_profile ai ;;
  set-google-proxy|set-google-socks) stage_changes set_socks_profile google ;;
  set-other-proxy|set-other-socks) stage_changes set_socks_profile other ;;
  configure-proxies|configure-socks) stage_changes set_socks_profile ai google other ;;
  status) if status_cmd; then exit 0; else exit "$?"; fi ;;
  show) show_node_details ;;
  -h|--help|help) usage ;;
  *) usage; die 'Unknown action.' ;;
esac
