#!/usr/bin/env bash
# sing-box deployment with config-driven inbound editing and owned firewall management.
# Google/YouTube via Google SOCKS5; remaining AI via AI SOCKS5; other public traffic via Other SOCKS5.
# Installs stable sing-box from the official APT/DNF repository; uses packaged systemd unit.
# Tested syntactically on Linux; run as root on a systemd server with apt-get or dnf.
set -Eeuo pipefail
umask 077

# Editable defaults. Environment variables override these; interactive input can override both.
# Keep credentials in single quotes (escape any literal single quote); protect this file if populated.
DEFAULT_AI_SOCKS_HOST=''
DEFAULT_AI_SOCKS_PORT=''
DEFAULT_AI_SOCKS_USER=''
DEFAULT_AI_SOCKS_PASS=''
DEFAULT_GOOGLE_SOCKS_HOST=''
DEFAULT_GOOGLE_SOCKS_PORT=''
DEFAULT_GOOGLE_SOCKS_USER=''
DEFAULT_GOOGLE_SOCKS_PASS=''
DEFAULT_OTHER_SOCKS_HOST=''
DEFAULT_OTHER_SOCKS_PORT=''
DEFAULT_OTHER_SOCKS_USER=''
DEFAULT_OTHER_SOCKS_PASS=''
DEFAULT_FIREWALL_AUTO='true' # Manage only this script's owned port permits.
DEFAULT_SOCKS_TFO='true' # Applies to all three SOCKS5 outbounds.
REQUEST_SOCKS_TFO="${SOCKS_TFO-}"
SOCKS_TFO="${SOCKS_TFO-$DEFAULT_SOCKS_TFO}"
DEFAULT_VLESS_PORT='443'
DEFAULT_HY2_PORT='443'
DEFAULT_TUIC_PORT='10443'
DEFAULT_TLS_HANDSHAKE_TIMEOUT='10s'
DEFAULT_ANYTLS_PORT='8443' # AnyTLS uses TCP; must differ from VLESS_PORT.
DEFAULT_HY2_HOP_PORTS='' # Empty disables hopping; e.g. 20000:20100,30000.
DEFAULT_HY2_HOP_INTERVAL='30s'
DEFAULT_HY2_BBR_PROFILE='standard'
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
DEFAULT_SERVER_IP='' # Empty: detect the public IPv4 automatically.
SERVER_IP="${SERVER_IP-$DEFAULT_SERVER_IP}"

SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
MANAGER="/usr/local/bin/sb-manager"
APP="/var/lib/sing-box/deployment"
BIN="/usr/bin/sing-box"
CONFIG="/etc/sing-box/config.json"
UNIT="sing-box.service"
HOP_UNIT="sing-box-hopping.service"
HOP_UNIT_FILE="/etc/systemd/system/sing-box-hopping.service"
BACKUP_DIR="/var/backups/sing-box-deploy"
REALITY_DOMAIN="${REALITY_DOMAIN:-la.mirrors.clouvider.net}"
AI_URL="https://github.com/DustinWin/ruleset_geodata/releases/download/sing-box-ruleset/ai.srs"
GOOGLE_URL="https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/google.srs"
YOUTUBE_URL="https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/youtube.srs"
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
OLD_PACKAGE=""
OLD_PACKAGE_ID=""
FW_MARK="sing-box-deploy-$BASHPID"

# Color only terminal output; redirected output and NO_COLOR remain plain text.
ui() {
  local kind="$1" text="$2" tail="${3:-}" color='' reset=''
  if [[ -t 1 && "${TERM:-dumb}" != dumb && ! ${NO_COLOR+x} ]]; then
    reset=$'\033[0m'
    case "$kind" in
      title) color=$'\033[1;36m' ;;
      item) color=$'\033[36m' ;;
      success) color=$'\033[1;32m' ;;
      warning) color=$'\033[1;33m' ;;
      error) color=$'\033[1;31m' ;;
      *) color=$'\033[34m' ;;
    esac
  fi
  printf '%s%s%s%s\n' "$color" "$text" "$reset" "$tail"
}

menu_choices() {
  local line
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" == *卸载* || "$line" == *关闭系统防火墙* ]]; then ui error "$line"
    elif [[ "$line" == *应用配置并重启* || "$line" == *'· 开启'* ]]; then ui success "$line"
    elif [[ "$line" == *重新生成* || "$line" == *含访问凭据* ]]; then ui warning "$line"
    elif [[ "$line" =~ ^([[:space:]]*[0-9]+\.)(.*)$ ]]; then
      ui item "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
    elif [[ -n "$line" ]]; then ui title "$line"
    else printf '\n'; fi
  done < <(printf '%s' "$1")
}

log() { printf '\n' >&2; ui info "[sing-box-deploy] $*" >&2; }
success() { printf '\n' >&2; ui success "[成功] $*" >&2; }
warn() { printf '\n' >&2; ui warning "[提示] $*" >&2; }
die() { printf '\n' >&2; ui error "[ERROR] $*" >&2; exit 1; }
[[ "$SOCKS_TFO" == true || "$SOCKS_TFO" == false ]] || die 'SOCKS_TFO must be true or false.'
[[ "$HY2_BBR_PROFILE" == standard || "$HY2_BBR_PROFILE" == conservative || "$HY2_BBR_PROFILE" == aggressive ]] || die 'HY2_BBR_PROFILE 必须是 standard、conservative 或 aggressive。'
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

usage() {
  cat <<'EOF'
用法：以 root 身份运行 bash sing-box-deploy.sh [命令]
  不带参数 / menu       进入中文管理菜单（非交互运行时显示帮助）
  install              安装 VLESS Reality + Hysteria2 + AnyTLS + TUIC 及三组 SOCKS5
  apply                应用全部待应用修改并重启服务（失败自动回滚，保留待应用修改）
  discard-pending      丢弃待应用修改；非交互需 DISCARD_CONFIRM=YES
  summary              显示真实服务/版本、已确认运行配置及待应用配置
  firewall-status / firewall-details  查看防火墙状态及规则详情
  firewall-auto true|false  开关脚本自动放行（保留现有规则，下次 apply 生效）
  firewall-enable / firewall-disable [ufw|firewalld]  系统开关，需明确 YES 确认
  set-ports            修改端口，默认保留当前值；可传 VLESS_PORT、HY2_PORT、ANYTLS_PORT、TUIC_PORT
  add-anytls           为旧部署添加 AnyTLS；可传 ANYTLS_PORT、NEW_ANYTLS_SNI、NEW_ANYTLS_PASS
  add-tuic             暂存生成 TUIC（独立 UUID/密码/证书），可传 TUIC_PORT、NEW_TUIC_SNI
  edit-field 标签 /字段路径 [JSON值|:remove]  逐项编辑或移除字段，保存后需 apply
  disable-hopping      暂存关闭 HY2 跳跃规则，保存后需 apply
  edit-protocol [标签] [JSON文件]  完整编辑现有入站所有字段；交互时调用 EDITOR
  set-protocol-defaults 更新已有协议的 TLS 10s、HY2 ignore_client_bandwidth 及 TUIC 默认参数
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
  set-tfo              开关三组 SOCKS5 TFO；非交互传 SOCKS_TFO=true/false
  set-ai-socks / set-google-socks / set-other-socks   修改单组 SOCKS5
  configure-socks      修改三组 SOCKS5；默认沿用已安装配置
  show / show-json / show-yaml   查看节点参数、分享链接、JSON 或 Clash/Mihomo proxies（含密码）
  export               导出到 /var/lib/sing-box/deployment/client
  start / stop / restart / status / logs / check    服务和连接检查
  setup-manager        安装或更新快捷管理命令 sb-manager

终端使用颜色强调状态与风险；重定向、TERM=dumb 或 NO_COLOR 时输出纯文本。
源码顶部 DEFAULT_* 是首次安装默认值，环境变量优先，交互输入可覆盖。
端口、TFO 等默认值读取源码顶部 DEFAULT_* 与环境变量；普通修改沿用当前值并保留未选择的凭据。
协议、SOCKS 和跳跃设置的修改仅保存到待应用区，执行 apply 才更新服务、防火墙和跳跃规则。
普通 show/export 查看已应用资料；待应用节点资料位于 deployment/pending/client，应用前不要导入。
安装支持 AI_SOCKS_*、GOOGLE_SOCKS_*、OTHER_SOCKS_*、SERVER_IP 等环境变量。
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
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends curl ca-certificates openssl python3 iproute2
  elif [[ $PKG == dnf5 ]]; then
    dnf5 install -y curl ca-certificates openssl python3 iproute
  else
    dnf install -y curl ca-certificates openssl python3 iproute
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

show_occupied_ports() {
  OCCUPIED_PORTS=''
  ui title '── 当前已占用端口 · TCP / UDP ──'
  if ! command -v ss >/dev/null; then
    warn '无法读取占用情况：未安装 ss，请安装 iproute2 / iproute 后再核实端口。'
    return 0
  fi
  OCCUPIED_PORTS="$(ss -H -lntup)" || { warn '读取端口失败，请先检查系统网络工具。'; return 1; }
  printf '%s\n' "${OCCUPIED_PORTS:-当前没有监听端口}"
  ui info 'TCP 与 UDP 分别判断；本机占用情况不代表云安全组已放行。'
} >&2

read_ports() {
  show_occupied_ports
  local name value answer
  for name in ${*:-VLESS_PORT HY2_PORT ANYTLS_PORT TUIC_PORT}; do
    [[ ( "$name" != ANYTLS_PORT && "$name" != TUIC_PORT ) || -n "${!name}" ]] || continue
    value="${!name}"
    if [[ -t 0 ]]; then
      read -r -p "${name} 监听端口 [$value]：" answer
      value="${answer:-$value}"
    fi
    [[ "$value" =~ ^[0-9]{1,5}$ ]] && ((10#$value >= 1 && 10#$value <= 65535)) || die "Invalid ${name} (1-65535)."
    printf -v "$name" '%s' "$((10#$value))"
  done
  [[ ${STAGING:-0} == 1 || -z "$ANYTLS_PORT" || "$ANYTLS_PORT" != "$VLESS_PORT" ]] || die 'AnyTLS 与 VLESS 不能使用相同 TCP 端口。'
  [[ ${STAGING:-0} == 1 || -z "$TUIC_PORT" || "$TUIC_PORT" != "$HY2_PORT" ]] || die 'TUIC 与 Hysteria2 不能使用相同 UDP 端口。'
}

# Each SOCKS upstream uses a separate set of credentials; never print passwords.
read_socks_profile() {
  show_occupied_ports
  local profile="$1" label prefix key fallback host port user pass answer
  label="${profile^}"
  prefix="${profile^^}_SOCKS"
  if [[ -f "$CONFIG" ]]; then
    local -a current=()
    mapfile -d '' -t current < <(node_config socks "$profile")
    [[ ${#current[@]} == 5 && "${current[4]}" == READY ]] || die '无法读取当前 SOCKS5 配置。'
    local DEFAULT_HOST="${current[0]}" DEFAULT_PORT="${current[1]}" DEFAULT_USER="${current[2]}" DEFAULT_PASS="${current[3]}"
    for key in HOST PORT USER PASS; do
      fallback="DEFAULT_$key"
      [[ -z "${!fallback}" ]] || printf -v "DEFAULT_${prefix}_$key" '%s' "${!fallback}"
    done
  fi
  key="${prefix}_HOST"; fallback="DEFAULT_${key}"; host="${!key-${!fallback}}"
  key="${prefix}_PORT"; fallback="DEFAULT_${key}"; port="${!key-${!fallback}}"
  key="${prefix}_USER"; fallback="DEFAULT_${key}"; user="${!key-${!fallback}}"
  key="${prefix}_PASS"; fallback="DEFAULT_${key}"; pass="${!key-${!fallback}}"
  if [[ -t 0 ]]; then
    read -r -p "${label} SOCKS5 地址${host:+ [$host]}：" answer
    host="${answer:-$host}"
    read -r -p "${label} SOCKS5 端口${port:+ [$port]}：" answer
    port="${answer:-$port}"
    read -r -p "${label} SOCKS5 用户名${user:+ [$user]}：" answer
    user="${answer:-$user}"
    read -r -s -p "${label} SOCKS5 密码（隐藏输入，回车保留当前值）：" answer
    printf '\n' >&2
    pass="${answer:-$pass}"
  fi
  [[ -n "$host" && "$host" =~ ^[a-zA-Z0-9.:-]+$ ]] || die "Invalid ${label} SOCKS host."
  [[ "$port" =~ ^[0-9]{1,5}$ ]] && ((10#$port >= 1 && 10#$port <= 65535)) || die "Invalid ${label} SOCKS port (1-65535)."
  [[ -n "$user" && -n "$pass" ]] || die "${label} SOCKS username/password cannot be empty."
  export "${prefix}_HOST=$host" "${prefix}_PORT=$((10#$port))" "${prefix}_USER=$user" "${prefix}_PASS=$pass"
}

# Check SOCKS5 authentication and CONNECT without placing credentials in argv/logs.
check_socks() {
  log "Checking $1 SOCKS5 authentication and outbound connectivity"
  SOCKS_PROFILE="$1" python3 - <<'PYCODE'
import os, socket, struct, sys
prefix = os.environ['SOCKS_PROFILE'].upper() + '_SOCKS'
e = os.environ
user, password = (e[prefix + suffix].encode() for suffix in ('_USER', '_PASS'))
if not (1 <= len(user) <= 255 and 1 <= len(password) <= 255):
    sys.exit('SOCKS5 username/password must each contain 1-255 UTF-8 bytes.')
def receive(sock, size):
    data = b''
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ValueError('upstream closed the connection')
        data += chunk
    return data
try:
    with socket.create_connection((e[prefix+'_HOST'], int(e[prefix+'_PORT'])), timeout=10) as sock:
        sock.sendall(b'\x05\x01\x02')
        if receive(sock, 2) != b'\x05\x02':
            raise ValueError('upstream did not accept username/password authentication')
        sock.sendall(b'\x01' + bytes([len(user)]) + user + bytes([len(password)]) + password)
        if receive(sock, 2) != b'\x01\x00':
            raise ValueError('authentication rejected')
        host = b'example.com'
        sock.sendall(b'\x05\x01\x00\x03' + bytes([len(host)]) + host + struct.pack('!H', 443))
        version, reply, reserved, atyp = receive(sock, 4)
        if version != 5 or reserved != 0 or reply != 0:
            raise ValueError(f'CONNECT failed (SOCKS reply {reply})')
        if atyp == 1:
            receive(sock, 4)
        elif atyp == 4:
            receive(sock, 16)
        elif atyp == 3:
            receive(sock, receive(sock, 1)[0])
        else:
            raise ValueError('invalid SOCKS address type')
        receive(sock, 2)
except (OSError, ValueError) as exc:
    sys.exit(f'SOCKS5 check failed: {exc}')
PYCODE
}

forget_socks() {
  unset AI_SOCKS_PASS GOOGLE_SOCKS_PASS OTHER_SOCKS_PASS AI_SOCKS_USER GOOGLE_SOCKS_USER OTHER_SOCKS_USER
}

public_ipv4() {
  SERVER_IP="${SERVER_IP:-}"
  if [[ -z "$SERVER_IP" ]]; then
    SERVER_IP="$(curl -4fsSL --connect-timeout 5 --max-time 12 https://api.ipify.org || true)"
  fi
  export SERVER_IP
  python3 - <<'PY'
import ipaddress, os, sys
try:
    ip = ipaddress.IPv4Address(os.environ['SERVER_IP'])
    if not ip.is_global:
        raise ValueError('not public')
except Exception as e:
    sys.exit(f'Cannot identify public IPv4 ({e}); set SERVER_IP=<your server public IP> and retry.')
PY
  log "Detected public IPv4: $SERVER_IP"
}

check_reality_target() {
  log "Testing third-party Reality handshake target ${REALITY_DOMAIN}:443"
  local output
  if output="$(timeout 12 openssl s_client -connect "${REALITY_DOMAIN}:443" \
    -servername "$REALITY_DOMAIN" -tls1_3 -verify_hostname "$REALITY_DOMAIN" \
    -verify_return_error </dev/null 2>&1)" && grep -qi 'Verify return code: 0 (ok)' <<< "$output"; then
    log 'Reality target TLS certificate validated.'
  else
    die 'Reality target TLS 1.3/hostname verification failed; check DNS, reachability and certificate.'
  fi
}

download_rules() {
  mkdir -p "$APP/rules"
  local entry name url
  local -a entries=("$@")
  if (( ${#entries[@]} == 0 )); then entries=(ai google youtube); fi
  for entry in "${entries[@]}"; do
    name="$entry"
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

make_hy2_certificate() { make_tls_certificate hy2 "${HY2_SNI:-$REALITY_DOMAIN}"; }

make_tls_certificate() {
  local name="$1" sni="$2" san
  [[ ! -L "$APP/tls/$name.crt" && ! -L "$APP/tls/$name.key" ]] || die '证书或私钥是符号链接，请先确认外部证书管理方式。'
  san="$(python3 - "$sni" <<'PYCODE'
import ipaddress, sys
try:
    ipaddress.ip_address(sys.argv[1])
    print('IP:' + sys.argv[1])
except ValueError:
    print('DNS:' + sys.argv[1])
PYCODE
)"
  log "正在生成 $name 自签证书：$sni"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -sha256 \
    -days 825 -nodes \
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

write_jsons() {
  export APP CONFIG REALITY_DOMAIN AI_URL GOOGLE_URL YOUTUBE_URL VLESS_PORT HY2_PORT ANYTLS_PORT ANYTLS_SNI ANYTLS_PASS HY2_BBR_PROFILE SOCKS_TFO TUIC_PORT TUIC_UUID TUIC_PASS TUIC_SNI DEFAULT_TLS_HANDSHAKE_TIMEOUT
  python3 - <<'PYCODE'
import json, os, pathlib, urllib.parse
p = pathlib.Path(os.environ['APP'])
e = os.environ
resolver = {'server':'local', 'strategy':'ipv4_only','timeout':'3s'}

def socks(tag, prefix):
    return {'type':'socks', 'tag':tag, 'server':e[prefix+'_HOST'],
            'server_port':int(e[prefix+'_PORT']), 'version':'5',
            'username':e[prefix+'_USER'], 'password':e[prefix+'_PASS'],
            'domain_resolver':resolver, 'connect_timeout':'5s',
            'tcp_fast_open':e['SOCKS_TFO'] == 'true',
            'tcp_keep_alive':'2m', 'tcp_keep_alive_interval':'30s'}

def ruleset(tag, url):
    return {'type':'remote', 'tag':tag,'format':'binary','url':url,
            'initial_path':str(p/'rules'/f'{tag}.srs'),
            'http_client':{'engine':'go','detour':'direct'}, 'update_interval':'1d'}

config = {
 'log':{'level':'info','timestamp':True},
 'dns':{'servers':[{'type':'local','tag':'local'}], 'final':'local','strategy':'ipv4_only'},
 'inbounds':[
   {'type':'vless','tag':'vless-reality','listen':'0.0.0.0','listen_port':int(e['VLESS_PORT']),
    'users':[{'name':'main','uuid':e['UUID'],'flow':'xtls-rprx-vision'}],
    'tls':{'enabled':True,'server_name':e['REALITY_DOMAIN'],
           'reality':{'enabled':True,
             'handshake':{'server':e['REALITY_DOMAIN'], 'server_port':443,
                          'domain_resolver':resolver, 'connect_timeout':'5s'},
             'private_key':e['REALITY_PRIVATE'], 'short_id':[e['SHORT_ID']],
             'max_time_difference':'1m'}}},
   {'type':'hysteria2','tag':'hysteria2','listen':'0.0.0.0','listen_port':int(e['HY2_PORT']),
    'bbr_profile':e['HY2_BBR_PROFILE'],'ignore_client_bandwidth':True,
    'users':[{'name':'main','password':e['HY2_PASS']}],
    'obfs':{'type':'salamander','password':e['HY2_OBFS_PASS']},
    'tls':{'enabled':True,'server_name':e['REALITY_DOMAIN'],'alpn':['h3'],
           'certificate_path':str(p/'tls/hy2.crt'),'key_path':str(p/'tls/hy2.key')}}
 ],
 'outbounds':[{'type':'direct','tag':'direct'},socks('ai-socks','AI_SOCKS'),socks('google-socks','GOOGLE_SOCKS'),socks('other-socks','OTHER_SOCKS')],
 'route':{
   'rules':[
     {'action':'sniff','sniffer':['http','tls','quic'],'timeout':'500ms'},
     {'ip_is_private':True,'action':'reject'},
     # Google first: Gemini/Google AI routes to Google SOCKS when both rules match.
     {'rule_set':['google','youtube'],'action':'route','outbound':'google-socks'},
     {'rule_set':['ai'],'action':'route','outbound':'ai-socks'},
     {'action':'resolve','server':'local','strategy':'ipv4_only','timeout':'3s'},
     {'ip_is_private':True,'action':'reject'}
   ],
   'rule_set':[
     ruleset('ai',e['AI_URL']),
     ruleset('google',e['GOOGLE_URL']),
     ruleset('youtube',e['YOUTUBE_URL'])
   ],
   'final':'other-socks','default_domain_resolver':'local','auto_detect_interface':True
 },
 'experimental':{'cache_file':{'enabled':True,'path':str(p/'cache.db'),'store_dns':True}}
}
if e.get('ANYTLS_PORT'):
    config['inbounds'].append({
        'type':'anytls','tag':'anytls','listen':'0.0.0.0','listen_port':int(e['ANYTLS_PORT']),
        'users':[{'name':'main','password':e['ANYTLS_PASS']}],
        'tls':{'enabled':True,'server_name':e.get('ANYTLS_SNI') or e['REALITY_DOMAIN'],
               'certificate_path':str(p/'tls/anytls.crt'),'key_path':str(p/'tls/anytls.key')}})
if e.get('TUIC_PORT'):
    config['inbounds'].append({
        'type':'tuic','tag':'tuic','listen':'0.0.0.0','listen_port':int(e['TUIC_PORT']),
        'users':[{'name':'main','uuid':e['TUIC_UUID'],'password':e['TUIC_PASS']}],
        'congestion_control':'bbr','auth_timeout':'3s','zero_rtt_handshake':False,'heartbeat':'10s',
        'disable_path_mtu_discovery':False,
        'tls':{'enabled':True,'server_name':e.get('TUIC_SNI') or e['REALITY_DOMAIN'],'alpn':['h3'],
               'certificate_path':str(p/'tls/tuic.crt'),'key_path':str(p/'tls/tuic.key')}})
for item in config['inbounds']:
    item['tls']['handshake_timeout']=e['DEFAULT_TLS_HANDSHAKE_TIMEOUT']
cert = (p/'tls/hy2.crt').read_text()
clients = {
 'vless-reality.outbound.json': {
   'type':'vless','tag':'vless-reality','server':e['SERVER_IP'],'server_port':int(e['VLESS_PORT']),
   'uuid':e['UUID'],'flow':'xtls-rprx-vision',
   'tls':{'enabled':True,'server_name':e['REALITY_DOMAIN'],
          'utls':{'enabled':True,'fingerprint':'chrome'},
          'reality':{'enabled':True,'public_key':e['REALITY_PUBLIC'],'short_id':e['SHORT_ID']}}
 },
 'hysteria2.outbound.json': {
   'type':'hysteria2','tag':'hysteria2','server':e['SERVER_IP'],'server_port':int(e['HY2_PORT']),
   'password':e['HY2_PASS'],
   'obfs':{'type':'salamander','password':e['HY2_OBFS_PASS']},
   'tls':{'enabled':True,'server_name':e['REALITY_DOMAIN'],'alpn':['h3'],
          'insecure':False,'certificate':cert}
 }
}
def write(path,contents):
    path.write_text(contents)
    path.chmod(0o600)
def write_json(path,obj):
    write(path,json.dumps(obj,indent=2,ensure_ascii=False)+'\n')
write_json(pathlib.Path(e['CONFIG']),config)
for name, obj in clients.items():
    obj['tls']['handshake_timeout']=e['DEFAULT_TLS_HANDSHAKE_TIMEOUT']
    write_json(p/'client'/name,obj)

PYCODE
  check_configuration || die 'sing-box check failed. Service was not started.'
  node_config export
}

configuration_listeners() {
  python3 - "${1:-$CONFIG}" <<'PYCODE'
import json,sys
labels={'vless':'VLESS','hysteria2':'Hysteria2','anytls':'AnyTLS','tuic':'TUIC'}
for item in json.load(open(sys.argv[1])).get('inbounds',[]):
    if 'listen_port' not in item: continue
    kind=item.get('type') or item.get('tag')
    # direct/shadowsocks listen on both networks when unspecified (official inbound docs).
    if (item.get('transport') or {}).get('type')=='quic': networks=['udp']
    elif item.get('network'): networks=[item['network']]
    elif kind in ('direct','shadowsocks'): networks=['tcp','udp']
    else: networks=['udp' if kind in ('hysteria','hysteria2','tuic') else 'tcp']
    for network in networks:
        print(network,item['listen_port'],labels.get(kind,item.get('tag','协议')))
PYCODE
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
    output="$(python3 -c '
import re, sys
def may_match(destination, entry):
    port, proto = entry.split("/")
    target = destination.split(" on ", 1)[0]
    if "/" in target:
        target, rule_proto = target.rsplit("/", 1)
        if rule_proto in ("tcp", "udp") and rule_proto != proto:
            return False
    parts = target.split(",")
    if not all(re.fullmatch(r"[0-9]+(?::[0-9]+)?", part) for part in parts):
        return True  # Anywhere or an application profile: cannot exclude this port.
    for part in parts:
        bounds = [int(v) for v in part.split(":")]
        if bounds[0] <= int(port) <= bounds[-1]:
            return True
    return False
rules = []
for line in sys.stdin:
    match = re.match(r"^\[\s*\d+\]\s+(.*?)\s{2,}(ALLOW|DENY|REJECT|LIMIT) IN\s+(.*)$", line.strip())
    if match and "(v6)" not in match[1]:
        rules.append(match.groups())
for entry in sys.argv[1:]:
    blocked = False
    for destination, action, source in rules:
        if destination == entry and action in ("DENY", "REJECT", "LIMIT") and source.split(" #", 1)[0].strip() == "Anywhere":
            sys.exit(f"UFW has a conflicting {action} rule for {entry}; update that policy before deploying.")
        if action in ("DENY", "REJECT", "LIMIT") and may_match(destination, entry):
            blocked = True
        if destination == entry and action == "ALLOW" and source.split(" #", 1)[0].strip() == "Anywhere":
            if blocked:
                sys.exit(f"UFW allow {entry} follows a deny/reject/limit rule; reorder conflicting rules before deploying.")
            break
    else:
        print(entry)
' "${endpoints[@]}" <<< "$rules")"
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
    chains="$(python3 -c '
import json, re, sys
for item in json.load(sys.stdin)["nftables"]:
    c = item.get("chain", {})
    if c.get("family") in ("ip", "inet") and c.get("hook") == "input":
        names = [c["family"], c["table"], c["name"]]
        if not all(re.fullmatch(r"[a-zA-Z0-9_.-]+", v) for v in names):
            sys.exit("Unsupported nftables identifier; configure this firewall manually.")
        if c.get("type") != "filter":
            sys.exit("Unsupported nftables input chain type.")
        print(" ".join(names))
' <<< "$rules")"
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
      if handles="$(FW_MARK="$FW_MARK" python3 -c '
import json, os, sys
for item in json.load(sys.stdin)["nftables"]:
    r = item.get("rule", {})
    if r.get("comment") == os.environ["FW_MARK"]:
        print(r["family"], r["table"], r["chain"], r["handle"])
' <<< "$rules")"; then
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
  python3 - "$APP/firewall-settings.json" "$DEFAULT_FIREWALL_AUTO" "${1:-}" <<'PYCODE'
import json, os, pathlib, sys, tempfile
p=pathlib.Path(sys.argv[1]);value=sys.argv[3]
if value:
    if value not in ('true','false'): sys.exit('自动放行开关必须是 true 或 false。')
    if not p.parent.is_dir(): sys.exit('请先安装节点，再设置自动放行端口。')
    if p.is_symlink(): sys.exit('拒绝覆盖防火墙设置符号链接。')
    with tempfile.NamedTemporaryFile(mode='w',dir=p.parent,prefix='.firewall-settings-',delete=False) as f:
        temporary=pathlib.Path(f.name)
        try:
            json.dump({'automatic_ports':value=='true'},f);f.write('\n');f.flush()
            os.fchmod(f.fileno(),0o600);temporary.replace(p)
        finally:
            temporary.unlink(missing_ok=True)
    print(value)
else:
    if p.is_symlink(): sys.exit('拒绝读取防火墙设置符号链接。')
    if p.exists():
        data=json.loads(p.read_text());value=data.get('automatic_ports')
        if type(value) is not bool: sys.exit('防火墙自动放行设置格式无效。')
        print('true' if value else 'false')
    else:
        if sys.argv[2] not in ('true','false'): sys.exit('DEFAULT_FIREWALL_AUTO 必须是 true 或 false。')
        print(sys.argv[2])
PYCODE
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
  ui title '防火墙状态'
  ui info "脚本自动放行端口：$automatic"
  python3 - "${1:-summary}" "$APP/firewall-owned.json" <<'PYCODE'
import json, os, pathlib, shutil, subprocess, sys
verbose=sys.argv[1]=='details';active=False;found=False

def run(args, allowed=(0,)):
    r=subprocess.run(args,text=True,capture_output=True,env={**os.environ,'LC_ALL':'C'})
    if r.returncode not in allowed:
        sys.stderr.write(r.stderr or r.stdout)
        sys.exit('无法读取防火墙状态：'+args[0])
    return r

if shutil.which('ufw'):
    found=True;r=run(['ufw','status']+(['verbose'] if verbose else []))
    if 'Status: active' in r.stdout: active=True;print('UFW：已开启')
    elif 'Status: inactive' in r.stdout: print('UFW：已关闭')
    else: sys.exit('无法识别 UFW 状态。')
    if verbose: print(r.stdout.rstrip())
if shutil.which('firewall-cmd'):
    found=True;r=run(['firewall-cmd','--state'],(0,252))
    if r.returncode==0 and r.stdout.strip()=='running':
        active=True;print('firewalld：已开启')
        if verbose:
            for mode in ([],['--permanent']):
                print('持久规则：' if mode else '运行规则：')
                print(run(['firewall-cmd',*mode,'--list-all-zones']).stdout.rstrip())
    elif r.returncode==252 and 'not running' in r.stdout+r.stderr: print('firewalld：已关闭')
    else: sys.exit('无法识别 firewalld 状态。')
# Without a manager, show the actual raw rules rather than equating an installed tool with protection.
if not active:
    if shutil.which('nft'):
        found=True;data=json.loads(run(['nft','-j','list','ruleset']).stdout)
        entries=[x for x in data.get('nftables',[]) if any(k in x for k in ('table','chain','rule'))]
        print(f'nftables：{len(entries)} 项表/链/规则（原始规则不提供一键开关）')
        if verbose: print(json.dumps(data,indent=2,ensure_ascii=False))
    if shutil.which('iptables'):
        found=True;args=['iptables','-w','-S']+([] if verbose else ['INPUT'])
        print('iptables：');print(run(args).stdout.rstrip())
if not found: print('未检测到可用的防火墙管理工具。')
p=pathlib.Path(sys.argv[2]);rules=json.loads(p.read_text()) if p.exists() else []
print(f'本脚本记录的放行规则：{len(rules)} 条')
if verbose:
    print(json.dumps(rules,indent=2,ensure_ascii=False))
    print('云安全组不在本机防火墙状态内，请在云平台查看。')
PYCODE
}

firewall_system() {
  need_root
  local operation="${1:-}" backend="${2:-}" answer="${FIREWALL_CONFIRM:-}" choice output rc other
  local -a managers=()
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
  ui warning "$operation $backend 会立即修改整台服务器的防火墙及其持久状态。启用前请确认 SSH 已放行；关闭会影响整机防护。"
  if [[ -t 0 ]]; then read -r -p '确认此系统操作？输入 YES：' answer; fi
  [[ "$answer" == YES ]] || die '未明确确认，系统防火墙保持不变；非交互操作需 FIREWALL_CONFIRM=YES。'
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
  log "Cloud firewall/security group must allow TCP/$VLESS_PORT${ANYTLS_PORT:+ and TCP/$ANYTLS_PORT} and UDP/$HY2_PORT${TUIC_PORT:+ and UDP/$TUIC_PORT}; confirm actual client connectivity."
}

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
    printf 'AI → %s:%s\nGoogle/YouTube → %s:%s\n其他 → %s:%s\n' "$AI_SOCKS_HOST" "$AI_SOCKS_PORT" "$GOOGLE_SOCKS_HOST" "$GOOGLE_SOCKS_PORT" "$OTHER_SOCKS_HOST" "$OTHER_SOCKS_PORT"
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
  download_rules
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

# One transaction covers validation, atomic replacement and service restart.
set_socks_profile() {
  need_root
  [[ -f "$CONFIG" && -x "$BIN" && -f "$APP/client/node-info.txt" ]] || die 'First run install.'
  local profile
  for profile in "$@"; do
    read_socks_profile "$profile"
    check_socks "$profile"
  done
  check_configuration
  begin_transaction update "$CONFIG" "$APP/client/node-info.txt"
  export CONFIG APP SOCKS_TFO REQUEST_SOCKS_TFO
  python3 - "$@" <<'PYCODE'
import json, os, pathlib, sys, tempfile
p = pathlib.Path(os.environ['CONFIG'])
c = json.loads(p.read_text())
for profile in sys.argv[1:]:
    tag = profile + '-socks'
    matches = [o for o in c['outbounds'] if o.get('tag') == tag and o.get('type') == 'socks']
    if profile == 'other' and not any(o.get('tag') == tag for o in c['outbounds']):
        matches = [{'type':'socks', 'tag':tag, 'version':'5',
                    'domain_resolver':{'server':'local','strategy':'ipv4_only','timeout':'3s'},
                    'connect_timeout':'5s','tcp_keep_alive':'2m','tcp_keep_alive_interval':'30s',
                    'tcp_fast_open':os.environ['SOCKS_TFO'] == 'true'}]
        c['outbounds'].append(matches[0])
    if len(matches) != 1:
        sys.exit(f'Expected exactly one SOCKS outbound: {tag}')
    prefix = profile.upper() + '_SOCKS'
    matches[0].update(server=os.environ[prefix+'_HOST'], server_port=int(os.environ[prefix+'_PORT']),
                      username=os.environ[prefix+'_USER'], password=os.environ[prefix+'_PASS'])
    if os.environ['REQUEST_SOCKS_TFO']:
        matches[0]['tcp_fast_open'] = os.environ['REQUEST_SOCKS_TFO'] == 'true'
if 'other' in sys.argv[1:]:
    c['route']['final'] = 'other-socks'
with tempfile.NamedTemporaryFile(mode='w', dir=p.parent, prefix='.config-', delete=False) as f:
    staging = pathlib.Path(f.name)
    try:
        json.dump(c, f, indent=2, ensure_ascii=False)
        f.write('\n')
        f.flush()
        st = p.stat()
        os.fchown(f.fileno(), st.st_uid, st.st_gid)
        os.fchmod(f.fileno(), 0o600)
        staging.replace(p)
    finally:
        if staging.exists():
            staging.unlink()
if 'other' in sys.argv[1:]:
    info = pathlib.Path(os.environ['APP'])/'client/node-info.txt'
    info.write_text(info.read_text().replace('Everything else: direct; private IPs rejected',
                                           'Everything else: Other SOCKS5; private IPs rejected'))
PYCODE
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
  show_node_details
  TRANSACTION=""
  if [[ ${STAGING:-0} != 1 ]]; then log 'Configuration updated, checked and service restarted.'; fi
}

show_node_details() {
  need_root
  node_config show
}

# Shared reader/writer for installed node settings and client exports.
# Pending edits never touch the active configuration, certificates or network rules.
check_configuration() {
  if [[ ${STAGING:-0} == 1 ]]; then "$BIN" check -c "$CONFIG"
  else "$BIN" check -C /etc/sing-box; fi
}

relocate_tls_paths() {
  python3 - "$1" "$2" "$3" <<'PYCODE'
import json,pathlib,sys
path,old,new = pathlib.Path(sys.argv[1]),pathlib.Path(sys.argv[2]),pathlib.Path(sys.argv[3])
if path.is_symlink(): sys.exit('配置文件是符号链接，拒绝覆盖。')
c=json.loads(path.read_text())
for inbound in c.get('inbounds',[]):
    for key in ('certificate_path','key_path'):
        tls=(inbound.get('tls') or {})
        if key not in tls: continue
        try: relative=pathlib.Path(tls[key]).relative_to(old/'tls')
        except ValueError: continue
        tls[key]=str(new/'tls'/relative)
path.write_text(json.dumps(c,indent=2,ensure_ascii=False)+'\n')
path.chmod(0o600)
PYCODE
}

pending_fingerprint() {
  python3 - "$1" <<'PYCODE'
import hashlib,pathlib,sys
root=pathlib.Path(sys.argv[1]); digest=hashlib.sha256()
for path in sorted(root.rglob('*')):
    if path.is_dir() and not path.is_symlink(): continue
    digest.update(str(path.relative_to(root)).encode()+b'\0')
    digest.update((str(path.readlink()).encode() if path.is_symlink() else path.read_bytes())+b'\0')
print(digest.hexdigest())
PYCODE
}

stage_changes() {
  need_root
  [[ -f "$CONFIG" && -d "$APP/client" ]] || die '请先安装节点。'
  local pending="$APP/pending" name existed=0 before
  [[ ! -d "$pending" ]] || existed=1
  begin_transaction files "$pending"
  if [[ ! -d "$pending" ]]; then
    install -d -m 0700 "$pending"
    for name in tls client; do
      [[ ! -L "$APP/$name" ]] || die '拒绝暂存符号链接目录。'
      cp -a "$APP/$name" "$pending/$name"
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
  local pending="$APP/pending" old_vless old_hy2 old_anytls old_tuic old_vnet name staged=0 answer
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
  load_node_settings
  old_vless="$VLESS_PORT" old_hy2="$HY2_PORT" old_anytls="$ANYTLS_PORT" old_tuic="$TUIC_PORT" old_vnet="$VLESS_NETWORK"
  begin_transaction update "$CONFIG" "$APP/tls" "$APP/client" "$APP/hopping.json" "$APP/firewall-owned.json" "$APP/manager.sh" "$MANAGER" "$HOP_UNIT_FILE" "$APP/runtime-state.json"
  snapshot_hopping
  if (( staged )); then
    if [[ -f "$pending/hopping.json" ]]; then cp "$pending/hopping.json" "$TEMP/hopping-plan.json"; fi
    for name in tls client; do rm -rf "$APP/$name"; cp -a "$pending/$name" "$APP/$name"; done
    install -m 0600 "$pending/config.json" "$CONFIG"
    relocate_tls_paths "$CONFIG" "$pending" "$APP"
  elif [[ -f "$APP/hopping.json" ]]; then
    cp "$APP/hopping.json" "$TEMP/hopping-plan.json"
  fi
  check_configuration
  install_manager
  if [[ -f "$TEMP/hopping-plan.json" ]]; then apply_hopping_plan; fi
  load_node_settings
  open_firewall "$old_vless" "$old_hy2" "$old_anytls" "$old_tuic" "$old_vnet"
  restart_checked
  update_firewall_ownership "$old_vless" "$old_hy2" "$old_anytls" "$old_tuic" "$old_vnet"
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
  local identity='' snapshot='' version='' pid='' active=0
  if systemctl is-active --quiet "$UNIT"; then active=1; fi
  if (( active )) && identity="$(systemctl show "$UNIT" -p InvocationID --value)" && [[ -n "$identity" ]] && snapshot="$(node_config running-summary "$identity")"; then
    ui success "${snapshot%%$'\n'*}"
    printf '%s\n' "${snapshot#*$'\n'}"
  else
    if (( active )) && pid="$(systemctl show "$UNIT" -p MainPID --value)" && [[ "$pid" =~ ^[1-9][0-9]*$ && -x "/proc/$pid/exe" ]]; then
      version="$("/proc/$pid/exe" version | sed -n '1s/.*version //p')"
      ui success "服务：运行中    版本：${version:-未知}"
    else
      if [[ -x "$BIN" ]]; then version="$("$BIN" version | sed -n '1s/.*version //p')"; fi
      if (( active )); then ui success "服务：运行中    已安装版本：${version:-未知}"
      else ui warning "服务：已停止或异常    已安装版本：${version:-未安装}"; fi
    fi
    if [[ -f "$CONFIG" ]]; then
      if (( active )); then ui warning '运行配置未确认；以下为已保存的配置文件（通过本工具启动或应用后可确认）。'
      else ui title '已保存配置：'; fi
      node_config summary
    else
      ui warning '尚未安装节点。'
    fi
  fi
  if [[ -f "$APP/pending/config.json" ]]; then
    ui warning '待应用配置（尚未生效）：'
    (CONFIG="$APP/pending/config.json"; APP="$APP/pending"; node_config summary)
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
  FIELD_VALUE="$value" python3 - "$TEMP/field-original.json" "$input" "$pointer" <<'PYCODE'
import json,os,pathlib,re,sys
obj=json.loads(pathlib.Path(sys.argv[1]).read_text());pointer=sys.argv[3];value=os.environ['FIELD_VALUE']
if not pointer.startswith('/') or re.search(r'~(?![01])',pointer): sys.exit('字段路径必须为 JSON Pointer，例如 /tls/handshake_timeout。')
keys=[p.replace('~1','/').replace('~0','~') for p in pointer[1:].split('/')]
try:
    current=obj
    for key in keys[:-1]:
        if isinstance(current,list): current=current[int(key)]
        else: current=current.setdefault(key,{})
    key=keys[-1]
    if isinstance(current,list):
        if key=='-' and value!=':remove': current.append(json.loads(value))
        elif value==':remove': del current[int(key)]
        else: current[int(key)]=json.loads(value)
    elif value==':remove': current.pop(key,None)
    else: current[key]=json.loads(value)
except (ValueError,IndexError,KeyError,TypeError,AttributeError) as error:
    sys.exit('字段或 JSON 值无效：'+str(error))
pathlib.Path(sys.argv[2]).write_text(json.dumps(obj,ensure_ascii=False,indent=2)+'\n')
PYCODE
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
    read -r -a editor <<< "${VISUAL:-${EDITOR:-vi}}"
    command -v "${editor[0]}" >/dev/null || die '编辑器未安装，请设置 EDITOR 或提供 JSON 文件。'
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

export_client_files() {
  local rc report
  [[ -n "$TEMP" ]] || TEMP="$(mktemp -d)"
  report="$TEMP/client-export-error"
  if node_config export 2>"$report"; then
    rm -f "$APP/client/EXPORT-ERROR.txt"
  else
    rc=$?
    if [[ $rc != 3 ]]; then cat "$report" >&2; return "$rc"; fi
    install -m 0600 "$report" "$APP/client/EXPORT-ERROR.txt"
    install -m 0600 "$report" "$APP/client/node-info.txt"
    warn '服务端配置有效，但该高级组合无法自动生成客户端资料；请查看 client/EXPORT-ERROR.txt 并手动配置客户端。'
  fi
}

node_config() {
  export APP CONFIG DEFAULT_HY2_HOP_INTERVAL DEFAULT_TLS_HANDSHAKE_TIMEOUT LIVE_APP
  python3 - "$@" <<'PYCODE'
import copy, hashlib, ipaddress, json, math, os, pathlib, re, ssl, sys, tempfile, uuid
p = pathlib.Path(os.environ['CONFIG'])
app = pathlib.Path(os.environ['APP'])
action = sys.argv[1]
if action=='running-summary':
    state_path = app/'runtime-state.json'
    if not state_path.exists(): sys.exit(1)
    state = json.loads(state_path.read_text())
    if not sys.argv[2] or state.get('identity')!=sys.argv[2]: sys.exit(1)
    print('服务：运行中    版本：'+state['version'])
    print(state['summary'])
    sys.exit()
if not p.exists(): sys.exit('请先安装节点。')
c = json.loads(p.read_text())
original = copy.deepcopy(c) if action == 'validate' else None

def inbound(tag):
    kind='vless' if tag=='vless-reality' else tag
    values=[i for i in c['inbounds'] if i.get('type')==kind]
    if not values: values=[i for i in c['inbounds'] if not i.get('type') and i.get('tag')==tag]
    if len(values)>1 and action=='load': return values[0]
    if len(values)!=1:
        if action in ('export','show','json','yaml','export-yaml'):
            sys.stderr.write(f'{kind} 存在多个入站或缺少预置入站，当前无法自动生成完整客户端资料，请手动配置客户端。\n');sys.exit(3)
        sys.exit(f'配置中应存在且仅存在一个入站：{kind}')
    return values[0]

def new_inbound_tag(kind):
    used={i.get('tag') for i in c.get('inbounds',[])}
    result=kind;index=1
    while result in used: result=f'{kind}-{index}';index+=1
    return result

def listener_conflict(left,right):
    def networks(item):
        if (item.get('transport') or {}).get('type')=='quic': return {'udp'}
        if item.get('network'): return {item['network']}
        if item.get('type') in ('direct','shadowsocks'): return {'tcp','udp'}
        return {'udp' if item.get('type') in ('hysteria','hysteria2','tuic') else 'tcp'}
    if not networks(left)&networks(right): return False
    if left.get('listen_port')!=right.get('listen_port'): return False
    a,b=left.get('listen','::'),right.get('listen','::')
    if a==b or '::' in (a,b): return True
    return ('0.0.0.0' in (a,b)) and ':' not in a and ':' not in b

def atomic(path, text):
    if path.is_symlink():
        sys.exit(f'拒绝覆盖符号链接：{path}')
    with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, prefix='.node-', delete=False) as f:
        staging = pathlib.Path(f.name)
        try:
            f.write(text)
            f.flush()
            if path.exists():
                st = path.stat()
                os.fchown(f.fileno(), st.st_uid, st.st_gid)
            os.fchmod(f.fileno(), 0o600)
            staging.replace(path)
        finally:
            if staging.exists():
                staging.unlink()

def write_json(path, obj):
    atomic(path, json.dumps(obj, indent=2, ensure_ascii=False) + '\n')

if action in ('menu-inbounds','menu-inbound','menu-fields','hopping-port','inbound-label'):
    def emit(label,command): sys.stdout.write(label+'\0'+command+'\0')
    def pointer_key(key): return str(key).replace('~','~0').replace('/','~1')
    if action=='menu-inbounds':
        for index,item in enumerate(c.get('inbounds',[])):
            identifier=item.get('tag') or '@'+str(index)
            emit(item.get('type','未知')+' · '+identifier,'inbound:@'+str(index))
        sys.exit()
    selector=sys.argv[2]
    values=[item for index,item in enumerate(c.get('inbounds',[])) if '@'+str(index)==selector]
    if not values: values=[item for item in c.get('inbounds',[]) if item.get('tag')==selector]
    if len(values)!=1: sys.exit('请选择唯一的现有入站标签。')
    item=values[0]
    if action=='inbound-label':
        print(item.get('type','未知')+' · '+(item.get('tag') or selector));sys.exit()
    if action=='hopping-port':
        if item.get('type')!='hysteria2': sys.exit('端口跳跃仅适用于 HY2 入站。')
        print(item['listen_port']);sys.exit()
    if action=='menu-inbound':
        emit('完整编辑入站 JSON','edit-current')
        emit('逐项修改字段 / 开关','group:')
        emit('添加可选字段（JSON Pointer）','add-field')
        if 'listen_port' in item: emit('修改监听端口','field:/listen_port')
        if item.get('type')=='hysteria2':
            # Hopping is implemented by the owned redirect service, not an inbound field.
            hop=app/'hopping.json'
            state=json.loads(hop.read_text()) if hop.exists() else {}
            enabled=state.get('enabled',False)
            owned=enabled and state.get('base_port')==item.get('listen_port')
            emit('端口跳跃 · '+('开启' if owned else '由其他 HY2 入站使用' if enabled else '关闭'),'hopping')
            if owned: emit('关闭端口跳跃','disable-hopping')
        sys.exit()
    pointer=sys.argv[3];value=item
    if pointer:
        for key in pointer[1:].split('/'):
            key=key.replace('~1','/').replace('~0','~')
            value=value[int(key)] if isinstance(value,list) else value[key]
    entries=enumerate(value) if isinstance(value,list) else value.items() if isinstance(value,dict) else []
    for key,child in entries:
        path=pointer+'/'+pointer_key(key)
        if isinstance(child,(dict,list)):
            emit(str(key)+' · '+str(len(child))+' 项','group:'+path)
        else:
            state=('开启' if child else '关闭') if isinstance(child,bool) else 'null' if child is None else '数值' if isinstance(child,(int,float)) else '文本'
            emit(str(key)+' · '+state,('switch:' if isinstance(child,bool) else 'field:')+path)
    if pointer: emit('移除此字段（恢复内核默认或停用可选功能）','remove:'+pointer)
    sys.exit()

if action=='inbound-types':
    print('\n'.join(dict.fromkeys(i.get('type','') for i in c.get('inbounds',[]))))
    sys.exit()

if action=='editable-protocols':
    for index,item in enumerate(c.get('inbounds',[])):
        identifier=item.get('tag') or '@'+str(index)
        sys.stdout.write(identifier+'\0'+item.get('type','未知')+' / '+identifier+'\0')
    sys.exit()

if action in ('extract-inbound','replace-inbound'):
    selector=sys.argv[2]
    matches=[(index,item) for index,item in enumerate(c.get('inbounds',[])) if '@'+str(index)==selector]
    if not matches: matches=[(index,item) for index,item in enumerate(c.get('inbounds',[])) if item.get('tag')==selector]
    if not matches: matches=[(index,item) for index,item in enumerate(c.get('inbounds',[])) if item.get('type')==selector]
    if len(matches)!=1: sys.exit('请选择唯一的现有入站标签。')
    index,old=matches[0]
    if action=='extract-inbound': print(json.dumps(old,indent=2,ensure_ascii=False));sys.exit()
    candidate=json.loads(pathlib.Path(sys.argv[3]).read_text())
    if not isinstance(candidate,dict) or candidate.get('type')!=old.get('type'): sys.exit('请保留协议类型；新增其他协议请使用生成协议菜单。')
    live=pathlib.Path(os.environ.get('LIVE_APP') or str(app))
    for key in ('certificate_path','key_path'):
        tls=(candidate.get('tls') or {})
        if key not in tls: continue
        try: relative=pathlib.Path(tls[key]).relative_to(live/'tls')
        except ValueError: continue
        tls[key]=str(app/'tls'/relative)
    if candidate==old: print('unchanged');sys.exit()
    tag=candidate.get('tag')
    if tag and any(i!=index and item.get('tag')==tag for i,item in enumerate(c['inbounds'])): sys.exit('入站标签重复。')
    if candidate.get('type') in ('hysteria2','tuic','vless','anytls'):
        if type(candidate.get('listen_port')) is not int or not 1<=candidate['listen_port']<=65535: sys.exit('监听端口必须是 1-65535 的整数。')
        for i,item in enumerate(c['inbounds']):
            if i!=index and listener_conflict(item,candidate): sys.exit('同类传输协议监听地址与端口冲突。')
    c['inbounds'][index]=candidate
    if old.get('tag') and tag and old['tag']!=tag:
        def rename_rules(rules):
            for rule in rules:
                if 'inbound' in rule:
                    value=rule['inbound']
                    rule['inbound']=[tag if x==old['tag'] else x for x in value] if isinstance(value,list) else tag if value==old['tag'] else value
                rename_rules(rule.get('rules',[]))
        rename_rules(c.get('route',{}).get('rules',[]))
        rename_rules(c.get('dns',{}).get('rules',[]))
    write_json(p,c)
    hop_path=app/'hopping.json'
    if candidate.get('type')=='hysteria2' and hop_path.exists():
        hop=json.loads(hop_path.read_text())
        if hop['base_port']==old.get('listen_port'):
            hop['base_port']=candidate['listen_port'];write_json(hop_path,hop)
    # A manually changed Reality private key requires a matching exported public key.
    reality=(candidate.get('tls') or {}).get('reality') or {}
    if candidate.get('type')=='vless' and reality.get('private_key')!=((old.get('tls') or {}).get('reality') or {}).get('private_key') and reality.get('enabled'):
        import base64,subprocess
        raw=base64.urlsafe_b64decode(reality['private_key']+'='*(-len(reality['private_key'])%4))
        if len(raw)!=32: sys.exit('Reality 私钥必须解码为 32 字节。')
        der=bytes.fromhex('302e020100300506032b656e04220420')+raw
        result=subprocess.run(['openssl','pkey','-inform','DER','-pubout','-outform','DER'],input=der,capture_output=True)
        if result.returncode: sys.exit('无法由 Reality 私钥导出公钥。')
        client_path=app/'client/vless-reality.outbound.json'
        client=json.loads(client_path.read_text())
        client['tls']['reality']['public_key']=base64.urlsafe_b64encode(result.stdout[-32:]).decode().rstrip('=')
        write_json(client_path,client)
    print('changed');sys.exit()

if action=='managed-sni-change':
    old=json.loads(pathlib.Path(sys.argv[2]).read_text());kind=old.get('type')
    if kind not in ('hysteria2','anytls','tuic'): sys.exit()
    values=[i for i in c['inbounds'] if i.get('type')==kind]
    if len(values)!=1: sys.exit()
    new=values[0];before=(old.get('tls') or {});after=(new.get('tls') or {})
    stem='hy2' if kind=='hysteria2' else kind
    if before.get('server_name')!=after.get('server_name') and after.get('server_name') and not after.get('certificate'):
        if all(before.get(key)==after.get(key)==str(app/'tls'/(stem+suffix)) for key,suffix in [('certificate_path','.crt'),('key_path','.key')]):
            sys.stdout.write(stem+'\0'+after['server_name']+'\0')
    sys.exit()

if action=='defaults':
    optional_quic=('initial_packet_size','disable_path_mtu_discovery','idle_timeout','keep_alive_period','stream_receive_window','connection_receive_window','max_concurrent_streams')
    for item in c.get('inbounds',[]):
        if item.get('type') not in ('vless','hysteria2','anytls','tuic'): continue
        if isinstance(item.get('tls'),dict): item['tls']['handshake_timeout']=os.environ['DEFAULT_TLS_HANDSHAKE_TIMEOUT']
        if item['type']=='hysteria2':
            item.update(ignore_client_bandwidth=True,bbr_profile='standard')
            for field in optional_quic: item.pop(field,None)
        elif item['type']=='tuic':
            for field in optional_quic: item.pop(field,None)
            item.update(congestion_control='bbr',auth_timeout='3s',zero_rtt_handshake=False,heartbeat='10s',disable_path_mtu_discovery=False)
    write_json(p,c);sys.exit()

if action in ('summary','record-runtime','protocols'):
    labels = {'vless':'VLESS','hysteria2':'Hysteria2','anytls':'AnyTLS','tuic':'TUIC'}
    if action=='protocols':
        for item in c.get('inbounds',[]):
            kind=item.get('type')
            if kind in labels: sys.stdout.write(kind+'\0'+labels[kind]+'\0')
        sys.exit()
    transports = {'vless':'TCP','hysteria2':'UDP','anytls':'TCP','tuic':'UDP'}
    lines = []
    ports = []
    for item in c.get('inbounds',[]):
        kind = item.get('type',item.get('tag','未知协议'))
        label = labels.get(kind,item.get('tag',kind))
        network = 'UDP' if (item.get('transport') or {}).get('type')=='quic' else item.get('network') or ('TCP/UDP' if kind in ('direct','shadowsocks') else transports.get(kind,'端口'))
        if 'listen_port' in item: ports.append(f"{label}：{network.upper()} {item['listen_port']}")
    lines.append('    '.join(ports) or '未配置监听协议')
    for item in c.get('inbounds',[]):
        if item.get('type')=='hysteria2' and 'bbr_profile' in item: lines.append('Hysteria2 BBR：'+item['bbr_profile'])
    hop_path = app/'hopping.json'
    if hop_path.exists():
        hop = json.loads(hop_path.read_text())
        if hop.get('enabled'): lines.append('HY2 跳跃：'+','.join(hop['ports'])+'，间隔 '+hop['hop_interval'])
    outbounds = {o.get('tag'):o for o in c.get('outbounds',[])}
    route = c.get('route',{})
    groups = []
    for rule in route.get('rules',[]):
        if rule.get('action')!='route' or not rule.get('outbound'): continue
        sets = rule.get('rule_set',[])
        if isinstance(sets,str): sets=[sets]
        label = 'Google' if set(sets)&{'google','youtube'} else 'AI' if 'ai' in sets else ' / '.join(sets) or '条件规则'
        groups.append((label,rule['outbound']))
    groups.append(('其他',route.get('final','未指定')))
    if [label for label,_ in groups]==['Google','AI','其他'] and all(outbounds.get(tag,{}).get('type')=='socks' for _,tag in groups):
        profiles = {(outbounds[tag].get('server'),outbounds[tag].get('server_port'),outbounds[tag].get('username'),outbounds[tag].get('password')) for _,tag in groups}
        count = len(profiles)
        lines.append('分流：Google / AI / 其他 → '+(f'{count} 组独立 SOCKS5' if count==len(groups) else f'共用 {count} 组 SOCKS5'))
    for label,tag in groups:
        outbound = outbounds.get(tag,{})
        endpoint = f"SOCKS5 {outbound.get('server','?')}:{outbound.get('server_port','?')}" if outbound.get('type')=='socks' else str(tag)
        lines.append(f'{label} → {endpoint}')
    summary_text = '\n'.join(lines)
    if action=='record-runtime':
        atomic(app/'runtime-state.json',json.dumps({'identity':sys.argv[2],'version':sys.argv[3],'summary':summary_text},ensure_ascii=False)+'\n')
    else:
        print(summary_text)
    sys.exit()

if action == 'socks':
    found = [o for o in c['outbounds'] if o.get('tag') == sys.argv[2] + '-socks' and o.get('type') == 'socks']
    if len(found) > 1:
        sys.exit('SOCKS5 出站标签重复。')
    o = found[0] if found else {}
    for key in ('server', 'server_port', 'username', 'password'):
        sys.stdout.write(str(o.get(key, '')) + '\0')
    sys.stdout.write('READY\0')
    sys.exit()

v = inbound('vless-reality')
h = inbound('hysteria2')
a = inbound('anytls') if any(i.get('type')=='anytls' or (not i.get('type') and i.get('tag')=='anytls') for i in c['inbounds']) else None
u = inbound('tuic') if any(i.get('type')=='tuic' or (not i.get('type') and i.get('tag')=='tuic') for i in c['inbounds']) else None
for i in (v, h, *([a] if a else []), *([u] if u else [])):
    if type(i.get('listen_port')) is not int or not 1 <= i['listen_port'] <= 65535:
        sys.exit('配置中的协议端口无效。')
    if not i.get('users') and action not in ('load','validate'):
        sys.stderr.write('该入站没有可自动导出的用户，请手动配置客户端。\n'); sys.exit(3)
if a and (a.get('type') != 'anytls' or listener_conflict(a,v)):
    sys.exit('AnyTLS 类型或 TCP 端口无效，不能与 VLESS 端口相同。')
if u and (u.get('type')!='tuic' or listener_conflict(u,h)):
    sys.exit('TUIC UDP 端口不能与 Hysteria2 相同。')
client_dir = app / 'client'
vpath = client_dir / 'vless-reality.outbound.json'
hpath = client_dir / 'hysteria2.outbound.json'
apath = client_dir / 'anytls.outbound.json'
upath = client_dir / 'tuic.outbound.json'
vc = json.loads(vpath.read_text())
hc = json.loads(hpath.read_text())
hop_path = app/'hopping.json'
hop = json.loads(hop_path.read_text()) if hop_path.exists() else {'enabled':False}
if hop.get('enabled'):
    expected_ports={i['listen_port'] for i in c['inbounds'] if i.get('type')=='hysteria2'} if action=='load' else {int(os.environ['HY2_PORT']) if action=='update' and len(sys.argv)>2 and sys.argv[2]=='ports' else h['listen_port']}
    if hop.get('version') != 1 or hop.get('base_port') not in expected_ports or not isinstance(hop.get('ports'),list) or not hop['ports']:
        sys.exit('跳跃配置与 HY2 监听端口不一致。')


if action == 'load':
    values = {
        'VLESS_PORT': v['listen_port'], 'HY2_PORT': h['listen_port'],
        'VLESS_NETWORK': 'udp' if (v.get('transport') or {}).get('type')=='quic' else 'tcp',
        'ANYTLS_PORT': a['listen_port'] if a else '',
        'ANYTLS_SNI': (a.get('tls') or {}).get('server_name','') if a else '',
        'ANYTLS_PASS': a.get('users',[{}])[0].get('password','') if a and a.get('users') else '',
        'TUIC_PORT': u['listen_port'] if u else '',
        'TUIC_SNI': (u.get('tls') or {}).get('server_name','') if u else '',
        'TUIC_UUID': u.get('users',[{}])[0].get('uuid','') if u and u.get('users') else '',
        'TUIC_PASS': u.get('users',[{}])[0].get('password','') if u and u.get('users') else '',
        'UUID': v.get('users',[{}])[0].get('uuid','') if v.get('users') else '', 'REALITY_DOMAIN': (((v.get('tls') or {}).get('reality') or {}).get('handshake') or {}).get('server',(v.get('tls') or {}).get('server_name','')),
        'HY2_SNI': h['tls'].get('server_name') or hc['tls']['server_name'],
        'HY2_BBR_CURRENT': h.get('bbr_profile',''),
        'HY2_PASS': h['users'][0].get('password','') if h.get('users') else '', 'HY2_OBFS_PASS': h.get('obfs', {}).get('password', ''),
        'HY2_HOP_PORTS': ','.join(hop['ports']) if hop.get('enabled') else '',
        'HY2_HOP_INTERVAL': hop.get('hop_interval',os.environ['DEFAULT_HY2_HOP_INTERVAL']),
    }
    for key, value in values.items():
        sys.stdout.write(key + '\0' + str(value) + '\0')
    sys.stdout.write('READY\0')
    sys.exit()

if action in ('update', 'validate'):
    mode = sys.argv[2]
    e = os.environ
    if mode == 'add-anytls':
        if a: sys.exit('AnyTLS 已存在，请使用修改端口、SNI 或凭据功能。')
        a = {'type':'anytls','tag':new_inbound_tag('anytls'),'listen':'0.0.0.0','listen_port':int(e['ANYTLS_PORT']),
             'users':[{'name':'main','password':e['ANYTLS_PASS']}],
             'tls':{'enabled':True,'handshake_timeout':e['DEFAULT_TLS_HANDSHAKE_TIMEOUT'],'server_name':e['ANYTLS_SNI'],
                    'certificate_path':str(app/'tls/anytls.crt'),'key_path':str(app/'tls/anytls.key')}}
        c['inbounds'].append(a)
    elif mode=='add-tuic':
        if u: sys.exit('TUIC 已存在，请修改现有协议。')
        u={'type':'tuic','tag':new_inbound_tag('tuic'),'listen':'0.0.0.0','listen_port':int(e['TUIC_PORT']),
           'users':[{'name':'main','uuid':e['TUIC_UUID'],'password':e['TUIC_PASS']}],
           'congestion_control':'bbr','auth_timeout':'3s','zero_rtt_handshake':False,'heartbeat':'10s',
           'disable_path_mtu_discovery':False,
           'tls':{'enabled':True,'server_name':e['TUIC_SNI'],'alpn':['h3'],
                  'handshake_timeout':e['DEFAULT_TLS_HANDSHAKE_TIMEOUT'],
                  'certificate_path':str(app/'tls/tuic.crt'),'key_path':str(app/'tls/tuic.key')}}
        c['inbounds'].append(u)
    elif mode == 'ports':
        if u: u['listen_port']=int(e['TUIC_PORT'])
        v['listen_port'], h['listen_port'] = int(e['VLESS_PORT']), int(e['HY2_PORT'])
        if a: a['listen_port'] = int(e['ANYTLS_PORT'])
    elif mode == 'sni':
        for key in ('REALITY_DOMAIN', 'HY2_SNI'):
            name = e[key]
            try:
                ipaddress.ip_address(name)
            except ValueError:
                if len(name) > 253 or not all(re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?', label) for label in name.split('.')):
                    sys.exit(f'{key} 必须是有效域名或 IP 地址。')
        v['tls']['server_name'] = e['REALITY_DOMAIN']
        v['tls']['reality']['handshake']['server'] = e['REALITY_DOMAIN']
        if e['HY2_SNI'] != (h['tls'].get('server_name') or hc['tls']['server_name']):
            for key, name in [('certificate_path','hy2.crt'),('key_path','hy2.key')]:
                if pathlib.Path(h['tls'][key]).absolute() != (app/'tls'/name).absolute():
                    sys.exit('HY2 证书由外部路径管理，请先手动处理证书再修改 SNI。')
        h['tls']['server_name'] = e['HY2_SNI']
        if u:
            if e['TUIC_SNI']!=u['tls'].get('server_name',''):
                for key,name in [('certificate_path','tuic.crt'),('key_path','tuic.key')]:
                    if pathlib.Path(u['tls'][key]).absolute() != (app/'tls'/name).absolute(): sys.exit('TUIC 证书由外部路径管理。')
            u['tls']['server_name']=e['TUIC_SNI']
        if a:
            if e['ANYTLS_SNI'] != a['tls']['server_name']:
                for key,name in [('certificate_path','anytls.crt'),('key_path','anytls.key')]:
                    if pathlib.Path(a['tls'][key]).absolute() != (app/'tls'/name).absolute():
                        sys.exit('AnyTLS 证书由外部路径管理，请先手动处理证书再修改 SNI。')
            a['tls']['server_name'] = e['ANYTLS_SNI']
    elif mode in ('credentials', 'rotate'):
        v['users'][0]['uuid'] = str(uuid.UUID(e['UUID']))
        if not e['HY2_PASS'] or not e['HY2_OBFS_PASS']:
            sys.exit('HY2 认证密码和混淆密码不能为空。')
        h['users'][0]['password'] = e['HY2_PASS']
        h['obfs'] = {'type':'salamander', 'password':e['HY2_OBFS_PASS']}
        if a: a['users'][0]['password'] = e['ANYTLS_PASS']
        if u:
            u['users'][0].update(uuid=str(uuid.UUID(e['TUIC_UUID'])),password=e['TUIC_PASS'])
        if mode == 'rotate':
            v['tls']['reality'].update(private_key=e['REALITY_PRIVATE'], short_id=[e['SHORT_ID']])
            vc['tls']['reality']['public_key'] = e['REALITY_PUBLIC']
    elif mode in ('regenerate-vless', 'regenerate-hysteria2', 'regenerate-anytls','regenerate-tuic'):
        if mode == 'regenerate-vless':
            v['users'][0]['uuid'] = str(uuid.UUID(e['UUID']))
            v['tls']['reality'].update(private_key=e['REALITY_PRIVATE'], short_id=[e['SHORT_ID']])
            vc['tls']['reality']['public_key'] = e['REALITY_PUBLIC']
        elif mode=='regenerate-tuic':
            if not u: sys.exit('尚未安装 TUIC。')
            for key,suffix in [('certificate_path','.crt'),('key_path','.key')]:
                if pathlib.Path(u['tls'][key]).absolute() != (app/'tls'/('tuic'+suffix)).absolute(): sys.exit('TUIC 证书由外部路径管理。')
            u['users'][0].update(uuid=str(uuid.UUID(e['TUIC_UUID'])),password=e['TUIC_PASS'])
        else:
            target, stem, password = (h, 'hy2', e['HY2_PASS']) if mode == 'regenerate-hysteria2' else (a, 'anytls', e['ANYTLS_PASS'])
            if target is None: sys.exit('尚未安装 AnyTLS，请先添加该协议。')
            for key,suffix in [('certificate_path','.crt'),('key_path','.key')]:
                if pathlib.Path(target['tls'][key]).absolute() != (app/'tls'/(stem+suffix)).absolute():
                    sys.exit('证书由外部路径管理，拒绝重新生成；请先手动处理证书。')
            target['users'][0]['password'] = password
            if stem == 'hy2': h['obfs'] = {'type':'salamander','password':e['HY2_OBFS_PASS']}
    elif mode == 'bbr':
        if e['HY2_BBR_PROFILE'] not in ('standard','conservative','aggressive'):
            sys.exit('BBR 档位必须是 standard、conservative 或 aggressive。')
        h['bbr_profile'] = e['HY2_BBR_PROFILE']
    elif mode == 'tfo':
        if e['SOCKS_TFO'] not in ('true', 'false'):
            sys.exit('TFO 只能设置为 true 或 false。')
        for o in c['outbounds']:
            if o.get('type') == 'socks' and o.get('tag') in ('ai-socks','google-socks','other-socks'):
                o['tcp_fast_open'] = e['SOCKS_TFO'] == 'true'
    else:
        sys.exit('未知配置修改操作。')
    if u:
        if not 1<=u['listen_port']<=65535 or listener_conflict(u,h): sys.exit('TUIC UDP 端口无效或与 HY2 冲突。')
        if u.get('users'):
            if not u['users'][0]['password']: sys.exit('TUIC 密码不能为空。')
            u['users'][0]['uuid']=str(uuid.UUID(u['users'][0]['uuid']))
    if a:
        if not 1 <= a['listen_port'] <= 65535 or listener_conflict(a,v):
            sys.exit('AnyTLS 端口必须在 1-65535 内且与 VLESS TCP 端口不同。')
        if not a['users'][0]['password']: sys.exit('AnyTLS 密码不能为空。')
        name = a['tls']['server_name']
        try: ipaddress.ip_address(name)
        except ValueError:
            if len(name)>253 or not all(re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?',label) for label in name.split('.')):
                sys.exit('ANYTLS_SNI 必须是有效域名或 IP 地址。')
    if action == 'validate':
        print('unchanged' if c == original else 'changed')
        sys.exit()
    write_json(p, c)
    if mode in ('rotate','regenerate-vless'): write_json(vpath,vc)

# Rebuild client artifacts from the installed server configuration, retaining its keys.
if not ((v.get('tls') or {}).get('reality') or {}).get('enabled') or v.get('transport') or (v.get('tls') or {}).get('client_authentication') or ((v.get('tls') or {}).get('ech') or {}).get('enabled'):
    sys.stderr.write('该 VLESS 高级 TLS/传输组合需手动配置客户端；服务端配置可正常应用。\n'); sys.exit(3)

def read_certificate(item):
    tls=(item.get('tls') or {})
    if tls.get('client_authentication') or (tls.get('ech') or {}).get('enabled'):
        sys.stderr.write('自定义 mTLS/ECH 需要手动补全客户端配置。\n');sys.exit(3)
    if not tls.get('server_name'):
        sys.stderr.write('未指定证书对应的 SNI，请手动配置客户端。\n'); sys.exit(3)
    if tls.get('certificate_path'): return pathlib.Path(tls['certificate_path']).read_text()
    if tls.get('certificate'):
        cert=tls['certificate']
        return '\n'.join(cert) if isinstance(cert,list) else cert
    sys.stderr.write('动态证书尚不可用于自动固定校验，请手动配置客户端。\n'); sys.exit(3)

def certificate_pin(cert):
    leaf=re.search(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',cert,re.S)
    if not leaf: sys.exit('证书内容无效。')
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(leaf[0])).hexdigest()

vc.update(server_port=v['listen_port'], uuid=v['users'][0]['uuid'], flow=(v['users'][0].get('flow') or ''))
vc['tls']['server_name'] = v['tls'].get('server_name') or v['tls']['reality']['handshake']['server']
short_ids=v['tls']['reality'].get('short_id',[])
vc['tls']['reality']['short_id'] = short_ids if isinstance(short_ids,str) else next(iter(short_ids),'')
hc.update(server_port=h['listen_port'], password=h['users'][0]['password'])
if hop.get('enabled'):
    hc.pop('server_port',None)
    hc.update(server_ports=hop['ports'],hop_interval=hop['hop_interval'])
else:
    hc.pop('server_ports',None); hc.pop('hop_interval',None)
if h.get('obfs'):
    hc['obfs'] = copy.deepcopy(h['obfs'])
else:
    hc.pop('obfs', None)
cert = read_certificate(h)
hc['tls'].update(server_name=h['tls'].get('server_name') or hc['tls']['server_name'], certificate=cert, insecure=False)
hc['tls']['alpn'] = h['tls'].get('alpn', ['h3'])
for key in ('handshake_timeout','alpn','min_version','max_version','cipher_suites','curve_preferences'):
    if key in v['tls']: vc['tls'][key]=copy.deepcopy(v['tls'][key])
    if key in h['tls']: hc['tls'][key]=copy.deepcopy(h['tls'][key])
vc['tls'].setdefault('handshake_timeout',os.environ['DEFAULT_TLS_HANDSHAKE_TIMEOUT'])
hc['tls'].setdefault('handshake_timeout',os.environ['DEFAULT_TLS_HANDSHAKE_TIMEOUT'])
ac = None
if a:
    anytls_cert = read_certificate(a)
    anytls_fingerprint = certificate_pin(anytls_cert)
    ac = {'type':'anytls','tag':'anytls','server':vc['server'],'server_port':a['listen_port'],
          'password':a['users'][0]['password'],
          'tls':{'enabled':True,'server_name':a['tls'].get('server_name',''),'insecure':False,'certificate':anytls_cert}}
    for key in ('handshake_timeout','alpn','min_version','max_version','cipher_suites','curve_preferences'):
        if key in a['tls']: ac['tls'][key]=copy.deepcopy(a['tls'][key])
    ac['tls'].setdefault('handshake_timeout',os.environ['DEFAULT_TLS_HANDSHAKE_TIMEOUT'])
uc = None
if u:
    tuic_cert=read_certificate(u);tuic_pin=certificate_pin(tuic_cert)
    uc={'type':'tuic','tag':'tuic','server':vc['server'],'server_port':u['listen_port'],
        'uuid':u['users'][0]['uuid'],'password':u['users'][0].get('password',''),
        'congestion_control':u.get('congestion_control','cubic'),'zero_rtt_handshake':u.get('zero_rtt_handshake',False),
        'heartbeat':u.get('heartbeat','10s'),'udp_relay_mode':'native',
        'tls':{'enabled':True,'server_name':u['tls'].get('server_name',''),'certificate':tuic_cert,'insecure':False,
               'handshake_timeout':u['tls'].get('handshake_timeout',os.environ['DEFAULT_TLS_HANDSHAKE_TIMEOUT'])}}
    for key in ('alpn','min_version','max_version','cipher_suites','curve_preferences'):
        if key in u['tls']: uc['tls'][key]=copy.deepcopy(u['tls'][key])
from urllib.parse import quote, urlencode
vless_uri = 'vless://' + vc['uuid'] + '@' + vc['server'] + ':' + str(vc['server_port']) + '?' + urlencode({
    'encryption':'none', 'flow':vc['flow'], 'security':'reality', 'sni':vc['tls']['server_name'],
    'fp':vc['tls'].get('utls', {}).get('fingerprint', 'chrome'), 'pbk':vc['tls']['reality']['public_key'],
    'sid':vc['tls']['reality']['short_id'], 'type':'tcp'}) + '#VLESS-Reality'
fingerprint = certificate_pin(cert)
params = {'sni':hc['tls']['server_name'], 'insecure':'0', 'pinSHA256':fingerprint}
if hc.get('obfs'):
    params.update(obfs=hc['obfs']['type'], **{'obfs-password':hc['obfs']['password']})
hy2_ports = ','.join(hop['ports']).replace(':','-') if hop.get('enabled') else str(h['listen_port'])
hy2_uri = 'hysteria2://' + quote(hc['password'], safe='') + '@' + hc['server'] + ':' + hy2_ports + '/?' + urlencode(params) + '#Hysteria2'
# JSON-quoted scalars are YAML-safe without adding a YAML runtime dependency.
def yaml_scalar(value):
    text = json.dumps(value, ensure_ascii=False)
    return ''.join(f'\\u{ord(ch):04x}' if 0x7f <= ord(ch) <= 0x9f or ord(ch) in (0x2028,0x2029) else ch for ch in text)

clash_vless = {
    'name':'VLESS-Reality', 'type':'vless', 'server':vc['server'], 'port':vc['server_port'],
    'uuid':vc['uuid'], 'udp':True, 'network':'tcp', 'tls':True,
    'flow':vc['flow'], 'packet-encoding':'xudp', 'servername':vc['tls']['server_name'],
    'client-fingerprint':vc['tls'].get('utls', {}).get('fingerprint','chrome'),
    'reality-opts':{'public-key':vc['tls']['reality']['public_key'], 'short-id':vc['tls']['reality']['short_id']}
}
clash_hy2 = {
    'name':'Hysteria2', 'type':'hysteria2', 'server':hc['server'], 'port':h['listen_port'],
    'password':hc['password'], 'sni':hc['tls']['server_name'], 'alpn':hc['tls']['alpn'],
    'skip-cert-verify':False, 'fingerprint':fingerprint
}
if hc.get('obfs'):
    clash_hy2.update(obfs=hc['obfs']['type'], **{'obfs-password':hc['obfs']['password']})
clash_hop_note = ''
if hop.get('enabled'):
    duration = re.fullmatch(r'([0-9]+(?:\.[0-9]+)?)(ms|s|m|h)',hop['hop_interval'])
    seconds = float(duration[1])*{'ms':0.001,'s':1,'m':60,'h':3600}[duration[2]]
    clash_seconds = math.ceil(seconds)
    clash_hy2.update(ports=','.join(hop['ports']).replace(':','-'), **{'hop-interval':clash_seconds})
    if clash_seconds != seconds:
        clash_hop_note = f'Mihomo 跳跃间隔仅支持整秒，已向上取整为 {clash_seconds} 秒；sing-box JSON 保留原间隔。\n'
clash_proxies = [clash_vless,clash_hy2]
anytls_uri = ''
anytls_summary = ''
if ac:
    clash_proxies.append({'name':'AnyTLS','type':'anytls','server':ac['server'],'port':ac['server_port'],
                          'password':ac['password'],'udp':True,'sni':ac['tls']['server_name'],
                          'client-fingerprint':'chrome','skip-cert-verify':False,'fingerprint':anytls_fingerprint})
    anytls_uri = 'anytls://' + quote(ac['password'],safe='') + '@' + ac['server'] + ':' + str(ac['server_port']) + '/?' + urlencode({'sni':ac['tls']['server_name'],'insecure':'0'}) + '#AnyTLS'
    anytls_summary = f'''
[AnyTLS]
地址：{ac['server']}   TCP 端口：{ac['server_port']}
Password: {ac['password']}
TLS SNI: {ac['tls']['server_name']}
AnyTLS URI: {anytls_uri}
证书 SHA-256: {anytls_fingerprint}
JSON 已内嵌证书，YAML 使用证书指纹校验；分享链接需另行信任 anytls.crt。
'''
tuic_uri='';tuic_summary=''
if uc:
    interval=re.fullmatch(r'([0-9]+(?:\.[0-9]+)?)(ms|s|m|h)',uc['heartbeat'])
    if not interval: sys.stderr.write('TUIC heartbeat 需手动换算为客户端配置。\n');sys.exit(3)
    milliseconds=float(interval[1])*{'ms':1,'s':1000,'m':60000,'h':3600000}[interval[2]]
    clash_tuic={'name':'TUIC','type':'tuic','server':uc['server'],'port':uc['server_port'],
                'uuid':uc['uuid'],'password':uc['password'],'udp':True,'sni':uc['tls']['server_name'],
                'congestion-controller':uc['congestion_control'],'heartbeat-interval':int(milliseconds),
                'reduce-rtt':uc['zero_rtt_handshake'],'udp-relay-mode':'native',
                'skip-cert-verify':False,'fingerprint':tuic_pin}
    if 'alpn' in uc['tls']: clash_tuic['alpn']=uc['tls']['alpn']
    clash_proxies.append(clash_tuic)
    tuic_uri='tuic://'+quote(uc['uuid'],safe='')+':'+quote(uc['password'],safe='')+'@'+uc['server']+':'+str(uc['server_port'])+'/?'+urlencode({'sni':uc['tls']['server_name'],'congestion_control':uc['congestion_control'],'alpn':','.join(uc['tls'].get('alpn',[])),'allow_insecure':'0'})+'#TUIC'
    tuic_summary=f'''\n[TUIC]\n地址：{uc['server']}   UDP 端口：{uc['server_port']}\nUUID: {uc['uuid']}\nPassword: {uc['password']}\nTLS SNI: {uc['tls']['server_name']}\n拥塞控制：{uc['congestion_control']}；0-RTT：{uc['zero_rtt_handshake']}；心跳：{uc['heartbeat']}\nTUIC URI: {tuic_uri}\n证书 SHA-256: {tuic_pin}\nJSON 内嵌证书；YAML 使用证书指纹。分享链接需另行信任 tuic.crt。\n'''
yaml_lines = ['proxies:']
for proxy in clash_proxies:
    for index,(key,value) in enumerate(proxy.items()):
        prefix = '  - ' if index == 0 else '    '
        if isinstance(value,dict):
            yaml_lines.append(prefix+key+':')
            yaml_lines.extend('      '+k+': '+yaml_scalar(v) for k,v in value.items())
        else:
            yaml_lines.append(prefix+key+': '+yaml_scalar(value))
clash_yaml = '\n'.join(yaml_lines)+'\n'

other_route = 'Other SOCKS5' if c['route'].get('final') == 'other-socks' else c['route'].get('final', 'unspecified')
summary = f'''=== 节点连接资料（包含密码，请妥善保管） ===

[VLESS Reality]
地址：{vc['server']}   TCP 端口：{vc['server_port']}
UUID: {vc['uuid']}
SNI: {vc['tls']['server_name']}
Reality Public Key: {vc['tls']['reality']['public_key']}
Short ID: {vc['tls']['reality']['short_id']}
VLESS URI: {vless_uri}

[Hysteria2]
地址：{hc['server']}   UDP 监听端口：{h['listen_port']}
客户端跳跃端口：{hy2_ports}，间隔：{hop.get('hop_interval','不启用')}
云安全组需开放上述客户端 UDP 端口。
Password: {hc['password']}
TLS SNI: {hc['tls']['server_name']}
BBR profile: {h.get('bbr_profile','standard')}
Obfuscation: {hc.get('obfs', {}).get('type', 'none')}
Obfuscation password: {hc.get('obfs', {}).get('password', 'not configured')}
Hysteria2 URI: {hy2_uri}
证书 SHA-256: {fingerprint}
HY2 JSON 已内嵌证书，保持 tls.insecure=false。
HY2 分享链接需客户端信任附带的 hy2.crt；仅有链接不能保证自签证书导入兼容。
端口范围已包含在分享链接中；自定义跳跃间隔请导入 JSON 或下方 YAML。

Google + YouTube => Google SOCKS5; other AI => AI SOCKS5; else {other_route}.
Everything else: {other_route}; private IPs rejected
上游 SOCKS5 密码不在此显示。
'''
summary += anytls_summary + tuic_summary
if any(len(i.get('users',[]))>1 for i in (v,h,*([a] if a else []),*([u] if u else []))): summary += '\n多用户入站：自动资料仅包含各协议第一个用户，其余用户请分别配置客户端。\n'
summary += '\n[Clash / Mihomo · proxies 配置]\n已有 proxies: 时只复制列表项，避免重复顶层键；HY2 / AnyTLS 使用证书 SHA-256 固定校验。\n以下是当前配置；proxies.yaml 文件仅通过 export-yaml 手动导出或更新。\n' + clash_hop_note + clash_yaml
if action == 'export-yaml':
    atomic(client_dir/'proxies.yaml', clash_yaml)
    sys.exit()
if action == 'yaml':
    print(clash_yaml, end='')
    sys.exit()
if action == 'json':
    print(json.dumps({'outbounds':[vc,hc]+([ac] if ac else [])+([uc] if uc else [])}, indent=2, ensure_ascii=False))
    sys.exit()
if action == 'show':
    colorful = sys.stdout.isatty() and os.environ.get('TERM','dumb') != 'dumb' and 'NO_COLOR' not in os.environ
    in_yaml = False
    for line in summary.splitlines():
        in_yaml = in_yaml or line == 'proxies:'
        color = ''
        if colorful and not in_yaml:
            if line.startswith('==='): color = '\033[1;33m'
            elif line.startswith('['): color = '\033[1;36m'
            elif line.startswith(('地址：','客户端跳跃端口：')): color = '\033[1;32m'
            elif line.startswith(('UUID:','Password:','Obfuscation password:','Short ID:')): color = '\033[1;33m'
        print(color + line + ('\033[0m' if color else ''))
    sys.exit()
if action not in ('export', 'update'):
    sys.exit('未知节点操作。')
selected = sys.argv[2] if action=='update' and sys.argv[2].startswith('regenerate-') else ''
if not selected or selected=='regenerate-vless': write_json(vpath, vc)
if not selected or selected=='regenerate-hysteria2': write_json(hpath, hc)
if ac and (not selected or selected=='regenerate-anytls'):
    write_json(apath, ac)
    atomic(client_dir/'anytls.crt', anytls_cert)
if uc and (not selected or selected=='regenerate-tuic'):
    write_json(upath,uc)
    atomic(client_dir/'tuic.crt',tuic_cert)
atomic(client_dir/'node-info.txt', summary)
atomic(client_dir/'nodes.txt', vless_uri + '\n' + hy2_uri + '\n' + (anytls_uri+'\n' if ac else '')+(tuic_uri+'\n' if uc else ''))
if not selected or selected=='regenerate-hysteria2': atomic(client_dir/'hy2.crt', cert)
atomic(client_dir/'README.txt', 'YAML 文件通过 export-yaml 可选导出；修改节点后需重新执行该命令。\nproxies.yaml 是 Clash/Mihomo 的 proxies 段，已有同名顶层键时仅复制列表项；HY2 / AnyTLS 通过证书 SHA-256 固定校验。\nMihomo 跳跃间隔仅支持整秒，小数秒向上取整；sing-box JSON 保留精确间隔。\nAnyTLS JSON 内嵌自签证书，insecure=false；分享链接需另行导入 anytls.crt。\nJSON 文件是单个 outbound 对象，需要合入客户端配置。\nHY2 JSON 内嵌自签证书，insecure=false；分享链接需要另行导入 hy2.crt。\n分享链接包含跳跃端口范围，自定义间隔以 JSON 为准。\n端口、SNI 或凭据修改后，请重新导入节点资料。\n')
PYCODE
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
        read -r -p '三组 SOCKS5 的 TFO：1 开启，2 关闭，0 返回：' answer
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
    [[ "$REALITY_DOMAIN" == "$old_reality" ]] || check_reality_target
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
    python3 - "$APP/hopping.json" "$TEMP/hopping-plan.json" "$HY2_PORT" <<'PYCODE'
import json,sys
c=json.load(open(sys.argv[1]));c['base_port']=int(sys.argv[3])
open(sys.argv[2],'w').write(json.dumps(c,indent=2)+'\n')
PYCODE
    apply_hopping_plan
  fi
  local update_status
  if node_config update "$mode"; then
    rm -f "$APP/client/EXPORT-ERROR.txt"
  else
    update_status=$?
    [[ $update_status == 3 ]] || return "$update_status"
    export_client_files
  fi
  check_configuration
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
  export APP TEMP FW_MARK FW_NFT FW_RESTORE VLESS_PORT HY2_PORT ANYTLS_PORT TUIC_PORT VLESS_NETWORK
  python3 - "$@" <<'PYCODE'
import json, os, pathlib, subprocess, sys, tempfile
app = pathlib.Path(os.environ['APP'])
ledger = app/'firewall-owned.json'
restore = pathlib.Path(os.environ['FW_RESTORE'])
mode = sys.argv[1] if len(sys.argv) > 1 else 'save'

def run(args, query=False):
    result = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={**os.environ, 'LC_ALL': 'C'})
    if result.returncode and not (query and result.returncode == 1):
        sys.stderr.write(result.stderr)
        sys.exit('防火墙操作失败：' + args[0])
    return result

def save(path, data):
    with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, prefix='.firewall-', delete=False) as f:
        staging = pathlib.Path(f.name)
        try:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.write('\n')
            f.flush()
            os.fchmod(f.fileno(), 0o600)
            staging.replace(path)
        finally:
            if staging.exists(): staging.unlink()

def matching_nft(record):
    rules = json.loads(run(['nft','-j','list','ruleset']).stdout)['nftables']
    found = []
    for item in rules:
        r = item.get('rule', {})
        if any(r.get(k) != record[k] for k in ('family','table','chain')) or r.get('comment') != record['marker']:
            continue
        for expr in r.get('expr', []):
            match = expr.get('match', {})
            payload = match.get('left', {}).get('payload', {})
            if payload.get('protocol') == record['proto'] and payload.get('field') == 'dport' and match.get('right') == record['port']:
                found.append(r)
                break
    return found

def command(record, add):
    backend = record['backend']
    if backend == 'ufw':
        args = ['ufw','insert','1','allow'] if add else ['ufw','--force','delete','allow']
        return args + ['proto',record['proto'],'from','0.0.0.0/0','to','0.0.0.0/0','port',str(record['port']),'comment',record['marker']]
    if backend == 'firewalld':
        args = ['firewall-cmd','--zone='+record['zone']]
        if record['mode'] == 'permanent': args.append('--permanent')
        return args + [('--add-port=' if add else '--remove-port=') + f"{record['port']}/{record['proto']}"]
    if backend == 'iptables':
        args = ['iptables','-w','-I','INPUT','1'] if add else ['iptables','-w','-D','INPUT']
        return args + ['-p',record['proto'],'--dport',str(record['port']),'-m','comment','--comment',record['marker'],'-j','ACCEPT']
    return ['nft','insert','rule',record['family'],record['table'],record['chain'],'meta','nfproto','ipv4',record['proto'],'dport',str(record['port']),'accept','comment',json.dumps(record['marker'])]

def exists(record):
    backend = record['backend']
    if backend == 'ufw':
        return any(record['marker'] in line and f"{record['port']}/{record['proto']}" in line
                   for line in run(['ufw','show','added']).stdout.splitlines())
    if backend == 'firewalld':
        args = command(record, True)
        args[-1] = args[-1].replace('--add-port=', '--query-port=')
        return run(args, query=True).returncode == 0
    if backend == 'iptables':
        args = command(record, False)
        args[2] = '-C'
        return run(args, query=True).returncode == 0
    return bool(matching_nft(record))

if mode == 'restore':
    for record in json.loads(restore.read_text()):
        if not exists(record): run(command(record, True))
    sys.exit()

old = json.loads(ledger.read_text()) if ledger.exists() else []
new = []
marker = os.environ['FW_MARK']
journal = pathlib.Path(os.environ['TEMP'])/'firewall.undo'
if journal.exists():
    for line in journal.read_text().splitlines():
        args = line.split()
        record = {'backend':args[0], 'marker':marker}
        if args[0] == 'ufw': port, proto = args[1].split('/')
        elif args[0] == 'firewalld':
            record.update(mode=args[1], zone=args[2]); port, proto = args[3].split('/')
        else: proto, port = args[1:]
        record.update(proto=proto, port=int(port))
        new.append(record)
if os.environ['FW_NFT'] == '1':
    rules = json.loads(run(['nft','-j','list','ruleset']).stdout)['nftables']
    for item in rules:
        r = item.get('rule', {})
        if r.get('comment') != marker: continue
        for expr in r.get('expr', []):
            match = expr.get('match', {}); payload = match.get('left', {}).get('payload', {})
            if payload.get('protocol') in ('tcp','udp') and payload.get('field') == 'dport' and type(match.get('right')) is int:
                new.append({'backend':'nft','marker':marker,'family':r['family'],'table':r['table'],'chain':r['chain'],
                            'proto':payload['protocol'],'port':match['right']})
                break
        else:
            sys.exit('无法识别本次新增的 nftables 端口规则。')
retired = set()
if len(sys.argv) in (3,4,5,6):
    current = {(os.environ.get('VLESS_NETWORK') or 'tcp',int(os.environ['VLESS_PORT'])),('udp',int(os.environ['HY2_PORT']))}
    if os.environ.get('ANYTLS_PORT'): current.add(('tcp',int(os.environ['ANYTLS_PORT'])))
    if os.environ.get('TUIC_PORT'): current.add(('udp',int(os.environ['TUIC_PORT'])))
    previous = {(sys.argv[5] if len(sys.argv)==6 else 'tcp',int(sys.argv[1])),('udp',int(sys.argv[2]))}
    if len(sys.argv)>=4 and sys.argv[3]: previous.add(('tcp',int(sys.argv[3])))
    if len(sys.argv)>=5 and sys.argv[4]: previous.add(('udp',int(sys.argv[4])))
    if os.environ.get('FW_CONFIG_ENDPOINTS'):
        current={(parts[0],int(parts[1])) for line in os.environ['FW_CONFIG_ENDPOINTS'].splitlines() if len(parts:=line.split())>=2}
        previous.update((parts[0],int(parts[1])) for line in os.environ.get('FW_PREVIOUS_ENDPOINTS','').splitlines() if len(parts:=line.split())>=2)
    retired = previous-current
    if not ledger.exists() and retired:
        print('提示：旧部署没有防火墙归属记录，已有旧端口规则将保留，请自行确认。', file=sys.stderr)
known_markers = {r['marker'] for r in old + new}
def leading_owned(record):
    backend = record['backend']
    if backend == 'firewalld':
        return
    if backend == 'ufw':
        import re
        rows = [line for line in run(['ufw','status','numbered']).stdout.splitlines()
                if re.match(r"^\[\s*\d+\]", line) and '(v6)' not in line and re.search(r"\sIN\s", line)]
        for line in rows:
            if record['marker'] in line and f"{record['port']}/{record['proto']}" in line:
                return
            if not any(marker in line for marker in known_markers):
                break
    elif backend == 'iptables':
        import shlex
        for line in run(['iptables','-w','-S','INPUT']).stdout.splitlines():
            args = shlex.split(line)
            if args[:2] != ['-A','INPUT']:
                continue
            marker = args[args.index('--comment')+1] if '--comment' in args else ''
            if marker == record['marker'] and '-p' in args and args[args.index('-p')+1] == record['proto'] and '--dport' in args and args[args.index('--dport')+1] == str(record['port']):
                return
            if marker not in known_markers:
                break
    else:
        matches = {r['handle'] for r in matching_nft(record)}
        for item in json.loads(run(['nft','-j','list','ruleset']).stdout)['nftables']:
            r = item.get('rule', {})
            if any(r.get(k) != record[k] for k in ('family','table','chain')):
                continue
            if r['handle'] in matches:
                return
            if r.get('comment') not in known_markers:
                break
    sys.exit('旧端口规则前存在非本脚本的规则，拒绝改变其顺序；请先手动清理该旧端口规则。')
remaining = []
removed = []
for record in old:
    if mode != 'remove-all' and (record['proto'],record['port']) not in retired:
        remaining.append(record)
        continue
    if not exists(record): continue
    leading_owned(record)
    removed.append(record)
    save(restore, removed)
    if record['backend'] == 'nft':
        for rule in matching_nft(record):
            run(['nft','delete','rule',record['family'],record['table'],record['chain'],'handle',str(rule['handle'])])
    else:
        run(command(record, False))
save(ledger, remaining + new)
PYCODE
}


status_cmd() {
  need_root
  local result=0 tcp udp
  systemctl status "$UNIT" --no-pager -l || result=1
  if [[ -f "$CONFIG" ]]; then
    node_config summary || result=1
    local endpoints proto port label
    endpoints="$(configuration_listeners)" || result=1
    while read -r proto port label; do
      [[ -n "$port" ]] || continue
      printf '\n=== %s %s %s ===\n' "$label" "${proto^^}" "$port"
      if [[ "$proto" == udp ]]; then tcp="$(ss -H -lunp "( sport = :$port )")" || result=1
      else tcp="$(ss -H -ltnp "( sport = :$port )")" || result=1; fi
      printf '%s\n' "$tcp"
      [[ "$tcp" == *'"sing-box"'* ]] || result=1
    done <<< "$endpoints"
  fi
  printf '\n=== Recent log ===\n'
  journalctl -u "$UNIT" -n 20 --no-pager || result=1
  printf '\n=== Config check ===\n'
  if [[ -x "$BIN" && -f "$CONFIG" ]]; then
    check_configuration || result=1
  else
    log 'sing-box binary or configuration is missing.'
    result=1
  fi
  if [[ -f "$APP/hopping.json" ]]; then
    local hopping_enabled
    hopping_enabled="$(python3 - "$APP/hopping.json" <<'PYCODE'
import json,sys
print('yes' if json.load(open(sys.argv[1])).get('enabled') else 'no')
PYCODE
)" || result=1
    if [[ "$hopping_enabled" == yes ]]; then systemctl status "$HOP_UNIT" --no-pager -l || result=1; fi
  fi
  firewall_hints
  return "$result"
}

install_manager() {
  [[ ${STAGING:-0} != 1 ]] || return 0
  [[ ! -L "$MANAGER" ]] || die '管理入口是符号链接，拒绝覆盖。'
  if [[ -e "$MANAGER" ]]; then
    grep -qxF '# sing-box-deploy 管理入口' "$MANAGER" || die '该管理命令不属于本脚本，拒绝覆盖。'
  fi
  [[ -f "$SCRIPT_PATH" ]] || die '请先把脚本保存为文件，再运行安装。'
  install -d -m 0755 "$(dirname "$MANAGER")"
  if [[ "$SCRIPT_PATH" != "$APP/manager.sh" ]]; then
    install -m 0700 "$SCRIPT_PATH" "$APP/manager.sh"
  fi
  printf '#!/usr/bin/env bash\n# sing-box-deploy 管理入口\nexec bash %q "$@"\n' "$APP/manager.sh" > "$MANAGER"
  chmod 0700 "$MANAGER"
  log '快捷管理命令已安装：sb-manager'
}

setup_manager() {
  need_root
  [[ -d "$APP/client" ]] || die '请先安装节点。'
  begin_transaction files "$APP/manager.sh" "$MANAGER"
  install_manager
  TRANSACTION=""
}

service_cmd() {
  need_root
  case "$1" in
    restart) require_no_pending; load_node_settings; restart_checked ;;
    start)
      require_no_pending
      if ! systemctl is-active --quiet "$UNIT"; then
        load_node_settings
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
  [[ -f "$CONFIG" && -x "$BIN" ]] || die '请先安装。'
  check_configuration
  load_node_settings
  local profile prefix
  local -a values=()
  for profile in ai google other; do
    mapfile -d '' -t values < <(node_config socks "$profile")
    [[ ${#values[@]} == 5 && "${values[4]}" == READY && -n "${values[0]}" ]] || die "未配置 $profile SOCKS5。"
    prefix="${profile^^}_SOCKS"
    export "${prefix}_HOST=${values[0]}" "${prefix}_PORT=${values[1]}" "${prefix}_USER=${values[2]}" "${prefix}_PASS=${values[3]}"
    check_socks "$profile"
  done
  forget_socks
  check_reality_target
  openssl x509 -in "$APP/tls/hy2.crt" -noout -dates -checkend 0
  if [[ -n "$ANYTLS_PORT" ]]; then openssl x509 -in "$APP/tls/anytls.crt" -noout -dates -checkend 0; fi
  if [[ -n "$TUIC_PORT" ]]; then openssl x509 -in "$APP/tls/tuic.crt" -noout -dates -checkend 0; fi
  log '配置、三组 SOCKS5、Reality 握手目标及证书有效期检查通过；公网节点连通性仍需客户端验证。'
}

menu_action() {
  local refresh=0
  # A separate process preserves errexit and transaction traps inside every operation.
  if bash "$SCRIPT_PATH" "$@"; then
    ui success '操作完成。'
    [[ "${1:-}" != apply ]] || refresh=1
  else
    ui error "操作未完成（退出码 $?），请查看上方错误；有备份时请保留。" >&2
  fi
  [[ -f "$SCRIPT_PATH" ]] || exit 0
  local answer
  read -r -p '按回车返回菜单。' answer || return 0
  if (( refresh )); then exec bash "$SCRIPT_PATH" menu; fi
}

# Labels and actions share one list; numbering and dispatch follow that list.
run_menu() {
  local title="$1" header="$2" choice action index text count provider=''
  shift 2
  local -a entries=("$@")
  if (( ${#entries[@]} == 1 )) && [[ "${entries[0]}" == @* ]]; then provider="${entries[0]#@}"; fi
  while true; do
    if [[ -n "$provider" ]]; then mapfile -d '' -t entries < <("$provider"); fi
    count=$((${#entries[@]}/2))
    printf '\n'; ui title "╭─ $title"
    ui info '│ 选择编号操作 · 0 返回 / 退出'
    ui info '╰────────────────────────────────────────'
    if [[ -n "$header" ]] && ! bash "$SCRIPT_PATH" "$header"; then ui warning '配置摘要读取失败，请查看状态和日志。'; fi
    text=''
    for ((index=0; index<${#entries[@]}; index+=2)); do
      text+=" $((index/2+1)). ${entries[index]}"$'\n'
    done
    text+=' 0. 返回 / 退出'
    menu_choices "$text"
    read -r -p '请选择：' choice || return 0
    [[ "$choice" != 0 ]] || return 0
    if [[ ! "$choice" =~ ^[0-9]+$ ]] || (( ${#choice}>${#count} || 10#$choice<1 || 10#$choice>count )); then
      ui warning '无效选择，请重新输入。'
      continue
    fi
    action="${entries[(10#$choice-1)*2+1]}"
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
    '查看状态和完整规则详情' firewall-details \
    '开启脚本自动放行端口（现有规则不变）' firewall-auto-on \
    '关闭脚本自动放行端口（保留现有规则）' firewall-auto-off \
    '开启系统防火墙（需确认）' firewall-enable \
    '关闭系统防火墙（需确认）' firewall-disable
}

socks_menu() {
  run_menu 'SOCKS5 出口' '' \
    'AI' set-ai-socks \
    'Google / YouTube' set-google-socks \
    '其他流量' set-other-socks \
    '同时修改三组' configure-socks \
    '三组 SOCKS5 的 TFO 开关' set-tfo
}

export_menu() {
  run_menu '节点资料（含访问凭据）' '' \
    '查看已应用的连接参数和分享链接' show \
    '查看已应用的客户端 JSON' show-json \
    '导出已应用节点到资料目录' export \
    '查看已应用的 Clash/Mihomo proxies YAML' show-yaml \
    '可选导出已应用的 proxies.yaml 文件' export-yaml
}

service_menu() {
  run_menu '服务管理' '' '启动' start '停止' stop '重启' restart
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
  HOP_SPEC="$spec" HOP_EXCLUDE="$exclusion" HOP_INTERVAL="$interval" HOP_BACKEND="$backend" HY2_PORT="$HY2_PORT" python3 - "$TEMP" <<'PYCODE'
import json, os, pathlib, re, sys
root = pathlib.Path(sys.argv[1]); e = os.environ

def ports(spec):
    result = set()
    if spec in ('', '0', 'none'): return result
    for item in spec.split(','):
        match = re.fullmatch(r'\s*([0-9]{1,5})(?:[:-]([0-9]{1,5}))?\s*', item)
        if not match: sys.exit('端口格式无效，示例：20000:20100,30000。')
        a, b = int(match[1]), int(match[2] or match[1])
        if not 1 <= a <= b <= 65535: sys.exit('端口必须在 1–65535，且区间起点不大于终点。')
        result.update(range(a,b+1))
    return result

def compact(values):
    runs=[]
    for port in sorted(values):
        if runs and port==runs[-1][1]+1: runs[-1][1]=port
        else: runs.append([port,port])
    return [str(a) if a==b else f'{a}:{b}' for a,b in runs]
selected = ports(e['HOP_SPEC']); busy=set(); base=int(e['HY2_PORT'])
for line in (root/'occupied.txt').read_text().splitlines():
    fields=line.split()
    if len(fields)<5 or fields[0] not in ('udp','tcp'): continue
    match=re.search(r':([0-9]+)$',fields[4])
    if not match or fields[0]!='udp': continue
    port=int(match[1])
    if port==base and '"sing-box"' in line: continue
    busy.add(port)
exclude = busy if e['HOP_EXCLUDE']=='auto' else ports(e['HOP_EXCLUDE'])
result = selected-exclude
conflicts=result & busy
if conflicts: sys.exit('仍有 UDP 占用端口，请选择排除：'+','.join(compact(conflicts)))
if selected and not result: sys.exit('排除后没有可用的跳跃端口。')
if selected and len(result)<2: sys.exit('端口跳跃至少需要两个可用端口。')
interval=e['HOP_INTERVAL']
duration=re.fullmatch(r'([0-9]+(?:\.[0-9]+)?)(ms|s|m|h)',interval)
if not duration or float(duration[1])*{'ms':0.001,'s':1,'m':60,'h':3600}[duration[2]]<5:
    sys.exit('跳跃间隔至少 5 秒，例如 30s、1m。')
plan={'version':1,'enabled':bool(result),'backend':e['HOP_BACKEND'],'base_port':base,'ports':compact(result),'hop_interval':interval}
(root/'hopping-plan.json').write_text(json.dumps(plan,indent=2)+'\n')
if selected:
    print('最终 UDP 跳跃端口：'+','.join(plan['ports']))
    print('已排除：'+(','.join(compact(selected & exclude)) or '无'))
PYCODE
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
  enabled="$(python3 - "$TEMP/hopping-plan.json" <<'PYCODE'
import json, sys
print('yes' if json.load(open(sys.argv[1]))['enabled'] else 'no')
PYCODE
)"
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
  python3 - "${2:-$APP/hopping.json}" "$1" "${3:-$CONFIG}" <<'PYCODE'
import json, os, pathlib, re, subprocess, sys
path=pathlib.Path(sys.argv[1]); action=sys.argv[2]
if not path.exists():
    if action=='stop': sys.exit()
    sys.exit('没有端口跳跃配置。')
c=json.loads(path.read_text())
if c.get('version')!=1 or c.get('backend') not in ('nft','iptables') or type(c.get('enabled')) is not bool or type(c.get('base_port')) is not int or not 1<=c['base_port']<=65535 or not isinstance(c.get('ports'),list):
    sys.exit('端口跳跃配置格式无效。')
ranges=[]
for item in c['ports']:
    if not isinstance(item,str) or not re.fullmatch(r'[0-9]{1,5}(?::[0-9]{1,5})?',item): sys.exit('跳跃端口格式无效。')
    parts=item.split(':'); a,b=int(parts[0]),int(parts[-1])
    if not 1<=a<=b<=65535: sys.exit('跳跃端口越界。')
    # The primary listener already receives this port without redirect.
    if a<=c['base_port']<=b:
        if a<c['base_port']: ranges.append((a,c['base_port']-1))
        if c['base_port']<b: ranges.append((c['base_port']+1,b))
    else: ranges.append((a,b))
if c['enabled'] and not c['ports']: sys.exit('跳跃端口不能为空。')
duration=re.fullmatch(r'([0-9]+(?:\.[0-9]+)?)(ms|s|m|h)',str(c.get('hop_interval','')))
if not duration or float(duration[1])*{'ms':0.001,'s':1,'m':60,'h':3600}[duration[2]]<5: sys.exit('跳跃间隔至少 5 秒。')
if c['enabled'] and action in ('start','validate') and pathlib.Path(sys.argv[3]).exists():
    config=json.loads(pathlib.Path(sys.argv[3]).read_text())
    for item in config.get('inbounds',[]):
        kind=item.get('type') or item.get('tag')
        if kind=='hysteria2' and item.get('listen_port')==c['base_port']: continue
        if kind in ('tuic','hysteria','hysteria2') or item.get('network')=='udp' or (kind in ('direct','shadowsocks') and not item.get('network')) or (item.get('transport') or {}).get('type')=='quic':
            port=item.get('listen_port')
            if type(port) is int and any(a<=port<=b for a,b in ranges):
                sys.exit(f'{kind} UDP/{port} 与 HY2 跳跃端口冲突，请先从跳跃范围排除该端口。')
if action not in ('start','stop','validate'): sys.exit('未知跳跃规则操作。')
if action=='validate' or not c['enabled']: sys.exit()

def run(args, **kwargs):
    r=subprocess.run(args,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={**os.environ,'LC_ALL':'C'},**kwargs)
    if r.returncode:
        sys.stderr.write(r.stderr); sys.exit('端口跳跃规则操作失败：'+args[0])
    return r.stdout
marker='sing-box-deploy-hopping'; table='sing_box_hy2_hop'; chain='SB_HY2_HOP'
if c['backend']=='nft':
    tables=json.loads(run(['nft','-j','list','tables']))['nftables']
    present=any(t.get('table',{}).get('family')=='ip' and t.get('table',{}).get('name')==table for t in tables)
    if present:
        data=json.loads(run(['nft','-j','list','table','ip',table]))['nftables']
        if not any(t.get('table',{}).get('comment')==marker for t in data): sys.exit('同名 nftables 表不属于本脚本，拒绝覆盖。')
    batch=f'delete table ip {table}\n' if present else ''
    if action=='start' and c['enabled'] and ranges:
        ports=', '.join(str(a) if a==b else f'{a}-{b}' for a,b in ranges)
        batch+=f'table ip {table} {{\n comment "{marker}"\n chain prerouting {{\n type nat hook prerouting priority dstnat; policy accept;\n fib daddr type local udp dport {{ {ports} }} redirect to :{c["base_port"]} comment "{marker}"\n }}\n}}\n'
    if batch: run(['nft','-f','-'],input=batch)
else:
    import shlex
    listing=run(['iptables','-w','-t','nat','-S'])
    jump=['PREROUTING','-p','udp','-m','addrtype','--dst-type','LOCAL','-m','comment','--comment',marker,'-j',chain]
    owned=any(shlex.split(line)==['-A',*jump] for line in listing.splitlines())
    present=any(shlex.split(line)==['-N',chain] for line in listing.splitlines())
    if present and not owned: sys.exit('同名 iptables 链不属于本脚本，拒绝覆盖。')
    if owned:
        run(['iptables','-w','-t','nat','-D',*jump])
        run(['iptables','-w','-t','nat','-F',chain]); run(['iptables','-w','-t','nat','-X',chain])
    if action=='start' and c['enabled'] and ranges:
        run(['iptables','-w','-t','nat','-N',chain])
        try:
            # Establish ownership before filling this private chain.
            run(['iptables','-w','-t','nat','-I',*jump])
            for a,b in ranges:
                spec=str(a) if a==b else f'{a}:{b}'
                run(['iptables','-w','-t','nat','-A',chain,'-p','udp','--dport',spec,'-j','REDIRECT','--to-ports',str(c['base_port'])])
        except SystemExit:
            # This is the chain created above, never a shared firewall chain.
            subprocess.run(['iptables','-w','-t','nat','-D',*jump],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            subprocess.run(['iptables','-w','-t','nat','-F',chain])
            subprocess.run(['iptables','-w','-t','nat','-X',chain])
            raise
PYCODE
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
  check_os
  [[ -x "$BIN" && -f "$CONFIG" ]] || die '请先安装。'
  load_node_settings
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
  python3 - "$@" <<'PYCODE'
import datetime, hashlib, io, json, os, pathlib, re, tarfile, tempfile, sys
app=pathlib.Path(os.environ['APP']); config=pathlib.Path(os.environ['CONFIG']); action=sys.argv[1]
allowed_roots={'rules','tls','client'}

def allowed(name):
    path=pathlib.PurePosixPath(name)
    return bool(path.parts) and str(path)==name and not path.is_absolute() and '..' not in path.parts and (name in ('config.json','manifest.json','hopping.json') or path.parts[0] in allowed_roots)

if action=='create':
    directory=pathlib.Path(os.environ['BACKUP_DIR'])
    def inside(path, root):
        try: path.resolve().relative_to(root.resolve()); return True
        except ValueError: return False
    def safe_target(path):
        if inside(path,app) or inside(path,config.parent) or path.resolve() in (pathlib.Path(os.environ['MANAGER']).resolve(),pathlib.Path(os.environ['HOP_UNIT_FILE']).resolve()):
            sys.exit('备份必须保存在部署、配置和管理入口目录之外，防止备份被覆盖或随卸载删除。')
    safe_target(directory)
    if directory.is_symlink(): sys.exit('备份目录不能是符号链接。')
    directory.mkdir(parents=True,exist_ok=True); directory.chmod(0o700)
    target=pathlib.Path(sys.argv[2]).absolute() if len(sys.argv)>2 and sys.argv[2] else None
    if target is not None:
        safe_target(target)
        stream=target.open('xb')
    else:
        stream=tempfile.NamedTemporaryFile(mode='w+b',dir=directory,prefix='sing-box-'+datetime.datetime.now().strftime('%Y%m%d-%H%M%S')+'-',suffix='.tar.gz',delete=False)
        target=pathlib.Path(stream.name)
    os.fchmod(stream.fileno(),0o600)
    manifest={'format':1,'created':datetime.datetime.now(datetime.timezone.utc).isoformat(),'app_path':str(app),
              'kernel_version':os.environ.get('BACKUP_KERNEL_VERSION','unknown'),
              'service':{'active':os.environ.get('BACKUP_SERVICE_ACTIVE')=='yes','enabled':os.environ.get('BACKUP_SERVICE_ENABLED')=='yes'},'files':{}}
    try:
        with stream, tarfile.open(fileobj=stream,mode='w:gz') as archive:
            paths=[(config,'config.json')]
            for root in sorted(allowed_roots):
                base=app/root
                if base.is_symlink(): sys.exit('不能备份符号链接目录：'+str(base))
                if base.exists():
                    paths.extend((p,str(p.relative_to(app))) for p in sorted(base.rglob('*')))
            if (app/'hopping.json').exists(): paths.append((app/'hopping.json','hopping.json'))
            for path,name in paths:
                if path.is_symlink() or (not path.is_file() and not path.is_dir()): sys.exit('备份只接受普通文件和目录：'+str(path))
                if path.is_dir(): continue
                data=path.read_bytes(); manifest['files'][name]=hashlib.sha256(data).hexdigest()
                info=tarfile.TarInfo(name); info.size=len(data); info.mode=0o600
                archive.addfile(info,io.BytesIO(data))
            data=json.dumps(manifest,ensure_ascii=False,indent=2).encode()
            info=tarfile.TarInfo('manifest.json');info.size=len(data);info.mode=0o600
            archive.addfile(info,io.BytesIO(data))
    except BaseException:
        target.unlink()
        raise
    print(target)
    sys.exit()

if action!='extract': sys.exit('未知备份操作。')
source=pathlib.Path(sys.argv[2]); destination=pathlib.Path(sys.argv[3])
destination.mkdir(mode=0o700)
with tarfile.open(source,'r:gz') as archive:
    members=archive.getmembers(); names=set()
    for member in members:
        if not member.isfile() or not allowed(member.name) or member.name in names:
            sys.exit('备份包含重复、越界路径、链接或特殊文件，拒绝恢复。')
        names.add(member.name)
    if 'manifest.json' not in names or 'config.json' not in names: sys.exit('不是本脚本的备份。')
    manifest=json.load(archive.extractfile('manifest.json'))
    if manifest.get('format')!=1 or not isinstance(manifest.get('files'),dict) or set(manifest['files']) != names-{'manifest.json'}:
        sys.exit('备份清单不匹配。')
    for member in members:
        if member.name=='manifest.json': continue
        data=archive.extractfile(member).read()
        if hashlib.sha256(data).hexdigest()!=manifest['files'][member.name]: sys.exit('备份校验失败：'+member.name)
        target=destination/member.name;target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        target.write_bytes(data); target.chmod(0o600)
# Relocate only managed certificate/rules paths; never replay archived firewall ownership.
c=json.loads((destination/'config.json').read_text()); old=pathlib.Path(manifest['app_path'])
required_tls=[]
for inbound in c['inbounds']:
    tls=inbound.get('tls') or {}
    for key in ('certificate_path','key_path'):
        if key not in tls: continue
        try: relative=pathlib.Path(tls[key]).relative_to(old/'tls')
        except ValueError: sys.exit('备份引用了外部证书，拒绝自动恢复。')
        if '..' in relative.parts: sys.exit('备份证书路径越界。')
        tls[key]=str(app/'tls'/relative)
        required_tls.append(str(pathlib.PurePosixPath('tls')/relative))
for rule in c.get('route',{}).get('rule_set',[]):
    if 'initial_path' in rule:
        path=pathlib.Path(rule['initial_path'])
        try: relative=path.relative_to(old/'rules')
        except ValueError: sys.exit('备份引用了外部规则集路径。')
        rule['initial_path']=str(app/'rules'/relative)
if old != app and c.get('experimental',{}).get('cache_file',{}).get('path') == str(old/'cache.db'):
    c['experimental']['cache_file']['path'] = str(app/'cache.db')
(destination/'config.json').write_text(json.dumps(c,indent=2,ensure_ascii=False)+'\n')
state=manifest.get('service',{'active':False,'enabled':False})
if not isinstance(state,dict) or any(type(state.get(key)) is not bool for key in ('active','enabled')): sys.exit('备份中的服务状态无效。')
(destination/'manifest.json').write_text(json.dumps(manifest)+'\n')
required = ['client/vless-reality.outbound.json','client/hysteria2.outbound.json']+required_tls
if 'client/EXPORT-ERROR.txt' not in names and any(i.get('type')=='anytls' or (not i.get('type') and i.get('tag')=='anytls') for i in c['inbounds']): required += ['client/anytls.outbound.json']
if 'client/EXPORT-ERROR.txt' not in names and any(i.get('type')=='tuic' or (not i.get('type') and i.get('tag')=='tuic') for i in c['inbounds']): required += ['client/tuic.outbound.json']
for name in required:
    if name not in names: sys.exit('备份缺少必要文件：'+name)
PYCODE
}

backup_cmd() {
  need_root
  if [[ -d "$APP/pending" ]]; then warn '本次备份仅包含已应用配置，待应用修改未纳入备份。'; fi
  [[ -f "$CONFIG" && -d "$APP/client" ]] || die '没有可备份的节点配置。'
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
  local source="${1:-${BACKUP_FILE:-}}" old_vless="" old_hy2="" old_anytls="" old_tuic="" old_vnet="tcp" answer
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
    local ports
    if ports="$(python3 - "$CONFIG" <<'PYCODE'
import json,sys
c=json.load(open(sys.argv[1]))
print(next(i['listen_port'] for i in c['inbounds'] if i.get('type')=='vless' or (not i.get('type') and i.get('tag')=='vless-reality')),next(i['listen_port'] for i in c['inbounds'] if i.get('type')=='hysteria2' or (not i.get('type') and i.get('tag')=='hysteria2')),next((i['listen_port'] for i in c['inbounds'] if i.get('type')=='anytls' or (not i.get('type') and i.get('tag')=='anytls')),'-'),next((i['listen_port'] for i in c['inbounds'] if i.get('type')=='tuic'),'-'),'udp' if any(i.get('type')=='vless' and (i.get('transport') or {}).get('type')=='quic' for i in c['inbounds']) else 'tcp')
PYCODE
)"; then
      read -r old_vless old_hy2 old_anytls old_tuic old_vnet <<< "$ports"
      FW_PREVIOUS_ENDPOINTS="$(configuration_listeners)"
      [[ "$old_anytls" != - ]] || old_anytls=""
      [[ "$old_tuic" != - ]] || old_tuic=""
    else log '当前配置已损坏，旧防火墙规则将保留。'; fi
  fi
  local -a restore_paths=("$APP/rules" "$APP/tls" "$APP/client" "$APP/hopping.json" "$APP/firewall-owned.json" "$APP/manager.sh")
  if [[ ! -e "$APP" && ! -L "$APP" ]]; then restore_paths=("$APP"); fi
  local restore_active restore_enabled states
  states="$(python3 - "$TEMP/restored/manifest.json" <<'PYCODE'
import json,sys
s=json.load(open(sys.argv[1])).get('service',{'active':False,'enabled':False})
print('yes' if s['active'] else 'no','yes' if s['enabled'] else 'no')
PYCODE
)"
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
    rm -rf "$APP/$name"
    if [[ -d "$TEMP/restored/$name" ]]; then cp -a "$TEMP/restored/$name" "$APP/$name"; else install -d -m 0700 "$APP/$name"; fi
  done
  if [[ -f "$TEMP/restored/hopping.json" ]]; then
    cp "$TEMP/restored/hopping.json" "$TEMP/hopping-plan.json"
  else
    python3 - "$CONFIG" "$TEMP/hopping-plan.json" "$DEFAULT_HY2_HOP_INTERVAL" <<'PYCODE'
import json,pathlib,sys
config=json.loads(pathlib.Path(sys.argv[1]).read_text())
port=next(i['listen_port'] for i in config['inbounds'] if i.get('type')=='hysteria2' or (not i.get('type') and i.get('tag')=='hysteria2'))
pathlib.Path(sys.argv[2]).write_text(json.dumps({'version':1,'enabled':False,'backend':'nft','base_port':port,'ports':[],'hop_interval':sys.argv[3]},indent=2)+'\n')
PYCODE
  fi
  # Old runtime has already been stopped; plan applies the restored redirect target.
  rm -f "$APP/hopping.json"
  install_manager
  apply_hopping_plan
  if [[ ! -f "$TEMP/restored/hopping.json" ]]; then rm -f "$APP/hopping.json"; fi
  export_client_files
  load_node_settings
  check_configuration
  rm -f "$APP/cache.db"
  open_firewall "$old_vless" "$old_hy2" "$old_anytls" "$old_tuic" "$old_vnet"
  if [[ "$restore_active" == yes ]]; then restart_checked; else systemctl stop "$UNIT"; fi
  if [[ "$restore_enabled" == yes ]]; then systemctl enable "$UNIT"; else systemctl disable "$UNIT"; fi
  if [[ -n "$old_vless" ]]; then update_firewall_ownership "$old_vless" "$old_hy2" "$old_anytls" "$old_tuic" "$old_vnet"; else update_firewall_ownership; fi
  if [[ ! -f "$APP/client/EXPORT-ERROR.txt" ]]; then show_node_details; fi
  TRANSACTION=""
  success '配置备份已恢复，服务启停和开机启动状态按备份恢复；内核版本未改变。请重新导入节点资料。'
}

uninstall_cmd() {
  need_root
  require_no_pending
  check_os
  [[ -d "$APP/client" && -f "$CONFIG" ]] || die '没有可确认的本脚本部署。'
  if [[ -e "$MANAGER" ]]; then
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

main_menu() {
  need_root
  [[ -t 0 ]] || { usage; return 0; }
  run_menu '━━━━━━━━━━ sing-box 管理工具 ━━━━━━━━━━' summary \
    '安装' install \
    '修改协议配置' @protocol_menu \
    '修改 SOCKS5 出口' @socks_menu \
    '查看 / 导出节点' @export_menu \
    '启动 / 停止 / 重启服务' @service_menu \
    '查看状态' status \
    '查看日志' logs \
    '检查连接' check \
    '安装 / 更新快捷命令 sb-manager' setup-manager \
    '更新 sing-box 内核' update \
    '手动备份已应用配置' backup \
    '恢复配置备份' restore \
    '卸载' uninstall \
    '应用配置并重启' apply \
    '丢弃待应用修改' discard-pending \
    '生成 / 重新生成协议' @protocol_creation_menu \
    '防火墙状态 / 详情 / 开关' @firewall_menu
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
  summary) show_dashboard ;;
  protocol-edit-header) protocol_edit_header ;;
  apply) apply_changes ;;
  discard-pending) discard_pending ;;
  setup-manager) setup_manager ;;
  start|stop|restart) service_cmd "$1" ;;
  logs) need_root; journalctl -u "$UNIT" -n 80 --no-pager ;;
  check) check_connections ;;
  set-ai-socks|set-socks) stage_changes set_socks_profile ai ;;
  set-google-socks) stage_changes set_socks_profile google ;;
  set-other-socks) stage_changes set_socks_profile other ;;
  configure-socks) stage_changes set_socks_profile ai google other ;;
  status) status_cmd ;;
  show) show_node_details ;;
  -h|--help|help) usage ;;
  *) usage; die 'Unknown action.' ;;
esac
