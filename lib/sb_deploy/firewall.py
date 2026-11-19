"""Firewall inspection, SSH safeguards and rule ownership."""


def automatic():
    import json
    import os
    import pathlib
    import sys
    import tempfile

    p = pathlib.Path(sys.argv[1])
    value = sys.argv[3]
    if value:
        if value not in ("true", "false"):
            sys.exit("自动放行开关必须是 true 或 false。")
        if not pathlib.Path(sys.argv[4]).is_file():
            sys.exit("配置文件不存在，无法设置自动放行端口。")
        p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if p.is_symlink():
            sys.exit("拒绝覆盖防火墙设置符号链接。")
        with tempfile.NamedTemporaryFile(
            mode="w", dir=p.parent, prefix=".firewall-settings-", delete=False
        ) as f:
            temporary = pathlib.Path(f.name)
            try:
                json.dump({"automatic_ports": value == "true"}, f)
                f.write("\n")
                f.flush()
                os.fchmod(f.fileno(), 0o600)
                temporary.replace(p)
            finally:
                temporary.unlink(missing_ok=True)
        print(value)
    else:
        if p.is_symlink():
            sys.exit("拒绝读取防火墙设置符号链接。")
        if p.exists():
            data = json.loads(p.read_text())
            value = data.get("automatic_ports")
            if type(value) is not bool:
                sys.exit("防火墙自动放行设置格式无效。")
            print("true" if value else "false")
        else:
            if sys.argv[2] not in ("true", "false"):
                sys.exit("DEFAULT_FIREWALL_AUTO 必须是 true 或 false。")
            print(sys.argv[2])


def status():
    import json
    import os
    import pathlib
    import shutil
    import subprocess
    import sys

    verbose = sys.argv[1] == "details"
    active = False
    found = False

    def run(args, allowed=(0,)):
        r = subprocess.run(args, text=True, capture_output=True, env={**os.environ, "LC_ALL": "C"})
        if r.returncode not in allowed:
            sys.stderr.write(r.stderr or r.stdout)
            sys.exit("无法读取防火墙状态：" + args[0])
        return r

    if shutil.which("ufw"):
        found = True
        r = run(["ufw", "status"] + (["verbose"] if verbose else []))
        if "Status: active" in r.stdout:
            active = True
            print("UFW：已开启")
        elif "Status: inactive" in r.stdout:
            print("UFW：已关闭")
        else:
            sys.exit("无法识别 UFW 状态。")
        if verbose:
            print(r.stdout.rstrip())
    if shutil.which("firewall-cmd"):
        found = True
        r = run(["firewall-cmd", "--state"], (0, 252))
        if r.returncode == 0 and r.stdout.strip() == "running":
            active = True
            print("firewalld：已开启")
            if verbose:
                for mode in ([], ["--permanent"]):
                    print("持久规则：" if mode else "运行规则：")
                    print(run(["firewall-cmd", *mode, "--list-all-zones"]).stdout.rstrip())
        elif r.returncode == 252 and "not running" in r.stdout + r.stderr:
            print("firewalld：已关闭")
        else:
            sys.exit("无法识别 firewalld 状态。")
    # Without a manager, show the actual raw rules rather than equating an installed tool with protection.
    if not active:
        if shutil.which("nft"):
            found = True
            data = json.loads(run(["nft", "-j", "list", "ruleset"]).stdout)
            entries = [
                x
                for x in data.get("nftables", [])
                if any(k in x for k in ("table", "chain", "rule"))
            ]
            print(f"nftables：{len(entries)} 项表/链/规则（原始规则不提供一键开关）")
            if verbose:
                print(json.dumps(data, indent=2, ensure_ascii=False))
        if shutil.which("iptables"):
            found = True
            args = ["iptables", "-w", "-S"] + ([] if verbose else ["INPUT"])
            print("iptables：")
            print(run(args).stdout.rstrip())
    if not found:
        print("未检测到可用的防火墙管理工具。")
    p = pathlib.Path(sys.argv[2])
    rules = json.loads(p.read_text()) if p.exists() else []
    print(f"本脚本记录的放行规则：{len(rules)} 条")
    if verbose:
        print(json.dumps(rules, indent=2, ensure_ascii=False))
        print("云安全组不在本机防火墙状态内，请在云平台查看。")


def ssh_listeners():
    import re
    import sys

    from sb_deploy.context import context

    listeners = {}
    ssh = set()
    systemd = set()
    for line in context.require("SSH_LISTENERS").splitlines():
        fields = line.split()
        if fields and fields[0] in ("tcp", "tcp6"):
            fields = fields[1:]
        if len(fields) < 5 or fields[0] != "LISTEN":
            continue
        match = re.search(r":([0-9]+)$", fields[3])
        if not match or not 1 <= int(match[1]) <= 65535:
            continue
        port = int(match[1])
        address = fields[3][: match.start()].strip("[]")
        family = 6 if ":" in address or address == "*" else 4
        entry = (family, port)
        listeners[entry] = line
        if re.search(r'\("(?:sshd|sshd-session|dropbear)"[,)]', line):
            ssh.add(entry)
        if re.search(r'\("systemd"[,)]', line):
            systemd.add(entry)
    configured = set()
    for line in context.require("SSH_EFFECTIVE_CONFIG").splitlines():
        fields = line.split()
        if len(fields) != 2:
            continue
        if fields[0] == "port" and fields[1].isdigit():
            configured.add(int(fields[1]))
        elif fields[0] == "listenaddress":
            match = re.search(r":([0-9]+)$", fields[1])
            if match:
                configured.add(int(match[1]))
    # Cover socket-activated sshd without trusting an unbound or stale config port.
    ssh.update(entry for entry in systemd if entry[1] in configured)
    connection = context.get("SSH_CONNECTION", "")
    client = context.get("SSH_CLIENT", "")
    if connection or client:
        fields = (connection or client).split()
        expected = 4 if connection else 3
        if len(fields) != expected or not fields[-1].isdigit() or not 1 <= int(fields[-1]) <= 65535:
            sys.exit("无法确认当前 SSH 会话的服务端口，拒绝启用系统防火墙。")
        port = int(fields[-1])
        ssh.update(entry for entry in systemd if entry[1] == port)
        if not any(entry[1] == port for entry in ssh):
            sys.exit("当前 SSH 会话端口不在已确认的监听列表中，拒绝启用系统防火墙。")
        address = fields[2] if connection else fields[0]
        ssh.add((6 if ":" in address else 4, port))
    if not ssh:
        sys.exit("未检测到可确认的 SSH 监听端口，拒绝启用系统防火墙；请先检查 sshd/sshd.socket。")
    for family, port in sorted(ssh):
        print(family, port)


def ufw_ipv6():
    import pathlib
    import re
    import sys

    try:
        lines = pathlib.Path(sys.argv[1]).read_text().splitlines()
    except OSError as error:
        sys.exit("无法确认 UFW IPv6 设置，拒绝启用：" + str(error))
    values = [line.split("=", 1)[1].strip() for line in lines if re.match(r"^\s*IPV6\s*=", line)]
    if not values or not re.fullmatch(r"(?:yes|'yes'|\"yes\")\s*(?:#.*)?", values[-1]):
        sys.exit("SSH 包含 IPv6 监听，但 UFW 未明确设置 IPV6=yes，拒绝启用以免断联。")


def ufw_ssh_rules():
    import pathlib
    import re
    import shlex
    import sys

    required = set(sys.argv[4:])
    paths = [(sys.argv[1], "ufw-user-input")]
    if sys.argv[3] == "1":
        paths.append((sys.argv[2], "ufw6-user-input"))
    for name, chain in paths:
        try:
            lines = pathlib.Path(name).read_text().splitlines()
        except OSError as error:
            sys.exit("无法核实 UFW SSH 放行规则，拒绝启用：" + str(error))
        try:
            parsed = [shlex.split(line, comments=True) for line in lines]
        except ValueError:
            sys.exit("UFW 规则格式无法识别，拒绝启用。")
        rules = []
        for rule in parsed:
            if rule and re.fullmatch(r"\[[0-9]+:[0-9]+\]", rule[0]):
                rule = rule[1:]
            if rule[:2] == ["-A", chain]:
                rules.append(rule)
        allowed = set()
        for rule in rules[: len(required)]:
            # UFW may include the tcp match module; other restrictions are not an SSH safeguard.
            if "-m" in rule:
                index = rule.index("-m")
                if rule[index : index + 2] == ["-m", "tcp"]:
                    del rule[index : index + 2]
            if (
                len(rule) == 8
                and rule[:4] == ["-A", chain, "-p", "tcp"]
                and rule[4] == "--dport"
                and rule[6:] == ["-j", "ACCEPT"]
            ):
                allowed.add(rule[5])
        if allowed != required:
            sys.exit("UFW SSH 规则未处于各地址族的优先放行位置，拒绝启用；请检查已有规则顺序。")


def release_ssh_ownership():
    import json
    import os
    import pathlib
    import sys
    import tempfile

    path = pathlib.Path(sys.argv[1])
    backend = sys.argv[2]
    ports = set(sys.argv[3:])
    if not path.exists():
        sys.exit()
    if path.is_symlink():
        sys.exit("防火墙归属记录是符号链接，拒绝修改。")
    records = json.loads(path.read_text())
    if not isinstance(records, list) or any(not isinstance(record, dict) for record in records):
        sys.exit("防火墙归属记录格式无效。")
    remaining = [
        record
        for record in records
        if not (
            record.get("backend") == backend
            and record.get("proto") == "tcp"
            and str(record.get("port")) in ports
        )
    ]
    if remaining != records:
        with tempfile.NamedTemporaryFile(
            mode="w", dir=path.parent, prefix=".ssh-ownership-", delete=False
        ) as stream:
            temporary = pathlib.Path(stream.name)
            try:
                json.dump(remaining, stream, indent=2, ensure_ascii=False)
                stream.write("\n")
                stream.flush()
                os.fchmod(stream.fileno(), 0o600)
                temporary.replace(path)
            finally:
                temporary.unlink(missing_ok=True)


def ownership():
    import json
    import os
    import pathlib
    import subprocess
    import sys
    import tempfile

    from sb_deploy.context import context

    app = pathlib.Path(context.require("APP"))
    ledger = app / "firewall-owned.json"
    restore = pathlib.Path(context.require("FW_RESTORE"))
    mode = sys.argv[1] if len(sys.argv) > 1 else "save"

    def run(args, query=False):
        result = subprocess.run(
            args,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={**os.environ, "LC_ALL": "C"},
        )
        if result.returncode and not (query and result.returncode == 1):
            sys.stderr.write(result.stderr)
            sys.exit("防火墙操作失败：" + args[0])
        return result

    def save(path, data):
        with tempfile.NamedTemporaryFile(
            mode="w", dir=path.parent, prefix=".firewall-", delete=False
        ) as f:
            staging = pathlib.Path(f.name)
            try:
                json.dump(data, f, ensure_ascii=False, indent=2)
                f.write("\n")
                f.flush()
                os.fchmod(f.fileno(), 0o600)
                staging.replace(path)
            finally:
                if staging.exists():
                    staging.unlink()

    def matching_nft(record):
        rules = json.loads(run(["nft", "-j", "list", "ruleset"]).stdout)["nftables"]
        found = []
        for item in rules:
            r = item.get("rule", {})
            if (
                any(r.get(k) != record[k] for k in ("family", "table", "chain"))
                or r.get("comment") != record["marker"]
            ):
                continue
            for expr in r.get("expr", []):
                match = expr.get("match", {})
                payload = match.get("left", {}).get("payload", {})
                if (
                    payload.get("protocol") == record["proto"]
                    and payload.get("field") == "dport"
                    and match.get("right") == record["port"]
                ):
                    found.append(r)
                    break
        return found

    def command(record, add):
        backend = record["backend"]
        if backend == "ufw":
            args = ["ufw", "insert", "1", "allow"] if add else ["ufw", "--force", "delete", "allow"]
            return args + [
                "proto",
                record["proto"],
                "from",
                "0.0.0.0/0",
                "to",
                "0.0.0.0/0",
                "port",
                str(record["port"]),
                "comment",
                record["marker"],
            ]
        if backend == "firewalld":
            args = ["firewall-cmd", "--zone=" + record["zone"]]
            if record["mode"] == "permanent":
                args.append("--permanent")
            return args + [
                ("--add-port=" if add else "--remove-port=") + f"{record['port']}/{record['proto']}"
            ]
        if backend == "iptables":
            args = (
                ["iptables", "-w", "-I", "INPUT", "1"] if add else ["iptables", "-w", "-D", "INPUT"]
            )
            return args + [
                "-p",
                record["proto"],
                "--dport",
                str(record["port"]),
                "-m",
                "comment",
                "--comment",
                record["marker"],
                "-j",
                "ACCEPT",
            ]
        return [
            "nft",
            "insert",
            "rule",
            record["family"],
            record["table"],
            record["chain"],
            "meta",
            "nfproto",
            "ipv4",
            record["proto"],
            "dport",
            str(record["port"]),
            "accept",
            "comment",
            json.dumps(record["marker"]),
        ]

    def exists(record):
        backend = record["backend"]
        if backend == "ufw":
            return any(
                record["marker"] in line and f"{record['port']}/{record['proto']}" in line
                for line in run(["ufw", "show", "added"]).stdout.splitlines()
            )
        if backend == "firewalld":
            args = command(record, True)
            args[-1] = args[-1].replace("--add-port=", "--query-port=")
            return run(args, query=True).returncode == 0
        if backend == "iptables":
            args = command(record, False)
            args[2] = "-C"
            return run(args, query=True).returncode == 0
        return bool(matching_nft(record))

    if mode == "restore":
        for record in json.loads(restore.read_text()):
            if not exists(record):
                run(command(record, True))
        sys.exit()

    old = json.loads(ledger.read_text()) if ledger.exists() else []
    new = []
    marker = context.require("FW_MARK")
    journal = pathlib.Path(context.require("TEMP")) / "firewall.undo"
    if journal.exists():
        for line in journal.read_text().splitlines():
            args = line.split()
            record = {"backend": args[0], "marker": marker}
            if args[0] == "ufw":
                port, proto = args[1].split("/")
            elif args[0] == "firewalld":
                record.update(mode=args[1], zone=args[2])
                port, proto = args[3].split("/")
            else:
                proto, port = args[1:]
            record.update(proto=proto, port=int(port))
            new.append(record)
    if context.require("FW_NFT") == "1":
        rules = json.loads(run(["nft", "-j", "list", "ruleset"]).stdout)["nftables"]
        for item in rules:
            r = item.get("rule", {})
            if r.get("comment") != marker:
                continue
            for expr in r.get("expr", []):
                match = expr.get("match", {})
                payload = match.get("left", {}).get("payload", {})
                if (
                    payload.get("protocol") in ("tcp", "udp")
                    and payload.get("field") == "dport"
                    and type(match.get("right")) is int
                ):
                    new.append(
                        {
                            "backend": "nft",
                            "marker": marker,
                            "family": r["family"],
                            "table": r["table"],
                            "chain": r["chain"],
                            "proto": payload["protocol"],
                            "port": match["right"],
                        }
                    )
                    break
            else:
                sys.exit("无法识别本次新增的 nftables 端口规则。")
    retired = set()
    legacy = len(sys.argv) in (3, 4, 5, 6)
    if legacy or context.get("FW_PREVIOUS_ENDPOINTS"):
        current = set()
        previous = set()
        if context.get("FW_CONFIG_ENDPOINTS"):
            current = {
                (parts[0], int(parts[1]))
                for line in context.require("FW_CONFIG_ENDPOINTS").splitlines()
                if len(parts := line.split()) >= 2
            }
        else:
            for proto, key in (
                (context.get("VLESS_NETWORK") or "tcp", "VLESS_PORT"),
                ("udp", "HY2_PORT"),
                ("tcp", "ANYTLS_PORT"),
                ("udp", "TUIC_PORT"),
            ):
                if context.get(key):
                    current.add((proto, int(context.require(key))))
        if legacy:
            for proto, value in (
                (sys.argv[5] if len(sys.argv) == 6 else "tcp", sys.argv[1]),
                ("udp", sys.argv[2]),
                ("tcp", sys.argv[3] if len(sys.argv) >= 4 else ""),
                ("udp", sys.argv[4] if len(sys.argv) >= 5 else ""),
            ):
                if value:
                    previous.add((proto, int(value)))
        previous.update(
            (parts[0], int(parts[1]))
            for line in context.get("FW_PREVIOUS_ENDPOINTS", "").splitlines()
            if len(parts := line.split()) >= 2
        )
        retired = previous - current
        if not ledger.exists() and retired:
            print(
                "提示：旧部署没有防火墙归属记录，已有旧端口规则将保留，请自行确认。",
                file=sys.stderr,
            )
    known_markers = {r["marker"] for r in old + new}

    def leading_owned(record):
        backend = record["backend"]
        if backend == "firewalld":
            return
        if backend == "ufw":
            import re

            rows = [
                line
                for line in run(["ufw", "status", "numbered"]).stdout.splitlines()
                if re.match(r"^\[\s*\d+\]", line)
                and "(v6)" not in line
                and re.search(r"\sIN\s", line)
            ]
            for line in rows:
                if record["marker"] in line and f"{record['port']}/{record['proto']}" in line:
                    return
                if re.search(r"\sALLOW\s+IN\s", line) and line.rstrip().endswith(
                    context.require("FW_SSH_MARK")
                ):
                    continue  # The SSH ACCEPT safeguard may precede unrelated node ACCEPT rules.
                if not any(marker in line for marker in known_markers):
                    break
        elif backend == "iptables":
            import shlex

            for line in run(["iptables", "-w", "-S", "INPUT"]).stdout.splitlines():
                args = shlex.split(line)
                if args[:2] != ["-A", "INPUT"]:
                    continue
                marker = args[args.index("--comment") + 1] if "--comment" in args else ""
                if (
                    marker == record["marker"]
                    and "-p" in args
                    and args[args.index("-p") + 1] == record["proto"]
                    and "--dport" in args
                    and args[args.index("--dport") + 1] == str(record["port"])
                ):
                    return
                if marker not in known_markers:
                    break
        else:
            matches = {r["handle"] for r in matching_nft(record)}
            for item in json.loads(run(["nft", "-j", "list", "ruleset"]).stdout)["nftables"]:
                r = item.get("rule", {})
                if any(r.get(k) != record[k] for k in ("family", "table", "chain")):
                    continue
                if r["handle"] in matches:
                    return
                if r.get("comment") not in known_markers:
                    break
        sys.exit("旧端口规则前存在非本脚本的规则，拒绝改变其顺序；请先手动清理该旧端口规则。")

    remaining = []
    removed = []
    for record in old:
        if mode != "remove-all" and (record["proto"], record["port"]) not in retired:
            remaining.append(record)
            continue
        if not exists(record):
            continue
        leading_owned(record)
        removed.append(record)
        save(restore, removed)
        if record["backend"] == "nft":
            for rule in matching_nft(record):
                run(
                    [
                        "nft",
                        "delete",
                        "rule",
                        record["family"],
                        record["table"],
                        record["chain"],
                        "handle",
                        str(rule["handle"]),
                    ]
                )
        else:
            run(command(record, False))
    save(ledger, remaining + new)


def nft_handles():
    import json
    import sys

    from sb_deploy.context import context

    for item in json.load(sys.stdin)["nftables"]:
        r = item.get("rule", {})
        if r.get("comment") == context.require("FW_MARK"):
            print(r["family"], r["table"], r["chain"], r["handle"])


def nft_chains():
    import json
    import re
    import sys

    for item in json.load(sys.stdin)["nftables"]:
        c = item.get("chain", {})
        if c.get("family") in ("ip", "inet") and c.get("hook") == "input":
            names = [c["family"], c["table"], c["name"]]
            if not all(re.fullmatch(r"[a-zA-Z0-9_.-]+", v) for v in names):
                sys.exit("Unsupported nftables identifier; configure this firewall manually.")
            if c.get("type") != "filter":
                sys.exit("Unsupported nftables input chain type.")
            print(" ".join(names))


def ufw_missing():
    import re
    import sys

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
        match = re.match(
            r"^\[\s*\d+\]\s+(.*?)\s{2,}(ALLOW|DENY|REJECT|LIMIT) IN\s+(.*)$", line.strip()
        )
        if match and "(v6)" not in match[1]:
            rules.append(match.groups())
    for entry in sys.argv[1:]:
        blocked = False
        for destination, action, source in rules:
            if (
                destination == entry
                and action in ("DENY", "REJECT", "LIMIT")
                and source.split(" #", 1)[0].strip() == "Anywhere"
            ):
                sys.exit(
                    f"UFW has a conflicting {action} rule for {entry}; update that policy before deploying."
                )
            if action in ("DENY", "REJECT", "LIMIT") and may_match(destination, entry):
                blocked = True
            if (
                destination == entry
                and action == "ALLOW"
                and source.split(" #", 1)[0].strip() == "Anywhere"
            ):
                if blocked:
                    sys.exit(
                        f"UFW allow {entry} follows a deny/reject/limit rule; reorder conflicting rules before deploying."
                    )
                break
        else:
            print(entry)
