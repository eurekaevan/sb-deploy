"""Hysteria2 hopping plans and owned NAT rule lifecycle."""


def set_base_port():
    import json
    import sys

    c = json.load(open(sys.argv[1]))
    c["base_port"] = int(sys.argv[3])
    open(sys.argv[2], "w").write(json.dumps(c, indent=2) + "\n")


def enabled():
    import json
    import sys

    print("yes" if json.load(open(sys.argv[1])).get("enabled") else "no")


def prepare():
    import json
    import pathlib
    import re
    import sys

    from sb_deploy.context import context

    root = pathlib.Path(sys.argv[1])
    e = context

    def ports(spec):
        result = set()
        if spec in ("", "0", "none"):
            return result
        for item in spec.split(","):
            match = re.fullmatch(r"\s*([0-9]{1,5})(?:[:-]([0-9]{1,5}))?\s*", item)
            if not match:
                sys.exit("端口格式无效，示例：20000:20100,30000。")
            a, b = int(match[1]), int(match[2] or match[1])
            if not 1 <= a <= b <= 65535:
                sys.exit("端口必须在 1–65535，且区间起点不大于终点。")
            result.update(range(a, b + 1))
        return result

    def compact(values):
        runs = []
        for port in sorted(values):
            if runs and port == runs[-1][1] + 1:
                runs[-1][1] = port
            else:
                runs.append([port, port])
        return [str(a) if a == b else f"{a}:{b}" for a, b in runs]

    selected = ports(e["HOP_SPEC"])
    busy = set()
    base = int(e["HY2_PORT"])
    for line in (root / "occupied.txt").read_text().splitlines():
        fields = line.split()
        if len(fields) < 5 or fields[0] not in ("udp", "tcp"):
            continue
        match = re.search(r":([0-9]+)$", fields[4])
        if not match or fields[0] != "udp":
            continue
        port = int(match[1])
        if port == base and '"sing-box"' in line:
            continue
        busy.add(port)
    exclude = busy if e["HOP_EXCLUDE"] == "auto" else ports(e["HOP_EXCLUDE"])
    result = selected - exclude
    conflicts = result & busy
    if conflicts:
        sys.exit("仍有 UDP 占用端口，请选择排除：" + ",".join(compact(conflicts)))
    if selected and not result:
        sys.exit("排除后没有可用的跳跃端口。")
    if selected and len(result) < 2:
        sys.exit("端口跳跃至少需要两个可用端口。")
    interval = e["HOP_INTERVAL"]
    duration = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)(ms|s|m|h)", interval)
    if (
        not duration
        or float(duration[1]) * {"ms": 0.001, "s": 1, "m": 60, "h": 3600}[duration[2]] < 5
    ):
        sys.exit("跳跃间隔至少 5 秒，例如 30s、1m。")
    plan = {
        "version": 1,
        "enabled": bool(result),
        "backend": e["HOP_BACKEND"],
        "base_port": base,
        "ports": compact(result),
        "hop_interval": interval,
    }
    (root / "hopping-plan.json").write_text(json.dumps(plan, indent=2) + "\n")
    if selected:
        print("最终 UDP 跳跃端口：" + ",".join(plan["ports"]))
        print("已排除：" + (",".join(compact(selected & exclude)) or "无"))


def plan_enabled():
    import json
    import sys

    print("yes" if json.load(open(sys.argv[1]))["enabled"] else "no")


def runtime():
    import json
    import os
    import pathlib
    import re
    import subprocess
    import sys

    path = pathlib.Path(sys.argv[1])
    action = sys.argv[2]
    if not path.exists():
        if action == "stop":
            sys.exit()
        sys.exit("没有端口跳跃配置。")
    c = json.loads(path.read_text())
    if (
        c.get("version") != 1
        or c.get("backend") not in ("nft", "iptables")
        or type(c.get("enabled")) is not bool
        or type(c.get("base_port")) is not int
        or not 1 <= c["base_port"] <= 65535
        or not isinstance(c.get("ports"), list)
    ):
        sys.exit("端口跳跃配置格式无效。")
    ranges = []
    for item in c["ports"]:
        if not isinstance(item, str) or not re.fullmatch(r"[0-9]{1,5}(?::[0-9]{1,5})?", item):
            sys.exit("跳跃端口格式无效。")
        parts = item.split(":")
        a, b = int(parts[0]), int(parts[-1])
        if not 1 <= a <= b <= 65535:
            sys.exit("跳跃端口越界。")
        # The primary listener already receives this port without redirect.
        if a <= c["base_port"] <= b:
            if a < c["base_port"]:
                ranges.append((a, c["base_port"] - 1))
            if c["base_port"] < b:
                ranges.append((c["base_port"] + 1, b))
        else:
            ranges.append((a, b))
    if c["enabled"] and not c["ports"]:
        sys.exit("跳跃端口不能为空。")
    duration = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)(ms|s|m|h)", str(c.get("hop_interval", "")))
    if (
        not duration
        or float(duration[1]) * {"ms": 0.001, "s": 1, "m": 60, "h": 3600}[duration[2]] < 5
    ):
        sys.exit("跳跃间隔至少 5 秒。")
    if c["enabled"] and action in ("start", "validate") and pathlib.Path(sys.argv[3]).exists():
        config = json.loads(pathlib.Path(sys.argv[3]).read_text())
        for item in config.get("inbounds", []):
            kind = item.get("type") or item.get("tag")
            if kind == "hysteria2" and item.get("listen_port") == c["base_port"]:
                continue
            if (
                kind in ("tuic", "hysteria", "hysteria2")
                or item.get("network") == "udp"
                or (kind in ("direct", "shadowsocks") and not item.get("network"))
                or (item.get("transport") or {}).get("type") == "quic"
            ):
                port = item.get("listen_port")
                if type(port) is int and any(a <= port <= b for a, b in ranges):
                    sys.exit(f"{kind} UDP/{port} 与 HY2 跳跃端口冲突，请先从跳跃范围排除该端口。")
    if action not in ("start", "stop", "validate"):
        sys.exit("未知跳跃规则操作。")
    if action == "validate" or not c["enabled"]:
        sys.exit()

    def run(args, **kwargs):
        r = subprocess.run(
            args,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={**os.environ, "LC_ALL": "C"},
            **kwargs,
        )
        if r.returncode:
            sys.stderr.write(r.stderr)
            sys.exit("端口跳跃规则操作失败：" + args[0])
        return r.stdout

    marker = "sing-box-deploy-hopping"
    table = "sing_box_hy2_hop"
    chain = "SB_HY2_HOP"
    if c["backend"] == "nft":
        tables = json.loads(run(["nft", "-j", "list", "tables"]))["nftables"]
        present = any(
            t.get("table", {}).get("family") == "ip" and t.get("table", {}).get("name") == table
            for t in tables
        )
        if present:
            data = json.loads(run(["nft", "-j", "list", "table", "ip", table]))["nftables"]
            if not any(t.get("table", {}).get("comment") == marker for t in data):
                sys.exit("同名 nftables 表不属于本脚本，拒绝覆盖。")
        batch = f"delete table ip {table}\n" if present else ""
        if action == "start" and c["enabled"] and ranges:
            ports = ", ".join(str(a) if a == b else f"{a}-{b}" for a, b in ranges)
            batch += f'table ip {table} {{\n comment "{marker}"\n chain prerouting {{\n type nat hook prerouting priority dstnat; policy accept;\n fib daddr type local udp dport {{ {ports} }} redirect to :{c["base_port"]} comment "{marker}"\n }}\n}}\n'
        if batch:
            run(["nft", "-f", "-"], input=batch)
    else:
        import shlex

        listing = run(["iptables", "-w", "-t", "nat", "-S"])
        jump = [
            "PREROUTING",
            "-p",
            "udp",
            "-m",
            "addrtype",
            "--dst-type",
            "LOCAL",
            "-m",
            "comment",
            "--comment",
            marker,
            "-j",
            chain,
        ]
        owned = any(shlex.split(line) == ["-A", *jump] for line in listing.splitlines())
        present = any(shlex.split(line) == ["-N", chain] for line in listing.splitlines())
        if present and not owned:
            sys.exit("同名 iptables 链不属于本脚本，拒绝覆盖。")
        if owned:
            run(["iptables", "-w", "-t", "nat", "-D", *jump])
            run(["iptables", "-w", "-t", "nat", "-F", chain])
            run(["iptables", "-w", "-t", "nat", "-X", chain])
        if action == "start" and c["enabled"] and ranges:
            run(["iptables", "-w", "-t", "nat", "-N", chain])
            try:
                # Establish ownership before filling this private chain.
                run(["iptables", "-w", "-t", "nat", "-I", *jump])
                for a, b in ranges:
                    spec = str(a) if a == b else f"{a}:{b}"
                    run(
                        [
                            "iptables",
                            "-w",
                            "-t",
                            "nat",
                            "-A",
                            chain,
                            "-p",
                            "udp",
                            "--dport",
                            spec,
                            "-j",
                            "REDIRECT",
                            "--to-ports",
                            str(c["base_port"]),
                        ]
                    )
            except SystemExit:
                # This is the chain created above, never a shared firewall chain.
                subprocess.run(
                    ["iptables", "-w", "-t", "nat", "-D", *jump],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                subprocess.run(["iptables", "-w", "-t", "nat", "-F", chain])
                subprocess.run(["iptables", "-w", "-t", "nat", "-X", chain])
                raise
