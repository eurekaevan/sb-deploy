"""Config-driven protocol editing and client exports."""


def proxy_name(outbound):
    if outbound.get("type") == "socks":
        return "SOCKS5"
    if outbound.get("type") == "http":
        return "HTTPS" if (outbound.get("tls") or {}).get("enabled") else "HTTP"
    return None


def run():
    import copy
    import hashlib
    import ipaddress
    import json
    import math
    import os
    import pathlib
    import re
    import ssl
    import sys
    import tempfile
    import uuid

    p = pathlib.Path(os.environ["CONFIG"])
    app = pathlib.Path(os.environ["APP"])
    action = sys.argv[1]
    if action == "running-summary":
        state_path = app / "runtime-state.json"
        if not state_path.exists():
            sys.exit(1)
        state = json.loads(state_path.read_text())
        if not sys.argv[2] or state.get("identity") != sys.argv[2]:
            sys.exit(1)
        print("服务：运行中    版本：" + state["version"])
        print(state["summary"])
        sys.exit()
    if not p.exists():
        sys.exit("请先安装节点。")
    c = json.loads(p.read_text())
    original = copy.deepcopy(c) if action == "validate" else None

    def inbound(tag):
        kind = "vless" if tag == "vless-reality" else tag
        values = [item for item in c["inbounds"] if item.get("type") == kind]
        if not values:
            values = [
                item for item in c["inbounds"] if not item.get("type") and item.get("tag") == tag
            ]
        if len(values) > 1:
            sys.exit(f"配置中应存在且仅存在一个入站：{kind}")
        return values[0] if values else None

    def new_inbound_tag(kind):
        used = {i.get("tag") for i in c.get("inbounds", [])}
        result = kind
        index = 1
        while result in used:
            result = f"{kind}-{index}"
            index += 1
        return result

    def listener_conflict(left, right):
        if not left or not right:
            return False

        def networks(item):
            if (item.get("transport") or {}).get("type") == "quic":
                return {"udp"}
            if item.get("network"):
                return {item["network"]}
            if item.get("type") in ("direct", "shadowsocks"):
                return {"tcp", "udp"}
            return {"udp" if item.get("type") in ("hysteria", "hysteria2", "tuic") else "tcp"}

        if not networks(left) & networks(right):
            return False
        if left.get("listen_port") != right.get("listen_port"):
            return False
        a, b = left.get("listen", "::"), right.get("listen", "::")
        if a == b or "::" in (a, b):
            return True
        return ("0.0.0.0" in (a, b)) and ":" not in a and ":" not in b

    def atomic(path, text):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if path.is_symlink():
            sys.exit(f"拒绝覆盖符号链接：{path}")
        with tempfile.NamedTemporaryFile(
            mode="w", dir=path.parent, prefix=".node-", delete=False
        ) as f:
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
        atomic(path, json.dumps(obj, indent=2, ensure_ascii=False) + "\n")

    if action == "log-level":
        levels = ("trace", "debug", "info", "warn", "error", "fatal", "panic")
        level = sys.argv[2] if len(sys.argv) > 2 else os.environ.get("LOG_LEVEL", "warn")
        if level not in levels:
            sys.exit("日志级别必须是 trace、debug、info、warn、error、fatal 或 panic。")
        if (c.get("log") or {}).get("level") == level:
            print("unchanged")
            sys.exit()
        c.setdefault("log", {})["level"] = level
        write_json(p, c)
        print(level)
        sys.exit()

    if action in ("menu-inbounds", "menu-inbound", "menu-fields", "hopping-port", "inbound-label"):

        def emit(label, command):
            sys.stdout.write(label + "\0" + command + "\0")

        def pointer_key(key):
            return str(key).replace("~", "~0").replace("/", "~1")

        if action == "menu-inbounds":
            for index, item in enumerate(c.get("inbounds", [])):
                identifier = item.get("tag") or "@" + str(index)
                emit(item.get("type", "未知") + " · " + identifier, "inbound:@" + str(index))
            sys.exit()
        selector = sys.argv[2]
        values = [
            item for index, item in enumerate(c.get("inbounds", [])) if "@" + str(index) == selector
        ]
        if not values:
            values = [item for item in c.get("inbounds", []) if item.get("tag") == selector]
        if len(values) != 1:
            sys.exit("请选择唯一的现有入站标签。")
        item = values[0]
        if action == "inbound-label":
            print(item.get("type", "未知") + " · " + (item.get("tag") or selector))
            sys.exit()
        if action == "hopping-port":
            if item.get("type") != "hysteria2":
                sys.exit("端口跳跃仅适用于 HY2 入站。")
            print(item["listen_port"])
            sys.exit()
        if action == "menu-inbound":
            emit("完整编辑入站 JSON", "edit-current")
            emit("逐项修改字段 / 开关", "group:")
            emit("添加可选字段（JSON Pointer）", "add-field")
            if "listen_port" in item:
                emit("修改监听端口", "field:/listen_port")
            if item.get("type") == "hysteria2":
                # Hopping is implemented by the owned redirect service, not an inbound field.
                hop = app / "hopping.json"
                state = json.loads(hop.read_text()) if hop.exists() else {}
                enabled = state.get("enabled", False)
                owned = enabled and state.get("base_port") == item.get("listen_port")
                emit(
                    "端口跳跃 · "
                    + ("开启" if owned else "由其他 HY2 入站使用" if enabled else "关闭"),
                    "hopping",
                )
                if owned:
                    emit("关闭端口跳跃", "disable-hopping")
            sys.exit()
        pointer = sys.argv[3]
        value = item
        if pointer:
            for key in pointer[1:].split("/"):
                key = key.replace("~1", "/").replace("~0", "~")
                value = value[int(key)] if isinstance(value, list) else value[key]
        entries = (
            enumerate(value)
            if isinstance(value, list)
            else value.items()
            if isinstance(value, dict)
            else []
        )
        for key, child in entries:
            path = pointer + "/" + pointer_key(key)
            if isinstance(child, (dict, list)):
                emit(str(key) + " · " + str(len(child)) + " 项", "group:" + path)
            else:
                state = (
                    ("开启" if child else "关闭")
                    if isinstance(child, bool)
                    else "null"
                    if child is None
                    else "数值"
                    if isinstance(child, (int, float))
                    else "文本"
                )
                emit(
                    str(key) + " · " + state,
                    ("switch:" if isinstance(child, bool) else "field:") + path,
                )
        if pointer:
            emit("移除此字段（恢复内核默认或停用可选功能）", "remove:" + pointer)
        sys.exit()

    if action == "inbound-types":
        print("\n".join(dict.fromkeys(i.get("type", "") for i in c.get("inbounds", []))))
        sys.exit()

    if action == "editable-protocols":
        for index, item in enumerate(c.get("inbounds", [])):
            identifier = item.get("tag") or "@" + str(index)
            sys.stdout.write(
                identifier + "\0" + item.get("type", "未知") + " / " + identifier + "\0"
            )
        sys.exit()

    if action in ("extract-inbound", "replace-inbound"):
        selector = sys.argv[2]
        matches = [
            (index, item)
            for index, item in enumerate(c.get("inbounds", []))
            if "@" + str(index) == selector
        ]
        if not matches:
            matches = [
                (index, item)
                for index, item in enumerate(c.get("inbounds", []))
                if item.get("tag") == selector
            ]
        if not matches:
            matches = [
                (index, item)
                for index, item in enumerate(c.get("inbounds", []))
                if item.get("type") == selector
            ]
        if len(matches) != 1:
            sys.exit("请选择唯一的现有入站标签。")
        index, old = matches[0]
        if action == "extract-inbound":
            print(json.dumps(old, indent=2, ensure_ascii=False))
            sys.exit()
        candidate = json.loads(pathlib.Path(sys.argv[3]).read_text())
        if not isinstance(candidate, dict) or candidate.get("type") != old.get("type"):
            sys.exit("请保留协议类型；新增其他协议请使用生成协议菜单。")
        live = pathlib.Path(os.environ.get("LIVE_APP") or str(app))
        for key in ("certificate_path", "key_path"):
            tls = candidate.get("tls") or {}
            if key not in tls:
                continue
            try:
                relative = pathlib.Path(tls[key]).relative_to(live / "tls")
            except ValueError:
                continue
            tls[key] = str(app / "tls" / relative)
        if candidate == old:
            print("unchanged")
            sys.exit()
        tag = candidate.get("tag")
        if tag and any(
            i != index and item.get("tag") == tag for i, item in enumerate(c["inbounds"])
        ):
            sys.exit("入站标签重复。")
        if candidate.get("type") in ("hysteria2", "tuic", "vless", "anytls"):
            if (
                type(candidate.get("listen_port")) is not int
                or not 1 <= candidate["listen_port"] <= 65535
            ):
                sys.exit("监听端口必须是 1-65535 的整数。")
            for i, item in enumerate(c["inbounds"]):
                if i != index and listener_conflict(item, candidate):
                    sys.exit("同类传输协议监听地址与端口冲突。")
        c["inbounds"][index] = candidate
        if old.get("tag") and tag and old["tag"] != tag:

            def rename_rules(rules):
                for rule in rules:
                    if "inbound" in rule:
                        value = rule["inbound"]
                        rule["inbound"] = (
                            [tag if x == old["tag"] else x for x in value]
                            if isinstance(value, list)
                            else tag
                            if value == old["tag"]
                            else value
                        )
                    rename_rules(rule.get("rules", []))

            rename_rules(c.get("route", {}).get("rules", []))
            rename_rules(c.get("dns", {}).get("rules", []))
        write_json(p, c)
        hop_path = app / "hopping.json"
        if candidate.get("type") == "hysteria2" and hop_path.exists():
            hop = json.loads(hop_path.read_text())
            if hop["base_port"] == old.get("listen_port"):
                hop["base_port"] = candidate["listen_port"]
                write_json(hop_path, hop)
        print("changed")
        sys.exit()

    if action == "managed-sni-change":
        old = json.loads(pathlib.Path(sys.argv[2]).read_text())
        kind = old.get("type")
        if kind not in ("hysteria2", "anytls", "tuic"):
            sys.exit()
        values = [i for i in c["inbounds"] if i.get("type") == kind]
        if len(values) != 1:
            sys.exit()
        new = values[0]
        before = old.get("tls") or {}
        after = new.get("tls") or {}
        stem = "hy2" if kind == "hysteria2" else kind
        if (
            before.get("server_name") != after.get("server_name")
            and after.get("server_name")
            and not after.get("certificate")
        ):
            if all(
                before.get(key) == after.get(key) == str(app / "tls" / (stem + suffix))
                for key, suffix in [("certificate_path", ".crt"), ("key_path", ".key")]
            ):
                sys.stdout.write(stem + "\0" + after["server_name"] + "\0")
        sys.exit()

    if action == "defaults":
        optional_quic = (
            "initial_packet_size",
            "disable_path_mtu_discovery",
            "idle_timeout",
            "keep_alive_period",
            "stream_receive_window",
            "connection_receive_window",
            "max_concurrent_streams",
        )
        for item in c.get("inbounds", []):
            if item.get("type") not in ("vless", "hysteria2", "anytls", "tuic"):
                continue
            if isinstance(item.get("tls"), dict):
                item["tls"]["handshake_timeout"] = os.environ["DEFAULT_TLS_HANDSHAKE_TIMEOUT"]
            if item["type"] == "hysteria2":
                item.update(ignore_client_bandwidth=True, bbr_profile="standard")
                for field in optional_quic:
                    item.pop(field, None)
            elif item["type"] == "tuic":
                for field in optional_quic:
                    item.pop(field, None)
                item.update(
                    congestion_control="bbr",
                    auth_timeout="3s",
                    zero_rtt_handshake=False,
                    heartbeat="10s",
                    disable_path_mtu_discovery=False,
                )
        write_json(p, c)
        sys.exit()

    if action in ("summary", "record-runtime", "protocols"):
        labels = {"vless": "VLESS", "hysteria2": "Hysteria2", "anytls": "AnyTLS", "tuic": "TUIC"}
        if action == "protocols":
            for item in c.get("inbounds", []):
                kind = item.get("type")
                if kind in labels:
                    sys.stdout.write(kind + "\0" + labels[kind] + "\0")
            sys.exit()
        transports = {"vless": "TCP", "hysteria2": "UDP", "anytls": "TCP", "tuic": "UDP"}
        lines = []
        ports = []
        for item in c.get("inbounds", []):
            kind = item.get("type", item.get("tag", "未知协议"))
            label = labels.get(kind, item.get("tag", kind))
            network = (
                "UDP"
                if (item.get("transport") or {}).get("type") == "quic"
                else item.get("network")
                or (
                    "TCP/UDP" if kind in ("direct", "shadowsocks") else transports.get(kind, "端口")
                )
            )
            if "listen_port" in item:
                ports.append(f"{label}：{network.upper()} {item['listen_port']}")
        lines.append("    ".join(ports) or "未配置监听协议")
        for item in c.get("inbounds", []):
            if item.get("type") == "hysteria2" and "bbr_profile" in item:
                lines.append("Hysteria2 BBR：" + item["bbr_profile"])
        hop_path = app / "hopping.json"
        if hop_path.exists():
            hop = json.loads(hop_path.read_text())
            if hop.get("enabled"):
                lines.append(
                    "HY2 跳跃：" + ",".join(hop["ports"]) + "，间隔 " + hop["hop_interval"]
                )
        outbounds = {o.get("tag"): o for o in c.get("outbounds", [])}
        route = c.get("route", {})
        groups = []
        for rule in route.get("rules", []):
            if rule.get("action") != "route" or not rule.get("outbound"):
                continue
            sets = rule.get("rule_set", [])
            if isinstance(sets, str):
                sets = [sets]
            label = (
                "Google"
                if set(sets) & {"google", "youtube"}
                else "AI"
                if "ai" in sets
                else " / ".join(sets) or "条件规则"
            )
            groups.append((label, rule["outbound"]))
        groups.append(("其他", route.get("final", "未指定")))
        if [label for label, _ in groups] == ["Google", "AI", "其他"] and all(
            proxy_name(outbounds.get(tag, {})) in ("SOCKS5", "HTTPS") for _, tag in groups
        ):
            profiles = {
                (
                    proxy_name(outbounds[tag]),
                    (outbounds[tag].get("tls") or {}).get("server_name"),
                    outbounds[tag].get("server"),
                    outbounds[tag].get("server_port"),
                    outbounds[tag].get("username"),
                    outbounds[tag].get("password"),
                )
                for _, tag in groups
            }
            count = len(profiles)
            protocols = " / ".join(dict.fromkeys(proxy_name(outbounds[tag]) for _, tag in groups))
            lines.append(
                "分流：Google / AI / 其他 → "
                + (
                    f"{count} 组独立 {protocols}"
                    if count == len(groups)
                    else f"共用 {count} 组 {protocols}"
                )
            )
        for label, tag in groups:
            outbound = outbounds.get(tag, {})
            endpoint = (
                f"{proxy_name(outbound)} {outbound.get('server', '?')}:{outbound.get('server_port', '?')}"
                if proxy_name(outbound)
                else str(tag)
            )
            lines.append(f"{label} → {endpoint}")
        summary_text = "\n".join(lines)
        if action == "record-runtime":
            atomic(
                app / "runtime-state.json",
                json.dumps(
                    {"identity": sys.argv[2], "version": sys.argv[3], "summary": summary_text},
                    ensure_ascii=False,
                )
                + "\n",
            )
        else:
            print(summary_text)
        sys.exit()

    if action in ("socks", "proxy"):
        found = [o for o in c["outbounds"] if o.get("tag") == sys.argv[2] + "-socks"]
        if len(found) > 1:
            sys.exit("代理出站标签重复。")
        o = found[0] if found else {}
        if o and proxy_name(o) not in ("SOCKS5", "HTTPS"):
            sys.exit("该出口不是 SOCKS5 或 HTTPS；请先确认 config.json 中的出口配置。")
        for key in ("server", "server_port", "username", "password"):
            sys.stdout.write(str(o.get(key, "")) + "\0")
        if action == "proxy":
            tls = o.get("tls") or {}
            values = [
                "https" if proxy_name(o) == "HTTPS" else "socks5" if o else "",
                tls.get("server_name", ""),
                json.dumps(tls, ensure_ascii=False),
                json.dumps(
                    {key: o[key] for key in ("path", "headers", "version") if key in o}
                    if o.get("type") == "http"
                    else {},
                    ensure_ascii=False,
                ),
            ]
            for value in values:
                sys.stdout.write(value + "\0")
        sys.stdout.write("READY\0")
        sys.exit()

    def export_clients():
        import base64
        import subprocess
        from urllib.parse import quote, urlencode

        client_dir = app / "client"
        records = []
        proxies = []
        notes = []
        hop_path = app / "hopping.json"
        hop = json.loads(hop_path.read_text()) if hop_path.exists() else {"enabled": False}

        def unavailable(message):
            sys.stderr.write(message + "\n")
            sys.exit(3)

        def certificate(item):
            tls = item.get("tls") or {}
            if tls.get("client_authentication") or (tls.get("ech") or {}).get("enabled"):
                unavailable("自定义 mTLS/ECH 需要手动补全客户端配置。")
            if not tls.get("server_name"):
                unavailable("未指定证书对应的 SNI，请手动配置客户端。")
            if tls.get("certificate_path"):
                return pathlib.Path(tls["certificate_path"]).read_text()
            if tls.get("certificate"):
                value = tls["certificate"]
                return "\n".join(value) if isinstance(value, list) else value
            unavailable("动态证书尚不可用于自动固定校验，请手动配置客户端。")

        def pin(cert):
            leaf = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", cert, re.S)
            if not leaf:
                sys.exit("证书内容无效。")
            return hashlib.sha256(ssl.PEM_cert_to_DER_cert(leaf[0])).hexdigest()

        labels = {
            "vless": ("vless-reality", "VLESS-Reality"),
            "hysteria2": ("hysteria2", "Hysteria2"),
            "anytls": ("anytls", "AnyTLS"),
            "tuic": ("tuic", "TUIC"),
        }
        for kind, (filename, label) in labels.items():
            items = [i for i in c.get("inbounds", []) if i.get("type") == kind]
            if not items:
                continue
            if len(items) > 1:
                unavailable(kind + " 存在多个入站，自动资料请分别手动配置客户端。")
            item = items[0]
            tls = item.get("tls") or {}
            users = item.get("users") or []
            if not users:
                unavailable("该入站没有可自动导出的用户，请手动配置客户端。")
            user = users[0]
            server = os.environ.get("SERVER_IP") or item.get("listen", "")
            if server in ("", "::", "0.0.0.0"):
                unavailable("配置仅提供通配监听地址；请用 SERVER_IP=公网地址 导出客户端资料。")
            try:
                ipaddress.ip_address(server)
            except ValueError:
                if not re.fullmatch(r"[a-zA-Z0-9.-]+", server):
                    unavailable("客户端服务器地址无效，请设置 SERVER_IP。")
            authority = "[" + server + "]" if ":" in server else server
            client = {
                "type": kind,
                "tag": filename,
                "server": server,
                "server_port": item["listen_port"],
            }
            client_tls = {"enabled": True, "server_name": tls.get("server_name", "")}
            for key in (
                "handshake_timeout",
                "alpn",
                "min_version",
                "max_version",
                "cipher_suites",
                "curve_preferences",
            ):
                if key in tls:
                    client_tls[key] = copy.deepcopy(tls[key])
            client_tls.setdefault("handshake_timeout", os.environ["DEFAULT_TLS_HANDSHAKE_TIMEOUT"])
            client["tls"] = client_tls
            proxy = {"name": label, "type": kind, "server": server, "port": item["listen_port"]}
            cert = ""
            fingerprint = ""
            extra = ""
            if kind == "vless":
                reality = tls.get("reality") or {}
                if (
                    not reality.get("enabled")
                    or item.get("transport")
                    or tls.get("client_authentication")
                    or (tls.get("ech") or {}).get("enabled")
                ):
                    unavailable(
                        "该 VLESS 高级 TLS/传输组合需手动配置客户端；服务端配置可正常应用。"
                    )
                try:
                    raw = base64.urlsafe_b64decode(
                        reality["private_key"] + "=" * (-len(reality["private_key"]) % 4)
                    )
                    if len(raw) != 32:
                        raise ValueError("长度不是 32 字节")
                except (ValueError, KeyError) as error:
                    unavailable("Reality 私钥无效，无法推导公钥：" + str(error))
                try:
                    result = subprocess.run(
                        ["openssl", "pkey", "-inform", "DER", "-pubout", "-outform", "DER"],
                        input=bytes.fromhex("302e020100300506032b656e04220420") + raw,
                        capture_output=True,
                    )
                except OSError:
                    unavailable(
                        "客户端资料需要 openssl 推导 Reality 公钥；服务端配置仍可正常应用。"
                    )
                if result.returncode:
                    unavailable("无法由配置中的 Reality 私钥推导公钥。")
                public = base64.urlsafe_b64encode(result.stdout[-32:]).decode().rstrip("=")
                ids = reality.get("short_id", [])
                short_id = ids if isinstance(ids, str) else next(iter(ids), "")
                client.update(uuid=user["uuid"], flow=user.get("flow") or "")
                client_tls.update(
                    server_name=tls.get("server_name")
                    or (reality.get("handshake") or {}).get("server", ""),
                    utls={"enabled": True, "fingerprint": "chrome"},
                    reality={"enabled": True, "public_key": public, "short_id": short_id},
                )
                proxy.update(
                    uuid=client["uuid"],
                    udp=True,
                    network="tcp",
                    tls=True,
                    flow=client["flow"],
                    **{
                        "packet-encoding": "xudp",
                        "servername": client_tls["server_name"],
                        "client-fingerprint": "chrome",
                        "reality-opts": {"public-key": public, "short-id": short_id},
                    },
                )
                uri = (
                    "vless://"
                    + client["uuid"]
                    + "@"
                    + authority
                    + ":"
                    + str(item["listen_port"])
                    + "?"
                    + urlencode(
                        {
                            "encryption": "none",
                            "flow": client["flow"],
                            "security": "reality",
                            "sni": client_tls["server_name"],
                            "fp": "chrome",
                            "pbk": public,
                            "sid": short_id,
                            "type": "tcp",
                        }
                    )
                    + "#VLESS-Reality"
                )
                detail = f"[VLESS Reality]\n地址：{server}   TCP 端口：{item['listen_port']}\nUUID: {client['uuid']}\nSNI: {client_tls['server_name']}\nReality Public Key: {public}\nShort ID: {short_id}\nVLESS URI: {uri}\n"
            else:
                cert = certificate(item)
                fingerprint = pin(cert)
                client_tls.update(insecure=False, certificate=cert)
                client["password"] = user.get("password", "")
                proxy.update(
                    password=client["password"],
                    sni=client_tls["server_name"],
                    **{"skip-cert-verify": False, "fingerprint": fingerprint},
                )
                port_text = str(item["listen_port"])
                if kind == "hysteria2":
                    client_tls.setdefault("alpn", ["h3"])
                    proxy["alpn"] = client_tls["alpn"]
                    params = {
                        "sni": client_tls["server_name"],
                        "insecure": "0",
                        "pinSHA256": fingerprint,
                    }
                    if item.get("obfs"):
                        client["obfs"] = copy.deepcopy(item["obfs"])
                        proxy.update(
                            obfs=item["obfs"]["type"], **{"obfs-password": item["obfs"]["password"]}
                        )
                        params.update(
                            obfs=item["obfs"]["type"], **{"obfs-password": item["obfs"]["password"]}
                        )
                    if hop.get("enabled") and hop.get("base_port") == item["listen_port"]:
                        client.pop("server_port")
                        client.update(server_ports=hop["ports"], hop_interval=hop["hop_interval"])
                        port_text = ",".join(hop["ports"]).replace(":", "-")
                        duration = re.fullmatch(
                            r"([0-9]+(?:\.[0-9]+)?)(ms|s|m|h)", hop["hop_interval"]
                        )
                        if not duration:
                            unavailable("跳跃间隔需手动换算客户端配置。")
                        seconds = (
                            float(duration[1])
                            * {"ms": 0.001, "s": 1, "m": 60, "h": 3600}[duration[2]]
                        )
                        proxy.update(ports=port_text, **{"hop-interval": math.ceil(seconds)})
                        if math.ceil(seconds) != seconds:
                            notes.append(
                                f"Mihomo 跳跃间隔仅支持整秒，已向上取整为 {math.ceil(seconds)} 秒；sing-box JSON 保留原间隔。"
                            )
                    uri = (
                        "hysteria2://"
                        + quote(client["password"], safe="")
                        + "@"
                        + authority
                        + ":"
                        + port_text
                        + "/?"
                        + urlencode(params)
                        + "#Hysteria2"
                    )
                    extra = f"客户端跳跃端口：{port_text}，间隔：{client.get('hop_interval', '不启用')}\nBBR profile: {item.get('bbr_profile', 'standard')}\nObfuscation: {client.get('obfs', {}).get('type', 'none')}\nObfuscation password: {client.get('obfs', {}).get('password', 'not configured')}\nHysteria2 URI: {uri}\n"
                elif kind == "anytls":
                    proxy.update(udp=True, **{"client-fingerprint": "chrome"})
                    uri = (
                        "anytls://"
                        + quote(client["password"], safe="")
                        + "@"
                        + authority
                        + ":"
                        + port_text
                        + "/?"
                        + urlencode({"sni": client_tls["server_name"], "insecure": "0"})
                        + "#AnyTLS"
                    )
                    extra = "AnyTLS URI: " + uri + "\n"
                else:
                    client.update(
                        uuid=user["uuid"],
                        congestion_control=item.get("congestion_control", "cubic"),
                        zero_rtt_handshake=item.get("zero_rtt_handshake", False),
                        heartbeat=item.get("heartbeat", "10s"),
                        udp_relay_mode="native",
                    )
                    duration = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)(ms|s|m|h)", client["heartbeat"])
                    if not duration:
                        unavailable("TUIC heartbeat 需手动换算为客户端配置。")
                    proxy.update(
                        uuid=client["uuid"],
                        udp=True,
                        **{
                            "congestion-controller": client["congestion_control"],
                            "heartbeat-interval": int(
                                float(duration[1])
                                * {"ms": 1, "s": 1000, "m": 60000, "h": 3600000}[duration[2]]
                            ),
                            "reduce-rtt": client["zero_rtt_handshake"],
                            "udp-relay-mode": "native",
                        },
                    )
                    if "alpn" in client_tls:
                        proxy["alpn"] = client_tls["alpn"]
                    uri = (
                        "tuic://"
                        + quote(client["uuid"], safe="")
                        + ":"
                        + quote(client["password"], safe="")
                        + "@"
                        + authority
                        + ":"
                        + port_text
                        + "/?"
                        + urlencode(
                            {
                                "sni": client_tls["server_name"],
                                "congestion_control": client["congestion_control"],
                                "alpn": ",".join(client_tls.get("alpn", [])),
                                "allow_insecure": "0",
                            }
                        )
                        + "#TUIC"
                    )
                    extra = f"UUID: {client['uuid']}\nTUIC URI: {uri}\n"
                detail = f"[{label}]\n地址：{server}   {'TCP 端口' if kind == 'anytls' else 'UDP 监听端口' if kind == 'hysteria2' else 'UDP 端口'}：{item['listen_port']}\nPassword: {client['password']}\nTLS SNI: {client_tls['server_name']}\n{extra}证书 SHA-256: {fingerprint}\nJSON 内嵌证书；YAML 使用证书指纹。分享链接需另行信任附带证书。\n"
            records.append((filename, client, uri, cert, detail))
            proxies.append(proxy)
            if len(users) > 1:
                notes.append(
                    "多用户入站：自动资料仅包含各协议第一个用户，其余用户请分别配置客户端。"
                )
        if not records:
            unavailable("当前入站没有支持自动生成的客户端资料；服务端配置仍可管理和应用。")

        def scalar(value):
            return "".join(
                f"\\u{ord(ch):04x}"
                if 0x7F <= ord(ch) <= 0x9F or ord(ch) in (0x2028, 0x2029)
                else ch
                for ch in json.dumps(value, ensure_ascii=False)
            )

        lines = ["proxies:"]
        for proxy in proxies:
            for index, (key, value) in enumerate(proxy.items()):
                prefix = "  - " if index == 0 else "    "
                if isinstance(value, dict):
                    lines.append(prefix + key + ":")
                    lines.extend("      " + k + ": " + scalar(v) for k, v in value.items())
                else:
                    lines.append(prefix + key + ": " + scalar(value))
        yaml = "\n".join(lines) + "\n"
        final = c.get("route", {}).get("final", "unspecified")
        if final == "other-socks":
            other = next((o for o in c["outbounds"] if o.get("tag") == final), {})
            final = "Other " + (proxy_name(other) or final)
        rejection = (
            "; private IPs rejected"
            if any(
                r.get("ip_is_private") and r.get("action") == "reject"
                for r in c.get("route", {}).get("rules", [])
            )
            else ""
        )
        summary = (
            "=== 节点连接资料（包含密码，请妥善保管） ===\n\n"
            + "\n".join(r[4] for r in records)
            + "\nEverything else: "
            + final
            + rejection
            + "\n上游代理密码不在此显示。\n"
            + "\n".join(notes)
            + "\n[Clash / Mihomo · proxies 配置]\n以下是当前配置；proxies.yaml 文件仅通过 export-yaml 手动导出或更新。\n"
            + yaml
        )
        if action == "yaml":
            print(yaml, end="")
            return
        if action == "json":
            print(json.dumps({"outbounds": [r[1] for r in records]}, indent=2, ensure_ascii=False))
            return
        if action == "show":
            colorful = (
                sys.stdout.isatty()
                and os.environ.get("TERM", "dumb") != "dumb"
                and "NO_COLOR" not in os.environ
            )
            in_yaml = False
            for line in summary.splitlines():
                in_yaml = in_yaml or line == "proxies:"
                color = ""
                if colorful and not in_yaml:
                    if line.startswith("==="):
                        color = "\033[1;33m"
                    elif line.startswith("["):
                        color = "\033[1;36m"
                    elif line.startswith(("地址：", "客户端跳跃端口：")):
                        color = "\033[1;32m"
                    elif line.startswith(
                        ("UUID:", "Password:", "Obfuscation password:", "Short ID:")
                    ):
                        color = "\033[1;33m"
                print(color + line + ("\033[0m" if color else ""))
            return
        if action == "export-yaml":
            atomic(client_dir / "proxies.yaml", yaml)
            return
        selected = (
            sys.argv[2].removeprefix("regenerate-")
            if len(sys.argv) > 2 and sys.argv[2].startswith("regenerate-")
            else ""
        )
        for filename, client, uri, cert, detail in records:
            if selected and client["type"] != selected:
                continue
            write_json(client_dir / (filename + ".outbound.json"), client)
            if cert:
                atomic(
                    client_dir
                    / ("hy2.crt" if client["type"] == "hysteria2" else filename + ".crt"),
                    cert,
                )
        atomic(client_dir / "node-info.txt", summary)
        atomic(client_dir / "nodes.txt", "\n".join(r[2] for r in records) + "\n")
        atomic(
            client_dir / "README.txt",
            "资料由 config.json 及其引用证书按需生成；不参与读取或修改服务端配置。\nproxies.yaml 仅通过 export-yaml 可选导出；JSON 为客户端 outbound 对象。\n自签证书需要客户端信任，YAML 使用证书 SHA-256 固定校验。\n",
        )

    if action in ("export", "show", "json", "yaml", "export-yaml"):
        export_clients()
        sys.exit()

    if action == "load":

        def first(kind):
            return next(
                (
                    i
                    for i in c.get("inbounds", [])
                    if i.get("type") == kind
                    or (
                        not i.get("type")
                        and i.get("tag") == ("vless-reality" if kind == "vless" else kind)
                    )
                ),
                {},
            )

        v, h, a, u = (first(kind) for kind in ("vless", "hysteria2", "anytls", "tuic"))

        def user(item, key):
            return (item.get("users") or [{}])[0].get(key, "")

        def tls(item):
            return item.get("tls") or {}

        hop_path = app / "hopping.json"
        hop = json.loads(hop_path.read_text()) if hop_path.exists() else {}
        values = {
            "VLESS_PORT": v.get("listen_port", ""),
            "HY2_PORT": h.get("listen_port", ""),
            "VLESS_NETWORK": "udp" if (v.get("transport") or {}).get("type") == "quic" else "tcp",
            "ANYTLS_PORT": a.get("listen_port", ""),
            "ANYTLS_SNI": tls(a).get("server_name", ""),
            "ANYTLS_PASS": user(a, "password"),
            "TUIC_PORT": u.get("listen_port", ""),
            "TUIC_SNI": tls(u).get("server_name", ""),
            "TUIC_UUID": user(u, "uuid"),
            "TUIC_PASS": user(u, "password"),
            "UUID": user(v, "uuid"),
            "REALITY_DOMAIN": ((tls(v).get("reality") or {}).get("handshake") or {}).get(
                "server", tls(v).get("server_name", "")
            ),
            "HY2_SNI": tls(h).get("server_name", ""),
            "HY2_BBR_CURRENT": h.get("bbr_profile", ""),
            "HY2_PASS": user(h, "password"),
            "HY2_OBFS_PASS": (h.get("obfs") or {}).get("password", ""),
            "HY2_HOP_PORTS": ",".join(hop.get("ports", [])) if hop.get("enabled") else "",
            "HY2_HOP_INTERVAL": hop.get("hop_interval", os.environ["DEFAULT_HY2_HOP_INTERVAL"]),
        }
        for key, value in values.items():
            sys.stdout.write(key + "\0" + str(value) + "\0")
        sys.stdout.write("READY\0")
        sys.exit()

    if action not in ("update", "validate"):
        sys.exit("未知节点操作。")

    def validate_server_name(name, label):
        try:
            ipaddress.ip_address(name)
        except ValueError:
            if len(name) > 253 or not all(
                re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", part)
                for part in name.split(".")
            ):
                sys.exit(f"{label} 必须是有效域名或 IP 地址。")

    v, h, a, u = (inbound(kind) for kind in ("vless-reality", "hysteria2", "anytls", "tuic"))
    for item in filter(None, (v, h, a, u)):
        if type(item.get("listen_port")) is not int or not 1 <= item["listen_port"] <= 65535:
            sys.exit("配置中的协议端口无效。")
    if action in ("update", "validate"):
        mode = sys.argv[2]
        e = os.environ
        if mode in ("ports", "sni", "credentials", "rotate") and (not v or not h):
            sys.exit("此批量快捷操作需要 VLESS 和 HY2；请通过协议子菜单逐项修改已有入站。")
        if mode in ("regenerate-vless", "regenerate-hysteria2", "bbr") and not (
            v if mode == "regenerate-vless" else h
        ):
            sys.exit("配置中不存在要修改的协议。")
        if mode == "add-anytls":
            if a:
                sys.exit("AnyTLS 已存在，请使用修改端口、SNI 或凭据功能。")
            a = {
                "type": "anytls",
                "tag": new_inbound_tag("anytls"),
                "listen": "0.0.0.0",
                "listen_port": int(e["ANYTLS_PORT"]),
                "users": [{"name": "main", "password": e["ANYTLS_PASS"]}],
                "tls": {
                    "enabled": True,
                    "handshake_timeout": e["DEFAULT_TLS_HANDSHAKE_TIMEOUT"],
                    "server_name": e["ANYTLS_SNI"],
                    "certificate_path": str(app / "tls/anytls.crt"),
                    "key_path": str(app / "tls/anytls.key"),
                },
            }
            c["inbounds"].append(a)
        elif mode == "add-tuic":
            if u:
                sys.exit("TUIC 已存在，请修改现有协议。")
            u = {
                "type": "tuic",
                "tag": new_inbound_tag("tuic"),
                "listen": "0.0.0.0",
                "listen_port": int(e["TUIC_PORT"]),
                "users": [{"name": "main", "uuid": e["TUIC_UUID"], "password": e["TUIC_PASS"]}],
                "congestion_control": "bbr",
                "auth_timeout": "3s",
                "zero_rtt_handshake": False,
                "heartbeat": "10s",
                "disable_path_mtu_discovery": False,
                "tls": {
                    "enabled": True,
                    "server_name": e["TUIC_SNI"],
                    "alpn": ["h3"],
                    "handshake_timeout": e["DEFAULT_TLS_HANDSHAKE_TIMEOUT"],
                    "certificate_path": str(app / "tls/tuic.crt"),
                    "key_path": str(app / "tls/tuic.key"),
                },
            }
            c["inbounds"].append(u)
        elif mode == "ports":
            if u:
                u["listen_port"] = int(e["TUIC_PORT"])
            v["listen_port"], h["listen_port"] = int(e["VLESS_PORT"]), int(e["HY2_PORT"])
            if a:
                a["listen_port"] = int(e["ANYTLS_PORT"])
        elif mode == "sni":
            for key in ("REALITY_DOMAIN", "HY2_SNI"):
                validate_server_name(e[key], key)
            v["tls"]["server_name"] = e["REALITY_DOMAIN"]
            v["tls"]["reality"]["handshake"]["server"] = e["REALITY_DOMAIN"]
            if e["HY2_SNI"] != h["tls"].get("server_name", ""):
                for key, name in [("certificate_path", "hy2.crt"), ("key_path", "hy2.key")]:
                    if pathlib.Path(h["tls"][key]).absolute() != (app / "tls" / name).absolute():
                        sys.exit("HY2 证书由外部路径管理，请先手动处理证书再修改 SNI。")
            h["tls"]["server_name"] = e["HY2_SNI"]
            if u:
                if e["TUIC_SNI"] != u["tls"].get("server_name", ""):
                    for key, name in [("certificate_path", "tuic.crt"), ("key_path", "tuic.key")]:
                        if (
                            pathlib.Path(u["tls"][key]).absolute()
                            != (app / "tls" / name).absolute()
                        ):
                            sys.exit("TUIC 证书由外部路径管理。")
                u["tls"]["server_name"] = e["TUIC_SNI"]
            if a:
                if e["ANYTLS_SNI"] != a["tls"]["server_name"]:
                    for key, name in [
                        ("certificate_path", "anytls.crt"),
                        ("key_path", "anytls.key"),
                    ]:
                        if (
                            pathlib.Path(a["tls"][key]).absolute()
                            != (app / "tls" / name).absolute()
                        ):
                            sys.exit("AnyTLS 证书由外部路径管理，请先手动处理证书再修改 SNI。")
                a["tls"]["server_name"] = e["ANYTLS_SNI"]
        elif mode in ("credentials", "rotate"):
            v["users"][0]["uuid"] = str(uuid.UUID(e["UUID"]))
            if not e["HY2_PASS"] or not e["HY2_OBFS_PASS"]:
                sys.exit("HY2 认证密码和混淆密码不能为空。")
            h["users"][0]["password"] = e["HY2_PASS"]
            h["obfs"] = {"type": "salamander", "password": e["HY2_OBFS_PASS"]}
            if a:
                a["users"][0]["password"] = e["ANYTLS_PASS"]
            if u:
                u["users"][0].update(uuid=str(uuid.UUID(e["TUIC_UUID"])), password=e["TUIC_PASS"])
            if mode == "rotate":
                v["tls"]["reality"].update(
                    private_key=e["REALITY_PRIVATE"], short_id=[e["SHORT_ID"]]
                )
        elif mode in (
            "regenerate-vless",
            "regenerate-hysteria2",
            "regenerate-anytls",
            "regenerate-tuic",
        ):
            if mode == "regenerate-vless":
                v["users"][0]["uuid"] = str(uuid.UUID(e["UUID"]))
                v["tls"]["reality"].update(
                    private_key=e["REALITY_PRIVATE"], short_id=[e["SHORT_ID"]]
                )
            elif mode == "regenerate-tuic":
                if not u:
                    sys.exit("尚未安装 TUIC。")
                for key, suffix in [("certificate_path", ".crt"), ("key_path", ".key")]:
                    if (
                        pathlib.Path(u["tls"][key]).absolute()
                        != (app / "tls" / ("tuic" + suffix)).absolute()
                    ):
                        sys.exit("TUIC 证书由外部路径管理。")
                u["users"][0].update(uuid=str(uuid.UUID(e["TUIC_UUID"])), password=e["TUIC_PASS"])
            else:
                target, stem, password = (
                    (h, "hy2", e["HY2_PASS"])
                    if mode == "regenerate-hysteria2"
                    else (a, "anytls", e["ANYTLS_PASS"])
                )
                if target is None:
                    sys.exit("尚未安装 AnyTLS，请先添加该协议。")
                for key, suffix in [("certificate_path", ".crt"), ("key_path", ".key")]:
                    if (
                        pathlib.Path(target["tls"][key]).absolute()
                        != (app / "tls" / (stem + suffix)).absolute()
                    ):
                        sys.exit("证书由外部路径管理，拒绝重新生成；请先手动处理证书。")
                target["users"][0]["password"] = password
                if stem == "hy2":
                    h["obfs"] = {"type": "salamander", "password": e["HY2_OBFS_PASS"]}
        elif mode == "bbr":
            if e["HY2_BBR_PROFILE"] not in ("standard", "conservative", "aggressive"):
                sys.exit("BBR 档位必须是 standard、conservative 或 aggressive。")
            h["bbr_profile"] = e["HY2_BBR_PROFILE"]
        elif mode == "tfo":
            if e["SOCKS_TFO"] not in ("true", "false"):
                sys.exit("TFO 只能设置为 true 或 false。")
            for o in c["outbounds"]:
                if proxy_name(o) in ("SOCKS5", "HTTPS") and o.get("tag") in (
                    "ai-socks",
                    "google-socks",
                    "other-socks",
                ):
                    o["tcp_fast_open"] = e["SOCKS_TFO"] == "true"
        else:
            sys.exit("未知配置修改操作。")
        if u:
            if not 1 <= u["listen_port"] <= 65535 or listener_conflict(u, h):
                sys.exit("TUIC UDP 端口无效或与 HY2 冲突。")
            if u.get("users"):
                if not u["users"][0]["password"]:
                    sys.exit("TUIC 密码不能为空。")
                u["users"][0]["uuid"] = str(uuid.UUID(u["users"][0]["uuid"]))
        if a:
            if not 1 <= a["listen_port"] <= 65535 or listener_conflict(a, v):
                sys.exit("AnyTLS 端口必须在 1-65535 内且与 VLESS TCP 端口不同。")
            if not a["users"][0]["password"]:
                sys.exit("AnyTLS 密码不能为空。")
            validate_server_name(a["tls"]["server_name"], "ANYTLS_SNI")
        if action == "validate":
            print("unchanged" if c == original else "changed")
            sys.exit()
        write_json(p, c)
