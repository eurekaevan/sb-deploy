"""Configuration creation, staged edits and listener discovery."""


def configure_proxy(outbound, prefix, environment):
    """Change proxy protocol while retaining its tag and shared dial options."""
    import copy
    import json
    import sys

    group = prefix.removesuffix("_SOCKS")
    was_https = outbound.get("type") == "http" and (outbound.get("tls") or {}).get("enabled")
    protocol = environment.get(group + "_PROXY_PROTOCOL") or ("https" if was_https else "socks5")
    if protocol not in ("socks5", "https"):
        sys.exit("出口协议必须是 socks5 或 https。")
    if protocol == "https":
        if outbound.get("type") != "http":
            outbound.pop("version", None)
        outbound.pop("udp_over_tcp", None)
        tls = copy.deepcopy(outbound.get("tls") or {}) if was_https else {}
        if environment.get(group + "_PROXY_TLS"):
            tls = json.loads(environment[group + "_PROXY_TLS"])
            if not isinstance(tls, dict):
                sys.exit("代理 TLS 配置必须是 JSON 对象。")
        tls["enabled"] = True
        tls["server_name"] = (
            environment.get(group + "_PROXY_SNI") or tls.get("server_name") or outbound["server"]
        )
        tls.setdefault("insecure", False)
        outbound.update(type="http", tls=tls)
    else:
        if outbound.get("type") != "socks":
            for key in ("tls", "path", "headers", "version"):
                outbound.pop(key, None)
            outbound["version"] = "5"
        outbound["type"] = "socks"
    return outbound


def generate():
    import json
    import pathlib

    from sb_deploy.context import context

    p = pathlib.Path(context.require("APP"))
    e = context
    log_level = e.get("LOG_LEVEL") or "warn"
    if log_level not in ("trace", "debug", "info", "warn", "error", "fatal", "panic"):
        raise SystemExit("LOG_LEVEL 必须是 trace、debug、info、warn、error、fatal 或 panic。")
    resolver = {"server": "local", "strategy": "ipv4_only", "timeout": "3s"}

    def proxy(tag, prefix):
        outbound = {
            "type": "socks",
            "tag": tag,
            "server": e[prefix + "_HOST"],
            "server_port": int(e[prefix + "_PORT"]),
            "version": "5",
            "username": e[prefix + "_USER"],
            "password": e[prefix + "_PASS"],
            "domain_resolver": resolver,
            "connect_timeout": "5s",
            "tcp_fast_open": e["SOCKS_TFO"] == "true",
            "tcp_keep_alive": "2m",
            "tcp_keep_alive_interval": "30s",
        }
        return configure_proxy(outbound, prefix, e)

    def ruleset(tag, url):
        return {
            "type": "remote",
            "tag": tag,
            "format": "binary",
            "url": url,
            "initial_path": str(p / "rules" / f"{tag}.srs"),
            "http_client": {"engine": "go", "detour": "direct"},
            "update_interval": "1d",
        }

    config = {
        "log": {"level": log_level, "timestamp": True},
        "dns": {
            "servers": [{"type": "local", "tag": "local"}],
            "final": "local",
            "strategy": "ipv4_only",
        },
        "inbounds": [
            {
                "type": "vless",
                "tag": "vless-reality",
                "listen": "0.0.0.0",  # noqa: S104 - proxy must accept remote clients
                "listen_port": int(e["VLESS_PORT"]),
                "users": [{"name": "main", "uuid": e["UUID"], "flow": "xtls-rprx-vision"}],
                "tls": {
                    "enabled": True,
                    "server_name": e["REALITY_DOMAIN"],
                    "reality": {
                        "enabled": True,
                        "handshake": {
                            "server": e["REALITY_DOMAIN"],
                            "server_port": 443,
                            "domain_resolver": resolver,
                            "connect_timeout": "5s",
                        },
                        "private_key": e["REALITY_PRIVATE"],
                        "short_id": [e["SHORT_ID"]],
                        "max_time_difference": "1m",
                    },
                },
            },
            {
                "type": "hysteria2",
                "tag": "hysteria2",
                "listen": "0.0.0.0",  # noqa: S104 - proxy must accept remote clients
                "listen_port": int(e["HY2_PORT"]),
                "bbr_profile": e["HY2_BBR_PROFILE"],
                "ignore_client_bandwidth": True,
                "users": [{"name": "main", "password": e["HY2_PASS"]}],
                "obfs": {"type": "salamander", "password": e["HY2_OBFS_PASS"]},
                "tls": {
                    "enabled": True,
                    "server_name": e["REALITY_DOMAIN"],
                    "alpn": ["h3"],
                    "certificate_path": str(p / "tls/hy2.crt"),
                    "key_path": str(p / "tls/hy2.key"),
                },
            },
        ],
        "outbounds": [
            {"type": "direct", "tag": "direct"},
            proxy("ai-socks", "AI_SOCKS"),
            proxy("google-socks", "GOOGLE_SOCKS"),
            proxy("other-socks", "OTHER_SOCKS"),
        ],
        "route": {
            "rules": [
                {"action": "sniff", "sniffer": ["http", "tls", "quic"], "timeout": "500ms"},
                {"ip_is_private": True, "action": "reject"},
                # Google first: Gemini/Google AI routes to the Google proxy when both rules match.
                {"rule_set": ["google", "youtube"], "action": "route", "outbound": "google-socks"},
                {"rule_set": ["ai"], "action": "route", "outbound": "ai-socks"},
                {"action": "resolve", "server": "local", "strategy": "ipv4_only", "timeout": "3s"},
                {"ip_is_private": True, "action": "reject"},
            ],
            "rule_set": [
                ruleset("ai", e["AI_URL"]),
                ruleset("google", e["GOOGLE_URL"]),
                ruleset("youtube", e["YOUTUBE_URL"]),
            ],
            "final": "other-socks",
            "default_domain_resolver": "local",
            "auto_detect_interface": True,
        },
        "experimental": {
            "cache_file": {"enabled": True, "path": str(p / "cache.db"), "store_dns": True}
        },
    }
    if e.get("ANYTLS_PORT"):
        config["inbounds"].append(
            {
                "type": "anytls",
                "tag": "anytls",
                "listen": "0.0.0.0",  # noqa: S104 - proxy must accept remote clients
                "listen_port": int(e["ANYTLS_PORT"]),
                "users": [{"name": "main", "password": e["ANYTLS_PASS"]}],
                "tls": {
                    "enabled": True,
                    "server_name": e.get("ANYTLS_SNI") or e["REALITY_DOMAIN"],
                    "certificate_path": str(p / "tls/anytls.crt"),
                    "key_path": str(p / "tls/anytls.key"),
                },
            }
        )
    if e.get("TUIC_PORT"):
        config["inbounds"].append(
            {
                "type": "tuic",
                "tag": "tuic",
                "listen": "0.0.0.0",  # noqa: S104 - proxy must accept remote clients
                "listen_port": int(e["TUIC_PORT"]),
                "users": [{"name": "main", "uuid": e["TUIC_UUID"], "password": e["TUIC_PASS"]}],
                "congestion_control": "bbr",
                "auth_timeout": "3s",
                "zero_rtt_handshake": False,
                "heartbeat": "10s",
                "disable_path_mtu_discovery": False,
                "tls": {
                    "enabled": True,
                    "server_name": e.get("TUIC_SNI") or e["REALITY_DOMAIN"],
                    "alpn": ["h3"],
                    "certificate_path": str(p / "tls/tuic.crt"),
                    "key_path": str(p / "tls/tuic.key"),
                },
            }
        )
    for item in config["inbounds"]:
        item["tls"]["handshake_timeout"] = e["DEFAULT_TLS_HANDSHAKE_TIMEOUT"]

    def write(path, contents):
        path.write_text(contents)
        path.chmod(0o600)

    def write_json(path, obj):
        write(path, json.dumps(obj, indent=2, ensure_ascii=False) + "\n")

    write_json(pathlib.Path(e["CONFIG"]), config)


def listeners():
    import json
    import sys

    labels = {"vless": "VLESS", "hysteria2": "Hysteria2", "anytls": "AnyTLS", "tuic": "TUIC"}
    for item in json.load(open(sys.argv[1])).get("inbounds", []):
        if "listen_port" not in item:
            continue
        kind = item.get("type") or item.get("tag")
        # direct/shadowsocks listen on both networks when unspecified (official inbound docs).
        if (item.get("transport") or {}).get("type") == "quic":
            networks = ["udp"]
        elif item.get("network"):
            networks = [item["network"]]
        elif kind in ("direct", "shadowsocks"):
            networks = ["tcp", "udp"]
        else:
            networks = ["udp" if kind in ("hysteria", "hysteria2", "tuic") else "tcp"]
        for network in networks:
            print(network, item["listen_port"], labels.get(kind, item.get("tag", "协议")))


def set_socks():
    import json
    import os
    import pathlib
    import sys
    import tempfile

    from sb_deploy.context import context

    p = pathlib.Path(context.require("CONFIG"))
    c = json.loads(p.read_text())
    for profile in sys.argv[1:]:
        tag = profile + "-socks"
        matches = [
            o
            for o in c["outbounds"]
            if o.get("tag") == tag
            and (
                o.get("type") == "socks"
                or (o.get("type") == "http" and (o.get("tls") or {}).get("enabled"))
            )
        ]
        if profile == "other" and not any(o.get("tag") == tag for o in c["outbounds"]):
            matches = [
                {
                    "type": "socks",
                    "tag": tag,
                    "version": "5",
                    "domain_resolver": {
                        "server": "local",
                        "strategy": "ipv4_only",
                        "timeout": "3s",
                    },
                    "connect_timeout": "5s",
                    "tcp_keep_alive": "2m",
                    "tcp_keep_alive_interval": "30s",
                    "tcp_fast_open": context.require("SOCKS_TFO") == "true",
                }
            ]
            c["outbounds"].append(matches[0])
        if len(matches) != 1:
            sys.exit(f"Expected exactly one supported proxy outbound: {tag}")
        prefix = profile.upper() + "_SOCKS"
        matches[0].update(
            server=context.require(prefix + "_HOST"),
            server_port=int(context.require(prefix + "_PORT")),
            username=context.require(prefix + "_USER"),
            password=context.require(prefix + "_PASS"),
        )
        configure_proxy(matches[0], prefix, context)
        if context.require("REQUEST_SOCKS_TFO"):
            matches[0]["tcp_fast_open"] = context.require("REQUEST_SOCKS_TFO") == "true"
    if "other" in sys.argv[1:]:
        c["route"]["final"] = "other-socks"
    with tempfile.NamedTemporaryFile(mode="w", dir=p.parent, prefix=".config-", delete=False) as f:
        staging = pathlib.Path(f.name)
        try:
            json.dump(c, f, indent=2, ensure_ascii=False)
            f.write("\n")
            f.flush()
            st = p.stat()
            os.fchown(f.fileno(), st.st_uid, st.st_gid)
            os.fchmod(f.fileno(), 0o600)
            staging.replace(p)
        finally:
            if staging.exists():
                staging.unlink()


def relocate_tls():
    import json
    import pathlib
    import sys

    path, old, new = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3])
    if path.is_symlink():
        sys.exit("配置文件是符号链接，拒绝覆盖。")
    c = json.loads(path.read_text())
    for inbound in c.get("inbounds", []):
        for key in ("certificate_path", "key_path"):
            tls = inbound.get("tls") or {}
            if key not in tls:
                continue
            try:
                relative = pathlib.Path(tls[key]).relative_to(old / "tls")
            except ValueError:
                continue
            tls[key] = str(new / "tls" / relative)
    path.write_text(json.dumps(c, indent=2, ensure_ascii=False) + "\n")
    path.chmod(0o600)


def fingerprint():
    import hashlib
    import pathlib
    import sys

    root = pathlib.Path(sys.argv[1])
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if path.is_dir() and not path.is_symlink():
            continue
        digest.update(str(path.relative_to(root)).encode() + b"\0")
        digest.update(
            (str(path.readlink()).encode() if path.is_symlink() else path.read_bytes()) + b"\0"
        )
    print(digest.hexdigest())


def edit_field():
    import json
    import pathlib
    import re
    import sys

    from sb_deploy.context import context

    obj = json.loads(pathlib.Path(sys.argv[1]).read_text())
    pointer = sys.argv[3]
    value = context.require("FIELD_VALUE")
    if not pointer.startswith("/") or re.search(r"~(?![01])", pointer):
        sys.exit("字段路径必须为 JSON Pointer，例如 /tls/handshake_timeout。")
    keys = [p.replace("~1", "/").replace("~0", "~") for p in pointer[1:].split("/")]
    try:
        current = obj
        for key in keys[:-1]:
            if isinstance(current, list):
                current = current[int(key)]
            else:
                current = current.setdefault(key, {})
        key = keys[-1]
        if isinstance(current, list):
            if key == "-" and value != ":remove":
                current.append(json.loads(value))
            elif value == ":remove":
                del current[int(key)]
            else:
                current[int(key)] = json.loads(value)
        elif value == ":remove":
            current.pop(key, None)
        else:
            current[key] = json.loads(value)
    except (ValueError, IndexError, KeyError, TypeError, AttributeError) as error:
        sys.exit("字段或 JSON 值无效：" + str(error))
    pathlib.Path(sys.argv[2]).write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n")
