"""Network validation and configured connection probes."""


def check_socks():
    import os
    import socket
    import struct
    import sys

    prefix = os.environ["SOCKS_PROFILE"].upper() + "_SOCKS"
    e = os.environ
    user, password = (e[prefix + suffix].encode() for suffix in ("_USER", "_PASS"))
    authenticated = bool(user or password)
    if authenticated and not (1 <= len(user) <= 255 and 1 <= len(password) <= 255):
        sys.exit("SOCKS5 username/password must each contain 1-255 UTF-8 bytes.")

    def receive(sock, size):
        data = b""
        while len(data) < size:
            chunk = sock.recv(size - len(data))
            if not chunk:
                raise ValueError("upstream closed the connection")
            data += chunk
        return data

    try:
        with socket.create_connection(
            (e[prefix + "_HOST"], int(e[prefix + "_PORT"])), timeout=10
        ) as sock:
            method = b"\x02" if authenticated else b"\x00"
            sock.sendall(b"\x05\x01" + method)
            if receive(sock, 2) != b"\x05" + method:
                raise ValueError("upstream did not accept the configured authentication method")
            if authenticated:
                sock.sendall(
                    b"\x01" + bytes([len(user)]) + user + bytes([len(password)]) + password
                )
                if receive(sock, 2) != b"\x01\x00":
                    raise ValueError("authentication rejected")
            host = b"example.com"
            sock.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + struct.pack("!H", 443))
            version, reply, reserved, atyp = receive(sock, 4)
            if version != 5 or reserved != 0 or reply != 0:
                raise ValueError(f"CONNECT failed (SOCKS reply {reply})")
            if atyp == 1:
                receive(sock, 4)
            elif atyp == 4:
                receive(sock, 16)
            elif atyp == 3:
                receive(sock, receive(sock, 1)[0])
            else:
                raise ValueError("invalid SOCKS address type")
            receive(sock, 2)
    except (OSError, ValueError) as exc:
        sys.exit(f"SOCKS5 check failed: {exc}")


def check_https(outbound: dict):
    """Verify the configured TLS proxy and perform an authenticated HTTP/1.1 CONNECT."""
    import base64
    import http.client
    import re
    import socket
    import ssl
    import sys

    host, port = outbound.get("server"), outbound.get("server_port")
    tls = outbound.get("tls") or {}
    user, password = outbound.get("username", ""), outbound.get("password", "")
    if not isinstance(host, str) or not host or type(port) is not int or not 1 <= port <= 65535:
        sys.exit("HTTPS proxy address or port is invalid.")
    if any(not isinstance(value, str) or "\0" in value for value in (host, user, password)):
        sys.exit("HTTPS proxy contains an invalid string.")
    if ":" in user:
        sys.exit("HTTPS Basic authorization username cannot contain a colon.")
    if not isinstance(tls, dict) or tls.get("enabled") is not True:
        sys.exit("HTTPS proxy requires enabled TLS.")
    supported = {
        "enabled",
        "server_name",
        "insecure",
        "certificate_path",
        "certificate",
        "alpn",
        "min_version",
        "max_version",
        "handshake_timeout",
    }
    unsupported = [
        key
        for key, value in tls.items()
        if key not in supported and value not in (None, False, "", [], {})
    ]
    if unsupported:
        sys.exit(
            "HTTPS probe cannot reproduce these TLS settings: " + ", ".join(sorted(unsupported))
        )
    if outbound.get("version") not in (None, 0, 1):
        sys.exit(
            "HTTPS probe only supports HTTP/1.1 CONNECT; configured HTTP version requires manual verification."
        )
    if outbound.get("path") or outbound.get("headers"):
        sys.exit(
            "HTTPS probe cannot reproduce custom CONNECT path/headers; verify this proxy manually."
        )
    name = tls.get("server_name") or host
    if not isinstance(name, str) or not name or any(char in name for char in ("\0", "\r", "\n")):
        sys.exit("HTTPS proxy TLS server_name is invalid.")
    if "insecure" in tls and type(tls["insecure"]) is not bool:
        sys.exit("HTTPS proxy TLS insecure must be a boolean.")
    if tls.get("alpn") not in (None, [], ["http/1.1"]):
        sys.exit(
            "HTTPS probe only supports HTTP/1.1 ALPN; configured ALPN requires manual verification."
        )
    timeout = 10.0
    if tls.get("handshake_timeout"):
        duration = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)(ms|s|m)", str(tls["handshake_timeout"]))
        if not duration:
            sys.exit("HTTPS proxy TLS handshake_timeout is unsupported.")
        timeout = float(duration[1]) * {"ms": 0.001, "s": 1, "m": 60}[duration[2]]
        if timeout <= 0:
            sys.exit("HTTPS proxy TLS handshake_timeout must be positive.")
    try:
        certificate = tls.get("certificate")
        # sing-box replaces its root pool when custom CA material is provided.
        context = (
            ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            if certificate or tls.get("certificate_path")
            else ssl.create_default_context()
        )
        if tls.get("insecure"):
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        if certificate:
            if isinstance(certificate, list) and all(isinstance(line, str) for line in certificate):
                certificate = "\n".join(certificate)
            if not isinstance(certificate, str):
                raise ValueError("invalid inline CA certificate")
            context.load_verify_locations(cadata=certificate)
        elif tls.get("certificate_path"):
            context.load_verify_locations(cafile=tls["certificate_path"])
        versions = {
            "1.0": ssl.TLSVersion.TLSv1,
            "1.1": ssl.TLSVersion.TLSv1_1,
            "1.2": ssl.TLSVersion.TLSv1_2,
            "1.3": ssl.TLSVersion.TLSv1_3,
        }
        for key, attribute in (
            ("min_version", "minimum_version"),
            ("max_version", "maximum_version"),
        ):
            if tls.get(key):
                if tls[key] not in versions:
                    raise ValueError("unsupported TLS version")
                setattr(context, attribute, versions[tls[key]])
        context.set_alpn_protocols(["http/1.1"])
        request = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n"
        if user or password:
            token = base64.b64encode((user + ":" + password).encode()).decode("ascii")
            request += "Proxy-Authorization: Basic " + token + "\r\n"
        request += "\r\n"
        with socket.create_connection((host, port), timeout=10) as raw:
            raw.settimeout(timeout)
            with context.wrap_socket(raw, server_hostname=name) as sock:
                sock.settimeout(10)
                sock.sendall(request.encode("ascii"))
                response = http.client.HTTPResponse(sock, method="CONNECT")
                try:
                    response.begin()
                    if not 200 <= response.status < 300:
                        sys.exit("HTTPS CONNECT failed: HTTP " + str(response.status) + ".")
                finally:
                    response.close()
    except ssl.SSLCertVerificationError as error:
        sys.exit(
            "HTTPS proxy TLS certificate verification failed (code " + str(error.verify_code) + ")."
        )
    except http.client.HTTPException:
        # A proxy may echo credentials in a malformed status line; never print that response.
        sys.exit("HTTPS CONNECT response is invalid or prematurely closed.")
    except (OSError, ValueError, TypeError):
        sys.exit(
            "HTTPS proxy connection/TLS check failed; check reachability, CA files and TLS settings."
        )


def check_proxy():
    """Use the protocol chosen for a profile while preserving legacy SOCKS variables."""
    import json
    import os
    import sys

    profile = os.environ["SOCKS_PROFILE"].upper()
    protocol = os.environ.get(profile + "_PROXY_PROTOCOL", "socks5")
    if protocol == "socks5":
        check_socks()
        return
    if protocol != "https":
        sys.exit("Unsupported proxy protocol; choose socks5 or https.")
    prefix = profile + "_SOCKS"
    try:
        tls = json.loads(os.environ.get(profile + "_PROXY_TLS") or "{}")
        if not isinstance(tls, dict):
            raise ValueError("TLS settings must be an object")
        tls = {**tls, "enabled": True}
        http = json.loads(os.environ.get(profile + "_PROXY_HTTP") or "{}")
        if not isinstance(http, dict):
            sys.exit("HTTPS proxy HTTP settings must be a JSON object.")
        if set(http) - {"path", "headers", "version"}:
            sys.exit(
                "Unsupported HTTPS proxy HTTP setting; allowed fields are path, headers and version."
            )
        name = os.environ.get(profile + "_PROXY_SNI")
        if name:
            tls["server_name"] = name
        outbound = {
            "type": "http",
            "server": os.environ[prefix + "_HOST"],
            "server_port": int(os.environ[prefix + "_PORT"]),
            "username": os.environ[prefix + "_USER"],
            "password": os.environ[prefix + "_PASS"],
            "tls": tls,
            **http,
        }
    except (ValueError, KeyError):
        sys.exit("HTTPS proxy profile contains invalid address/TLS/HTTP settings.")
    check_https(outbound)


def public_ipv4():
    import ipaddress
    import os
    import sys

    try:
        ip = ipaddress.IPv4Address(os.environ["SERVER_IP"])
        if not ip.is_global:
            raise ValueError("not public")
    except Exception as e:
        sys.exit(
            f"Cannot identify public IPv4 ({e}); set SERVER_IP=<your server public IP> and retry."
        )


def connection_probes():
    import ipaddress
    import json
    import pathlib
    import subprocess
    import sys

    config = json.loads(pathlib.Path(sys.argv[1]).read_text())
    probes = []
    for outbound in config.get("outbounds", []):
        if outbound.get("type") == "http":
            label = json.dumps(outbound.get("tag", "未命名"), ensure_ascii=False)
            if (outbound.get("tls") or {}).get("enabled"):
                print("检查 HTTPS 出口：" + label, file=sys.stderr)
                check_https(outbound)
            else:
                print("非 TLS HTTP 出口跳过 HTTPS 探测：" + label, file=sys.stderr)
            continue
        if outbound.get("type") != "socks":
            continue
        if str(outbound.get("version", "5")) != "5":
            print(
                "非 SOCKS5 出站跳过协议探测："
                + json.dumps(outbound.get("tag", "未命名"), ensure_ascii=False),
                file=sys.stderr,
            )
            continue
        host, port = outbound.get("server"), outbound.get("server_port")
        user, password = outbound.get("username", ""), outbound.get("password", "")
        if not isinstance(host, str) or not host or type(port) is not int or not 1 <= port <= 65535:
            sys.exit("SOCKS5 出站地址或端口无效。")
        if any(not isinstance(value, str) or "\0" in value for value in (host, user, password)):
            sys.exit("SOCKS5 出站包含无效字符串。")
        label = json.dumps(outbound.get("tag", "未命名"), ensure_ascii=False)
        probes.append((label, host, str(port), user, password))
    if not probes:
        print("未配置 SOCKS5 出站，跳过 SOCKS5 连通性探测。", file=sys.stderr)
    reality_count = 0
    for inbound in config.get("inbounds", []):
        label = json.dumps(inbound.get("tag", inbound.get("type", "未命名")), ensure_ascii=False)
        tls = inbound.get("tls") or {}
        if not tls.get("enabled"):
            continue
        reality = tls.get("reality") or {}
        if reality.get("enabled"):
            reality_count += 1
            handshake = reality.get("handshake") or {}
            host, port = handshake.get("server"), handshake.get("server_port")
            if (
                not isinstance(host, str)
                or not host
                or type(port) is not int
                or not 1 <= port <= 65535
            ):
                sys.exit("Reality 握手目标地址或端口无效。")
            name = tls.get("server_name") or host
            endpoint = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
            args = [
                "openssl",
                "s_client",
                "-connect",
                endpoint,
                "-tls1_3",
                "-verify_return_error",
                "-brief",
            ]
            try:
                ipaddress.ip_address(name)
            except ValueError:
                args += ["-servername", name, "-verify_hostname", name]
            else:
                args += ["-verify_ip", name]
            print("检查 Reality 握手目标 " + label + "：" + endpoint, file=sys.stderr)
            try:
                result = subprocess.run(args, input="", text=True, capture_output=True, timeout=12)
            except (OSError, subprocess.TimeoutExpired):
                sys.exit("Reality 握手目标检查无法完成或超时。")
            if result.returncode:
                sys.stderr.write(result.stderr)
                sys.exit("Reality 目标 TLS 1.3/证书校验失败。")
            continue
        cert_path = tls.get("certificate_path")
        cert = tls.get("certificate")
        if cert_path:
            args = ["openssl", "x509", "-in", str(cert_path), "-noout", "-dates", "-checkend", "0"]
            data = ""
        elif cert:
            data = "\n".join(cert) if isinstance(cert, list) else cert
            if not isinstance(data, str):
                sys.exit("TLS 内嵌证书格式无效。")
            args = ["openssl", "x509", "-noout", "-dates", "-checkend", "0"]
        else:
            print(
                "TLS 入站 "
                + label
                + " 未提供静态证书，跳过离线到期检查；动态证书需在服务运行时核实。",
                file=sys.stderr,
            )
            continue
        print("检查 TLS 静态证书到期时间：" + label, file=sys.stderr)
        try:
            result = subprocess.run(args, input=data, text=True, capture_output=True, timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            sys.exit("TLS 证书检查无法完成或超时。")
        if result.returncode:
            sys.stderr.write(result.stderr)
            sys.exit("TLS 证书无效、无法读取或已经到期。")
        sys.stderr.write(result.stdout)
    if not reality_count:
        print("未配置 Reality 入站，跳过握手目标检查。", file=sys.stderr)
    for row in probes:
        for value in row:
            sys.stdout.write(value + "\0")
    sys.stdout.write("READY\0")
