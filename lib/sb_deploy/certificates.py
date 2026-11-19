"""Certificate status and managed self-signed renewal."""


def status():
    import datetime
    import json
    import math
    import pathlib
    import re
    import shutil
    import ssl
    import subprocess
    import sys

    from sb_deploy.context import context

    def emit(level, message):
        sys.stdout.write(level + "\0" + message + "\0")

    try:
        value = context.get("CERT_WARN_DAYS", "")
        if not re.fullmatch(r"[0-9]+", value):
            raise ValueError("CERT_WARN_DAYS 必须是非负整数。")
        warning_days = int(value)
        config = json.loads(pathlib.Path(context.require("CONFIG")).read_text())
        if not isinstance(config, dict) or not isinstance(config.get("inbounds", []), list):
            raise ValueError("配置中的 inbounds 必须是数组。")
    except (OSError, UnicodeError, ValueError, KeyError) as error:
        emit("error", "无法读取证书到期状态：" + str(error))
    else:
        now = datetime.datetime.now(datetime.timezone.utc).timestamp()
        matched = 0
        for index, inbound in enumerate(config.get("inbounds", [])):
            if not isinstance(inbound, dict):
                emit("error", "入站配置格式无效，无法读取证书到期状态。")
                continue
            tls = inbound.get("tls") or {}
            if not isinstance(tls, dict):
                emit("error", "入站 TLS 配置格式无效，无法读取证书到期状态。")
                continue
            reality = tls.get("reality") or {}
            if not tls.get("enabled") or (isinstance(reality, dict) and reality.get("enabled")):
                continue
            matched += 1
            label = json.dumps(
                str(inbound.get("type", "未知协议"))
                + " · "
                + str(inbound.get("tag") or "@" + str(index)),
                ensure_ascii=False,
            )
            cert_path = tls.get("certificate_path")
            cert = tls.get("certificate")
            if not cert_path and not cert:
                emit(
                    "info",
                    "证书 "
                    + label
                    + "：未提供静态证书，离线无法确认到期时间；动态证书需在服务运行时核实。",
                )
                continue
            try:
                if cert_path:
                    pem = pathlib.Path(cert_path).read_text()
                elif isinstance(cert, list) and all(isinstance(item, str) for item in cert):
                    pem = "\n".join(cert)
                elif isinstance(cert, str):
                    pem = cert
                else:
                    raise ValueError("内嵌证书必须是 PEM 文本或文本数组。")
                leaf = re.search(
                    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem, re.S
                )
                if not leaf:
                    raise ValueError("没有找到 PEM 叶证书。")
                openssl = shutil.which("openssl")
                if not openssl:
                    raise ValueError("未安装 openssl，无法读取证书到期时间。")
                process = subprocess.run(
                    [openssl, "x509", "-noout", "-enddate"],
                    input=leaf[0] + "\n",
                    text=True,
                    capture_output=True,
                    timeout=10,
                )
                if process.returncode:
                    raise ValueError("openssl 无法解析叶证书：" + process.stderr.strip())
                expiry_line = next(
                    (line for line in process.stdout.splitlines() if line.startswith("notAfter=")),
                    None,
                )
                if not expiry_line:
                    raise ValueError("openssl 未返回证书到期时间。")
                expiry = ssl.cert_time_to_seconds(expiry_line.partition("=")[2])
                end = datetime.datetime.fromtimestamp(expiry, datetime.timezone.utc).strftime(
                    "%Y-%m-%d %H:%M:%S UTC"
                )
                remaining = expiry - now
                days = (
                    math.ceil(remaining / 86400) if remaining > 0 else math.floor(remaining / 86400)
                )
                message = "证书 " + label + "：剩余 " + str(days) + " 天；到期 " + end
                if remaining <= 0:
                    emit("error", message + "（已过期）")
                elif remaining <= warning_days * 86400:
                    emit("warning", message + "（即将到期）")
                else:
                    emit("success", message)
            except (
                OSError,
                UnicodeError,
                ValueError,
                TypeError,
                OverflowError,
                subprocess.TimeoutExpired,
            ) as error:
                emit("error", "证书 " + label + "：到期状态读取失败：" + str(error))
        if not matched:
            emit(
                "info",
                "当前没有需检查到期时间的 TLS 静态证书；Reality 和未启用的 TLS 不适用此检查。",
            )
    sys.stdout.write("READY\0")


def san():
    import ipaddress
    import sys

    try:
        ipaddress.ip_address(sys.argv[1])
        print("IP:" + sys.argv[1])
    except ValueError:
        print("DNS:" + sys.argv[1])


def renew():
    import ipaddress
    import json
    import os
    import pathlib
    import secrets
    import stat
    import subprocess
    import sys
    import tempfile

    config = json.loads(pathlib.Path(sys.argv[1]).read_text())
    root = pathlib.Path(sys.argv[2]).resolve()
    days = sys.argv[3]

    def run(args):
        try:
            result = subprocess.run(["openssl", *args], capture_output=True, text=True, timeout=20)
        except (OSError, subprocess.TimeoutExpired) as error:
            sys.exit("证书续期无法完成：" + str(error))
        return result

    def require(result, message):
        if result.returncode:
            sys.stderr.write(result.stderr)
            sys.exit(message)
        return result.stdout

    candidates = {}
    for index, item in enumerate(config.get("inbounds", [])):
        tls = item.get("tls") or {}
        if not tls.get("enabled") or (tls.get("reality") or {}).get("enabled"):
            continue
        label = str(item.get("type", "未知协议")) + " · " + str(item.get("tag") or "@" + str(index))
        cert_path = tls.get("certificate_path")
        key_path = tls.get("key_path")
        if not cert_path or not key_path or tls.get("certificate") or tls.get("key"):
            print(label + "：跳过内嵌或动态/外部管理的证书。", file=sys.stderr)
            continue
        cert = pathlib.Path(cert_path)
        key = pathlib.Path(key_path)
        try:
            cert_relative = cert.resolve().relative_to(root)
            key_relative = key.resolve().relative_to(root)
        except ValueError:
            print(label + "：跳过托管目录以外的自有证书。", file=sys.stderr)
            continue
        if (
            cert.is_symlink()
            or key.is_symlink()
            or any(
                part.startswith("imported-") for part in (*cert_relative.parts, *key_relative.parts)
            )
        ):
            print(label + "：跳过链接或备份导入的外部证书。", file=sys.stderr)
            continue
        identity = cert.resolve()
        if identity in candidates and candidates[identity]["key"].resolve() != key.resolve():
            sys.exit("同一证书被配置为使用不同私钥，拒绝续期。")
        record = candidates.setdefault(
            identity, {"cert": cert, "key": key, "names": set(), "labels": []}
        )
        if tls.get("server_name"):
            record["names"].add(tls["server_name"])
        record["labels"].append(label)

    renewed = 0
    for record in candidates.values():
        cert, key = record["cert"], record["key"]
        label = " / ".join(record["labels"])
        names = require(
            run(["x509", "-in", str(cert), "-noout", "-subject", "-issuer", "-nameopt", "RFC2253"]),
            "无法读取托管证书：" + str(cert),
        ).splitlines()
        if len(names) != 2 or names[0].partition("=")[2] != names[1].partition("=")[2]:
            print(label + "：跳过 CA 签发的自有证书。", file=sys.stderr)
            continue
        if run(
            ["verify", "-no_check_time", "-check_ss_sig", "-CAfile", str(cert), str(cert)]
        ).returncode:
            print(label + "：无法确认自签签名，保持原证书不变，请手动处理。", file=sys.stderr)
            continue
        public = require(run(["x509", "-in", str(cert), "-pubkey", "-noout"]), "无法读取证书公钥。")
        private_public = require(
            run(["pkey", "-in", str(key), "-passin", "pass:", "-pubout"]),
            "无法读取托管私钥，请检查文件或口令。",
        )
        if public != private_public:
            sys.exit("托管证书与私钥不匹配，拒绝续期：" + str(cert))
        metadata = cert.stat()
        with tempfile.NamedTemporaryFile(
            dir=cert.parent, prefix=".renew-cert-", delete=False
        ) as stream:
            temporary = pathlib.Path(stream.name)
        try:
            require(
                run(
                    [
                        "x509",
                        "-in",
                        str(cert),
                        "-signkey",
                        str(key),
                        "-passin",
                        "pass:",
                        "-days",
                        days,
                        "-set_serial",
                        "0x" + secrets.token_hex(16),
                        "-out",
                        str(temporary),
                    ]
                ),
                "证书续期签名失败。",
            )
            require(
                run(["verify", "-check_ss_sig", "-CAfile", str(temporary), str(temporary)]),
                "续期证书校验失败。",
            )
            for name in record["names"]:
                try:
                    ipaddress.ip_address(name)
                    option = "-verify_ip"
                except ValueError:
                    option = "-verify_hostname"
                require(
                    run(["verify", "-CAfile", str(temporary), option, name, str(temporary)]),
                    "续期证书与现有 SNI 不匹配，拒绝保存。",
                )
            os.chown(temporary, metadata.st_uid, metadata.st_gid)
            os.chmod(temporary, stat.S_IMODE(metadata.st_mode))
            temporary.replace(cert)
        finally:
            temporary.unlink(missing_ok=True)
        renewed += 1
        print(label + "：证书续期已暂存，保留原私钥、SNI 和证书扩展。", file=sys.stderr)
    print(renewed)
