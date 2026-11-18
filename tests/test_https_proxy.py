"""Exercise HTTPS proxy probes against local TLS sockets, without external traffic."""

import base64
import contextlib
import importlib.util
import io
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("https_network", ROOT / "lib/sb_deploy/network.py")
network = importlib.util.module_from_spec(spec)
spec.loader.exec_module(network)


class LocalProxy:
    """A one-connection TLS peer that records CONNECT and returns a controlled response."""

    def __init__(self, certificate, key, response=b"HTTP/1.1 200 Connection established\r\n\r\n"):
        self.certificate = certificate
        self.response = response
        self.request = b""
        self.sni = None
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.listener.settimeout(3)
        self.port = self.listener.getsockname()[1]
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(certificate, key)
        self.context.set_alpn_protocols(["http/1.1"])
        self.context.set_servername_callback(self.record_sni)
        self.thread = threading.Thread(target=self.serve, daemon=True)

    def record_sni(self, sock, name, context):
        self.sni = name

    def serve(self):
        try:
            raw, _ = self.listener.accept()
            with raw:
                raw.settimeout(3)
                with self.context.wrap_socket(raw, server_side=True) as sock:
                    while b"\r\n\r\n" not in self.request:
                        data = sock.recv(1024)
                        if not data:
                            return
                        self.request += data
                    if self.response:
                        sock.sendall(self.response)
        except (OSError, ssl.SSLError):
            # Client certificate rejection intentionally terminates the handshake.
            pass

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.listener.close()
        self.thread.join(timeout=4)
        if self.thread.is_alive():
            raise AssertionError("Local TLS proxy did not finish")

    def outbound(self):
        return {
            "type": "http",
            "tag": "custom-https",
            "server": "127.0.0.1",
            "server_port": self.port,
            "username": "user",
            "password": "secret-密码:$",
            "tls": {
                "enabled": True,
                "server_name": "proxy.example",
                "certificate_path": str(self.certificate),
            },
        }


class HttpsProxyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.certificate = cls.root / "proxy.crt"
        cls.key = cls.root / "proxy.key"
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-nodes",
                "-days",
                "2",
                "-subj",
                "/CN=proxy.example",
                "-addext",
                "subjectAltName=DNS:proxy.example",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-keyout",
                str(cls.key),
                "-out",
                str(cls.certificate),
            ],
            check=True,
            capture_output=True,
        )

    def proxy(self, **kwargs):
        return LocalProxy(self.certificate, self.key, **kwargs)

    def test_tls_sni_and_basic_authorization_are_used(self):
        with self.proxy() as proxy:
            outbound = proxy.outbound()
            network.check_https(outbound)
        self.assertEqual(proxy.sni, "proxy.example")
        self.assertTrue(proxy.request.startswith(b"CONNECT example.com:443 HTTP/1.1\r\n"))
        token = base64.b64encode((outbound["username"] + ":" + outbound["password"]).encode())
        self.assertIn(b"Proxy-Authorization: Basic " + token + b"\r\n", proxy.request)
        self.assertNotIn(outbound["password"].encode(), proxy.request)

    def test_inline_ca_and_no_authentication(self):
        with self.proxy() as proxy:
            outbound = proxy.outbound()
            outbound["tls"].pop("certificate_path")
            outbound["tls"]["certificate"] = [self.certificate.read_text()]
            outbound["username"] = outbound["password"] = ""
            network.check_https(outbound)
        self.assertNotIn(b"Proxy-Authorization", proxy.request)

    def test_default_trust_store_is_used_without_disabling_verification(self):
        with (
            self.proxy() as proxy,
            patch.dict(os.environ, {"SSL_CERT_FILE": str(self.certificate)}),
        ):
            outbound = proxy.outbound()
            outbound["tls"].pop("certificate_path")
            network.check_https(outbound)
        self.assertEqual(proxy.sni, "proxy.example")

    def test_custom_ca_replaces_default_roots_and_inline_takes_precedence(self):
        with tempfile.TemporaryDirectory() as directory:
            other = Path(directory) / "unrelated-ca.crt"
            subprocess.run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-newkey",
                    "ec",
                    "-pkeyopt",
                    "ec_paramgen_curve:P-256",
                    "-nodes",
                    "-days",
                    "2",
                    "-subj",
                    "/CN=Unrelated CA",
                    "-addext",
                    "basicConstraints=critical,CA:TRUE",
                    "-keyout",
                    str(Path(directory) / "unrelated-ca.key"),
                    "-out",
                    str(other),
                ],
                check=True,
                capture_output=True,
            )
            # The default store deliberately trusts the proxy. Specifying an unrelated
            # custom CA must replace that store, and inline CA takes precedence over path.
            settings = (
                {"certificate_path": str(other)},
                {"certificate": [other.read_text()], "certificate_path": str(self.certificate)},
            )
            for trust in settings:
                with (
                    self.subTest(trust=trust),
                    self.proxy() as proxy,
                    patch.dict(os.environ, {"SSL_CERT_FILE": str(self.certificate)}),
                ):
                    outbound = proxy.outbound()
                    outbound["tls"].update(trust)
                    with self.assertRaisesRegex(SystemExit, "certificate verification failed"):
                        network.check_https(outbound)
                self.assertEqual(proxy.request, b"")

    def test_untrusted_certificate_fails(self):
        with self.proxy() as proxy:
            outbound = proxy.outbound()
            outbound["tls"].pop("certificate_path")
            with self.assertRaisesRegex(SystemExit, "certificate verification failed"):
                network.check_https(outbound)
        self.assertEqual(proxy.request, b"")

    def test_hostname_mismatch_fails_even_with_trusted_ca(self):
        with self.proxy() as proxy:
            outbound = proxy.outbound()
            outbound["tls"]["server_name"] = "wrong.example"
            with self.assertRaisesRegex(SystemExit, "certificate verification failed"):
                network.check_https(outbound)
        self.assertEqual(proxy.request, b"")

    def test_existing_insecure_policy_is_honored_only_when_explicit(self):
        with self.proxy() as proxy:
            outbound = proxy.outbound()
            outbound["tls"] = {"enabled": True, "server_name": "wrong.example", "insecure": True}
            network.check_https(outbound)
        self.assertNotEqual(proxy.request, b"")

    def test_http_407_reports_status_without_response_or_password(self):
        with self.proxy(response=b"HTTP/1.1 407 echoed-sensitive-response\r\n\r\n") as proxy:
            outbound = proxy.outbound()
            with self.assertRaises(SystemExit) as failure:
                network.check_https(outbound)
        message = str(failure.exception)
        self.assertIn("HTTP 407", message)
        self.assertNotIn("echoed-sensitive-response", message)
        self.assertNotIn(outbound["password"], message)

    def test_malformed_or_closed_response_does_not_leak_server_text(self):
        for response in (b"echoed-sensitive-response\r\n\r\n", b""):
            with self.subTest(response=response), self.proxy(response=response) as proxy:
                with self.assertRaisesRegex(
                    SystemExit, "response is invalid or prematurely closed"
                ) as failure:
                    network.check_https(proxy.outbound())
            self.assertNotIn("echoed-sensitive-response", str(failure.exception))

    def test_unimplemented_tls_and_http_settings_require_manual_check(self):
        for field, value in (
            ("certificate_sha256", ["00" * 32]),
            ("disable_sni", True),
            ("alpn", ["h2"]),
        ):
            outbound = {
                "server": "127.0.0.1",
                "server_port": 1,
                "tls": {"enabled": True, field: value},
            }
            with self.subTest(field=field), self.assertRaisesRegex(SystemExit, "TLS settings|ALPN"):
                network.check_https(outbound)
        for field, value in (
            ("version", 2),
            ("headers", {"X-Example": "test"}),
            ("path", "/proxy"),
        ):
            outbound = {
                "server": "127.0.0.1",
                "server_port": 1,
                "tls": {"enabled": True},
                field: value,
            }
            with self.subTest(field=field), self.assertRaisesRegex(SystemExit, "HTTP|CONNECT path"):
                network.check_https(outbound)

    def test_profile_dispatch_reads_environment_and_preserves_tls_settings(self):
        with self.proxy() as proxy:
            env = {
                "SOCKS_PROFILE": "ai",
                "AI_PROXY_PROTOCOL": "https",
                "AI_PROXY_SNI": "proxy.example",
                "AI_SOCKS_HOST": "127.0.0.1",
                "AI_SOCKS_PORT": str(proxy.port),
                "AI_SOCKS_USER": "user",
                "AI_SOCKS_PASS": "secret",
                "AI_PROXY_TLS": json.dumps(
                    {"certificate_path": str(self.certificate), "min_version": "1.2"}
                ),
            }
            with patch.dict(os.environ, env):
                network.check_proxy()
        self.assertEqual(proxy.sni, "proxy.example")

    def test_profile_dispatch_preserves_http_settings_and_refuses_before_connecting(self):
        env = {
            "SOCKS_PROFILE": "ai",
            "AI_PROXY_PROTOCOL": "https",
            "AI_PROXY_TLS": "{}",
            "AI_SOCKS_HOST": "127.0.0.1",
            "AI_SOCKS_PORT": "443",
            "AI_SOCKS_USER": "user",
            "AI_SOCKS_PASS": "private",
        }
        for settings in ({"headers": {"X-Example": "private"}}, {"path": "/proxy"}, {"version": 2}):
            with (
                self.subTest(settings=settings),
                patch.dict(os.environ, {**env, "AI_PROXY_HTTP": json.dumps(settings)}),
                patch("socket.create_connection") as connect,
            ):
                with self.assertRaisesRegex(SystemExit, "CONNECT path|HTTP/1.1 CONNECT") as failure:
                    network.check_proxy()
                connect.assert_not_called()
                self.assertNotIn("private", str(failure.exception))

    def test_profile_dispatch_rejects_invalid_http_object_or_unknown_fields(self):
        env = {"SOCKS_PROFILE": "ai", "AI_PROXY_PROTOCOL": "https", "AI_PROXY_TLS": "{}"}
        for settings in ("[]", '"text"', '{"server": "private"}', "invalid"):
            with (
                self.subTest(settings=settings),
                patch.dict(os.environ, {**env, "AI_PROXY_HTTP": settings}),
                patch("socket.create_connection") as connect,
            ):
                with self.assertRaisesRegex(SystemExit, "HTTP setting|HTTP settings") as failure:
                    network.check_proxy()
                connect.assert_not_called()
                self.assertNotIn("private", str(failure.exception))

    def test_config_scan_checks_https_and_keeps_socks_record_format(self):
        with self.proxy() as proxy, tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(
                json.dumps(
                    {
                        "outbounds": [
                            proxy.outbound(),
                            {
                                "type": "socks",
                                "tag": "arbitrary",
                                "server": "localhost",
                                "server_port": 1080,
                                "username": "user",
                                "password": "secret",
                            },
                        ],
                        "inbounds": [],
                    }
                )
            )
            output, errors = io.StringIO(), io.StringIO()
            with (
                patch.object(sys, "argv", ["probe", str(path)]),
                contextlib.redirect_stdout(output),
                contextlib.redirect_stderr(errors),
            ):
                network.connection_probes()
        self.assertEqual(
            output.getvalue().split("\0"),
            ['"arbitrary"', "localhost", "1080", "user", "secret", "READY", ""],
        )
        self.assertIn("检查 HTTPS 出口", errors.getvalue())
        self.assertNotIn(proxy.outbound()["password"], errors.getvalue())

    def test_failed_https_scan_does_not_emit_false_ready(self):
        with (
            self.proxy(response=b"HTTP/1.1 407 Authentication required\r\n\r\n") as proxy,
            tempfile.TemporaryDirectory() as directory,
        ):
            path = Path(directory) / "config.json"
            path.write_text(json.dumps({"outbounds": [proxy.outbound()], "inbounds": []}))
            output = io.StringIO()
            with (
                patch.object(sys, "argv", ["probe", str(path)]),
                contextlib.redirect_stdout(output),
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaisesRegex(SystemExit, "407"),
            ):
                network.connection_probes()
        self.assertNotIn("READY", output.getvalue())

    def test_invalid_profile_and_partial_auth_are_rejected_safely(self):
        with patch.dict(os.environ, {"SOCKS_PROFILE": "ai", "AI_PROXY_PROTOCOL": "invalid"}):
            with self.assertRaisesRegex(SystemExit, "Unsupported proxy protocol"):
                network.check_proxy()
        outbound = {
            "server": "127.0.0.1",
            "server_port": 1,
            "username": "invalid:user",
            "password": "private",
            "tls": {"enabled": True},
        }
        with self.assertRaisesRegex(SystemExit, "colon") as failure:
            network.check_https(outbound)
        self.assertNotIn("private", str(failure.exception))
