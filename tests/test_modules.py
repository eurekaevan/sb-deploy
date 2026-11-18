"""Direct Python contracts and standalone-release checks, without fake system tools."""

import contextlib
import io
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))
from sb_deploy import backup, certificates, configuration, firewall, hopping, network, nodes
from sb_deploy.bundle import bundle_script


class ModuleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = self.root / "config.json"
        self.data = {"inbounds": [], "outbounds": [], "route": {"final": "direct"}}
        self.save()
        self.env = {"CONFIG": str(self.config), "APP": str(self.root), "SERVER_IP": "8.8.8.8"}

    def save(self):
        self.config.write_text(json.dumps(self.data))

    def invoke(self, function, *args, env=None, stdin=""):
        output = io.StringIO()
        with (
            patch.dict(os.environ, {**self.env, **(env or {})}),
            patch.object(sys, "argv", ["module", *map(str, args)]),
            patch.object(sys, "stdin", io.StringIO(stdin)),
            contextlib.redirect_stdout(output),
        ):
            try:
                function()
            except SystemExit as error:
                if error.code not in (None, 0):
                    raise
        return output.getvalue()

    def test_listener_discovery_follows_network_and_transport(self):
        self.data["inbounds"] = [
            {"type": "hysteria2", "listen_port": 9443},
            {"type": "direct", "tag": "both", "listen_port": 5353},
            {"type": "custom", "tag": "quic", "listen_port": 1234, "transport": {"type": "quic"}},
            {"type": "shadowsocks", "tag": "tcp-only", "listen_port": 7777, "network": "tcp"},
            {"type": "tun", "tag": "no-port"},
        ]
        self.save()
        self.assertEqual(
            self.invoke(configuration.listeners, self.config).splitlines(),
            [
                "udp 9443 Hysteria2",
                "tcp 5353 both",
                "udp 5353 both",
                "udp 1234 quic",
                "tcp 7777 tcp-only",
            ],
        )

    def test_relocating_tls_preserves_external_certificate_paths(self):
        self.data["inbounds"] = [
            {
                "tls": {
                    "certificate_path": str(self.root / "tls/a.crt"),
                    "key_path": "/external/a.key",
                }
            }
        ]
        self.save()
        self.invoke(configuration.relocate_tls, self.config, self.root, self.root / "pending")
        tls = json.loads(self.config.read_text())["inbounds"][0]["tls"]
        self.assertEqual(tls["certificate_path"], str(self.root / "pending/tls/a.crt"))
        self.assertEqual(tls["key_path"], "/external/a.key")

    def test_relocating_tls_rejects_symlink(self):
        link = self.root / "link.json"
        link.symlink_to(self.config)
        with self.assertRaisesRegex(SystemExit, "符号链接"):
            self.invoke(configuration.relocate_tls, link, self.root, self.root / "pending")

    def test_json_pointer_supports_escaped_keys_and_array_append(self):
        self.data = {"a/b": {"~key": [1]}}
        self.save()
        output = self.root / "edited.json"
        self.invoke(
            configuration.edit_field,
            self.config,
            output,
            "/a~1b/~0key/-",
            env={"FIELD_VALUE": "false"},
        )
        self.assertEqual(json.loads(output.read_text()), {"a/b": {"~key": [1, False]}})
        self.assertEqual(json.loads(self.config.read_text()), self.data)

    def test_json_pointer_remove_and_invalid_input(self):
        self.data = {"users": [{"name": "main", "password": "keep"}]}
        self.save()
        output = self.root / "edited.json"
        self.invoke(
            configuration.edit_field,
            self.config,
            output,
            "/users/0/name",
            env={"FIELD_VALUE": ":remove"},
        )
        self.assertEqual(json.loads(output.read_text()), {"users": [{"password": "keep"}]})
        for pointer, value in (
            ("invalid", "1"),
            ("/~2", "1"),
            ("/users/9/name", "null"),
            ("/x", "invalid-json"),
        ):
            with self.subTest(pointer=pointer, value=value), self.assertRaises(SystemExit):
                self.invoke(
                    configuration.edit_field,
                    self.config,
                    output,
                    pointer,
                    env={"FIELD_VALUE": value},
                )

    def test_socks_edit_preserves_unselected_values_and_tfo(self):
        self.data["outbounds"] = [
            {"type": "socks", "tag": "ai-socks", "server": "old", "tcp_fast_open": False},
            {"type": "direct", "tag": "direct"},
        ]
        self.save()
        self.invoke(
            configuration.set_socks,
            "ai",
            env={
                "AI_SOCKS_HOST": "new.example",
                "AI_SOCKS_PORT": "1080",
                "AI_SOCKS_USER": "user",
                "AI_SOCKS_PASS": "空格 $ ' secret",
                "REQUEST_SOCKS_TFO": "",
            },
        )
        updated = json.loads(self.config.read_text())
        self.assertEqual(updated["outbounds"][1], self.data["outbounds"][1])
        self.assertFalse(updated["outbounds"][0]["tcp_fast_open"])
        self.assertEqual(updated["outbounds"][0]["password"], "空格 $ ' secret")
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o600)

    def test_node_summary_reads_current_config_without_cache(self):
        self.data["inbounds"] = [{"type": "tuic", "tag": "custom", "listen_port": 12345}]
        self.save()
        self.assertIn("TUIC：UDP 12345", self.invoke(nodes.run, "summary"))
        self.data["inbounds"][0]["listen_port"] = 23456
        self.save()
        self.assertIn("TUIC：UDP 23456", self.invoke(nodes.run, "summary"))

    def test_field_menu_keeps_unknown_fields_and_escaped_pointer_names(self):
        self.data["inbounds"] = [
            {"type": "custom", "tag": "test", "x/y": True, "nested": {"count": 3}}
        ]
        self.save()
        output = self.invoke(nodes.run, "menu-fields", "test", "")
        self.assertIn("switch:/x~1y\0", output)
        self.assertIn("group:/nested\0", output)

    def test_runtime_summary_requires_matching_service_identity(self):
        (self.root / "runtime-state.json").write_text(
            json.dumps(
                {"identity": "current", "version": "test-version", "summary": "actual state"}
            )
        )
        self.assertIn("actual state", self.invoke(nodes.run, "running-summary", "current"))
        with self.assertRaises(SystemExit):
            self.invoke(nodes.run, "running-summary", "stale")

    def test_firewall_auto_setting_is_private_and_round_trips(self):
        path = self.root / "firewall-settings.json"
        self.assertEqual(self.invoke(firewall.automatic, path, "true", "", self.config), "true\n")
        self.assertEqual(
            self.invoke(firewall.automatic, path, "true", "false", self.config), "false\n"
        )
        self.assertEqual(self.invoke(firewall.automatic, path, "true", "", self.config), "false\n")
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_ssh_parser_uses_actual_nondefault_port_and_refuses_missing_listener(self):
        env = {
            "SSH_LISTENERS": 'LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:(("sshd",pid=1,fd=3))',
            "SSH_EFFECTIVE_CONFIG": "port 22",
            "SSH_CONNECTION": "",
            "SSH_CLIENT": "",
        }
        self.assertEqual(self.invoke(firewall.ssh_listeners, env=env), "4 2222\n")
        with self.assertRaisesRegex(SystemExit, "未检测到"):
            self.invoke(firewall.ssh_listeners, env={**env, "SSH_LISTENERS": ""})

    def test_ufw_parser_preserves_stdin_and_refuses_shadowed_allow(self):
        rules = "[ 1] 443/tcp                    ALLOW IN    Anywhere\n"
        self.assertEqual(
            self.invoke(firewall.ufw_missing, "443/tcp", "9443/udp", stdin=rules), "9443/udp\n"
        )
        rules = "[ 1] Anywhere                    DENY IN    Anywhere\n" + rules
        with self.assertRaisesRegex(SystemExit, "follows a deny"):
            self.invoke(firewall.ufw_missing, "443/tcp", stdin=rules)

    def test_hopping_plan_compacts_ranges_and_excludes_busy_ports(self):
        (self.root / "occupied.txt").write_text("udp UNCONN 0 0 0.0.0.0:20001 0.0.0.0:*\n")
        env = {
            "HOP_SPEC": "20000:20003,30000",
            "HOP_EXCLUDE": "auto",
            "HOP_INTERVAL": "30s",
            "HOP_BACKEND": "nft",
            "HY2_PORT": "9443",
        }
        self.invoke(hopping.prepare, self.root, env=env)
        plan = json.loads((self.root / "hopping-plan.json").read_text())
        self.assertEqual(plan["ports"], ["20000", "20002:20003", "30000"])
        self.assertTrue(plan["enabled"])
        for spec, interval in (
            ("65536", "30s"),
            ("30000:20000", "30s"),
            ("20000", "30s"),
            ("20000:20002", "4s"),
        ):
            with self.subTest(spec=spec, interval=interval), self.assertRaises(SystemExit):
                self.invoke(
                    hopping.prepare,
                    self.root,
                    env={**env, "HOP_SPEC": spec, "HOP_INTERVAL": interval},
                )

    def test_certificate_san_distinguishes_hostname_and_ip(self):
        self.assertEqual(self.invoke(certificates.san, "example.com"), "DNS:example.com\n")
        self.assertEqual(self.invoke(certificates.san, "192.0.2.1"), "IP:192.0.2.1\n")
        self.assertEqual(self.invoke(certificates.san, "2001:db8::1"), "IP:2001:db8::1\n")

    def test_public_ipv4_validation_rejects_private_and_invalid_addresses(self):
        self.invoke(network.public_ipv4, env={"SERVER_IP": "8.8.8.8"})
        for address in ("192.168.1.1", "not-an-ip", "::1"):
            with self.subTest(address=address), self.assertRaises(SystemExit):
                self.invoke(network.public_ipv4, env={"SERVER_IP": address})

    def test_backup_service_state_reads_manifest(self):
        path = self.root / "manifest.json"
        path.write_text(json.dumps({"service": {"active": True, "enabled": False}}))
        self.assertEqual(self.invoke(backup.service_state, path), "yes no\n")

    def test_https_switch_removes_socks_fields_and_preserves_shared_dial_options(self):
        outbound = {
            "type": "socks",
            "tag": "ai-socks",
            "server": "proxy.example",
            "version": "5",
            "udp_over_tcp": {"enabled": True},
            "tcp_fast_open": False,
            "connect_timeout": "9s",
            "bind_interface": "eth0",
        }
        result = configuration.configure_proxy(
            outbound, "AI_SOCKS", {"AI_PROXY_PROTOCOL": "https", "AI_PROXY_SNI": "secure.example"}
        )
        self.assertEqual(result["type"], "http")
        self.assertEqual(
            result["tls"], {"enabled": True, "server_name": "secure.example", "insecure": False}
        )
        self.assertNotIn("version", result)
        self.assertNotIn("udp_over_tcp", result)
        self.assertFalse(result["tcp_fast_open"])
        self.assertEqual(result["connect_timeout"], "9s")
        self.assertEqual(result["bind_interface"], "eth0")
        self.assertEqual(result["tag"], "ai-socks")
        result.update(path="/connect", headers={"X-Test": "value"})
        configuration.configure_proxy(result, "AI_SOCKS", {"AI_PROXY_PROTOCOL": "socks5"})
        self.assertEqual(result["version"], "5")
        self.assertEqual(result["type"], "socks")
        for key in ("tls", "path", "headers"):
            self.assertNotIn(key, result)

    def test_https_edit_preserves_existing_tls_policy_and_other_groups(self):
        tls = {
            "enabled": True,
            "server_name": "secure.example",
            "certificate_path": "/own/ca.pem",
            "insecure": False,
            "handshake_timeout": "8s",
        }
        self.data["outbounds"] = [
            {
                "type": "http",
                "tag": "ai-socks",
                "server": "old.example",
                "server_port": 443,
                "tls": tls,
                "tcp_fast_open": True,
            },
            {
                "type": "socks",
                "tag": "google-socks",
                "server": "google.example",
                "server_port": 1080,
            },
        ]
        self.save()
        self.invoke(
            configuration.set_socks,
            "ai",
            env={
                "AI_SOCKS_HOST": "new.example",
                "AI_SOCKS_PORT": "8443",
                "AI_SOCKS_USER": "",
                "AI_SOCKS_PASS": "",
                "REQUEST_SOCKS_TFO": "",
            },
        )
        updated = json.loads(self.config.read_text())
        self.assertEqual(updated["outbounds"][0]["tls"], tls)
        self.assertEqual(updated["outbounds"][1], self.data["outbounds"][1])
        self.assertEqual(updated["route"], self.data["route"])
        self.assertEqual(updated["outbounds"][0]["server"], "new.example")

    def test_generated_mixed_proxies_keep_routing_and_strict_tls_defaults(self):
        env = {
            "REALITY_DOMAIN": "example.com",
            "VLESS_PORT": "443",
            "HY2_PORT": "9443",
            "UUID": "2cad7241-60e6-4557-89b6-0d32b1930d91",
            "REALITY_PRIVATE": "private",
            "SHORT_ID": "0123456789abcdef",
            "HY2_PASS": "hy2-password",
            "HY2_OBFS_PASS": "obfs-password",
            "HY2_BBR_PROFILE": "standard",
            "SOCKS_TFO": "true",
            "DEFAULT_TLS_HANDSHAKE_TIMEOUT": "10s",
            "AI_URL": "https://example.com/ai.srs",
            "GOOGLE_URL": "https://example.com/google.srs",
            "YOUTUBE_URL": "https://example.com/youtube.srs",
            "ANYTLS_PORT": "",
            "TUIC_PORT": "",
        }
        for group in ("AI", "GOOGLE", "OTHER"):
            env.update(
                {
                    group + "_SOCKS_HOST": group.lower() + ".example",
                    group + "_SOCKS_PORT": "443",
                    group + "_SOCKS_USER": "user",
                    group + "_SOCKS_PASS": "secret",
                    group + "_PROXY_PROTOCOL": "socks5" if group == "GOOGLE" else "https",
                }
            )
        env["AI_PROXY_SNI"] = "custom.example"
        self.invoke(configuration.generate, env=env)
        generated = json.loads(self.config.read_text())
        outbounds = generated["outbounds"][1:]
        self.assertEqual([o["type"] for o in outbounds], ["http", "socks", "http"])
        for outbound in (outbounds[0], outbounds[2]):
            self.assertNotIn("version", outbound)
            self.assertTrue(outbound["tls"]["enabled"])
            self.assertFalse(outbound["tls"]["insecure"])
            self.assertTrue(outbound["tcp_fast_open"])
        self.assertEqual(outbounds[0]["tls"]["server_name"], "custom.example")
        self.assertEqual(outbounds[2]["tls"]["server_name"], "other.example")
        self.assertEqual(generated["route"]["final"], "other-socks")
        self.assertEqual(
            [r["outbound"] for r in generated["route"]["rules"] if r.get("action") == "route"],
            ["google-socks", "ai-socks"],
        )

    def test_mixed_proxy_summary_and_metadata_follow_config_without_credentials(self):
        self.data["outbounds"] = [
            {
                "type": "http",
                "tag": "ai-socks",
                "server": "ai.example",
                "server_port": 443,
                "username": "",
                "password": "",
                "tls": {"enabled": True, "server_name": "secure.example"},
            },
            {
                "type": "socks",
                "tag": "google-socks",
                "server": "google.example",
                "server_port": 1080,
                "username": "user",
                "password": "hidden-password",
            },
            {
                "type": "http",
                "tag": "other-socks",
                "server": "other.example",
                "server_port": 8443,
                "tls": {"enabled": True},
            },
        ]
        self.data["route"] = {
            "final": "other-socks",
            "rules": [
                {"action": "route", "rule_set": ["google"], "outbound": "google-socks"},
                {"action": "route", "rule_set": ["ai"], "outbound": "ai-socks"},
            ],
        }
        self.save()
        output = self.invoke(nodes.run, "summary")
        self.assertIn("3 组独立 SOCKS5 / HTTPS", output)
        self.assertIn("AI → HTTPS ai.example:443", output)
        self.assertIn("其他 → HTTPS other.example:8443", output)
        self.assertNotIn("hidden-password", output)
        values = self.invoke(nodes.run, "proxy", "ai").split("\0")
        self.assertEqual(values[:6], ["ai.example", "443", "", "", "https", "secure.example"])
        self.assertEqual(values[8], "READY")


class PackagingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        source = (ROOT / "sing-box-deploy.sh").read_text()
        self.release = self.root / "standalone.sh"
        self.release.write_text(bundle_script(source, ROOT / "lib/sb_deploy"))

    def run_function(self, script, command, stdin=""):
        library = script.read_text().split('\ncase "${1:')[0]
        entry = self.root / "invoke.sh"
        entry.write_text(library + "\n" + command)
        return subprocess.run(
            ["bash", str(entry)],
            input=stdin,
            text=True,
            capture_output=True,
            cwd=self.root,
            timeout=10,
        )

    def test_release_runs_without_source_tree_and_preserves_stdin(self):
        result = self.run_function(
            self.release,
            "python_module firewall ufw_missing 443/tcp 9443/udp",
            "[ 1] 443/tcp                    ALLOW IN    Anywhere\n",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "9443/udp\n")
        result = self.run_function(self.release, "python_module certificates san 192.0.2.1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "IP:192.0.2.1\n")

    def test_source_and_release_produce_identical_node_summary(self):
        config = self.root / "config.json"
        config.write_text(
            json.dumps(
                {
                    "inbounds": [{"type": "tuic", "tag": "demo", "listen_port": 45678}],
                    "outbounds": [],
                    "route": {},
                }
            )
        )
        command = f"CONFIG={shlex.quote(str(config))}; APP={shlex.quote(str(self.root))}; node_config summary"
        source = ROOT / "sing-box-deploy.sh"
        # Sourcing a string makes BASH_SOURCE unavailable; fix its module root explicitly.
        original = self.run_function(
            source, "PYTHON_ROOT=" + shlex.quote(str(ROOT / "lib")) + "\n" + command
        )
        release = self.run_function(self.release, command)
        self.assertEqual(original.returncode, 0, original.stderr)
        self.assertEqual(release.returncode, 0, release.stderr)
        self.assertEqual(release.stdout, original.stdout)
        self.assertIn("UDP 45678", release.stdout)

    def test_installed_release_can_copy_itself_and_keep_arguments(self):
        output = self.root / "copied.sh"
        result = self.run_function(
            self.release,
            f"python_module bundle build {shlex.quote(str(self.release))} {shlex.quote(str(output))}",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output.read_bytes(), self.release.read_bytes())
        self.assertEqual(output.stat().st_mode & 0o777, 0o700)

    def test_bundle_is_reproducible_and_preserves_source_defaults(self):
        source = (
            (ROOT / "sing-box-deploy.sh")
            .read_text()
            .replace("DEFAULT_HY2_PORT='443'", "DEFAULT_HY2_PORT='9443'")
        )
        first = bundle_script(source, ROOT / "lib/sb_deploy")
        self.assertEqual(first, bundle_script(source, ROOT / "lib/sb_deploy"))
        self.assertIn("DEFAULT_HY2_PORT='9443'", first)
        self.assertEqual(first, bundle_script(first, self.root / "no-modules"))

    def test_release_cli_help_works_without_source_tree(self):
        result = subprocess.run(
            ["bash", str(self.release), "--help"],
            capture_output=True,
            text=True,
            cwd=self.root,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("renew-certs", result.stdout)

    def test_real_distribution_selects_available_package_manager(self):
        # A container has the real distribution tools, but does not run systemd.
        # Isolate only that prerequisite; package detection still uses the real PATH.
        text = self.release.read_text().replace(
            "[[ -d /run/systemd/system ]]", "[[ -d " + shlex.quote(str(self.root)) + " ]]"
        )
        self.release.write_text(text)
        result = self.run_function(self.release, 'check_os; printf "%s\\n" "$PKG"')
        self.assertEqual(result.returncode, 0, result.stderr)
        expected = (
            "apt" if shutil.which("apt-get") else ("dnf5" if shutil.which("dnf5") else "dnf4")
        )
        self.assertEqual(result.stdout.strip(), expected)

    def test_preflight_rejects_missing_systemd_before_package_detection(self):
        text = self.release.read_text().replace(
            "/run/systemd/system", str(self.root / "missing-systemd")
        )
        self.release.write_text(text)
        result = self.run_function(self.release, "check_os")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("using systemd is required", result.stderr)
