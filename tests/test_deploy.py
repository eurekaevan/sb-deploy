"""Exercise deployment failures in temporary paths without installing or managing services."""
import ast
import json
import os
import pty
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import threading
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'sing-box-deploy.sh'
SOURCE = SCRIPT.read_text()
LIB = SOURCE[:SOURCE.index('\ncase "${1:')]


class DeployTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.config = self.root / 'etc/sing-box/config.json'
        self.app = self.root / 'deployment'
        self.repo = self.root / 'etc/apt/sources.list.d/sagernet.sources'
        source = LIB.replace('/etc/sing-box', str(self.config.parent))
        source = source.replace('/var/lib/sing-box/deployment', str(self.app))
        source = source.replace('/etc/apt', str(self.root / 'etc/apt'))
        source = source.replace('/usr/local/bin/sb-manager', str(self.root / 'bin/sb-manager'))
        source = source.replace('/etc/systemd/system/sing-box-hopping.service',str(self.root/'units/sing-box-hopping.service'))
        source = source.replace('/var/backups/sing-box-deploy',str(self.root/'backups'))
        self.lib = self.root / 'lib.sh'
        self.lib.write_text(source)
        self.bin = self.root / 'sing-box'
        self.bin.write_text('''#!/bin/bash
if [[ $1 == check ]]; then
  [[ ! -f "$TEST_ROOT/fail-check" ]] || exit 1
elif [[ $1 == generate ]]; then
  printf 'PrivateKey: test-private\\nPublicKey: test-public\\n'
fi
''')
        self.bin.chmod(0o700)
        self.prelude = f'''source {self.lib}
BIN={self.bin}
# Existing fixtures model deployments created before AnyTLS support.
ANYTLS_PORT="${{ANYTLS_PORT_REQUEST:-}}"
need_root() {{ :; }}
sleep() {{ :; }}
systemctl() {{
  echo "$*" >> "$TEST_ROOT/service.log"
  if [[ "$*" == *sing-box-hopping.service* ]]; then
    case "$1" in
      cat) [[ -f "$HOP_UNIT_FILE" ]] ;;
      is-active) [[ -f "$TEST_ROOT/hop-active" ]] ;;
      is-enabled) [[ -f "$TEST_ROOT/hop-enabled" ]] ;;
      enable) touch "$TEST_ROOT/hop-enabled"; if [[ "$*" == *--now* ]]; then hopping_runtime start || return 1; touch "$TEST_ROOT/hop-active"; fi ;;
      disable) rm -f "$TEST_ROOT/hop-enabled"; if [[ "$*" == *--now* ]]; then hopping_runtime stop || return 1; rm -f "$TEST_ROOT/hop-active"; fi ;;
      start) hopping_runtime start || return 1; touch "$TEST_ROOT/hop-active" ;;
      stop) hopping_runtime stop || return 1; rm -f "$TEST_ROOT/hop-active" ;;
    esac
    return
  fi
  case "$1" in
    cat) [[ ! -f "$TEST_ROOT/no-unit" ]] ;;
    is-active) [[ -f "$TEST_ROOT/active" ]] ;;
    is-enabled) if [[ -f "$TEST_ROOT/enabled" ]]; then echo enabled; else echo disabled; return 1; fi ;;
    stop) rm -f "$TEST_ROOT/active" ;;
    restart)
      if [[ -f "$TEST_ROOT/fail-restart" ]]; then rm "$TEST_ROOT/fail-restart"; return 1; fi
      touch "$TEST_ROOT/active" ;;
    enable) touch "$TEST_ROOT/enabled" ;;
    disable) rm -f "$TEST_ROOT/enabled" ;;
    status) [[ -f "$TEST_ROOT/active" ]] ;;
  esac
}}
journalctl() {{ :; }}
ss() {{
  if [[ "$*" == *-ltnp* || "$*" == *-lunp* ]]; then echo 'LISTEN users:(("sing-box",pid=123))'; fi
}}
'''

    def run_bash(self, body, **env):
        return subprocess.run(['bash', '-c', self.prelude + body], text=True, capture_output=True,
                              env={**os.environ, 'TEST_ROOT': str(self.root), **env}, timeout=20)

    def old_config(self):
        self.config.parent.mkdir(parents=True)
        self.config.write_text(json.dumps({'outbounds': [
            {'type': 'socks', 'tag': name+'-socks', 'server': 'old', 'password': 'old', 'tcp_fast_open': True}
            for name in ('ai', 'google')], 'route': {'final': 'direct'}, 'inbounds': [
                {'tag': 'vless-reality', 'listen_port': 443}, {'tag': 'hysteria2', 'listen_port': 443}]}))
        self.config.chmod(0o640)
        (self.app / 'client').mkdir(parents=True)
        (self.app / 'client/node-info.txt').write_text('old client')
        return self.config.read_bytes()

    def update_body(self):
        return '''read_socks_profile() {
  export AI_SOCKS_HOST=new-ai AI_SOCKS_PORT=1080 AI_SOCKS_USER=user AI_SOCKS_PASS=secret
  export GOOGLE_SOCKS_HOST=new-google GOOGLE_SOCKS_PORT=1081 GOOGLE_SOCKS_USER=user GOOGLE_SOCKS_PASS=secret
  export OTHER_SOCKS_HOST=new-other OTHER_SOCKS_PORT=1082 OTHER_SOCKS_USER=user OTHER_SOCKS_PASS=other-secret
}
check_socks() { :; }
show_node_details() { :; }
set_socks_profile ai google
'''

    def test_syntax(self):
        subprocess.run(['bash', '-n', str(SCRIPT)], check=True)
        for marker, block in re.findall(r"<<'(PY(?:CODE)?)'\n(.*?)\n\1", SOURCE, re.S):
            ast.parse(block)

    def test_update_success(self):
        self.old_config()
        result = self.run_bash(self.update_body())
        self.assertEqual(result.returncode, 0, result.stderr)
        out = json.loads(self.config.read_text())['outbounds']
        self.assertEqual([x['server'] for x in out], ['new-ai', 'new-google'])
        self.assertTrue(all(x['tcp_fast_open'] is True for x in out))
        self.assertTrue((self.root / 'active').exists())
        self.assertFalse(list(self.config.parent.glob('.config-*')))

    def test_socks_update_preserves_legacy_omitted_tfo(self):
        self.old_config()
        config=json.loads(self.config.read_text())
        for o in config['outbounds']: o.pop('tcp_fast_open')
        self.config.write_text(json.dumps(config))
        result=self.run_bash(self.update_body())
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertTrue(all('tcp_fast_open' not in o for o in json.loads(self.config.read_text())['outbounds']))

    def test_socks_tfo_can_be_disabled(self):
        self.old_config()
        result = self.run_bash(self.update_body(), SOCKS_TFO='false')
        self.assertEqual(result.returncode, 0, result.stderr)
        out = json.loads(self.config.read_text())['outbounds']
        self.assertTrue(all(o['tcp_fast_open'] is False for o in out))

    def test_invalid_tfo_option_rejected_before_changes(self):
        original = self.old_config()
        result = self.run_bash(self.update_body(), SOCKS_TFO='invalid')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.config.read_bytes(), original)
        self.assertIn('SOCKS_TFO must be true or false', result.stderr)

    def test_other_socks_migrates_existing_dual_profile_config(self):
        self.old_config()
        info = self.app / 'client/node-info.txt'
        info.write_text('Everything else: direct; private IPs rejected\n')
        result = self.run_bash(self.update_body().replace('set_socks_profile ai google', 'set_socks_profile other'))
        self.assertEqual(result.returncode, 0, result.stderr)
        config = json.loads(self.config.read_text())
        self.assertEqual(config['route']['final'], 'other-socks')
        self.assertEqual([o['server'] for o in config['outbounds']], ['old', 'old', 'new-other'])
        self.assertEqual(config['outbounds'][2]['password'], 'other-secret')
        self.assertIs(config['outbounds'][2]['tcp_fast_open'], True)
        self.assertIn('Everything else: Other SOCKS5', info.read_text())

    def test_configure_all_three_profiles(self):
        self.old_config()
        result = self.run_bash(self.update_body().replace('set_socks_profile ai google', 'set_socks_profile ai google other'))
        self.assertEqual(result.returncode, 0, result.stderr)
        config = json.loads(self.config.read_text())
        self.assertEqual([o['server'] for o in config['outbounds']], ['new-ai', 'new-google', 'new-other'])
        self.assertEqual(config['route']['final'], 'other-socks')
        # Updating an existing Other outbound must not append a duplicate.
        result = self.run_bash(self.update_body().replace('set_socks_profile ai google', 'set_socks_profile other'))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(json.loads(self.config.read_text())['outbounds']), 3)

    def test_other_migration_failure_restores_config_and_summary(self):
        original = self.old_config()
        info = self.app / 'client/node-info.txt'
        info.write_text('Everything else: direct; private IPs rejected\n')
        (self.root / 'fail-restart').touch()
        result = self.run_bash(self.update_body().replace('set_socks_profile ai google', 'set_socks_profile other'))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.config.read_bytes(), original)
        self.assertEqual(info.read_text(), 'Everything else: direct; private IPs rejected\n')

    def test_source_defaults_and_environment_precedence(self):
        source = self.lib.read_text()
        for key, value in [('HOST', 'source.example'), ('PORT', '1080'), ('USER', 'source-user'), ('PASS', 'source-pass')]:
            source = source.replace(f"DEFAULT_OTHER_SOCKS_{key}=''", f"DEFAULT_OTHER_SOCKS_{key}='{value}'")
        source = source.replace("DEFAULT_SERVER_IP=''", "DEFAULT_SERVER_IP='8.8.8.8'")
        self.lib.write_text(source)
        body = '''read_socks_profile other
python3 - <<'PYOUT'
import json, os
print(json.dumps([os.environ['OTHER_SOCKS_'+k] for k in ('HOST','PORT','USER','PASS')]))
PYOUT
printf '%s' "$SERVER_IP"
'''
        result = self.run_bash(body)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout.splitlines()[0]), ['source.example','1080','source-user','source-pass'])
        self.assertTrue(result.stdout.endswith('8.8.8.8'))
        result = self.run_bash(body, OTHER_SOCKS_HOST='env.example', OTHER_SOCKS_PORT='01081',
                               OTHER_SOCKS_USER='env-user', OTHER_SOCKS_PASS='env-pass', SERVER_IP='1.1.1.1')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout.splitlines()[0]), ['env.example','1081','env-user','env-pass'])
        self.assertTrue(result.stdout.endswith('1.1.1.1'))
        self.assertNotIn('source-pass', result.stderr)
        self.assertNotIn('env-pass', result.stderr)
        result = self.run_bash(body, OTHER_SOCKS_HOST='')
        self.assertNotEqual(result.returncode, 0)

    def test_update_restart_failure_restores_active_service(self):
        original = self.old_config()
        (self.root / 'active').touch()
        (self.root / 'fail-restart').touch()
        result = self.run_bash(self.update_body())
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.config.read_bytes(), original)
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o640)
        self.assertTrue((self.root / 'active').exists())
        self.assertIn('Rollback completed', result.stderr)

    def test_update_validation_failure_restores_inactive_service(self):
        original = self.old_config()
        self.bin.write_text('''#!/bin/bash
if [[ -f "$TEST_ROOT/checked" ]]; then exit 1; fi
touch "$TEST_ROOT/checked"
''')
        result = self.run_bash(self.update_body())
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.config.read_bytes(), original)
        self.assertFalse((self.root / 'active').exists())

    def test_install_rollback_restores_repo_and_removes_new_files(self):
        self.repo.parent.mkdir(parents=True)
        self.repo.write_text('original repo')
        body = f'''begin_transaction install {self.config.parent} "$APP" {self.repo}
mkdir -p {self.config.parent} "$APP/client"
echo new > "$CONFIG"
echo generated > "$APP/client/new"
echo changed > {self.repo}
touch "$TEST_ROOT/active" "$TEST_ROOT/enabled"
die 'injected install failure'
'''
        result = self.run_bash(body)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.config.parent.exists())
        self.assertFalse(self.app.exists())
        self.assertEqual(self.repo.read_text(), 'original repo')
        self.assertFalse((self.root / 'active').exists())
        self.assertFalse((self.root / 'enabled').exists())

    def test_update_display_failure_rolls_back(self):
        original = self.old_config()
        result = self.run_bash(self.update_body().replace('show_node_details() { :; }',
                                                        'show_node_details() { return 1; }'))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.config.read_bytes(), original)
        self.assertFalse((self.root / 'active').exists())

    def test_symlink_snapshot_rejected_before_mutation(self):
        target = self.root / 'actual-config'
        target.write_text('original')
        self.config.parent.mkdir(parents=True)
        self.config.symlink_to(target)
        result = self.run_bash('begin_transaction update "$CONFIG"\necho changed > "$CONFIG"')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(target.read_text(), 'original')
        self.assertTrue(self.config.is_symlink())

    def test_install_retry_with_retained_package_without_config_directory(self):
        body = '''check_os() { PKG=apt; }
read_socks_profile() { :; }
install_deps() { :; }
check_socks() { :; }
ss() { :; }
public_ipv4() { :; }
check_reality_target() { :; }
install_sing_box_official() { :; }
download_rules() { die 'injected download failure'; }
fresh_install
'''
        for _ in range(2):
            result = self.run_bash(body)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('injected download failure', result.stderr)
            self.assertNotIn('No such file or directory', result.stderr)
            self.assertFalse(self.config.parent.exists())
            self.assertFalse(self.app.exists())

    def test_status_reports_failure(self):
        self.old_config()
        (self.root / 'active').touch()
        body = '''ss() { echo 'LISTEN users:(("sing-box",pid=123))'; }
firewall_hints() { :; }
status_cmd
'''
        result = self.run_bash(body)
        self.assertEqual(result.returncode, 0, result.stderr)
        (self.root / 'fail-check').touch()
        result = self.run_bash(body)
        self.assertNotEqual(result.returncode, 0)
        (self.root / 'fail-check').unlink()
        result = self.run_bash(body.replace('status_cmd\n', 'ss() { :; }\nstatus_cmd\n'))
        self.assertNotEqual(result.returncode, 0)

    def test_exit_signal_rolls_back(self):
        original = self.old_config()
        result = self.run_bash('begin_transaction update "$CONFIG"\necho changed > "$CONFIG"\nkill -TERM $$\n')
        self.assertEqual(result.returncode, 143)
        self.assertEqual(self.config.read_bytes(), original)

    def test_failed_restore_retains_backup(self):
        original = self.old_config()
        result = self.run_bash('''begin_transaction update "$CONFIG"
printf '%s' "$TEMP" > "$TEST_ROOT/backup-path"
echo changed > "$CONFIG"
cp() { return 1; }
die 'injected failure'
''')
        self.assertNotEqual(result.returncode, 0)
        backup = Path((self.root / 'backup-path').read_text())
        self.addCleanup(lambda: subprocess.run(['rm', '-rf', str(backup)], check=True))
        self.assertEqual((backup / '0').read_bytes(), original)
        self.assertIn('Rollback incomplete', result.stderr)

    def test_hy2_generation_and_certificate(self):
        self.config.parent.mkdir(parents=True)
        (self.app / 'tls').mkdir(parents=True)
        (self.app / 'client').mkdir()
        result = self.run_bash('''VLESS_PORT=8443
HY2_PORT=9443
read_ports
export SERVER_IP=8.8.8.8
export AI_SOCKS_HOST=localhost AI_SOCKS_PORT=1080 AI_SOCKS_USER=user AI_SOCKS_PASS=secret
export GOOGLE_SOCKS_HOST=localhost GOOGLE_SOCKS_PORT=1081 GOOGLE_SOCKS_USER=user GOOGLE_SOCKS_PASS=secret
export OTHER_SOCKS_HOST=localhost OTHER_SOCKS_PORT=1082 OTHER_SOCKS_USER=user OTHER_SOCKS_PASS=other-secret
new_credentials
make_hy2_certificate
write_jsons
show_node_details
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        config = json.loads(self.config.read_text())
        self.assertEqual(config['inbounds'][0]['listen_port'], 8443)
        self.assertEqual(config['inbounds'][1]['listen_port'], 9443)
        self.assertEqual(config['inbounds'][0]['tls']['reality']['handshake']['server_port'], 443)
        self.assertIn(':8443?', result.stdout)
        self.assertIn('UDP 监听端口：9443', result.stdout)
        vless = json.loads((self.app / 'client/vless-reality.outbound.json').read_text())
        self.assertEqual(vless['server_port'], 8443)
        summary = (self.app / 'client/node-info.txt').read_text()
        self.assertIn('TCP 端口：8443', summary)
        self.assertIn('UDP 监听端口：9443', summary)
        self.assertEqual(config['route']['final'], 'other-socks')
        routed = [r['outbound'] for r in config['route']['rules'] if r['action'] == 'route']
        self.assertEqual(routed, ['google-socks', 'ai-socks'])
        other = next(o for o in config['outbounds'] if o['tag'] == 'other-socks')
        self.assertEqual(other['password'], 'other-secret')
        self.assertTrue(all(o['tcp_fast_open'] is True for o in config['outbounds'] if o['type'] == 'socks'))
        self.assertTrue(all(r['http_client']['detour'] == 'direct' for r in config['route']['rule_set']))
        self.assertNotIn('other-secret', result.stdout)
        self.assertIn('else Other SOCKS5.', result.stdout)
        server = config['inbounds'][1]
        self.assertEqual(server['bbr_profile'],'standard')
        client = json.loads((self.app / 'client/hysteria2.outbound.json').read_text())
        self.assertEqual(client['server_port'], 9443)
        self.assertEqual(server['obfs'], client['obfs'])
        self.assertEqual(client['obfs']['type'], 'salamander')
        self.assertEqual(len(client['obfs']['password']), 48)
        self.assertNotEqual(client['obfs']['password'], client['password'])
        self.assertEqual(server['tls']['server_name'], 'la.mirrors.clouvider.net')
        self.assertEqual(client['tls']['server_name'], server['tls']['server_name'])
        self.assertFalse(client['tls']['insecure'])
        self.assertEqual(client['tls']['certificate'], (self.app / 'tls/hy2.crt').read_text())
        self.assertIn(client['obfs']['password'], result.stdout)

    def test_clash_yaml_exports_secure_nodes_and_escapes_passwords(self):
        config = self.managed_node()
        password = 'Mixed: #"\\Pass\n中文\u0085\u2028'
        config['inbounds'][1]['users'][0]['password'] = password
        self.config.write_text(json.dumps(config))
        result = self.run_bash('node_config export\nnode_config export-yaml\nnode_config show')
        self.assertEqual(result.returncode, 0, result.stderr)
        text = (self.app/'client/proxies.yaml').read_text()
        self.assertTrue(text.startswith('proxies:\n  - name:'))
        self.assertNotIn('\x1b', text)
        self.assertIn(text, result.stdout)
        self.assertIn(text, (self.app/'client/node-info.txt').read_text())
        scalars = {}
        for line in text.splitlines():
            key, _, value = line.strip().removeprefix('- ').partition(': ')
            if value:
                scalars[key] = json.loads(value)
        self.assertEqual(scalars['password'], password)
        self.assertEqual(scalars['type'], 'hysteria2')
        self.assertEqual(scalars['port'], 9443)
        self.assertEqual(scalars['obfs'], 'salamander')
        self.assertFalse(scalars['skip-cert-verify'])
        import hashlib, ssl
        cert = (self.app/'tls/hy2.crt').read_text()
        self.assertEqual(scalars['fingerprint'], hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert)).hexdigest())
        self.assertEqual((self.app/'client/proxies.yaml').stat().st_mode & 0o777, 0o600)
        result = self.run_bash('node_config yaml')
        self.assertEqual(result.stdout, text)
        self.assertNotIn('other-secret', text)

    def test_clash_yaml_hopping_conversion_and_disable(self):
        self.managed_node()
        path = self.app/'hopping.json'
        for interval, seconds in [('10s',10),('5500ms',6),('1m',60),('1.5h',5400)]:
            path.write_text(json.dumps({'version':1,'base_port':9443,'enabled':True,
                                       'ports':['20000:20005','30000'],'hop_interval':interval}))
            result = self.run_bash('node_config export\nnode_config export-yaml\nnode_config show')
            self.assertEqual(result.returncode, 0, result.stderr)
            text = (self.app/'client/proxies.yaml').read_text()
            self.assertIn('ports: "20000-20005,30000"', text)
            self.assertIn(f'hop-interval: {seconds}\n', text)
            if interval == '5500ms':
                self.assertIn('向上取整为 6 秒', result.stdout)
            client = json.loads((self.app/'client/hysteria2.outbound.json').read_text())
            self.assertEqual(client['hop_interval'], interval)
        path.unlink()
        result = self.run_bash('node_config export\nnode_config export-yaml')
        self.assertEqual(result.returncode, 0, result.stderr)
        text = (self.app/'client/proxies.yaml').read_text()
        self.assertNotIn('hop-interval:', text)
        self.assertNotIn('    ports:', text)

    def test_output_colors_require_terminal_and_leave_yaml_plain(self):
        self.managed_node()
        body = "ui title '标题'\nmenu_choices ' 1. 安装\\n13. 卸载\\n'\nnode_config show"
        result = self.run_bash(body, TERM='xterm')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('\x1b', result.stdout)
        for overrides, colored in [({},True),({'NO_COLOR':''},False),({'TERM':'dumb'},False)]:
            master, slave = pty.openpty()
            env = {**os.environ,'TEST_ROOT':str(self.root),'TERM':'xterm'}
            env.pop('NO_COLOR',None)
            env.update(overrides)
            try:
                proc = subprocess.Popen(['bash','-c',self.prelude+body],stdout=slave,stderr=subprocess.PIPE,env=env)
                os.close(slave)
                slave = None
                chunks = []
                while True:
                    try:
                        chunk = os.read(master,65536)
                    except OSError as exc:
                        import errno
                        if exc.errno != errno.EIO:
                            raise
                        break
                    if not chunk:
                        break
                    chunks.append(chunk)
                _, err = proc.communicate(timeout=20)
                self.assertEqual(proc.returncode,0,err.decode())
                out = b''.join(chunks).decode().replace('\r\n','\n')
                self.assertEqual('\x1b[' in out, colored)
                self.assertNotIn('\x1b', out.split('proxies:\n',1)[1])
                if colored:
                    self.assertIn('\x1b[1;31m13. 卸载\x1b[0m',out)
                    self.assertIn('\x1b[1;33mPassword:',out)
            finally:
                os.close(master)
                if slave is not None:
                    os.close(slave)

    def test_yaml_file_export_is_optional_and_never_required_by_updates(self):
        self.managed_node()
        path = self.app/'client/proxies.yaml'
        self.assertFalse(path.exists())
        for body in ('node_config show','export_nodes','set_node credentials'):
            result = self.run_bash(body, NEW_HY2_PASS='changed-password')
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn('proxies:',result.stdout)
            self.assertFalse(path.exists())
        target = self.root/'unrelated';target.write_text('keep')
        path.symlink_to(target)
        result = self.run_bash('set_node credentials',NEW_HY2_PASS='changed-again')
        self.assertEqual(result.returncode,0,result.stderr)
        result = self.run_bash('node_config export-yaml')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(target.read_text(),'keep')
        path.unlink()
        result = self.run_bash('node_config export-yaml')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(path.stat().st_mode&0o777,0o600)

    def test_anytls_generation_has_independent_password_certificate_and_clients(self):
        import base64, hashlib, ssl
        config = self.managed_node(anytls=True)
        a = config['inbounds'][2];h = config['inbounds'][1]
        self.assertEqual(a['type'],'anytls')
        self.assertEqual(a['listen_port'],10443)
        self.assertEqual(len(base64.b64decode(a['users'][0]['password'],validate=True)),32)
        self.assertNotEqual(a['users'][0]['password'],h['users'][0]['password'])
        cert = (self.app/'tls/anytls.crt').read_text()
        self.assertNotEqual(cert,(self.app/'tls/hy2.crt').read_text())
        client = json.loads((self.app/'client/anytls.outbound.json').read_text())
        self.assertEqual(client['password'],a['users'][0]['password'])
        self.assertEqual(client['tls']['certificate'],cert)
        self.assertFalse(client['tls']['insecure'])
        result = self.run_bash('node_config show\nnode_config json')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('anytls://',result.stdout)
        self.assertIn('type: "anytls"',result.stdout)
        pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert)).hexdigest()
        self.assertIn('fingerprint: "'+pin+'"',result.stdout)
        self.assertFalse((self.app/'client/proxies.yaml').exists())

    def test_anytls_add_to_legacy_preserves_existing_protocols_and_opens_owned_port(self):
        original = self.managed_node()
        self.setup_firewall('ufw',ufw=['ALLOW 22/tcp'])
        result = self.run_bash('set_node add-anytls',ANYTLS_PORT='10443',NEW_ANYTLS_PASS='Mixed: #"/Pass',NEW_ANYTLS_SNI='any.example.com')
        self.assertEqual(result.returncode,0,result.stderr)
        config = json.loads(self.config.read_text())
        self.assertEqual(config['inbounds'][:2],original['inbounds'])
        self.assertEqual(config['outbounds'],original['outbounds'])
        self.assertEqual(config['inbounds'][2]['users'][0]['password'],'Mixed: #"/Pass')
        self.assertEqual(config['inbounds'][2]['tls']['server_name'],'any.example.com')
        self.assertEqual(json.loads(self.firewall_state.read_text())['ufw'],['ALLOW 10443/tcp','ALLOW 22/tcp'])
        ledger = json.loads((self.app/'firewall-owned.json').read_text())
        self.assertEqual([(r['proto'],r['port']) for r in ledger],[('tcp',10443)])
        result = self.run_bash('set_node add-anytls')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(json.loads(self.config.read_text()),config)

    def test_anytls_add_failure_and_invalid_inputs_leave_legacy_unchanged(self):
        self.managed_node()
        self.setup_firewall('ufw',ufw=['ALLOW 22/tcp'])
        before = self.file_snapshot()
        for env in ({'ANYTLS_PORT':'8443'},{'ANYTLS_PORT':'70000'},
                    {'ANYTLS_PORT':'10443','NEW_ANYTLS_SNI':'bad/domain'},
                    {'ANYTLS_PORT':'10443','NEW_ANYTLS_PASS':''}):
            result = self.run_bash('set_node add-anytls',**env)
            self.assertNotEqual(result.returncode,0)
            self.assertEqual(self.file_snapshot(),before)
        result = self.run_bash('ss() { echo occupied; }; set_node add-anytls',ANYTLS_PORT='10443')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(self.file_snapshot(),before)
        (self.root/'active').touch();(self.root/'fail-restart').touch()
        result = self.run_bash('set_node add-anytls',ANYTLS_PORT='10443')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(self.file_snapshot(),before)
        self.assertEqual(json.loads(self.firewall_state.read_text())['ufw'],['ALLOW 22/tcp'])
        self.assertTrue((self.root/'active').exists())

    def test_anytls_edit_ports_sni_password_and_rotation(self):
        original = self.managed_node(anytls=True)
        self.setup_firewall('ufw')
        result = self.run_bash('load_node_settings\nbegin_transaction update "$APP/firewall-owned.json"\nopen_firewall\nupdate_firewall_ownership\nTRANSACTION=""')
        self.assertEqual(result.returncode,0,result.stderr)
        result = self.run_bash('set_node ports',ANYTLS_PORT='10444')
        self.assertEqual(result.returncode,0,result.stderr)
        state = json.loads(self.firewall_state.read_text())
        self.assertEqual(set(state['ufw']),{'ALLOW 8443/tcp','ALLOW 9443/udp','ALLOW 10444/tcp'})
        hycert = (self.app/'tls/hy2.crt').read_bytes()
        acert = (self.app/'tls/anytls.crt').read_bytes()
        for body,env in [('set_node sni',{'NEW_ANYTLS_SNI':'new-any.example.com'}),
                         ('set_node credentials',{'NEW_ANYTLS_PASS':'中文: #"\\pass/?'} )]:
            result = self.run_bash(body,**env)
            self.assertEqual(result.returncode,0,result.stderr)
        current = json.loads(self.config.read_text())
        self.assertEqual(current['inbounds'][:2],original['inbounds'][:2])
        self.assertEqual((self.app/'tls/hy2.crt').read_bytes(),hycert)
        self.assertNotEqual((self.app/'tls/anytls.crt').read_bytes(),acert)
        client = json.loads((self.app/'client/anytls.outbound.json').read_text())
        self.assertEqual(client['server_port'],10444)
        self.assertEqual(client['tls']['server_name'],'new-any.example.com')
        self.assertEqual(client['password'],'中文: #"\\pass/?')
        result = self.run_bash('set_node rotate')
        self.assertEqual(result.returncode,0,result.stderr)
        rotated = json.loads(self.config.read_text())
        self.assertNotEqual(rotated['inbounds'][2]['users'],current['inbounds'][2]['users'])
        before = self.file_snapshot()
        result = self.run_bash('set_node ports',ANYTLS_PORT='8443')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(self.file_snapshot(),before)

    def test_anytls_backup_restore_and_restoring_legacy_retires_only_owned_anytls_port(self):
        original = self.managed_node()
        self.setup_firewall('ufw',ufw=['ALLOW 22/tcp'])
        legacy = self.root/'legacy.tar.gz';modern = self.root/'modern.tar.gz'
        result = self.run_bash(f'backup_cmd "{legacy}"\nset_node add-anytls\nbackup_cmd "{modern}"',ANYTLS_PORT='10443')
        self.assertEqual(result.returncode,0,result.stderr)
        enabled = self.file_snapshot()
        expected = json.loads(self.config.read_text())
        result = self.run_bash(f'restore_backup "{legacy}"')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(self.config.read_text()),original)
        self.assertFalse((self.app/'tls/anytls.key').exists())
        self.assertFalse((self.app/'client/anytls.outbound.json').exists())
        self.assertNotIn('ALLOW 10443/tcp',json.loads(self.firewall_state.read_text())['ufw'])
        self.assertIn('ALLOW 22/tcp',json.loads(self.firewall_state.read_text())['ufw'])
        result = self.run_bash(f'restore_backup "{modern}"')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(self.config.read_text()),expected)
        self.assertEqual((self.app/'tls/anytls.key').read_bytes(),enabled['deployment/tls/anytls.key'])
        self.assertIn('ALLOW 10443/tcp',json.loads(self.firewall_state.read_text())['ufw'])

    def test_anytls_status_reports_deployed_port_and_detects_missing_listener(self):
        self.managed_node(anytls=True)
        (self.root/'active').touch()
        result = self.run_bash('status_cmd',ANYTLS_PORT='29999')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('AnyTLS TCP 10443',result.stdout)
        result = self.run_bash('''ss() {
  if [[ "$*" != *10443* ]]; then echo 'LISTEN users:(("sing-box",pid=123))'; fi
}
status_cmd
''')
        self.assertNotEqual(result.returncode,0)
        self.assertIn('AnyTLS TCP 10443',result.stdout)

    def test_firewall_retirement_keeps_tcp_port_reused_by_anytls(self):
        self.managed_node(anytls=True)
        self.setup_firewall('ufw')
        result = self.run_bash('''load_node_settings
begin_transaction update "$APP/firewall-owned.json"
open_firewall
update_firewall_ownership
TRANSACTION=""
''')
        self.assertEqual(result.returncode,0,result.stderr)
        result = self.run_bash('''VLESS_PORT=10443
HY2_PORT=9443
ANYTLS_PORT=10444
begin_transaction update "$APP/firewall-owned.json"
open_firewall 8443 9443 10443
update_firewall_ownership 8443 9443 10443
TRANSACTION=""
''')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(set(json.loads(self.firewall_state.read_text())['ufw']),
                         {'ALLOW 10443/tcp','ALLOW 10444/tcp','ALLOW 9443/udp'})

    def check_single_protocol_regeneration(self, protocol):
        original = self.managed_node(anytls=True)
        self.bin.write_text(self.bin.read_text().replace('test-private','new-private').replace('test-public','new-public'))
        hop = {'version':1,'enabled':True,'backend':'nft','base_port':9443,
               'ports':['20000:20005'],'hop_interval':'10s'}
        (self.app/'hopping.json').write_text(json.dumps(hop))
        (self.app/'client/proxies.yaml').write_text('manually exported YAML')
        for name in ('vless-reality','hysteria2','anytls'):
            path = self.app/f'client/{name}.outbound.json'
            client = json.loads(path.read_text());client['test-sentinel'] = name
            path.write_text(json.dumps(client))
        before = self.file_snapshot()
        result = self.run_bash(f'''open_firewall() {{ die 'must not change firewall'; }}
set_node regenerate {protocol}
''',VLESS_PORT='29999',HY2_PORT='29998',ANYTLS_PORT='29997')
        self.assertEqual(result.returncode,0,result.stderr)
        current = json.loads(self.config.read_text())
        tag = 'vless-reality' if protocol=='vless' else protocol
        changed = next(i for i in current['inbounds'] if i['tag']==tag)
        old = next(i for i in original['inbounds'] if i['tag']==tag)
        self.assertNotEqual(changed['users'],old['users'])
        self.assertEqual(changed['listen_port'],old['listen_port'])
        self.assertEqual(changed['tls']['server_name'],old['tls']['server_name'])
        expected = json.loads(json.dumps(original))
        expected['inbounds'][original['inbounds'].index(old)] = changed
        self.assertEqual(current,expected)
        allowed = {'etc/sing-box/config.json','deployment/client/node-info.txt','deployment/client/nodes.txt',
                   f'deployment/client/{tag}.outbound.json'}
        if protocol=='vless':
            self.assertNotEqual(changed['tls']['reality']['private_key'],old['tls']['reality']['private_key'])
            self.assertNotEqual(changed['tls']['reality']['short_id'],old['tls']['reality']['short_id'])
            client = json.loads((self.app/'client/vless-reality.outbound.json').read_text())
            self.assertEqual(client['tls']['reality']['public_key'],'new-public')
        else:
            stem = 'hy2' if protocol=='hysteria2' else 'anytls'
            allowed |= {f'deployment/tls/{stem}.crt',f'deployment/tls/{stem}.key',f'deployment/client/{stem}.crt'}
            for suffix in ('crt','key'):
                self.assertNotEqual((self.app/f'tls/{stem}.{suffix}').read_bytes(),before[f'deployment/tls/{stem}.{suffix}'])
            client = json.loads((self.app/f'client/{tag}.outbound.json').read_text())
            self.assertEqual(client['password'],changed['users'][0]['password'])
            self.assertEqual(client['tls']['certificate'],(self.app/f'tls/{stem}.crt').read_text())
            self.assertFalse(client['tls']['insecure'])
            if protocol=='hysteria2':
                self.assertNotEqual(changed['obfs'],old['obfs'])
                self.assertEqual(client['server_ports'],hop['ports'])
                self.assertEqual(client['hop_interval'],hop['hop_interval'])
        after = self.file_snapshot()
        self.assertEqual(set(after),set(before))
        for path,data in before.items():
            if path not in allowed: self.assertEqual(after[path],data,path)
        self.assertIn('proxies:',result.stdout)
        self.assertIn('restart sing-box.service',(self.root/'service.log').read_text())

    def test_regenerate_vless_only(self): self.check_single_protocol_regeneration('vless')
    def test_regenerate_hysteria2_only(self): self.check_single_protocol_regeneration('hysteria2')
    def test_regenerate_anytls_only(self): self.check_single_protocol_regeneration('anytls')

    def test_regenerate_restart_failure_restores_all_credentials_certificates_and_exports(self):
        self.managed_node(anytls=True)
        (self.root/'active').touch()
        original = self.file_snapshot()
        for protocol in ('vless','hysteria2','anytls'):
            (self.root/'fail-restart').touch()
            result = self.run_bash(f'set_node regenerate {protocol}')
            self.assertNotEqual(result.returncode,0)
            self.assertEqual(self.file_snapshot(),original)
            self.assertTrue((self.root/'active').exists())
            self.assertIn('Rollback completed',result.stderr)

    def test_regenerate_legacy_rejects_missing_anytls_or_invalid_protocol_without_mutation(self):
        self.managed_node()
        before = self.file_snapshot()
        for protocol in ('','anytls','unsupported'):
            result = self.run_bash(f'set_node regenerate {protocol}')
            self.assertNotEqual(result.returncode,0)
            self.assertEqual(self.file_snapshot(),before)
        result = self.run_bash('set_node regenerate hysteria2')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(len(json.loads(self.config.read_text())['inbounds']),2)
        self.assertFalse((self.app/'client/anytls.outbound.json').exists())

    def test_regenerate_external_certificate_is_rejected_before_changes(self):
        original = self.managed_node(anytls=True)
        external = self.root/'external.crt';external.write_text('external certificate')
        for protocol,index in [('hysteria2',1),('anytls',2)]:
            config = json.loads(json.dumps(original))
            config['inbounds'][index]['tls']['certificate_path'] = str(external)
            self.config.write_text(json.dumps(config))
            before = self.file_snapshot()
            result = self.run_bash(f'set_node regenerate {protocol}')
            self.assertNotEqual(result.returncode,0)
            self.assertIn('外部路径',result.stderr)
            self.assertEqual(self.file_snapshot(),before)
            self.assertEqual(external.read_text(),'external certificate')

    def test_regenerate_interactive_selection_and_cancellation(self):
        self.managed_node(anytls=True)
        before = self.file_snapshot()
        for inputs in ('0\n','1\nNO\n'):
            result = self.run_terminal('set_node regenerate',inputs)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(self.file_snapshot(),before)
        result = self.run_terminal('set_node regenerate','3\nYES\n')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('AnyTLS',result.stdout)
        old = json.loads(before['etc/sing-box/config.json'])
        new = json.loads(self.config.read_text())
        self.assertEqual(new['inbounds'][:2],old['inbounds'][:2])
        self.assertNotEqual(new['inbounds'][2]['users'],old['inbounds'][2]['users'])

    def test_pending_protocol_edits_do_not_touch_live_files_or_service(self):
        original = self.managed_node()
        before = self.file_snapshot()
        result = self.run_bash('stage_changes set_node add-anytls',ANYTLS_PORT='10443')
        self.assertEqual(result.returncode,0,result.stderr)
        pending = self.app/'pending'
        current = self.file_snapshot()
        self.assertEqual({p:data for p,data in current.items() if not p.startswith('deployment/pending/')},before)
        self.assertFalse((self.root/'service.log').exists())
        config = json.loads((pending/'config.json').read_text())
        self.assertEqual([i['type'] for i in config['inbounds']],['vless','hysteria2','anytls'])
        self.assertTrue(all(i['tls']['certificate_path'].startswith(str(pending)) for i in config['inbounds'][1:]))
        result = self.run_bash('stage_changes set_node ports',ANYTLS_PORT='10444')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads((pending/'config.json').read_text())['inbounds'][2]['listen_port'],10444)
        self.assertEqual(json.loads(self.config.read_text()),original)
        self.assertFalse((pending/'client/proxies.yaml').exists())
        self.assertFalse((self.root/'service.log').exists())

    def test_pending_socks_hopping_and_rotation_wait_for_manual_apply(self):
        original = self.managed_node(anytls=True)
        before = self.file_snapshot()
        self.setup_nat()
        nat_before = self.nat_state.read_bytes()
        result = self.run_bash('''read_socks_profile() {
  export AI_SOCKS_HOST=new-ai AI_SOCKS_PORT=2080 AI_SOCKS_USER=user AI_SOCKS_PASS=new-password
}
check_socks() { :; }
stage_changes set_socks_profile ai
stage_changes set_node regenerate anytls
stage_changes set_hopping
''',HY2_HOP_PORTS='20000:20005',HY2_HOP_INTERVAL='20s')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(self.config.read_text()),original)
        after = self.file_snapshot()
        self.assertEqual({p:data for p,data in after.items() if not p.startswith('deployment/pending/')},before)
        self.assertEqual(self.nat_state.read_bytes(),nat_before)
        self.assertFalse((self.root/'service.log').exists())
        self.assertFalse((self.root/'units/sing-box-hopping.service').exists())
        config = json.loads((self.app/'pending/config.json').read_text())
        self.assertEqual(next(o for o in config['outbounds'] if o['tag']=='ai-socks')['server'],'new-ai')
        self.assertNotEqual(config['inbounds'][2]['users'],original['inbounds'][2]['users'])
        self.assertEqual(json.loads((self.app/'pending/hopping.json').read_text())['ports'],['20000:20005'])

    def test_pending_save_failure_restores_previous_pending_and_leaves_service_alone(self):
        self.managed_node(anytls=True)
        result = self.run_bash('stage_changes set_node credentials',NEW_ANYTLS_PASS='keep-pending')
        self.assertEqual(result.returncode,0,result.stderr)
        before = self.file_snapshot()
        result = self.run_bash('stage_changes set_node credentials',NEW_ANYTLS_PASS='')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(self.file_snapshot(),before)
        (self.root/'fail-check').touch()
        result = self.run_bash('stage_changes set_node regenerate anytls')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(self.file_snapshot(),before)
        self.assertFalse((self.root/'service.log').exists())

    def test_apply_pending_commits_all_files_and_network_rules_together(self):
        original = self.managed_node()
        self.setup_firewall('ufw',ufw=['ALLOW 22/tcp'])
        result = self.run_bash('stage_changes set_node add-anytls',ANYTLS_PORT='10443')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(self.firewall_state.read_text())['ufw'],['ALLOW 22/tcp'])
        result = self.run_bash('apply_changes')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertFalse((self.app/'pending').exists())
        config = json.loads(self.config.read_text())
        self.assertEqual(config['inbounds'][:2],original['inbounds'])
        self.assertEqual(config['inbounds'][2]['tls']['certificate_path'],str(self.app/'tls/anytls.crt'))
        self.assertTrue((self.app/'client/anytls.outbound.json').exists())
        self.assertIn('ALLOW 10443/tcp',json.loads(self.firewall_state.read_text())['ufw'])
        self.assertTrue((self.root/'active').exists())
        self.assertIn('restart sing-box.service',(self.root/'service.log').read_text())

    def test_apply_failure_restores_live_files_rules_and_keeps_pending(self):
        self.managed_node()
        self.setup_firewall('ufw',ufw=['ALLOW 22/tcp'])
        (self.root/'active').touch()
        result = self.run_bash('stage_changes set_node add-anytls',ANYTLS_PORT='10443')
        self.assertEqual(result.returncode,0,result.stderr)
        before = self.file_snapshot()
        (self.root/'fail-restart').touch()
        result = self.run_bash('apply_changes')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(self.file_snapshot(),before)
        self.assertEqual(json.loads(self.firewall_state.read_text())['ufw'],['ALLOW 22/tcp'])
        self.assertTrue((self.root/'active').exists())

    def test_apply_pending_hopping_is_the_first_nat_mutation(self):
        self.managed_node()
        self.setup_nat()
        result = self.run_bash('stage_changes set_hopping',HY2_HOP_PORTS='20000:20005')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertFalse((self.root/'hop-active').exists())
        result = self.run_bash('apply_changes')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertTrue((self.root/'hop-active').exists())
        self.assertIn(str(self.app/'manager.sh'),(self.root/'units/sing-box-hopping.service').read_text())
        self.assertNotIn('/pending/',(self.root/'units/sing-box-hopping.service').read_text())

    def test_summary_uses_configuration_without_client_exports_or_fixed_protocols(self):
        self.config.parent.mkdir(parents=True)
        config = {'inbounds':[{'type':'anytls','tag':'a','listen_port':23123},
                              {'type':'custom','tag':'extra','listen_port':24567}],
                  'outbounds':[{'tag':'custom-out','type':'direct'}],
                  'route':{'rules':[{'action':'route','rule_set':['custom-set'],'outbound':'custom-out'}],'final':'custom-out'}}
        self.config.write_text(json.dumps(config))
        result = self.run_bash('node_config summary')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('AnyTLS：TCP 23123',result.stdout)
        self.assertIn('extra：端口 24567',result.stdout)
        self.assertIn('custom-set → custom-out',result.stdout)
        self.assertNotIn('VLESS',result.stdout)
        self.assertNotIn('独立 SOCKS5',result.stdout)

    def test_dashboard_distinguishes_process_bound_running_state_and_pending(self):
        self.managed_node()
        self.bin.write_text(self.bin.read_text().replace('elif [[ $1 == generate ]]',
            "elif [[ $1 == version ]]; then echo 'sing-box version 1.14.77'\nelif [[ $1 == generate ]]"))
        self.prelude = self.prelude.replace('  case "$1" in\n    cat)',
            '  case "$1" in\n    show) echo "${TEST_SERVICE_ID:-instance-one}" ;;\n    cat)',1)
        (self.root/'active').touch()
        result = self.run_bash('record_runtime_state\nstage_changes set_node add-anytls\nshow_dashboard',ANYTLS_PORT='10443')
        self.assertEqual(result.returncode,0,result.stderr)
        dashboard = result.stdout[result.stdout.index('服务：运行中'):]
        self.assertIn('版本：1.14.77',dashboard)
        running,pending = dashboard.split('待应用配置（尚未生效）：')
        self.assertIn('VLESS：TCP 8443    Hysteria2：UDP 9443',running)
        self.assertIn('3 组独立 SOCKS5',running)
        self.assertNotIn('AnyTLS',running)
        self.assertIn('AnyTLS：TCP 10443',pending)
        self.assertNotIn('ai-secret',dashboard)
        self.assertNotIn('google-secret',dashboard)
        result = self.run_bash('show_dashboard',TEST_SERVICE_ID='another-instance')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('运行配置未确认',result.stdout)

    def test_summary_does_not_claim_shared_socks_are_independent(self):
        config = self.managed_node()
        socks = [o for o in config['outbounds'] if o['type']=='socks']
        for outbound in socks:
            outbound.update(server='shared.example',server_port=1080,username='same',password='same')
        self.config.write_text(json.dumps(config))
        result = self.run_bash('node_config summary')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('共用 1 组 SOCKS5',result.stdout)
        self.assertNotIn('独立',result.stdout)

    def test_pending_requires_explicit_apply_or_discard_before_destructive_operations(self):
        self.managed_node()
        result = self.run_bash('stage_changes set_node credentials',NEW_HY2_PASS='pending')
        self.assertEqual(result.returncode,0,result.stderr)
        before = self.file_snapshot()
        for body in ('service_cmd restart','service_cmd start','restore_backup','uninstall_cmd','discard_pending'):
            result = self.run_bash(body)
            self.assertNotEqual(result.returncode,0)
            self.assertEqual(self.file_snapshot(),before)
        result = self.run_bash('discard_pending',DISCARD_CONFIRM='YES')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertFalse((self.app/'pending').exists())
        self.assertNotIn('restart',(self.root/'service.log').read_text() if (self.root/'service.log').exists() else '')

    def test_pending_noop_or_cancel_does_not_create_pending_and_preserves_existing_edits(self):
        self.managed_node()
        for body in ('stage_changes set_node ports',):
            result = self.run_bash(body)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertFalse((self.app/'pending').exists())
        result = self.run_terminal('stage_changes set_node regenerate','0\n')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertFalse((self.app/'pending').exists())
        result = self.run_bash('stage_changes set_node credentials',NEW_HY2_PASS='pending')
        self.assertEqual(result.returncode,0,result.stderr)
        before = self.file_snapshot()
        result = self.run_bash('stage_changes set_node ports')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(self.file_snapshot(),before)

    def test_apply_pending_hopping_and_new_listen_port_keeps_metadata_consistent(self):
        self.managed_node()
        self.setup_nat()
        result = self.run_bash('set_hopping',HY2_HOP_PORTS='20000:20005')
        self.assertEqual(result.returncode,0,result.stderr)
        result = self.run_bash('stage_changes set_node ports',HY2_PORT='19555')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads((self.app/'hopping.json').read_text())['base_port'],9443)
        result = self.run_bash('apply_changes')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads((self.app/'hopping.json').read_text())['base_port'],19555)
        self.assertIn('redirect to :19555',json.loads(self.nat_state.read_text())['batch'])

    def test_apply_rejects_live_config_changed_after_staging(self):
        self.managed_node()
        result = self.run_bash('stage_changes set_node credentials',NEW_HY2_PASS='pending')
        self.assertEqual(result.returncode,0,result.stderr)
        config = json.loads(self.config.read_text());config['log']['level']='debug'
        self.config.write_text(json.dumps(config))
        before = self.file_snapshot()
        result = self.run_bash('apply_changes')
        self.assertNotEqual(result.returncode,0)
        self.assertIn('被其他操作修改',result.stderr)
        self.assertEqual(self.file_snapshot(),before)
        self.assertFalse((self.root/'service.log').exists())

    def test_start_already_active_service_does_not_falsely_record_disk_config(self):
        self.managed_node()
        (self.root/'active').touch()
        result = self.run_bash("record_runtime_state() { die 'must not record unchanged process'; }; service_cmd start")
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertFalse((self.app/'runtime-state.json').exists())

    def test_regenerate_choices_follow_actual_protocol_order_and_omit_missing_protocols(self):
        config = self.managed_node()
        config['inbounds'].reverse()
        self.config.write_text(json.dumps(config))
        result = self.run_terminal('stage_changes set_node regenerate','1\nYES\n')
        self.assertEqual(result.returncode,0,result.stderr)
        menu = result.stdout[:result.stdout.index('proxies:')]
        self.assertIn('1. Hysteria2',menu)
        self.assertIn('2. VLESS',menu)
        self.assertNotIn('3. AnyTLS',menu)
        pending = json.loads((self.app/'pending/config.json').read_text())
        self.assertNotEqual(pending['inbounds'][0]['users'],config['inbounds'][0]['users'])
        self.assertEqual(pending['inbounds'][1],config['inbounds'][1])

    def test_pending_rejects_config_symlink_without_touching_external_file(self):
        self.managed_node()
        external = self.root/'external-config.json'
        original = self.config.read_bytes()
        self.config.rename(external)
        self.config.symlink_to(external)
        result = self.run_bash('stage_changes set_node credentials',NEW_HY2_PASS='pending')
        self.assertNotEqual(result.returncode,0)
        self.assertIn('符号链接',result.stderr)
        self.assertEqual(external.read_bytes(),original)
        self.assertTrue(self.config.is_symlink())
        self.assertFalse((self.app/'pending').exists())
        self.assertFalse((self.root/'service.log').exists())

    def test_menu_numbers_and_actions_follow_option_list_and_reject_overflow(self):
        result = self.run_terminal("menu_action() { printf 'ACTION:%s\\n' \"$1\"; }; run_menu '自定义菜单' '' '第二项名称' status '第一项名称' check",
                                   '9999999999999999999999999999999999999\n2\n0\n')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('1. 第二项名称',result.stdout)
        self.assertIn('2. 第一项名称',result.stdout)
        self.assertIn('无效选择',result.stdout)
        self.assertIn('ACTION:check',result.stdout)
        self.assertNotIn('ACTION:status',result.stdout)

    def test_hy2_bbr_edit_is_staged_without_rotating_credentials(self):
        config = self.managed_node(anytls=True)
        config['inbounds'][1].pop('bbr_profile')
        self.config.write_text(json.dumps(config))
        before = self.file_snapshot()
        result = self.run_bash('stage_changes set_node bbr')
        self.assertEqual(result.returncode,0,result.stderr)
        pending = json.loads((self.app/'pending/config.json').read_text())
        pending['inbounds'][1].pop('bbr_profile')
        for item in pending['inbounds']:
            tls = item['tls']
            for key in ('certificate_path','key_path'):
                if key in tls: tls[key]=tls[key].replace('/pending/tls/','/tls/')
        self.assertEqual(pending,config)
        self.assertEqual(json.loads((self.app/'pending/config.json').read_text())['inbounds'][1]['bbr_profile'],'standard')
        after = self.file_snapshot()
        self.assertEqual({p:data for p,data in after.items() if not p.startswith('deployment/pending/')},before)
        self.assertFalse((self.root/'service.log').exists())
        result = self.run_terminal('stage_changes set_node bbr','invalid-profile\n')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(self.file_snapshot(),after)

    def test_status_reads_deployed_ports(self):
        self.old_config()
        config = json.loads(self.config.read_text())
        config['inbounds'][0]['listen_port'] = 12345
        config['inbounds'][1]['listen_port'] = 23456
        self.config.write_text(json.dumps(config))
        (self.root/'active').touch()
        result = self.run_bash('''ss() {
  printf '%s\\n' "$*" >> "$TEST_ROOT/ss.log"
  echo 'LISTEN users:(("sing-box",pid=123))'
}
firewall_hints() { :; }
status_cmd
''', VLESS_PORT='8443', HY2_PORT='9443')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('TCP 12345 and UDP 23456', result.stdout)
        queries = (self.root/'ss.log').read_text()
        self.assertIn(':12345', queries)
        self.assertIn(':23456', queries)
        self.assertNotIn(':8443', queries)

    def managed_node(self, anytls=False):
        self.config.parent.mkdir(parents=True)
        for name in ('tls', 'client', 'rules'):
            (self.app / name).mkdir(parents=True)
        result = self.run_bash('''VLESS_PORT=8443
HY2_PORT=9443
export SERVER_IP=8.8.8.8
export AI_SOCKS_HOST=old-ai AI_SOCKS_PORT=1080 AI_SOCKS_USER=user AI_SOCKS_PASS=ai-secret
export GOOGLE_SOCKS_HOST=old-google GOOGLE_SOCKS_PORT=1081 GOOGLE_SOCKS_USER=user GOOGLE_SOCKS_PASS=google-secret
export OTHER_SOCKS_HOST=old-other OTHER_SOCKS_PORT=1082 OTHER_SOCKS_USER=user OTHER_SOCKS_PASS=other-secret
new_credentials
make_hy2_certificate
if [[ -n "$ANYTLS_PORT" ]]; then
  ANYTLS_SNI="$REALITY_DOMAIN"
  make_tls_certificate anytls "$ANYTLS_SNI"
fi
write_jsons
''', ANYTLS_PORT='10443' if anytls else '')
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(self.config.read_text())

    def file_snapshot(self):
        return {str(p.relative_to(self.root)):p.read_bytes() for p in [self.config, *self.app.rglob('*')]
                if p.is_file()}

    def run_terminal(self, body, input_text, **env):
        master, slave = pty.openpty()
        try:
            proc = subprocess.Popen(['bash','-c',self.prelude+body],stdin=slave,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                                    text=True,env={**os.environ,'TEST_ROOT':str(self.root),**env})
            os.write(master,input_text.encode())
            out, err = proc.communicate(timeout=20)
            return subprocess.CompletedProcess(proc.args,proc.returncode,out,err)
        finally:
            os.close(master);os.close(slave)

    def test_port_edit_preserves_credentials_and_syncs_exports(self):
        before = self.managed_node()
        self.setup_firewall('ufw',ufw=['ALLOW 8443/tcp','ALLOW 9443/udp'])
        result = self.run_bash('set_node ports', VLESS_PORT='12345')
        self.assertEqual(result.returncode, 0, result.stderr)
        after = json.loads(self.config.read_text())
        expected = json.loads(json.dumps(before))
        expected['inbounds'][0]['listen_port'] = 12345
        self.assertEqual(after, expected)
        v = json.loads((self.app/'client/vless-reality.outbound.json').read_text())
        h = json.loads((self.app/'client/hysteria2.outbound.json').read_text())
        self.assertEqual(v['server_port'],12345)
        self.assertEqual(h['server_port'],9443)
        self.assertIn(':12345?',(self.app/'client/nodes.txt').read_text())
        self.assertIn('没有防火墙归属记录',result.stderr)
        state = json.loads(self.firewall_state.read_text())
        self.assertEqual(state['ufw'],['ALLOW 12345/tcp','ALLOW 8443/tcp','ALLOW 9443/udp'])

    def check_owned_port_replacement(self, backend):
        self.managed_node()
        self.setup_firewall(backend)
        result=self.run_bash('begin_transaction update "$APP/firewall-owned.json"\nopen_firewall\nupdate_firewall_ownership\nTRANSACTION=""',
                             VLESS_PORT='8443',HY2_PORT='9443')
        self.assertEqual(result.returncode,0,result.stderr)
        old=json.loads((self.app/'firewall-owned.json').read_text())
        self.assertTrue(old)
        result=self.run_bash('set_node ports',VLESS_PORT='12345')
        self.assertEqual(result.returncode,0,result.stderr)
        new=json.loads((self.app/'firewall-owned.json').read_text())
        self.assertFalse(any(r['port']==8443 and r['proto']=='tcp' for r in new))
        self.assertTrue(any(r['port']==12345 and r['proto']=='tcp' for r in new))
        self.assertEqual([r for r in old if r['port']==9443],[r for r in new if r['port']==9443])
        state=json.loads(self.firewall_state.read_text())
        if backend=='ufw': self.assertEqual(set(state['ufw']),{'ALLOW 12345/tcp','ALLOW 9443/udp'})
        elif backend=='firewalld':
            self.assertFalse(any(':8443/tcp' in k for k in state['firewalld']))
        elif backend=='nft': self.assertFalse(any(r.get('port')=='8443' for r in state['nft']))
        else: self.assertFalse(any(k.startswith('tcp:8443:') for k in state['iptables']))

    def test_owned_ufw_old_port_is_removed(self): self.check_owned_port_replacement('ufw')
    def test_owned_firewalld_old_port_is_removed(self): self.check_owned_port_replacement('firewalld')
    def test_owned_nft_old_port_is_removed(self): self.check_owned_port_replacement('nft')
    def test_owned_iptables_old_port_is_removed(self): self.check_owned_port_replacement('iptables')

    def test_port_cleanup_refuses_reordered_admin_rules_without_broadening_access(self):
        self.managed_node()
        self.setup_firewall('ufw')
        result=self.run_bash('begin_transaction update "$APP/firewall-owned.json"\nopen_firewall\nupdate_firewall_ownership\nTRANSACTION=""',
                             VLESS_PORT='8443',HY2_PORT='9443')
        self.assertEqual(result.returncode,0,result.stderr)
        state=json.loads(self.firewall_state.read_text())
        state['ufw'].insert(0,'DENY 8443/tcp')
        self.firewall_state.write_text(json.dumps(state))
        before=self.file_snapshot()
        result=self.run_bash('set_node ports',VLESS_PORT='12345')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(self.file_snapshot(),before)
        self.assertEqual(json.loads(self.firewall_state.read_text()),state)
        self.assertIn('拒绝改变其顺序',result.stderr)

    def test_old_port_removal_failure_restores_firewall_and_all_files(self):
        self.managed_node()
        self.setup_firewall('firewalld')
        result=self.run_bash('begin_transaction update "$APP/firewall-owned.json"\nopen_firewall\nupdate_firewall_ownership\nTRANSACTION=""',
                             VLESS_PORT='8443',HY2_PORT='9443')
        self.assertEqual(result.returncode,0,result.stderr)
        before=self.file_snapshot()
        state=json.loads(self.firewall_state.read_text())
        state['fail_remove']='runtime:public:8443/tcp'
        self.firewall_state.write_text(json.dumps(state))
        (self.root/'active').touch()
        result=self.run_bash('set_node ports',VLESS_PORT='12345')
        self.assertNotEqual(result.returncode,0)
        after=json.loads(self.firewall_state.read_text())
        self.assertEqual(set(after['firewalld']),set(state['firewalld']))
        self.assertEqual(self.file_snapshot(),before)
        self.assertTrue((self.root/'active').exists())
        self.assertIn('Rollback completed',result.stderr)

    def test_port_edit_failure_restores_all_node_files_and_rules(self):
        self.managed_node()
        self.setup_firewall('ufw',ufw=['ALLOW 22/tcp'])
        before = self.file_snapshot()
        (self.root/'active').touch()
        (self.root/'fail-restart').touch()
        result = self.run_bash('set_node ports',VLESS_PORT='12345',HY2_PORT='23456')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(self.file_snapshot(),before)
        self.assertEqual(json.loads(self.firewall_state.read_text())['ufw'],['ALLOW 22/tcp'])
        self.assertTrue((self.root/'active').exists())

    def test_occupied_port_rejected_before_mutation(self):
        self.managed_node()
        before=self.file_snapshot()
        result=self.run_bash("ss() { echo occupied; }\nset_node ports",VLESS_PORT='12345')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(self.file_snapshot(),before)
        self.assertIn('已被占用',result.stderr)

    def test_sni_edit_renews_certificate_and_preserves_other_credentials(self):
        before=self.managed_node()
        old_cert=(self.app/'tls/hy2.crt').read_bytes()
        result=self.run_bash('set_node sni',NEW_HY2_SNI='hy2.example.com')
        self.assertEqual(result.returncode,0,result.stderr)
        after=json.loads(self.config.read_text())
        expected=json.loads(json.dumps(before))
        expected['inbounds'][1]['tls']['server_name']='hy2.example.com'
        self.assertEqual(after,expected)
        self.assertNotEqual((self.app/'tls/hy2.crt').read_bytes(),old_cert)
        h=json.loads((self.app/'client/hysteria2.outbound.json').read_text())
        self.assertEqual(h['tls']['server_name'],'hy2.example.com')
        self.assertEqual(h['tls']['certificate'],(self.app/'tls/hy2.crt').read_text())
        self.assertFalse(h['tls']['insecure'])
        verify=subprocess.run(['openssl','verify','-CAfile',str(self.app/'tls/hy2.crt'),'-verify_hostname','hy2.example.com',str(self.app/'tls/hy2.crt')],capture_output=True)
        self.assertEqual(verify.returncode,0,verify.stderr)

    def test_unchanged_ports_keep_installed_values_without_restart(self):
        self.managed_node()
        before=self.file_snapshot()
        result=self.run_terminal('set_node ports','\n\n')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(self.file_snapshot(),before)
        self.assertFalse((self.root/'service.log').exists())

    def test_external_certificate_is_not_overwritten_by_sni_edit(self):
        self.managed_node()
        external=self.root/'external.crt'
        external.write_text((self.app/'tls/hy2.crt').read_text())
        config=json.loads(self.config.read_text())
        config['inbounds'][1]['tls']['certificate_path']=str(external)
        self.config.write_text(json.dumps(config))
        before=self.file_snapshot(); old_external=external.read_bytes()
        result=self.run_bash('set_node sni',NEW_HY2_SNI='new.example.com')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(self.file_snapshot(),before)
        self.assertEqual(external.read_bytes(),old_external)
        self.assertIn('外部路径管理',result.stderr)

    def test_sni_failure_restores_certificate_and_client(self):
        self.managed_node()
        before=self.file_snapshot()
        (self.root/'fail-restart').touch()
        result=self.run_bash('set_node sni',NEW_HY2_SNI='new.example.com')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(self.file_snapshot(),before)

    def test_invalid_sni_and_uuid_rejected_without_mutation(self):
        self.managed_node()
        before=self.file_snapshot()
        for command,env in [('set_node sni',{'NEW_HY2_SNI':'bad/domain'}),('set_node credentials',{'NEW_UUID':'bad-uuid'})]:
            result=self.run_bash(command,**env)
            self.assertNotEqual(result.returncode,0)
            self.assertEqual(self.file_snapshot(),before)

    def test_password_edit_and_export_uri_encoding(self):
        from urllib.parse import urlsplit,parse_qs,unquote
        before=self.managed_node()
        secret='Aa@:/?&+ %密码'
        result=self.run_bash('set_node credentials',NEW_HY2_PASS=secret)
        self.assertEqual(result.returncode,0,result.stderr)
        after=json.loads(self.config.read_text())
        expected=json.loads(json.dumps(before));expected['inbounds'][1]['users'][0]['password']=secret
        self.assertEqual(after,expected)
        lines=(self.app/'client/nodes.txt').read_text().splitlines()
        uri=urlsplit(lines[1])
        self.assertEqual(unquote(uri.username),secret)
        params=parse_qs(uri.query)
        self.assertEqual(params['obfs-password'],[before['inbounds'][1]['obfs']['password']])
        self.assertEqual(params['insecure'],['0'])
        self.assertEqual(len(params['pinSHA256'][0]),64)
        for path in (self.app/'client').iterdir():
            self.assertEqual(path.stat().st_mode&0o777,0o600)

    def test_rotation_is_explicit_and_syncs_reality_public_key(self):
        before=self.managed_node()
        self.bin.write_text('''#!/bin/bash
if [[ $1 == generate ]]; then printf 'PrivateKey: rotated-private\\nPublicKey: rotated-public\\n'; fi
''')
        result=self.run_bash('set_node rotate')
        self.assertEqual(result.returncode,0,result.stderr)
        after=json.loads(self.config.read_text())
        self.assertNotEqual(before['inbounds'][0]['users'][0]['uuid'],after['inbounds'][0]['users'][0]['uuid'])
        self.assertNotEqual(before['inbounds'][1]['users'][0]['password'],after['inbounds'][1]['users'][0]['password'])
        self.assertEqual(after['inbounds'][0]['tls']['reality']['private_key'],'rotated-private')
        client=json.loads((self.app/'client/vless-reality.outbound.json').read_text())
        self.assertEqual(client['tls']['reality']['public_key'],'rotated-public')
        self.assertEqual(client['tls']['reality']['short_id'],after['inbounds'][0]['tls']['reality']['short_id'][0])
        self.assertEqual(after['route'],before['route'])

    def test_export_does_not_restart_or_change_server(self):
        self.managed_node()
        before=self.config.read_bytes()
        result=self.run_bash('export_nodes')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(self.config.read_bytes(),before)
        service_log=(self.root/'service.log').read_text() if (self.root/'service.log').exists() else ''
        self.assertNotIn('restart',service_log)
        self.assertNotIn('stop',service_log)
        result=self.run_bash('node_config json')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(len(json.loads(result.stdout)['outbounds']),2)

    def test_installed_values_win_over_source_defaults_on_enter(self):
        self.managed_node()
        before=self.config.read_bytes()
        result=self.run_terminal('read_socks_profile ai\npython3 - <<\'PYASSERT\'\nimport os\nassert os.environ["AI_SOCKS_HOST"]=="old-ai"\nassert os.environ["AI_SOCKS_PASS"]=="ai-secret"\nprint("CURRENT_VALUES_OK")\nPYASSERT\n','\n\n\n\n')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('CURRENT_VALUES_OK',result.stdout)
        self.assertNotIn('ai-secret',result.stdout)
        self.assertEqual(self.config.read_bytes(),before)

    def test_tfo_edit_changes_only_three_socks_outbounds(self):
        before=self.managed_node()
        result=self.run_bash('set_node tfo',SOCKS_TFO='false')
        self.assertEqual(result.returncode,0,result.stderr)
        expected=json.loads(json.dumps(before))
        for o in expected['outbounds']:
            if o['type']=='socks':o['tcp_fast_open']=False
        self.assertEqual(json.loads(self.config.read_text()),expected)

    def isolated_install_body(self):
        return '''check_os() { PKG=apt; }
install_deps() { :; }
check_socks() { :; }
public_ipv4() { export SERVER_IP=8.8.8.8; }
check_reality_target() { :; }
install_sing_box_official() { mkdir -p "$(dirname "$CONFIG")"; }
download_rules() { :; }
'''

    def install_environment(self):
        return {f'{profile}_SOCKS_{key}': value for profile in ('AI','GOOGLE','OTHER')
                for key,value in [('HOST','proxy.example'),('PORT','1080'),('USER','user'),('PASS','secret')]}

    def test_install_creates_management_exports_and_firewall_ledger(self):
        self.setup_firewall('none')
        result=self.run_bash(self.isolated_install_body()+'fresh_install',**self.install_environment())
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertTrue(self.config.exists())
        config = json.loads(self.config.read_text())
        self.assertEqual([(i['type'],i['listen_port']) for i in config['inbounds']],
                         [('vless',443),('hysteria2',443),('anytls',8443)])
        self.assertFalse((self.app/'client/proxies.yaml').exists())
        self.assertTrue((self.app/'manager.sh').exists())
        self.assertTrue((self.root/'bin/sb-manager').exists())
        self.assertTrue((self.app/'client/nodes.txt').exists())
        self.assertEqual(json.loads((self.app/'firewall-owned.json').read_text()),[])
        self.assertTrue((self.root/'active').exists())
        self.assertTrue((self.root/'enabled').exists())

    def test_failed_install_removes_new_manager_exports_and_firewall_rules(self):
        self.setup_firewall('ufw')
        body=self.isolated_install_body()+'''install_manager() {
  install -d "$(dirname "$MANAGER")"
  echo partial > "$MANAGER"
  return 1
}
fresh_install
'''
        result=self.run_bash(body,**self.install_environment())
        self.assertNotEqual(result.returncode,0)
        self.assertFalse(self.config.exists())
        self.assertFalse(self.app.exists())
        self.assertFalse((self.root/'bin/sb-manager').exists())
        self.assertEqual(json.loads(self.firewall_state.read_text())['ufw'],[])
        self.assertFalse((self.root/'active').exists())
        self.assertFalse((self.root/'enabled').exists())

    def test_manager_install_is_private_and_export_failure_preserves_service(self):
        self.managed_node()
        result=self.run_bash('setup_manager')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual((self.root/'bin/sb-manager').stat().st_mode&0o777,0o700)
        self.assertEqual((self.app/'manager.sh').stat().st_mode&0o777,0o700)
        before=self.file_snapshot()
        (self.root/'active').touch()
        result=self.run_bash('node_config() { return 1; }\nexport_nodes')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(self.file_snapshot(),before)
        self.assertTrue((self.root/'active').exists())
        log=(self.root/'service.log').read_text() if (self.root/'service.log').exists() else ''
        self.assertNotIn('stop',log)

    def test_installed_manager_wrapper_preserves_arguments(self):
        self.managed_node()
        source=self.root/'manager-source.sh'
        source.write_text('#!/bin/bash\nprintf "%s\\n" "$@"\n')
        result=self.run_bash('SCRIPT_PATH="'+str(source)+'"\nsetup_manager\n"$MANAGER" "first argument" second')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout,'first argument\nsecond\n')

    def test_manager_can_update_itself(self):
        self.managed_node()
        result=self.run_bash('setup_manager\nSCRIPT_PATH="$APP/manager.sh"\nsetup_manager')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertTrue((self.app/'manager.sh').exists())

    def test_menu_child_failure_rolls_back_and_next_action_works(self):
        original=self.old_config()
        (self.root/'active').touch()
        entry=self.root/'entry.sh'
        dispatch=SOURCE[SOURCE.index('\ncase "${1:'):]
        dispatch=dispatch.replace('install) fresh_install ;;','install) begin_transaction update "$CONFIG"; echo changed > "$CONFIG"; false ;;')
        dispatch=dispatch.replace('status) status_cmd ;;','status) echo NEXT_ACTION_OK ;;')
        dispatch=dispatch.replace('summary) need_root; node_config summary; "$BIN" version | sed -n \'1p\' ;;','summary) echo 节点摘要 ;;')
        entry.write_text(self.prelude+'\nSCRIPT_PATH="'+str(entry)+'"\n'+dispatch)
        result=self.run_terminal('bash "'+str(entry)+'"','bad\n2\n0\n1\n\n6\n\n0\n')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('无效选择',result.stdout)
        self.assertIn('NEXT_ACTION_OK',result.stdout)
        self.assertIn('操作未完成',result.stderr)
        self.assertEqual(self.config.read_bytes(),original)
        self.assertTrue((self.root/'active').exists())

    def test_noninteractive_menu_shows_help_without_waiting(self):
        result=self.run_bash('main_menu')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('进入中文管理菜单',result.stdout)

    def setup_package_manager(self, kind='apt', **options):
        fake = self.root / 'package-bin'
        fake.mkdir()
        script = fake / 'package-tool'
        script.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
root=pathlib.Path(os.environ['TEST_ROOT']); path=root/'package-state.json'
s=json.loads(path.read_text()); tool=pathlib.Path(sys.argv[0]).name; a=sys.argv[1:]
with (root/'package.log').open('a') as f: f.write(json.dumps([tool,*a])+'\\n')
def save(): path.write_text(json.dumps(s))
def done(code=0,text=''):
    if text: print(text)
    sys.exit(code)
if tool=='dpkg-query':
    if '-f=${db:Status-Status}' in a: done(0 if s['installed'] else 1,'installed' if s['installed'] else '')
    done(0 if s['installed'] else 1,s['installed'])
if tool=='dpkg-deb':
    candidate=pathlib.Path(a[-1]); s['artifact_path']=str(candidate.parent.parent/'package-rollback'/candidate.name);save()
    done(text=json.loads(candidate.read_text())['identity'])
if tool=='rpm':
    if '-qp' in a:
        candidate=pathlib.Path(a[-1]);s['artifact_path']=str(candidate.parent.parent/'package-rollback'/candidate.name);save()
        done(text=json.loads(candidate.read_text())['identity'])
    if '-q' in a: done(0 if s['installed'] else 1,s['installed'])
    if a[:2]==['-e','--test']: done()
if tool=='apt-get' and a==['update']: done()
if 'download' in a:
    if '--help' in a: done()
    if s.get('download_fail'): done(1,'download unavailable')
    if tool=='apt-get': dest=pathlib.Path.cwd(); ext='.deb'
    else:
        flag='--destdir' if '--destdir' in a else '--downloaddir'
        dest=pathlib.Path(a[a.index(flag)+1]); ext='.rpm'
    identity=s['old'] if not s.get('mismatch') else s['old']+'-wrong-architecture'
    (dest/('sing-box-old'+ext)).write_text(json.dumps({'identity':identity}))
    done()
local=next((pathlib.Path(x) for x in a if x.endswith(('.deb','.rpm'))),None)
if local is not None and ('install' in a or 'downgrade' in a or 'reinstall' in a):
    if not s.get('rollback_noop'): s['installed']=json.loads(local.read_text())['identity']; save()
    done()
if ('upgrade' in a) or (tool=='apt-get' and '--only-upgrade' in a):
    ready=bool(s.get('artifact_path')) and pathlib.Path(s['artifact_path']).is_file()
    s['rollback_ready']=ready
    if not ready: save(); done(91,'upgrade began without a retained old package')
    s['installed']=s['new']; save()
    if s.get('mutate_config'):
        config=pathlib.Path(os.environ['TEST_CONFIG']); c=json.loads(config.read_text()); c['log']['level']='debug'; config.write_text(json.dumps(c))
    done(1 if s.get('upgrade_fail') else 0)
if 'remove' in a:
    if '-s' in a: done(text='Remv sing-box [old]')
    s['installed']=''; save(); done()
done(99,'Unexpected package operation: '+repr([tool,*a]))
''')
        script.chmod(0o700)
        for tool in ('apt-get','dpkg-query','dpkg-deb','rpm','dnf','dnf5'):
            (fake/tool).symlink_to(script)
        old='sing-box|1.14.4-1|amd64' if kind=='apt' else 'sing-box-0:1.14.4-1.x86_64'
        new='sing-box|1.14.5-1|amd64' if kind=='apt' else 'sing-box-0:1.14.5-1.x86_64'
        self.package_state=self.root/'package-state.json'
        self.package_state.write_text(json.dumps({'installed':old,'old':old,'new':new,**options}))
        self.prelude += f'''export PATH={fake}:"$PATH"
export TEST_CONFIG={self.config}
check_os() {{ PKG={kind}; }}
'''
        return old,new

    def package_commands(self):
        return [json.loads(line) for line in (self.root/'package.log').read_text().splitlines()]

    def test_package_prepare_retains_exact_apt_version_and_architecture(self):
        old,_=self.setup_package_manager('apt')
        result=self.run_bash('PKG=apt\nbegin_transaction files\nprepare_package_rollback\n[[ -f "$OLD_PACKAGE" && "$OLD_PACKAGE" == "$TEMP/package-rollback/"* ]]\ncp "$OLD_PACKAGE" "$TEST_ROOT/retained.deb"\nTRANSACTION=""')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads((self.root/'retained.deb').read_text())['identity'],old)
        downloads=[a for a in self.package_commands() if a[:2]==['apt-get','download']]
        self.assertEqual(downloads,[['apt-get','download','sing-box=1.14.4-1']])

    def test_package_mismatched_download_aborts_before_upgrade(self):
        self.managed_node()
        old,_=self.setup_package_manager('apt',mismatch=True)
        before=self.file_snapshot()
        result=self.run_bash('kernel_update')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(json.loads(self.package_state.read_text())['installed'],old)
        self.assertEqual(self.file_snapshot(),before)
        self.assertFalse(any('--only-upgrade' in a for a in self.package_commands()))
        self.assertIn('版本/架构匹配',result.stderr)

    def test_package_download_failure_aborts_before_upgrade(self):
        self.managed_node()
        old,_=self.setup_package_manager('apt',download_fail=True)
        before=self.file_snapshot()
        result=self.run_bash('kernel_update')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(json.loads(self.package_state.read_text())['installed'],old)
        self.assertEqual(self.file_snapshot(),before)
        self.assertFalse(any('--only-upgrade' in a for a in self.package_commands()))

    def test_package_update_preserves_config_and_caches_old_package_first(self):
        self.managed_node()
        _,new=self.setup_package_manager('apt')
        before=self.file_snapshot()
        (self.root/'active').touch(); (self.root/'enabled').touch()
        result=self.run_bash('kernel_update')
        self.assertEqual(result.returncode,0,result.stderr)
        state=json.loads(self.package_state.read_text())
        self.assertEqual(state['installed'],new)
        self.assertTrue(state['rollback_ready'])
        self.assertEqual(self.file_snapshot(),before)
        self.assertTrue((self.root/'active').exists())
        self.assertTrue((self.root/'enabled').exists())

    def test_package_update_restart_failure_restores_exact_package_and_files(self):
        self.managed_node()
        old,_=self.setup_package_manager('apt')
        before=self.file_snapshot()
        (self.root/'active').touch(); (self.root/'enabled').touch(); (self.root/'fail-restart').touch()
        result=self.run_bash('kernel_update')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(json.loads(self.package_state.read_text())['installed'],old)
        self.assertEqual(self.file_snapshot(),before)
        self.assertTrue((self.root/'active').exists())
        self.assertTrue((self.root/'enabled').exists())
        restore=[a for a in self.package_commands() if '--allow-downgrades' in a]
        self.assertEqual(len(restore),1)
        self.assertIn('--no-remove',restore[0])

    def check_rpm_update_failure_rollback(self,kind):
        self.managed_node()
        old,_=self.setup_package_manager(kind)
        before=self.file_snapshot()
        (self.root/'active').touch(); (self.root/'fail-restart').touch()
        result=self.run_bash('kernel_update')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(json.loads(self.package_state.read_text())['installed'],old)
        self.assertEqual(self.file_snapshot(),before)
        manager='dnf5' if kind=='dnf5' else 'dnf'
        calls=self.package_commands()
        downloads=[a for a in calls if a[:2]==[manager,'download'] and '--help' not in a]
        self.assertEqual(len(downloads),1)
        self.assertIn(old,downloads[0])
        self.assertIn('--destdir' if kind=='dnf5' else '--downloaddir',downloads[0])
        downgraded=[a for a in calls if a[:2]==[manager,'downgrade']]
        self.assertEqual(len(downgraded),1)
        self.assertTrue(downgraded[0][-1].endswith('.rpm'))
        self.assertFalse(any('--allowerasing' in a for a in calls))

    def test_package_dnf4_rollback_uses_exact_local_rpm(self):
        self.check_rpm_update_failure_rollback('dnf4')

    def test_package_dnf5_rollback_uses_exact_local_rpm(self):
        self.check_rpm_update_failure_rollback('dnf5')

    def test_package_rollback_checks_resulting_installed_version(self):
        old,new=self.setup_package_manager('apt',rollback_noop=True)
        result=self.run_bash('PKG=apt\nbegin_transaction files\nprepare_package_rollback\npython3 - <<\'PYSTATE\'\nimport json,os,pathlib\np=pathlib.Path(os.environ["TEST_ROOT"])/"package-state.json"\ns=json.loads(p.read_text());s["installed"]=s["new"];p.write_text(json.dumps(s))\nPYSTATE\nrestore_package')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(json.loads(self.package_state.read_text())['installed'],new)
        self.assertIn('版本不匹配',result.stderr)

    def setup_nat(self, backend='nft', **options):
        fake=self.root/'nat-bin'; fake.mkdir()
        script=fake/'nat-tool'
        script.write_text('''#!/usr/bin/env python3
import json,os,pathlib,re,shlex,sys
p=pathlib.Path(os.environ['TEST_ROOT'])/'nat.json';s=json.loads(p.read_text());a=sys.argv[1:];tool=pathlib.Path(sys.argv[0]).name
with (p.parent/'nat.log').open('a') as f:f.write(json.dumps([tool,*a])+'\\n')
def save():p.write_text(json.dumps(s))
def done(code=0,text=''):
    if text:print(text)
    sys.exit(code)
if tool=='nft':
    if a==['-j','list','tables']:
        done(text=json.dumps({'nftables':[{'table':{'family':'ip','name':'sing_box_hy2_hop'}}] if s.get('batch') else []}))
    if a==['-j','list','table','ip','sing_box_hy2_hop']:
        done(text=json.dumps({'nftables':[{'table':{'family':'ip','name':'sing_box_hy2_hop','comment':s.get('owner','sing-box-deploy-hopping')}}]}))
    if a==['-j','list','ruleset']:done(text='{"nftables":[]}')
    if a==['-f','-']:
        batch=sys.stdin.read();create=bool(re.search(r'^table ip ',batch,re.M))
        if create and s.get('fail_start'):done(1,'injected NAT failure')
        s['batch']=batch if create else '';save();done()
else:
    if a==['--version']:done(text='iptables v1.8 (legacy)')
    if a==['-w','-S','INPUT']:done(text='-P INPUT ACCEPT')
    if a==['-w','-t','nat','-S']:
        done(text='\\n'.join(['-N '+c for c in s['chains']]+[shlex.join(r) for r in s['rules']]))
    if '-N' in a:s['chains'].append(a[-1]);save();done()
    if '-I' in a or '-A' in a:
        op='-I' if '-I' in a else '-A';r=['-A',*a[a.index(op)+1:]]
        if op=='-I':s['rules'].insert(0,r)
        else:s['rules'].append(r)
        save();done()
    if '-D' in a:
        r=['-A',*a[a.index('-D')+1:]]
        if r not in s['rules']:done(1)
        s['rules'].remove(r);save();done()
    if '-F' in a:s['rules']=[r for r in s['rules'] if r[1]!=a[-1]];save();done()
    if '-X' in a:s['chains'].remove(a[-1]);save();done()
done(99,'Unexpected NAT operation: '+repr([tool,*a]))
''')
        script.chmod(0o700)
        for tool in ('nft','iptables'):(fake/tool).symlink_to(script)
        self.nat_state=self.root/'nat.json'
        self.nat_state.write_text(json.dumps({'batch':'','chains':[],'rules':[],**options}))
        self.prelude+=f'export PATH={fake}:"$PATH"\n'
        if backend=='iptables':
            self.prelude+='command() { if [[ "$1" == -v && "$2" == nft ]]; then return 1; else builtin command "$@"; fi; }\n'

    def test_hopping_excludes_udp_conflicts_but_not_tcp_only_ports(self):
        self.setup_nat()
        result=self.run_bash('''HY2_PORT=9443
ss() { printf '%s\\n' 'tcp LISTEN 0 0 0.0.0.0:20001 0.0.0.0:*' 'udp UNCONN 0 0 0.0.0.0:20002 0.0.0.0:*' 'udp UNCONN 0 0 0.0.0.0:9443 0.0.0.0:* users:(("sing-box",pid=1))'; }
prepare_hopping
cp "$TEMP/hopping-plan.json" "$TEST_ROOT/plan.json"
''',HY2_HOP_PORTS='20000:20005,30000')
        self.assertEqual(result.returncode,0,result.stderr)
        plan=json.loads((self.root/'plan.json').read_text())
        self.assertEqual(plan['ports'],['20000:20001','20003:20005','30000'])
        self.assertIn('已排除：20002',result.stdout)

    def test_hopping_explicit_exclusions_and_unexcluded_conflict_rejection(self):
        self.setup_nat()
        body='''ss() { echo 'udp UNCONN 0 0 0.0.0.0:20002 0.0.0.0:*'; }
prepare_hopping
cp "$TEMP/hopping-plan.json" "$TEST_ROOT/plan.json"
'''
        result=self.run_bash(body,HY2_HOP_PORTS='20000:20005',HY2_HOP_EXCLUDE='20002,20004')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads((self.root/'plan.json').read_text())['ports'],['20000:20001','20003','20005'])
        result=self.run_bash(body,HY2_HOP_PORTS='20000:20005',HY2_HOP_EXCLUDE='none')
        self.assertNotEqual(result.returncode,0)
        self.assertIn('仍有 UDP 占用',result.stderr)

    def test_hopping_rejects_intervals_below_core_minimum(self):
        self.setup_nat()
        for interval in ('1s','4999ms','0s'):
            result=self.run_bash('prepare_hopping',HY2_HOP_PORTS='20000:20005',HY2_HOP_INTERVAL=interval)
            self.assertNotEqual(result.returncode,0)
            self.assertIn('至少 5 秒',result.stderr)

    def test_hopping_enable_syncs_clients_and_persistent_unit(self):
        self.managed_node();before=self.config.read_bytes();self.setup_nat()
        result=self.run_bash('set_hopping',HY2_HOP_PORTS='20000:20005,30000',HY2_HOP_INTERVAL='10s')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(self.config.read_bytes(),before)
        h=json.loads((self.app/'client/hysteria2.outbound.json').read_text())
        self.assertEqual(h['server_ports'],['20000:20005','30000'])
        self.assertEqual(h['hop_interval'],'10s')
        self.assertNotIn('server_port',h)
        self.assertIn(':20000-20005,30000/',(self.app/'client/nodes.txt').read_text())
        unit=(self.root/'units/sing-box-hopping.service').read_text()
        self.assertIn('hopping-runtime start',unit)
        self.assertTrue((self.root/'hop-enabled').exists())
        batch=json.loads(self.nat_state.read_text())['batch']
        self.assertIn('fib daddr type local',batch)
        self.assertIn('redirect to :9443',batch)

    def test_hopping_primary_port_edit_updates_redirect_and_disable_removes_owned_nat(self):
        self.managed_node();self.setup_nat()
        result=self.run_bash('set_hopping',HY2_HOP_PORTS='20000:20005')
        self.assertEqual(result.returncode,0,result.stderr)
        result=self.run_bash('set_node ports',HY2_PORT='9555')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads((self.app/'hopping.json').read_text())['base_port'],9555)
        self.assertIn('redirect to :9555',json.loads(self.nat_state.read_text())['batch'])
        result=self.run_bash('set_hopping',HY2_HOP_PORTS='0')
        self.assertEqual(result.returncode,0,result.stderr)
        h=json.loads((self.app/'client/hysteria2.outbound.json').read_text())
        self.assertEqual(h['server_port'],9555)
        self.assertNotIn('server_ports',h)
        self.assertEqual(json.loads(self.nat_state.read_text())['batch'],'')
        self.assertFalse((self.root/'hop-enabled').exists())

    def test_hopping_failure_restores_nat_metadata_and_client_artifacts(self):
        self.managed_node();self.setup_nat()
        result=self.run_bash('set_hopping',HY2_HOP_PORTS='20000:20005')
        self.assertEqual(result.returncode,0,result.stderr)
        before=self.file_snapshot();nat=json.loads(self.nat_state.read_text())
        (self.root/'fail-restart').touch()
        result=self.run_bash('set_hopping',HY2_HOP_PORTS='30000:30005')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(self.file_snapshot(),before)
        self.assertEqual(json.loads(self.nat_state.read_text()),nat)
        self.assertTrue((self.root/'hop-active').exists())

    def test_hopping_iptables_private_chain_targets_only_local_destinations(self):
        self.managed_node();self.setup_nat('iptables')
        result=self.run_bash('set_hopping',HY2_HOP_PORTS='20000:20005')
        self.assertEqual(result.returncode,0,result.stderr)
        state=json.loads(self.nat_state.read_text())
        jump=next(r for r in state['rules'] if r[1]=='PREROUTING')
        self.assertIn('--dst-type',jump);self.assertIn('LOCAL',jump)
        redirect=next(r for r in state['rules'] if 'REDIRECT' in r)
        self.assertEqual(redirect[-1],'9443')
        result=self.run_bash('set_hopping',HY2_HOP_PORTS='0')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(self.nat_state.read_text())['chains'],[])

    def test_hopping_refuses_foreign_service_unit(self):
        self.managed_node();self.setup_nat()
        unit=self.root/'units/sing-box-hopping.service';unit.parent.mkdir();unit.write_text('Description=other administrator service\n')
        result=self.run_bash('set_hopping',HY2_HOP_PORTS='20000:20005')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(unit.read_text(),'Description=other administrator service\n')
        self.assertEqual(json.loads(self.nat_state.read_text())['batch'],'')

    def test_backup_roundtrip_restores_credentials_and_retains_live_firewall_ledger(self):
        import tarfile
        original=self.managed_node()
        (self.app/'cache.db').write_text('transient')
        ledger=[{'backend':'ufw','marker':'live-owner','proto':'tcp','port':2222}]
        (self.app/'firewall-owned.json').write_text(json.dumps(ledger))
        result=self.run_bash('backup_cmd')
        self.assertEqual(result.returncode,0,result.stderr)
        archive=next((self.root/'backups').glob('*.tar.gz'))
        self.assertEqual(archive.stat().st_mode&0o777,0o600)
        with tarfile.open(archive) as f:
            self.assertNotIn('cache.db',f.getnames());self.assertNotIn('firewall-owned.json',f.getnames())
            self.assertNotIn('manager.sh',f.getnames());self.assertIn('tls/hy2.key',f.getnames())
            manifest=json.load(f.extractfile('manifest.json'));self.assertEqual(manifest['format'],1)
            self.assertIn('kernel_version',manifest)
        result=self.run_bash('set_node credentials',NEW_HY2_PASS='changed-after-backup')
        self.assertEqual(result.returncode,0,result.stderr)
        result=self.run_bash('restore_backup "'+str(archive)+'"')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(self.config.read_text()),original)
        self.assertEqual(json.loads((self.app/'firewall-owned.json').read_text()),ledger)

    def test_restore_failure_rolls_back_current_files_and_service_state(self):
        self.managed_node()
        (self.root/'active').touch()
        result=self.run_bash('backup_cmd');self.assertEqual(result.returncode,0,result.stderr)
        archive=next((self.root/'backups').glob('*.tar.gz'))
        result=self.run_bash('set_node credentials',NEW_HY2_PASS='keep-this-on-failure')
        self.assertEqual(result.returncode,0,result.stderr)
        before=self.file_snapshot();(self.root/'fail-restart').touch()
        result=self.run_bash('restore_backup "'+str(archive)+'"')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(self.file_snapshot(),before)
        self.assertTrue((self.root/'active').exists())

    def test_restore_can_recover_a_broken_current_config(self):
        original=self.managed_node()
        result=self.run_bash('backup_cmd');self.assertEqual(result.returncode,0,result.stderr)
        archive=next((self.root/'backups').glob('*.tar.gz'))
        self.config.write_text('broken json')
        self.setup_firewall('none')
        result=self.run_bash('restore_backup "'+str(archive)+'"')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(self.config.read_text()),original)

    def test_backup_rejects_links_and_does_not_overwrite_existing_target(self):
        self.managed_node()
        target=self.root/'existing.tar.gz';target.write_text('keep')
        result=self.run_bash('backup_cmd "'+str(target)+'"')
        self.assertNotEqual(result.returncode,0);self.assertEqual(target.read_text(),'keep')
        (self.app/'client/symlink').symlink_to(self.config)
        result=self.run_bash('backup_cmd')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(list((self.root/'backups').glob('*.tar.gz')),[])

    def test_restore_rejects_traversal_links_and_corrupted_manifest_before_mutation(self):
        import tarfile,io,hashlib
        self.managed_node();before=self.file_snapshot()
        for kind in ('traversal','link','hash'):
            with self.subTest(kind=kind):
                archive=self.root/(kind+'.tar.gz')
                with tarfile.open(archive,'w:gz') as f:
                    if kind=='traversal':
                        m=tarfile.TarInfo('../escape');m.size=1;f.addfile(m,io.BytesIO(b'x'))
                    elif kind=='link':
                        m=tarfile.TarInfo('client/linked');m.type=tarfile.SYMTYPE;m.linkname='/etc/passwd';f.addfile(m)
                    else:
                        data=b'{}';m=tarfile.TarInfo('config.json');m.size=len(data);f.addfile(m,io.BytesIO(data))
                        manifest=json.dumps({'format':1,'app_path':str(self.app),'files':{'config.json':'0'*64}}).encode()
                        m=tarfile.TarInfo('manifest.json');m.size=len(manifest);f.addfile(m,io.BytesIO(manifest))
                result=self.run_bash('restore_backup "'+str(archive)+'"')
                self.assertNotEqual(result.returncode,0)
                self.assertEqual(self.file_snapshot(),before)
                self.assertFalse((self.root/'escape').exists())

    def setup_uninstall_fixture(self, kind='apt', anytls=False, **package_options):
        self.managed_node(anytls=anytls)
        result=self.run_bash('setup_manager')
        self.assertEqual(result.returncode,0,result.stderr)
        self.setup_firewall('ufw',ufw=['ALLOW 22/tcp'])
        result=self.run_bash('begin_transaction update "$APP/firewall-owned.json"\nopen_firewall\nupdate_firewall_ownership\nTRANSACTION=""',
                             VLESS_PORT='8443',HY2_PORT='9443',ANYTLS_PORT='10443' if anytls else '')
        self.assertEqual(result.returncode,0,result.stderr)
        old,new=self.setup_package_manager(kind,dependencies=['curl','openssl','python3'],**package_options)
        tool=self.root/'package-bin/package-tool'
        source=tool.read_text()
        source=source.replace("if '-s' in a: done(text='Remv sing-box [old]')",
                              "if '-s' in a: done(text='Remv sing-box [old]'+('\\nRemv unrelated-admin-package [old]' if s.get('reverse_dependency') else ''))")
        source=source.replace("s['installed']=''; save(); done()",
                              "s['installed']=''; save(); done(1 if s.get('remove_fail') else 0)")
        source=source.replace("if not s.get('rollback_noop'): s['installed']=json.loads(local.read_text())['identity']; save()",
                              "if not s.get('rollback_noop'):\n        s['app_missing_at_rollback']=not (root/'deployment').exists()\n        s['installed']=json.loads(local.read_text())['identity']; save()")
        tool.write_text(source)
        self.repo.parent.mkdir(parents=True,exist_ok=True)
        self.repo.write_text('administrator repository configuration\n')
        (self.config.parent/'admin-extra.json').write_text('{"admin":"preserve"}\n')
        (self.root/'dependency-sentinel').write_text('shared dependency data\n')
        (self.root/'active').touch();(self.root/'enabled').touch()
        return old,new

    def test_uninstall_requires_explicit_yes_and_preserves_deployment(self):
        self.setup_uninstall_fixture()
        before=self.file_snapshot()
        firewall=json.loads(self.firewall_state.read_text())
        result=self.run_bash('uninstall_cmd')
        self.assertNotEqual(result.returncode,0)
        self.assertIn('未确认卸载',result.stderr)
        self.assertEqual(self.file_snapshot(),before)
        self.assertEqual(json.loads(self.firewall_state.read_text()),firewall)
        self.assertTrue((self.root/'active').exists())
        self.assertTrue((self.root/'enabled').exists())
        self.assertFalse((self.root/'package.log').exists())
        backups=list((self.root/'backups').glob('*.tar.gz'))
        self.assertEqual(len(backups),1)
        self.assertEqual(backups[0].stat().st_mode&0o777,0o600)

    def test_uninstall_backup_survives_and_only_owned_items_are_removed(self):
        import tarfile
        self.setup_uninstall_fixture(anytls=True)
        admin=(self.config.parent/'admin-extra.json').read_bytes()
        result=self.run_bash('uninstall_cmd',UNINSTALL_CONFIRM='YES')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertFalse(self.config.exists())
        self.assertFalse(self.app.exists())
        self.assertFalse((self.root/'bin/sb-manager').exists())
        self.assertEqual(json.loads(self.package_state.read_text())['installed'],'')
        self.assertEqual(json.loads(self.package_state.read_text())['dependencies'],['curl','openssl','python3'])
        self.assertEqual(json.loads(self.firewall_state.read_text())['ufw'],['ALLOW 22/tcp'])
        self.assertEqual(self.repo.read_text(),'administrator repository configuration\n')
        self.assertEqual((self.config.parent/'admin-extra.json').read_bytes(),admin)
        self.assertEqual((self.root/'dependency-sentinel').read_text(),'shared dependency data\n')
        self.assertFalse((self.root/'active').exists())
        self.assertFalse((self.root/'enabled').exists())
        backups=list((self.root/'backups').glob('*.tar.gz'))
        self.assertEqual(len(backups),1)
        self.assertEqual(backups[0].stat().st_mode&0o777,0o600)
        with tarfile.open(backups[0],'r:gz') as archive:
            names=set(archive.getnames())
            self.assertIn('config.json',names)
            self.assertIn('tls/hy2.key',names)
            self.assertIn('tls/anytls.key',names)
            self.assertIn('client/anytls.outbound.json',names)
            self.assertIn('client/vless-reality.outbound.json',names)
            self.assertNotIn('firewall-owned.json',names)
            self.assertNotIn('manager.sh',names)
        remove=[a for a in self.package_commands() if a[0]=='apt-get' and 'remove' in a and '-s' not in a]
        self.assertEqual(len(remove),1)
        self.assertIn('--no-auto-remove',remove[0])
        self.assertNotIn('autoremove',remove[0])

    def test_uninstall_package_removal_error_restores_package_files_and_service(self):
        old,_=self.setup_uninstall_fixture(remove_fail=True)
        before=self.file_snapshot();firewall=json.loads(self.firewall_state.read_text())
        wrapper=(self.root/'bin/sb-manager').read_bytes()
        result=self.run_bash('uninstall_cmd',UNINSTALL_CONFIRM='YES')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(json.loads(self.package_state.read_text())['installed'],old)
        self.assertEqual(self.file_snapshot(),before)
        self.assertEqual((self.root/'bin/sb-manager').read_bytes(),wrapper)
        self.assertEqual(json.loads(self.firewall_state.read_text()),firewall)
        self.assertTrue((self.root/'active').exists())
        self.assertTrue((self.root/'enabled').exists())
        self.assertEqual(len(list((self.root/'backups').glob('*.tar.gz'))),1)
        self.assertIn('Rollback completed',result.stderr)

    def test_uninstall_failure_after_files_removed_restores_everything(self):
        old,_=self.setup_uninstall_fixture(anytls=True)
        before=self.file_snapshot();firewall=json.loads(self.firewall_state.read_text())
        wrapper=(self.root/'bin/sb-manager').read_bytes()
        (self.root/'fail-daemon-reload').touch()
        self.prelude=self.prelude.replace('  case "$1" in\n    cat)',
            '  case "$1" in\n    daemon-reload) if [[ -f "$TEST_ROOT/fail-daemon-reload" ]]; then rm "$TEST_ROOT/fail-daemon-reload"; return 1; fi ;;\n    cat)',1)
        result=self.run_bash('uninstall_cmd',UNINSTALL_CONFIRM='YES')
        self.assertNotEqual(result.returncode,0)
        state=json.loads(self.package_state.read_text())
        self.assertTrue(state['app_missing_at_rollback'])
        self.assertEqual(state['installed'],old)
        self.assertEqual(self.file_snapshot(),before)
        self.assertEqual((self.root/'bin/sb-manager').read_bytes(),wrapper)
        self.assertEqual(json.loads(self.firewall_state.read_text()),firewall)
        self.assertTrue((self.root/'active').exists())
        self.assertTrue((self.root/'enabled').exists())
        self.assertEqual(len(list((self.root/'backups').glob('*.tar.gz'))),1)
        self.assertIn('Rollback completed',result.stderr)

    def test_uninstall_reverse_dependency_is_rejected_without_removing_packages(self):
        old,_=self.setup_uninstall_fixture(reverse_dependency=True)
        before=self.file_snapshot();firewall=json.loads(self.firewall_state.read_text())
        result=self.run_bash('uninstall_cmd',UNINSTALL_CONFIRM='YES')
        self.assertNotEqual(result.returncode,0)
        self.assertIn('移除其他软件包',result.stderr)
        self.assertEqual(json.loads(self.package_state.read_text())['installed'],old)
        self.assertEqual(self.file_snapshot(),before)
        self.assertEqual(json.loads(self.firewall_state.read_text()),firewall)
        self.assertTrue((self.root/'active').exists())
        self.assertTrue((self.root/'enabled').exists())
        actual_remove=[a for a in self.package_commands() if 'remove' in a and '-s' not in a]
        self.assertEqual(actual_remove,[])

    def test_uninstall_refuses_administrator_wrapper(self):
        old,_=self.setup_uninstall_fixture()
        wrapper=self.root/'bin/sb-manager'
        wrapper.write_text('#!/bin/bash\n# administrator managed entry\n')
        before=self.file_snapshot();firewall=json.loads(self.firewall_state.read_text())
        result=self.run_bash('uninstall_cmd',UNINSTALL_CONFIRM='YES')
        self.assertNotEqual(result.returncode,0)
        self.assertIn('拒绝删除',result.stderr)
        self.assertEqual(self.file_snapshot(),before)
        self.assertEqual(wrapper.read_text(),'#!/bin/bash\n# administrator managed entry\n')
        self.assertEqual(json.loads(self.firewall_state.read_text()),firewall)
        self.assertEqual(json.loads(self.package_state.read_text())['installed'],old)

    def test_uninstall_dnf_preserves_dependencies_by_command_contract(self):
        self.setup_uninstall_fixture('dnf4')
        result=self.run_bash('uninstall_cmd',UNINSTALL_CONFIRM='YES')
        self.assertEqual(result.returncode,0,result.stderr)
        calls=self.package_commands()
        self.assertTrue(any(a[:3]==['rpm','-e','--test'] for a in calls))
        removes=[a for a in calls if a[:2]==['dnf','remove']]
        self.assertEqual(len(removes),1)
        self.assertIn('--setopt=clean_requirements_on_remove=False',removes[0])
        self.assertFalse(any('--allowerasing' in a or 'autoremove' in a for a in calls))
        self.assertEqual(json.loads(self.package_state.read_text())['dependencies'],['curl','openssl','python3'])

    def test_backup_cannot_be_placed_inside_deployment_or_config_tree(self):
        self.managed_node()
        for target in (self.app/'client/only-backup.tar.gz',self.config.parent/'backup.tar.gz'):
            result=self.run_bash('backup_cmd "'+str(target)+'"')
            self.assertNotEqual(result.returncode,0)
            self.assertFalse(target.exists())
            self.assertIn('防止备份被覆盖',result.stderr)

    def test_restore_does_not_overwrite_foreign_manager(self):
        self.managed_node()
        result=self.run_bash('backup_cmd');self.assertEqual(result.returncode,0,result.stderr)
        archive=next((self.root/'backups').glob('*.tar.gz'))
        manager=self.root/'bin/sb-manager';manager.parent.mkdir();manager.write_text('unrelated admin tool')
        before=self.file_snapshot()
        result=self.run_bash('restore_backup "'+str(archive)+'"')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(manager.read_text(),'unrelated admin tool')
        self.assertEqual(self.file_snapshot(),before)

    def test_restore_to_clean_host_failure_does_not_leave_deployment_directory(self):
        import shutil
        self.managed_node();(self.root/'active').touch()
        result=self.run_bash('backup_cmd');self.assertEqual(result.returncode,0,result.stderr)
        archive=next((self.root/'backups').glob('*.tar.gz'))
        shutil.rmtree(self.app);self.config.unlink();(self.root/'active').unlink()
        self.setup_firewall('none');(self.root/'fail-restart').touch()
        result=self.run_bash('restore_backup "'+str(archive)+'"')
        self.assertNotEqual(result.returncode,0)
        self.assertFalse(self.app.exists())
        self.assertFalse(self.config.exists())

    def test_restore_recovers_recorded_stopped_service_state(self):
        self.managed_node()
        result=self.run_bash('backup_cmd');self.assertEqual(result.returncode,0,result.stderr)
        archive=next((self.root/'backups').glob('*.tar.gz'))
        (self.root/'active').touch();(self.root/'enabled').touch()
        result=self.run_bash('restore_backup "'+str(archive)+'"')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertFalse((self.root/'active').exists());self.assertFalse((self.root/'enabled').exists())

    def test_uninstall_rollback_drops_only_regenerable_cache(self):
        self.managed_node()
        (self.app/'cache.db').write_text('live mutable cache')
        original=self.config.read_bytes()
        result=self.run_bash('begin_transaction uninstall "$APP"\n[[ ! -e "$TEMP/0/cache.db" ]]\necho changed > "$APP/client/node-info.txt"\ndie "injected failure"')
        self.assertNotEqual(result.returncode,0)
        self.assertFalse((self.app/'cache.db').exists())
        self.assertEqual(self.config.read_bytes(),original)
        self.assertTrue((self.app/'client/node-info.txt').exists())

    def setup_firewall(self, backend, **state):
        fake = self.root / 'firewall-bin'
        fake.mkdir()
        script = fake / 'backend'
        script.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
p = pathlib.Path(os.environ['TEST_ROOT']) / 'firewall.json'
s = json.loads(p.read_text()); tool = pathlib.Path(sys.argv[0]).name; a = sys.argv[1:]
with (p.parent/'firewall.log').open('a') as f: f.write(json.dumps([tool, *a])+'\\n')
def save(): p.write_text(json.dumps(s))
def done(code=0, text=''):
    if text: print(text)
    sys.exit(code)
if tool == 'ufw':
    if a==['show','added']:
        done(text='\\n'.join('ufw '+r.split(' ',1)[0].lower()+' '+r.split(' ',1)[1]+' comment '+s['ufw_markers'].get(r.split(' ',1)[1], '') for r in s['ufw']))
    if a[:1] == ['status']:
        if s['backend'] != 'ufw': done(text='Status: inactive')
        rows = ['Status: active']
        for i, rule in enumerate(s['ufw'], 1):
            action, entry = rule.split(' ',1)
            rows.append(f'[{i:2}] {entry}  {action} IN  Anywhere # '+(s['ufw_markers'].get(entry,'') if action=='ALLOW' else ''))
        done(text='\\n'.join(rows))
    if a[:2] == ['insert','1']:
        entry=a[a.index('port')+1]+'/'+a[a.index('proto')+1]
        if s.get('skip'): done(text='Skipping inserting existing rule')
        s['ufw'].insert(0,'ALLOW '+entry); s['ufw_markers'][entry]=a[-1]; save()
        done(1 if s.get('fail') == entry else 0)
    if a[:3] == ['--force','delete','allow']:
        rule='ALLOW '+a[a.index('port')+1]+'/'+a[a.index('proto')+1]
        if rule in s['ufw'] and s['ufw_markers'].get(rule.split(' ',1)[1])==a[-1]:
            s['ufw'].remove(rule); s['ufw_markers'].pop(rule.split(' ',1)[1],None); save()
        done()
if tool == 'firewall-cmd':
    if a == ['--state']:
        if s.get('inspect_error'): done(254,'inspection failed')
        done(0 if s['backend'] == 'firewalld' else 252,'running' if s['backend'] == 'firewalld' else 'not running')
    if a == ['--get-active-zones']: done(text='public\\n  interfaces: eth0\\nwork\\n  sources: 10.0.0.0/8')
    if a == ['--get-default-zone']: done(text='public')
    zone=next(x.split('=',1)[1] for x in a if x.startswith('--zone='))
    mode='permanent' if '--permanent' in a else 'runtime'
    op,entry=next(x[2:].split('=',1) for x in a if x.startswith(('--query-port=','--add-port=','--remove-port=')))
    key=mode+':'+zone+':'+entry
    if op=='query-port': done(2 if s.get('query_error') else (0 if key in s['firewalld'] else 1))
    if op=='add-port':
        s['firewalld'].append(key); save(); done(1 if s.get('fail')==key else 0)
    if op=='remove-port':
        if key in s['firewalld']: s['firewalld'].remove(key); save()
        done(1 if s.get('fail_remove')==key else 0)
if tool == 'nft':
    if a==['-j','list','ruleset']:
        chains=[]
        if s['backend']=='nft':
            chains=[{'chain':{'family':f,'table':'filter','name':'input','hook':'input','type':'filter'}} for f in ('ip','inet','ip6')]
        done(text=json.dumps({'nftables': chains+[{'rule':r} for r in s['nft']]}))
    if a[:2]==['insert','rule']:
        s['nft'].insert(0,{'family':a[2],'table':a[3],'chain':a[4], 'comment':a[-1].strip('"'), 'handle':max([r['handle'] for r in s['nft']]+[99])+1, 'protocol':a[8], 'port':a[10], 'expr':[{'match':{'left':{'payload':{'protocol':a[8],'field':'dport'}},'right':int(a[10])}}]})
        save(); done(1 if s.get('fail')==a[8]+':'+a[10] else 0)
    if a[:2]==['delete','rule']:
        s['nft']=[r for r in s['nft'] if not (r['family']==a[2] and str(r['handle'])==a[-1])]
        save();done()
if tool=='iptables':
    if a==['--version']: done(text='iptables v1.8 (nf_tables)' if s['backend']=='nft' else 'iptables v1.8 (legacy)')
    if a==['-w','-S','INPUT']:
        rows=['-P INPUT DROP' if s['backend']=='iptables' else '-P INPUT ACCEPT']
        for key in s['iptables']:
            proto,port,mark=key.split(':',2)
            rows.append(f'-A INPUT -p {proto} --dport {port} -m comment --comment {mark} -j ACCEPT')
        done(text='\\n'.join(rows))
    proto=a[a.index('-p')+1];port=a[a.index('--dport')+1];mark=a[a.index('--comment')+1]
    key=proto+':'+port+':'+mark
    if '-I' in a:
        s['iptables'].insert(0,key);save();done(1 if s.get('fail')==proto+':'+port else 0)
    if '-C' in a: done(0 if key in s['iptables'] else 1)
    if '-D' in a:
        s['iptables'].remove(key);save();done()
done(99,'Unexpected firewall operation: '+repr([tool,*a]))
''')
        script.chmod(0o700)
        for name in ('ufw','firewall-cmd','nft','iptables'):
            (fake/name).symlink_to(script)
        self.firewall_state = self.root / 'firewall.json'
        initial = {'backend':backend, 'ufw':[], 'ufw_markers':{}, 'firewalld':[], 'nft':[], 'iptables':[], **state}
        self.firewall_state.write_text(json.dumps(initial))
        self.prelude += f'export PATH={fake}:"$PATH"\n'
        return initial

    def test_ports_validation(self):
        result = self.run_bash('read_ports\nprintf "%s %s" "$VLESS_PORT" "$HY2_PORT"',
                               VLESS_PORT='08443', HY2_PORT='9443')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, '8443 9443')
        for invalid in ('0','65536','-1','443/tcp','999999999999999999999',''):
            result = self.run_bash('read_ports', VLESS_PORT=invalid)
            self.assertNotEqual(result.returncode, 0, invalid)

    def test_firewall_ufw_preserves_existing_allow(self):
        self.setup_firewall('ufw', ufw=['ALLOW 8443/tcp'])
        result = self.run_bash('begin_transaction install\nopen_firewall\nTRANSACTION=""',
                               VLESS_PORT='8443', HY2_PORT='9443')
        self.assertEqual(result.returncode, 0, result.stderr)
        state = json.loads(self.firewall_state.read_text())
        self.assertEqual(state['ufw'], ['ALLOW 9443/udp','ALLOW 8443/tcp'])
        log = (self.root/'firewall.log').read_text()
        self.assertNotIn('"enable"',log)

    def test_firewall_ufw_failure_restores_existing_rules(self):
        initial = self.setup_firewall('ufw', ufw=['ALLOW 8443/tcp'], fail='9443/udp')
        result = self.run_bash('begin_transaction install\nopen_firewall', VLESS_PORT='8443', HY2_PORT='9443')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(self.firewall_state.read_text()), initial)
        self.assertIn('Rollback completed', result.stderr)

    def test_firewall_ufw_conflicting_order_fails_without_mutation(self):
        initial = self.setup_firewall('ufw', ufw=['DENY 8443/tcp','ALLOW 8443/tcp'])
        result = self.run_bash('begin_transaction install\nopen_firewall', VLESS_PORT='8443', HY2_PORT='9443')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(self.firewall_state.read_text()), initial)
        self.assertIn('conflicting', result.stderr)

    def test_ufw_unrelated_denies_do_not_block_existing_allow(self):
        self.setup_firewall('ufw')
        for rule in ('25/tcp', '8443/udp', '20:30/tcp', '21,22/tcp'):
            with self.subTest(rule=rule):
                state = json.loads(self.firewall_state.read_text())
                state['ufw'] = ['DENY '+rule, 'ALLOW 8443/tcp', 'ALLOW 9443/udp']
                self.firewall_state.write_text(json.dumps(state))
                result = self.run_bash('begin_transaction install\nopen_firewall\nTRANSACTION=""',
                                       VLESS_PORT='8443', HY2_PORT='9443')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(self.firewall_state.read_text()), state)

    def test_ufw_skipped_insert_is_failure(self):
        initial = self.setup_firewall('ufw', skip=True)
        result = self.run_bash('begin_transaction install\nopen_firewall', VLESS_PORT='8443', HY2_PORT='9443')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(self.firewall_state.read_text()), initial)
        self.assertIn('UFW skipped inserting', result.stderr)
        self.assertIn('Rollback completed', result.stderr)

    def test_firewalld_runtime_permanent_zones_preserved(self):
        existing = ['runtime:public:8443/tcp','permanent:work:9443/udp']
        self.setup_firewall('firewalld', firewalld=existing)
        result = self.run_bash('begin_transaction install\nopen_firewall\nTRANSACTION=""',
                               VLESS_PORT='8443', HY2_PORT='9443')
        self.assertEqual(result.returncode, 0, result.stderr)
        actual = json.loads(self.firewall_state.read_text())['firewalld']
        expected = {f'{mode}:{zone}:{port}' for mode in ('runtime','permanent') for zone in ('public','work')
                    for port in ('8443/tcp','9443/udp')}
        self.assertEqual(set(actual), expected)
        self.assertEqual(len(actual), 8)
        self.assertNotIn('--reload', (self.root/'firewall.log').read_text())

    def test_firewalld_partial_failure_rolls_back_only_additions(self):
        initial = self.setup_firewall('firewalld', firewalld=['runtime:public:8443/tcp'],
                                      fail='permanent:work:9443/udp')
        result = self.run_bash('begin_transaction install\nopen_firewall', VLESS_PORT='8443', HY2_PORT='9443')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(self.firewall_state.read_text()), initial)
        self.assertIn('Rollback completed', result.stderr)

    def test_firewall_inspection_error_fails(self):
        initial = self.setup_firewall('none', inspect_error=True)
        result = self.run_bash('begin_transaction install\nopen_firewall')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(self.firewall_state.read_text()), initial)
        self.assertIn('Cannot determine firewalld state', result.stderr)

    def test_firewalld_query_error_fails_before_opening(self):
        initial = self.setup_firewall('firewalld', query_error=True)
        result = self.run_bash('begin_transaction install\nopen_firewall')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(self.firewall_state.read_text()), initial)

    def test_native_nft_opens_all_ipv4_input_chains(self):
        self.setup_firewall('nft')
        result = self.run_bash('begin_transaction install\nopen_firewall\nTRANSACTION=""',
                               VLESS_PORT='8443', HY2_PORT='9443')
        self.assertEqual(result.returncode, 0, result.stderr)
        rules = json.loads(self.firewall_state.read_text())['nft']
        self.assertEqual({(r['family'],r['protocol'],r['port']) for r in rules},
                         {(f,p,str(port)) for f in ('ip','inet') for p,port in [('tcp',8443),('udp',9443)]})
        self.assertIn('runtime only', result.stderr)

    def test_native_nft_partial_failure_preserves_existing_rule(self):
        initial = self.setup_firewall('nft', nft=[{'family':'ip','table':'filter','chain':'input',
                                    'handle':99,'comment':'existing-rule'}], fail='udp:9443')
        result = self.run_bash('begin_transaction install\nopen_firewall', VLESS_PORT='8443', HY2_PORT='9443')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(self.firewall_state.read_text()), initial)
        self.assertIn('Rollback completed', result.stderr)

    def test_native_iptables_success_and_rollback(self):
        initial = self.setup_firewall('iptables', iptables=['tcp:22:existing-rule'])
        result = self.run_bash('begin_transaction install\nopen_firewall\ndie "injected later failure"',
                               VLESS_PORT='8443', HY2_PORT='9443')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(self.firewall_state.read_text()), initial)
        self.assertIn('Rollback completed', result.stderr)
        commands = [json.loads(x) for x in (self.root/'firewall.log').read_text().splitlines()]
        added = [x for x in commands if x[0]=='iptables' and '-I' in x]
        self.assertEqual(len(added), 2)
        self.assertTrue(all('-w' in x for x in added))

    def test_no_active_firewall_is_not_enabled(self):
        initial = self.setup_firewall('none')
        result = self.run_bash('begin_transaction install\nopen_firewall\nTRANSACTION=""')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(self.firewall_state.read_text()), initial)
        self.assertIn('No active supported host input firewall detected', result.stderr)


    def test_socks_protocol_success_auth_rejection_and_truncated_reply(self):
        for reply in ('success', 'auth-reject', 'truncated', 'connect-reject'):
            with self.subTest(reply=reply):
                with socket.socket() as listener:
                    listener.bind(('127.0.0.1', 0))
                    listener.listen()
                    port = listener.getsockname()[1]
                    errors = []
                    def serve():
                        try:
                            with listener.accept()[0] as conn:
                                conn.settimeout(5)
                                self.assertEqual(conn.recv(3), b'\x05\x01\x02')
                                conn.sendall(b'\x05\x02')
                                conn.recv(1024)
                                if reply == 'auth-reject':
                                    conn.sendall(b'\x01\x01')
                                    return
                                conn.sendall(b'\x01\x00')
                                conn.recv(1024)
                                if reply == 'truncated':
                                    conn.sendall(b'\x05')
                                else:
                                    conn.sendall(bytes([5, 1 if reply == 'connect-reject' else 0, 0, 1]) + bytes(6))
                        except BaseException as exc:
                            errors.append(exc)
                    thread = threading.Thread(target=serve, daemon=True)
                    thread.start()
                    result = self.run_bash('check_socks ai', AI_SOCKS_HOST='127.0.0.1',
                                           AI_SOCKS_PORT=str(port), AI_SOCKS_USER='user', AI_SOCKS_PASS='secret')
                    thread.join(6)
                    self.assertFalse(errors, errors)
                    self.assertFalse(thread.is_alive())
                    self.assertEqual(result.returncode == 0, reply == 'success', result.stderr)
                    self.assertNotIn('secret', result.stderr)


if __name__ == '__main__':
    unittest.main()
