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
  printf 'PrivateKey: dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo\\nPublicKey: hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo\\n'
fi
''')
        self.bin.chmod(0o700)
        # Never inspect or mutate the workstation firewall when a test omits a backend fixture.
        inactive = self.root/'inactive-firewall'
        inactive.mkdir()
        tool = inactive/'backend'
        tool.write_text("""#!/usr/bin/env python3
import pathlib,sys
name=pathlib.Path(sys.argv[0]).name;args=sys.argv[1:]
if name=='ufw' and args==['status']: print('Status: inactive')
elif name=='firewall-cmd' and args==['--state']: print('not running');sys.exit(252)
elif name=='nft' and args[:3]==['-j','list','ruleset']: print('{"nftables": []}')
elif name=='nft' and args[:3]==['-j','list','tables']: print('{"nftables": []}')
elif name=='iptables' and args==['--version']: print('iptables v1.8 (legacy)')
elif name=='iptables' and args==['-w','-S','INPUT']: print('-P INPUT ACCEPT')
else: sys.exit(1)
""")
        tool.chmod(0o700)
        for name in ('ufw','firewall-cmd','nft','iptables'):
            (inactive/name).symlink_to(tool)
        self.prelude = f'''source {self.lib}
export PATH={inactive}:"$PATH"
BIN={self.bin}
export SERVER_IP="${{SERVER_IP:-8.8.8.8}}"
# Existing fixtures model deployments created before AnyTLS support.
ANYTLS_PORT="${{ANYTLS_PORT_REQUEST:-}}"
TUIC_PORT="${{TUIC_PORT_REQUEST:-}}"
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
      restart) hopping_runtime stop || return 1; hopping_runtime start || return 1; touch "$TEST_ROOT/hop-active" ;;
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
        return subprocess.run(['bash', '-c', self.prelude + body], stdin=subprocess.DEVNULL, text=True,
                              capture_output=True, env={**os.environ, 'TEST_ROOT': str(self.root), **env}, timeout=20)

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
        self.assertIn('其他 → SOCKS5 new-other:1082', info.read_text())

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
        self.managed_node()
        original = self.config.read_bytes()
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
        self.assertIn('Everything else: Other SOCKS5', result.stdout)
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

    def test_check_connections_reads_arbitrary_socks_tags_without_managed_node_files(self):
        self.config.parent.mkdir(parents=True)
        config = {'inbounds':[], 'outbounds':[
            {'type':'socks','tag':'custom-auth','server':'auth.example','server_port':19001,
             'username':'actual-user','password':'actual-secret'},
            {'type':'socks','tag':'custom-open','server':'open.example','server_port':19002},
            {'type':'direct','tag':'direct'},
            {'type':'socks','tag':'old-socks4','server':'v4.example','server_port':19003,'version':'4'}]}
        self.config.write_text(json.dumps(config))
        result=self.run_bash('''check_socks() {
  python3 - <<'PYCODE'
import json,os,pathlib
p=pathlib.Path(os.environ['TEST_ROOT'])/'probes.jsonl'
with p.open('a') as f: f.write(json.dumps([os.environ['PROBE_SOCKS_'+k] for k in ('HOST','PORT','USER','PASS')])+'\\n')
PYCODE
}
load_node_settings() { die 'managed settings must not be read'; }
check_reality_target() { die 'fixed Reality target must not be read'; }
check_connections
''',AI_SOCKS_HOST='wrong.example',AI_SOCKS_PORT='1080',AI_SOCKS_USER='wrong',AI_SOCKS_PASS='wrong')
        self.assertEqual(result.returncode,0,result.stderr)
        rows=[json.loads(line) for line in (self.root/'probes.jsonl').read_text().splitlines()]
        self.assertEqual(rows,[['auth.example','19001','actual-user','actual-secret'],['open.example','19002','','']])
        self.assertIn('custom-auth',result.stderr)
        self.assertIn('custom-open',result.stderr)
        self.assertNotIn('actual-secret',result.stderr+result.stdout)
        self.assertIn('跳过',result.stderr)
        self.assertFalse(self.app.exists())
        self.assertFalse((self.root/'service.log').exists())

    def test_check_socks_supports_no_auth_and_rejects_unexpected_method(self):
        for accepted in (True,False):
            with self.subTest(accepted=accepted),socket.socket() as listener:
                listener.bind(('127.0.0.1',0));listener.listen();listener.settimeout(5)
                errors=[]
                def serve():
                    try:
                        with listener.accept()[0] as conn:
                            conn.settimeout(5)
                            self.assertEqual(conn.recv(3),b'\x05\x01\x00')
                            conn.sendall(b'\x05\x00' if accepted else b'\x05\x02')
                            if accepted:
                                self.assertTrue(conn.recv(1024).startswith(b'\x05\x01\x00\x03'))
                                conn.sendall(b'\x05\x00\x00\x01'+bytes(6))
                    except BaseException as exc: errors.append(exc)
                thread=threading.Thread(target=serve,daemon=True);thread.start()
                result=self.run_bash('check_socks probe',PROBE_SOCKS_HOST='127.0.0.1',
                    PROBE_SOCKS_PORT=str(listener.getsockname()[1]),PROBE_SOCKS_USER='',PROBE_SOCKS_PASS='')
                thread.join(6)
                self.assertFalse(thread.is_alive());self.assertFalse(errors,errors)
                self.assertEqual(result.returncode==0,accepted,result.stderr)
        result=self.run_bash('check_socks probe',PROBE_SOCKS_HOST='127.0.0.1',PROBE_SOCKS_PORT='1',
                             PROBE_SOCKS_USER='user',PROBE_SOCKS_PASS='')
        self.assertNotEqual(result.returncode,0)
        self.assertIn('1-255',result.stderr)

    def test_check_connections_uses_configured_certificates_and_reality_endpoint(self):
        import shutil
        self.config.parent.mkdir(parents=True)
        cert=self.root/'external-public.crt';key=self.root/'external-private.key'
        openssl=shutil.which('openssl')
        subprocess.run([openssl,'req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256',
                        '-nodes','-days','1','-keyout',str(key),'-out',str(cert),'-subj','/CN=certificate.example'],
                       check=True,capture_output=True)
        tools=self.root/'openssl-probe';tools.mkdir();fake=tools/'openssl'
        fake.write_text('''#!/usr/bin/env python3
import json,os,pathlib,sys
args=sys.argv[1:]
with (pathlib.Path(os.environ['TEST_ROOT'])/'openssl-args.jsonl').open('a') as f: f.write(json.dumps(args)+'\\n')
if args[0]=='s_client':
    assert '-verify_return_error' in args and '-tls1_3' in args
    print('CONNECTION ESTABLISHED',file=sys.stderr)
else: os.execv(os.environ['REAL_OPENSSL'],[os.environ['REAL_OPENSSL'],*args])
''');fake.chmod(0o700)
        self.config.write_text(json.dumps({'outbounds':[], 'inbounds':[
            {'type':'anytls','tag':'external-file','tls':{'enabled':True,'certificate_path':str(cert)}},
            {'type':'tuic','tag':'embedded','tls':{'enabled':True,'certificate':[cert.read_text()]}},
            {'type':'vless','tag':'custom-reality','tls':{'enabled':True,'server_name':'certificate.example',
                'reality':{'enabled':True,'handshake':{'server':'::1','server_port':18443}}}},
            {'type':'anytls','tag':'dynamic','tls':{'enabled':True,'certificate_provider':'custom-provider'}},
            {'type':'anytls','tag':'disabled-tls','tls':{'enabled':False,'certificate_path':'/must/not/read'}}]}))
        result=self.run_bash(f'export PATH={tools}:"$PATH"\ncheck_connections',REAL_OPENSSL=openssl)
        self.assertEqual(result.returncode,0,result.stderr)
        calls=[json.loads(line) for line in (self.root/'openssl-args.jsonl').read_text().splitlines()]
        self.assertEqual(len(calls),3)
        self.assertIn(str(cert),calls[0]);self.assertNotIn('-in',calls[1])
        self.assertEqual(calls[2][calls[2].index('-connect')+1],'[::1]:18443')
        self.assertEqual(calls[2][calls[2].index('-servername')+1],'certificate.example')
        self.assertIn('动态证书需在服务运行时核实',result.stderr)
        self.assertNotIn('/must/not/read',result.stdout+result.stderr)
        self.assertFalse(self.app.exists())

    def test_check_connections_propagates_certificate_failures_without_fake_success(self):
        self.config.parent.mkdir(parents=True)
        self.config.write_text(json.dumps({'outbounds':[], 'inbounds':[
            {'type':'anytls','tag':'actual','tls':{'enabled':True,'certificate_path':str(self.root/'missing.crt')}}]}))
        result=self.run_bash('check_connections')
        self.assertNotEqual(result.returncode,0)
        self.assertIn('TLS 证书无效',result.stderr)
        self.assertNotIn('项目检查通过',result.stderr)

    def test_check_connections_skips_absent_optional_protocols(self):
        self.config.parent.mkdir(parents=True)
        self.config.write_text(json.dumps({'inbounds':[],'outbounds':[{'type':'direct','tag':'only-direct'}]}))
        result=self.run_bash('check_connections')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('未配置 SOCKS5',result.stderr)
        self.assertIn('未配置 Reality',result.stderr)
        self.assertFalse(self.app.exists())

    def test_output_colors_require_terminal_and_leave_yaml_plain(self):
        self.managed_node()
        body = "ui title '标题'\nmenu_choices $' 1. 安装\\n13. 卸载\\n'\nnode_config show"
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
        config=json.loads(self.config.read_text())
        config['inbounds'][0]['listen_port']=10443
        config['inbounds'][2]['listen_port']=10444
        self.config.write_text(json.dumps(config))
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
        self.bin.write_text(self.bin.read_text().replace('dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo','XasIfmJKikt54X-Lg4AO5m87sSkmGLb9HC-LJ_-I4Os').replace('hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo','3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08'))
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
            self.assertEqual(client['tls']['reality']['public_key'],'3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08')
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
        self.setup_nat()
        for body in ('stage_changes set_node ports','stage_changes set_hopping'):
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

    def test_port_adjustment_boundaries_display_current_occupied_ports(self):
        self.managed_node()
        # Every JSON field edit can alter a nested port, so it also displays the snapshot.
        result=self.run_terminal('stage_changes edit_inbound_field hysteria2 /listen_port', '9555\n')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertLess(result.stderr.index('当前已占用端口'),result.stderr.index('/listen_port：'))
        pending=json.loads((self.app/'pending/config.json').read_text())
        self.assertEqual(pending['inbounds'][1]['listen_port'],9555)
        self.assertFalse((self.root/'service.log').exists())
        result=self.run_terminal('read_ports HY2_PORT','9443\n')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertLess(result.stderr.index('当前已占用端口'),result.stderr.index('HY2_PORT 监听端口'))
        result=self.run_bash('ss() { echo "udp UNCONN 0 0 0.0.0.0:32100 *:*"; }; show_occupied_ports')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('32100',result.stderr)
        self.assertEqual(result.stdout,'')

    def test_protocol_menu_follows_pending_inbounds_including_custom_types(self):
        config=self.managed_node()
        config['inbounds'].append({'type':'socks','tag':'custom-entry','listen_port':1080,'listen':'127.0.0.1','users':[{'username':'private-user','password':'private-password'}]})
        self.config.write_text(json.dumps(config))
        result=self.run_bash("stage_changes edit_inbound_field @2 /tag '\"renamed-custom\"'")
        self.assertEqual(result.returncode,0,result.stderr)
        result=self.run_bash('protocol_entries')
        self.assertEqual(result.returncode,0,result.stderr)
        entries=result.stdout.split('\0')
        self.assertIn('socks · renamed-custom',entries);self.assertIn('inbound:@2',entries)
        self.assertNotIn('private-password',result.stdout)
        result=self.run_bash('menu_config menu-inbound @2')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('field:/listen_port',result.stdout)
        self.assertNotIn('hopping',result.stdout)
        self.assertNotIn('AnyTLS',result.stdout)

    def test_field_menu_recurses_and_keeps_values_private(self):
        self.managed_node(tuic=True)
        result=self.run_bash('node_config menu-fields @2 /tls')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('switch:/tls/enabled',result.stdout)
        result=self.run_bash('node_config menu-fields @2 /users/0')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('field:/users/0/password',result.stdout)
        self.assertNotIn('tuic-secret',result.stdout)
        self.assertIn('remove:/users/0',result.stdout)

    def test_optional_fields_can_be_disabled_removed_and_added_without_reload(self):
        self.managed_node(tuic=True)
        result=self.run_bash("stage_changes edit_inbound_field tuic /zero_rtt_handshake true\nstage_changes edit_inbound_field tuic /zero_rtt_handshake false\nstage_changes edit_inbound_field tuic /heartbeat :remove\nstage_changes edit_inbound_field tuic /heartbeat '\"17s\"'")
        self.assertEqual(result.returncode,0,result.stderr)
        item=json.loads((self.app/'pending/config.json').read_text())['inbounds'][2]
        self.assertFalse(item['zero_rtt_handshake']);self.assertEqual(item['heartbeat'],'17s')
        self.assertEqual(json.loads(self.config.read_text())['inbounds'][2]['heartbeat'],'10s')
        self.assertFalse((self.root/'service.log').exists())
        before=self.file_snapshot()
        for pointer,value in (('/heartbeat','invalid-json'),('not-pointer','true'),('/users/nope/password','true')):
            result=self.run_bash(f'stage_changes edit_inbound_field tuic "{pointer}" "{value}"')
            self.assertNotEqual(result.returncode,0)
            self.assertEqual(self.file_snapshot(),before)

    def test_dynamic_menu_rebuilds_after_each_action(self):
        result=self.run_terminal("""counter_file="$TEST_ROOT/menu-counter"
echo first > "$counter_file"
entries() { if [[ $(cat "$counter_file") == first ]]; then printf '初始项\\0status\\0'; else printf '更新项\\0check\\0'; fi; }
menu_action() { printf 'ACTION:%s\\n' "$1"; echo second > "$counter_file"; }
run_menu 动态菜单 '' @entries""",'1\n1\n0\n')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('ACTION:status',result.stdout);self.assertIn('ACTION:check',result.stdout)
        self.assertIn('1. 更新项',result.stdout)

    def test_creation_menu_omits_already_pending_protocol(self):
        self.managed_node()
        result=self.run_bash('stage_changes set_node add-tuic')
        self.assertEqual(result.returncode,0,result.stderr)
        result=self.run_bash('protocol_creation_entries')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('add-anytls',result.stdout);self.assertNotIn('add-tuic',result.stdout)

    def test_config_tags_are_rendered_literally_without_hiding_exit(self):
        config=self.managed_node()
        config['inbounds'][0]['tag']=r'user\cnode'
        self.config.write_text(json.dumps(config))
        result=self.run_terminal('protocol_menu','0\n')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn(r'user\cnode',result.stdout)
        self.assertIn('hysteria2',result.stdout);self.assertIn('0. 返回 / 退出',result.stdout)

    def test_custom_inbound_port_edits_update_owned_firewall(self):
        config=self.managed_node()
        config['inbounds'].append({'type':'socks','tag':'custom','listen':'::','listen_port':12443})
        self.config.write_text(json.dumps(config))
        self.setup_firewall('ufw',ufw=['ALLOW 22/tcp'])
        result=self.run_bash('begin_transaction update "$APP/firewall-owned.json"\nopen_firewall\nupdate_firewall_ownership\nTRANSACTION=""')
        self.assertEqual(result.returncode,0,result.stderr)
        result=self.run_bash('stage_changes edit_inbound_field @2 /listen_port 12444\napply_changes')
        self.assertEqual(result.returncode,0,result.stderr)
        rules=json.loads(self.firewall_state.read_text())['ufw']
        self.assertIn('ALLOW 12444/tcp',rules);self.assertNotIn('ALLOW 12443/tcp',rules)
        self.assertIn('ALLOW 22/tcp',rules)

    def test_duplicate_protocol_instances_can_be_edited_and_applied_separately(self):
        config=self.managed_node()
        extra=json.loads(json.dumps(config['inbounds'][0]));extra.update(tag='second-vless',listen_port=12443)
        config['inbounds'].append(extra);self.config.write_text(json.dumps(config))
        result=self.run_bash('stage_changes edit_inbound_field @2 /listen_port 12444\napply_changes')
        self.assertEqual(result.returncode,0,result.stderr)
        current=json.loads(self.config.read_text())
        self.assertEqual(current['inbounds'][0],config['inbounds'][0])
        self.assertEqual(current['inbounds'][2]['listen_port'],12444)
        self.assertTrue((self.app/'client/EXPORT-ERROR.txt').exists())

    def test_hopping_menu_and_edits_follow_selected_hy2_instance(self):
        config=self.managed_node();self.setup_nat()
        extra=json.loads(json.dumps(config['inbounds'][1]));extra.update(tag='second-hy2',listen_port=12443)
        config['inbounds'].append(extra);self.config.write_text(json.dumps(config))
        result=self.run_bash('stage_changes set_hopping @2',HY2_HOP_PORTS='20000:20005')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads((self.app/'pending/hopping.json').read_text())['base_port'],12443)
        result=self.run_bash('menu_config menu-inbound @1')
        self.assertEqual(result.returncode,0,result.stderr);self.assertNotIn('disable-hopping',result.stdout)
        result=self.run_bash('menu_config menu-inbound @2')
        self.assertEqual(result.returncode,0,result.stderr);self.assertIn('disable-hopping',result.stdout)
        result=self.run_bash('stage_changes edit_inbound_field @1 /listen_port 9555\napply_changes')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads((self.app/'hopping.json').read_text())['base_port'],12443)
        self.assertEqual(json.loads(self.config.read_text())['inbounds'][1]['listen_port'],9555)

    def test_generic_listener_network_controls_firewall_and_retirement(self):
        config=self.managed_node()
        config['inbounds'].append({'type':'direct','tag':'direct-test','listen':'::','listen_port':12443,'network':'udp'})
        self.config.write_text(json.dumps(config));self.setup_firewall('ufw')
        result=self.run_bash('configuration_listeners')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('udp 12443 direct-test',result.stdout);self.assertNotIn('tcp 12443',result.stdout)
        result=self.run_bash('apply_changes')
        self.assertEqual(result.returncode,0,result.stderr)
        result=self.run_bash('stage_changes edit_inbound_field @2 /network \'"tcp"\'\napply_changes')
        self.assertEqual(result.returncode,0,result.stderr)
        rules=json.loads(self.firewall_state.read_text())['ufw']
        self.assertIn('ALLOW 12443/tcp',rules);self.assertNotIn('ALLOW 12443/udp',rules)
        result=self.run_bash('stage_changes edit_inbound_field @2 /network :remove\napply_changes')
        self.assertEqual(result.returncode,0,result.stderr)
        rules=json.loads(self.firewall_state.read_text())['ufw']
        self.assertIn('ALLOW 12443/tcp',rules);self.assertIn('ALLOW 12443/udp',rules)

    def test_config_only_edit_stage_and_apply_without_management_files(self):
        self.config.parent.mkdir(parents=True)
        original={'inbounds':[{'type':'direct','tag':'existing','listen':'127.0.0.1','listen_port':18443,'network':'tcp'}],'outbounds':[{'type':'direct','tag':'direct'}]}
        self.config.write_text(json.dumps(original))
        self.assertFalse(self.app.exists())
        result=self.run_bash('stage_changes edit_inbound_field @0 /listen_port 18444')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(self.config.read_text()),original)
        self.assertFalse((self.root/'service.log').exists())
        result=self.run_bash('apply_changes')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(self.config.read_text())['inbounds'][0]['listen_port'],18444)
        self.assertTrue((self.root/'active').exists())
        self.assertFalse((self.app/'pending').exists())

    def test_missing_client_exports_are_rebuilt_entirely_from_config(self):
        import shutil
        config=self.managed_node(anytls=True,tuic=True)
        shutil.rmtree(self.app/'client')
        result=self.run_bash('load_node_settings\nnode_config export\nnode_config json')
        self.assertEqual(result.returncode,0,result.stderr)
        clients=json.loads(result.stdout)['outbounds']
        self.assertEqual([i['type'] for i in clients],['vless','hysteria2','anytls','tuic'])
        self.assertEqual(clients[0]['uuid'],config['inbounds'][0]['users'][0]['uuid'])
        self.assertEqual(clients[0]['tls']['reality']['public_key'],'hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo')
        self.assertEqual(clients[1]['password'],config['inbounds'][1]['users'][0]['password'])
        for file in (self.app/'client').iterdir():
            if file.is_file(): self.assertEqual(file.stat().st_mode&0o777,0o600)
        (self.app/'client/vless-reality.outbound.json').write_text('broken cached JSON')
        result=self.run_bash('node_config json')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(result.stdout)['outbounds'],clients)

    def test_single_protocol_inline_tls_config_without_any_app_exports(self):
        import shutil
        config=self.managed_node(anytls=True)
        item=config['inbounds'][2]
        item['tls']['certificate']=(self.app/'tls/anytls.crt').read_text()
        item['tls']['key']=(self.app/'tls/anytls.key').read_text()
        item['tls'].pop('certificate_path');item['tls'].pop('key_path')
        only={'inbounds':[item],'outbounds':[{'type':'direct'}]}
        self.config.write_text(json.dumps(only));shutil.rmtree(self.app)
        result=self.run_bash('node_config json')
        self.assertEqual(result.returncode,0,result.stderr)
        clients=json.loads(result.stdout)['outbounds']
        self.assertEqual(len(clients),1);self.assertEqual(clients[0]['type'],'anytls')
        self.assertEqual(clients[0]['password'],item['users'][0]['password'])
        self.assertFalse(self.app.exists())
        result=self.run_bash('stage_changes edit_inbound_field @0 /listen_port 19444\napply_changes')
        self.assertEqual(result.returncode,0,result.stderr)
        current=json.loads(self.config.read_text())
        self.assertEqual(current['inbounds'][0]['listen_port'],19444)
        self.assertEqual(current['inbounds'][0]['tls'],item['tls'])

    def test_external_tls_paths_survive_missing_app_edit_and_apply(self):
        import shutil
        config=self.managed_node()
        item=config['inbounds'][1]
        cert=self.root/'external.crt';key=self.root/'external.key'
        cert.write_bytes((self.app/'tls/hy2.crt').read_bytes());key.write_bytes((self.app/'tls/hy2.key').read_bytes())
        before=(cert.read_bytes(),key.read_bytes())
        item['tls'].update(certificate_path=str(cert),key_path=str(key))
        self.config.write_text(json.dumps({'inbounds':[item],'outbounds':[{'type':'direct'}]}))
        shutil.rmtree(self.app)
        result=self.run_bash('stage_changes edit_inbound_field @0 /listen_port 19444\napply_changes')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual((cert.read_bytes(),key.read_bytes()),before)
        self.assertEqual(json.loads(self.config.read_text())['inbounds'][0]['tls']['certificate_path'],str(cert))

    def test_config_only_failed_stage_preserves_original_and_can_restart(self):
        self.config.parent.mkdir(parents=True)
        self.config.write_text(json.dumps({'inbounds':[{'type':'direct','tag':'existing','listen_port':18443}],'outbounds':[{'type':'direct'}]}))
        before=self.config.read_bytes();(self.root/'fail-check').touch()
        result=self.run_bash('stage_changes edit_inbound_field @0 /listen_port 18444')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(self.config.read_bytes(),before);self.assertFalse((self.app/'pending').exists())
        (self.root/'fail-check').unlink()
        result=self.run_bash('service_cmd restart')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertTrue((self.root/'active').exists())
        self.assertFalse((self.app/'client').exists())

    def test_socks_changes_do_not_require_exported_node_info(self):
        import shutil
        self.managed_node();shutil.rmtree(self.app/'client')
        result=self.run_bash(self.update_body())
        self.assertEqual(result.returncode,0,result.stderr)
        out={o.get('tag'):o for o in json.loads(self.config.read_text())['outbounds']}
        self.assertEqual(out['ai-socks']['server'],'new-ai')
        self.assertEqual(out['google-socks']['server'],'new-google')

    def test_optional_export_missing_openssl_does_not_require_management_files(self):
        self.managed_node()
        fake=self.root/'python-fakes';fake.mkdir()
        (fake/'subprocess.py').write_text('def run(*args, **kwargs):\n    raise FileNotFoundError("openssl unavailable")\n')
        original=self.config.read_bytes()
        result=self.run_bash('export_client_files',PYTHONPATH=str(fake))
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(self.config.read_bytes(),original)
        self.assertIn('openssl',(self.app/'client/EXPORT-ERROR.txt').read_text())

    def test_tuic_config_with_omitted_password_exports_without_client_seed(self):
        import shutil
        config=self.managed_node(tuic=True)
        item=config['inbounds'][2];item['users'][0].pop('password')
        self.config.write_text(json.dumps({'inbounds':[item],'outbounds':[{'type':'direct'}]}))
        shutil.rmtree(self.app/'client')
        result=self.run_bash('node_config json')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(result.stdout)['outbounds'][0]['password'],'')
        self.assertFalse((self.app/'client').exists())

    def test_missing_export_address_does_not_block_valid_config_changes(self):
        config=self.managed_node(anytls=True)
        self.config.write_text(json.dumps({'inbounds':[config['inbounds'][2]],'outbounds':[{'type':'direct'}]}))
        result=self.run_bash('SERVER_IP=""\ncurl() { echo UNEXPECTED_NETWORK >&2; return 1; }\nstage_changes edit_inbound_field @0 /listen_port 19444\napply_changes')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertNotIn('UNEXPECTED_NETWORK',result.stderr)
        self.assertEqual(json.loads(self.config.read_text())['inbounds'][0]['listen_port'],19444)
        self.assertIn('SERVER_IP',(self.app/'client/EXPORT-ERROR.txt').read_text())

    def test_unwritable_client_output_does_not_roll_back_valid_server_edit(self):
        self.managed_node()
        external=self.root/'untouched-client-file';external.write_text('keep external file')
        exported=self.app/'client/vless-reality.outbound.json';exported.unlink();exported.symlink_to(external)
        result=self.run_bash('stage_changes edit_inbound_field @1 /listen_port 19444\napply_changes')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('客户端资料导出失败',result.stderr)
        self.assertEqual(json.loads(self.config.read_text())['inbounds'][1]['listen_port'],19444)
        self.assertEqual(external.read_text(),'keep external file')
        self.assertTrue((self.root/'active').exists())

    def test_backup_ignores_disposable_client_output_cache(self):
        import tarfile
        self.managed_node()
        (self.app/'client/broken-cache').symlink_to(self.config)
        result=self.run_bash('backup_cmd')
        self.assertEqual(result.returncode,0,result.stderr)
        archive=next((self.root/'backups').glob('*.tar.gz'))
        with tarfile.open(archive) as handle:
            self.assertFalse(any(name.startswith('client/') for name in handle.getnames()))
            self.assertIn('config.json',handle.getnames())

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

    def test_menu_zero_is_rendered_without_a_final_newline(self):
        result=self.run_bash("menu_choices $' 1. 测试\\n 0. 退出'")
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('0. 退出',result.stdout)
        result=self.run_terminal("run_menu '测试菜单' '' '测试' status",'0\n')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('0. 返回 / 退出',result.stdout)

    def test_tuic_generated_defaults_and_secure_exports(self):
        import base64,uuid,hashlib,ssl
        config=self.managed_node(anytls=True,tuic=True)
        u=config['inbounds'][3]
        self.assertEqual(u['type'],'tuic');self.assertEqual(u['listen_port'],11443)
        self.assertEqual(u['congestion_control'],'bbr')
        self.assertEqual(u['auth_timeout'],'3s');self.assertEqual(u['heartbeat'],'10s')
        self.assertFalse(u['zero_rtt_handshake']);self.assertFalse(u['disable_path_mtu_discovery'])
        uuid.UUID(u['users'][0]['uuid'])
        self.assertNotEqual(u['users'][0]['uuid'],config['inbounds'][0]['users'][0]['uuid'])
        self.assertEqual(len(base64.b64decode(u['users'][0]['password'])),32)
        self.assertTrue(config['inbounds'][1]['ignore_client_bandwidth'])
        for item in config['inbounds']:self.assertEqual(item['tls']['handshake_timeout'],'10s')
        h=config['inbounds'][1]
        for key in ('initial_packet_size','disable_path_mtu_discovery','idle_timeout','keep_alive_period','stream_receive_window','connection_receive_window','max_concurrent_streams'):
            self.assertNotIn(key,h)
        client=json.loads((self.app/'client/tuic.outbound.json').read_text())
        self.assertEqual(client['uuid'],u['users'][0]['uuid'])
        self.assertEqual(client['password'],u['users'][0]['password'])
        self.assertFalse(client['tls']['insecure']);self.assertFalse(client['zero_rtt_handshake'])
        self.assertEqual(client['tls']['handshake_timeout'],'10s')
        self.assertNotIn('auth_timeout',client)
        self.assertNotIn('ignore_client_bandwidth',json.loads((self.app/'client/hysteria2.outbound.json').read_text()))
        result=self.run_bash('node_config yaml')
        self.assertEqual(result.returncode,0,result.stderr)
        text=result.stdout.split('  - name: "TUIC"',1)[1]
        self.assertIn('heartbeat-interval: 10000',text)
        self.assertIn('reduce-rtt: false',text)
        self.assertIn('congestion-controller: "bbr"',text)
        self.assertNotIn('token:',text)
        pin=hashlib.sha256(ssl.PEM_cert_to_DER_cert((self.app/'tls/tuic.crt').read_text())).hexdigest()
        self.assertIn(pin,text)
        self.assertFalse((self.app/'client/proxies.yaml').exists())

    def test_tuic_add_apply_port_change_rotation_and_owned_firewall(self):
        original=self.managed_node()
        self.setup_firewall('ufw',ufw=['ALLOW 22/tcp'])
        result=self.run_bash('stage_changes set_node add-tuic',TUIC_PORT='11443')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(self.config.read_text()),original)
        self.assertFalse((self.root/'service.log').exists())
        result=self.run_bash('apply_changes')
        self.assertEqual(result.returncode,0,result.stderr)
        before=json.loads(self.config.read_text());self.assertEqual(before['inbounds'][:2],original['inbounds'])
        self.assertIn('ALLOW 11443/udp',json.loads(self.firewall_state.read_text())['ufw'])
        result=self.run_bash('stage_changes set_node ports',TUIC_PORT='12443')
        self.assertEqual(result.returncode,0,result.stderr)
        result=self.run_bash('stage_changes set_node regenerate tuic')
        self.assertEqual(result.returncode,0,result.stderr)
        pending=json.loads((self.app/'pending/config.json').read_text())
        self.assertNotEqual(pending['inbounds'][2]['users'],before['inbounds'][2]['users'])
        result=self.run_bash('apply_changes')
        self.assertEqual(result.returncode,0,result.stderr)
        state=json.loads(self.firewall_state.read_text())['ufw']
        self.assertIn('ALLOW 12443/udp',state);self.assertNotIn('ALLOW 11443/udp',state)
        self.assertIn('ALLOW 22/tcp',state)
        self.assertEqual(json.loads(self.config.read_text())['inbounds'][2]['listen_port'],12443)

    def test_tuic_conflict_and_apply_failure_preserve_live_and_pending(self):
        self.managed_node()
        before=self.file_snapshot()
        result=self.run_bash('stage_changes set_node add-tuic',TUIC_PORT='9443')
        self.assertNotEqual(result.returncode,0);self.assertEqual(self.file_snapshot(),before)
        self.setup_firewall('ufw',ufw=['ALLOW 22/tcp'])
        result=self.run_bash('stage_changes set_node add-tuic',TUIC_PORT='11443')
        self.assertEqual(result.returncode,0,result.stderr)
        before=self.file_snapshot();(self.root/'active').touch();(self.root/'fail-restart').touch()
        result=self.run_bash('apply_changes')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(self.file_snapshot(),before)
        self.assertEqual(json.loads(self.firewall_state.read_text())['ufw'],['ALLOW 22/tcp'])
        self.assertTrue((self.root/'active').exists())

    def test_protocol_full_editor_preserves_all_fields_and_other_protocols(self):
        original=self.managed_node(anytls=True,tuic=True)
        candidate=json.loads(json.dumps(original['inbounds'][3]))
        candidate.update(auth_timeout='7s',heartbeat='17s',congestion_control='cubic',max_concurrent_streams=37,idle_timeout='2m')
        candidate['tls']['handshake_timeout']='20s'
        candidate['users'].append({'name':'second','uuid':'00000000-0000-4000-8000-000000000001','password':'second: #password'})
        candidate['tag']='renamed-tuic'
        source=self.root/'input.json';source.write_text(json.dumps(candidate))
        result=self.run_bash(f'stage_changes edit_protocol tuic "{source}"')
        self.assertEqual(result.returncode,0,result.stderr)
        pending=json.loads((self.app/'pending/config.json').read_text())
        expected=json.loads(json.dumps(candidate))
        for key in ('certificate_path','key_path'):expected['tls'][key]=expected['tls'][key].replace('/tls/','/pending/tls/')
        self.assertEqual(pending['inbounds'][3],expected)
        self.assertEqual(json.loads(self.config.read_text()),original)
        self.assertFalse((self.root/'service.log').exists())
        result=self.run_bash('apply_changes')
        self.assertEqual(result.returncode,0,result.stderr)
        current=json.loads(self.config.read_text())
        self.assertEqual(current['inbounds'][:3],original['inbounds'][:3])
        self.assertEqual(current['inbounds'][3],candidate)
        client=json.loads((self.app/'client/tuic.outbound.json').read_text())
        self.assertEqual(client['heartbeat'],'17s');self.assertEqual(client['tls']['handshake_timeout'],'20s')
        self.assertEqual(client['password'],candidate['users'][0]['password'])
        self.assertIn('第一个用户',result.stdout)

    def test_protocol_full_editor_rejects_invalid_document_without_touching_live(self):
        self.managed_node(anytls=True,tuic=True)
        before=self.file_snapshot()
        source=self.root/'bad.json'
        for data in ('not json',json.dumps({'type':'vless','tag':'tuic','listen_port':11443}),json.dumps({'type':'tuic','tag':'hysteria2','listen_port':11443})):
            source.write_text(data)
            result=self.run_bash(f'stage_changes edit_protocol tuic "{source}"')
            self.assertNotEqual(result.returncode,0)
            self.assertEqual(self.file_snapshot(),before)
        self.assertFalse((self.root/'service.log').exists())

    def test_protocol_defaults_migration_is_staged_and_removes_optional_quic(self):
        config=self.managed_node(anytls=True,tuic=True)
        h=config['inbounds'][1]
        h.update(ignore_client_bandwidth=False,initial_packet_size=1300,disable_path_mtu_discovery=True,idle_timeout='1m',keep_alive_period='15s',stream_receive_window='8 MB',connection_receive_window='20 MB',max_concurrent_streams=1024)
        for item in config['inbounds']:item['tls']['handshake_timeout']='15s'
        self.config.write_text(json.dumps(config))
        result=self.run_bash('stage_changes update_protocol_defaults')
        self.assertEqual(result.returncode,0,result.stderr)
        pending=json.loads((self.app/'pending/config.json').read_text())
        self.assertTrue(pending['inbounds'][1]['ignore_client_bandwidth'])
        for field in ('initial_packet_size','disable_path_mtu_discovery','idle_timeout','keep_alive_period','stream_receive_window','connection_receive_window','max_concurrent_streams'):
            self.assertNotIn(field,pending['inbounds'][1])
        for item in pending['inbounds']:self.assertEqual(item['tls']['handshake_timeout'],'10s')
        self.assertEqual(json.loads(self.config.read_text()),config)
        self.assertFalse((self.root/'service.log').exists())

    def test_apply_confirmation_and_restart_without_pending_refreshes_owned_service(self):
        self.managed_node()
        self.setup_nat()
        result=self.run_bash('set_hopping',HY2_HOP_PORTS='20000:20005')
        self.assertEqual(result.returncode,0,result.stderr)
        (self.root/'service.log').unlink()
        result=self.run_terminal('apply_changes','NO\n')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('确认即将应用',result.stdout)
        self.assertNotIn('restart',(self.root/'service.log').read_text() if (self.root/'service.log').exists() else '')
        result=self.run_terminal('apply_changes','YES\n')
        self.assertEqual(result.returncode,0,result.stderr)
        calls=(self.root/'service.log').read_text()
        self.assertIn('restart sing-box.service',calls)
        self.assertIn('restart sing-box-hopping.service',calls)
        self.assertTrue((self.root/'active').exists());self.assertTrue((self.root/'hop-active').exists())

    def test_tuic_backup_restore_roundtrip_and_legacy_restore(self):
        original=self.managed_node()
        self.setup_firewall('ufw',ufw=['ALLOW 22/tcp'])
        legacy=self.root/'legacy.tar.gz';modern=self.root/'tuic.tar.gz'
        result=self.run_bash(f'backup_cmd "{legacy}"\nstage_changes set_node add-tuic\napply_changes\nbackup_cmd "{modern}"',TUIC_PORT='11443')
        self.assertEqual(result.returncode,0,result.stderr)
        current=json.loads(self.config.read_text())
        result=self.run_bash(f'restore_backup "{legacy}"')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(self.config.read_text()),original)
        self.assertFalse((self.app/'tls/tuic.key').exists())
        self.assertNotIn('ALLOW 11443/udp',json.loads(self.firewall_state.read_text())['ufw'])
        result=self.run_bash(f'restore_backup "{modern}"')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(self.config.read_text()),current)
        self.assertTrue((self.app/'client/tuic.outbound.json').exists())
        self.assertIn('ALLOW 11443/udp',json.loads(self.firewall_state.read_text())['ufw'])

    def test_interactive_full_editor_renews_managed_certificate_after_sni_change(self):
        self.managed_node(anytls=True)
        before=(self.app/'tls/anytls.crt').read_bytes()
        editor=self.root/'editor'
        editor.write_text('''#!/usr/bin/env python3
import json,pathlib,sys
p=pathlib.Path(sys.argv[1]);c=json.loads(p.read_text());c['tls']['server_name']='edited.example.com';p.write_text(json.dumps(c))
''')
        editor.chmod(0o700)
        result=self.run_terminal('stage_changes edit_protocol anytls','',EDITOR=str(editor))
        self.assertEqual(result.returncode,0,result.stderr)
        cert=(self.app/'pending/tls/anytls.crt').read_bytes()
        self.assertNotEqual(cert,before)
        self.assertEqual((self.app/'tls/anytls.crt').read_bytes(),before)
        verify=subprocess.run(['openssl','verify','-CAfile',str(self.app/'pending/tls/anytls.crt'),'-verify_hostname','edited.example.com',str(self.app/'pending/tls/anytls.crt')],capture_output=True)
        self.assertEqual(verify.returncode,0,verify.stderr)

    def test_advanced_export_limitation_does_not_block_later_changes_or_restore(self):
        original=self.managed_node()
        candidate=json.loads(json.dumps(original['inbounds'][0]));candidate['transport']={'type':'ws','path':'/example'}
        source=self.root/'advanced.json';source.write_text(json.dumps(candidate))
        result=self.run_bash(f'stage_changes edit_protocol vless "{source}"')
        self.assertEqual(result.returncode,0,result.stderr)
        result=self.run_bash('stage_changes set_node add-tuic',TUIC_PORT='11443')
        self.assertEqual(result.returncode,0,result.stderr)
        result=self.run_bash('apply_changes')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(self.config.read_text())['inbounds'][0]['transport'],candidate['transport'])
        self.assertTrue((self.app/'client/EXPORT-ERROR.txt').exists())
        self.assertFalse((self.app/'client/tuic.outbound.json').exists())
        path=self.root/'advanced.tar.gz'
        result=self.run_bash(f'backup_cmd "{path}"\nrestore_backup "{path}"')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertTrue((self.app/'client/EXPORT-ERROR.txt').exists())

    def test_full_editor_tag_rename_and_plain_vless_flow_export(self):
        config=self.managed_node(anytls=True)
        config['inbounds'][2]['tag']='a-custom'
        config['dns']['rules']=[{'inbound':['vless-reality'],'server':'local'}]
        self.config.write_text(json.dumps(config))
        candidate=json.loads(json.dumps(config['inbounds'][0]));candidate['tag']='anytls';candidate['users'][0].pop('flow')
        path=self.root/'renamed.json';path.write_text(json.dumps(candidate))
        result=self.run_bash(f'stage_changes edit_protocol vless "{path}"\napply_changes')
        self.assertEqual(result.returncode,0,result.stderr)
        current=json.loads(self.config.read_text())
        self.assertEqual(current['dns']['rules'][0]['inbound'],['anytls'])
        outbound=json.loads((self.app/'client/vless-reality.outbound.json').read_text())
        self.assertEqual(outbound['flow'],'')
        result=self.run_bash('load_node_settings')
        self.assertEqual(result.returncode,0,result.stderr)

    def test_full_editor_allows_same_port_on_disjoint_listen_addresses(self):
        config=self.managed_node(anytls=True)
        config['inbounds'][0]['listen']='127.0.0.1'
        self.config.write_text(json.dumps(config))
        candidate=json.loads(json.dumps(config['inbounds'][2]));candidate.update(listen='127.0.0.2',listen_port=8443)
        path=self.root/'separate.json';path.write_text(json.dumps(candidate))
        result=self.run_bash(f'stage_changes edit_protocol anytls "{path}"\napply_changes')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(self.config.read_text())['inbounds'][2]['listen'],'127.0.0.2')

    def test_apply_menu_reexecutes_manager_after_success(self):
        entry=self.root/'entry.sh'
        entry.write_text('''case "$1" in
apply) echo APPLIED ;;
menu) echo MANAGER_REFRESHED ;;
esac
''')
        result=self.run_terminal(f'SCRIPT_PATH="{entry}"\nmenu_action apply','\n')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('MANAGER_REFRESHED',result.stdout)

    def test_full_editor_quic_transport_changes_listener_firewall_and_summary(self):
        config=self.managed_node(anytls=True)
        self.setup_firewall('ufw',ufw=['ALLOW 22/tcp'])
        result=self.run_bash('load_node_settings\nbegin_transaction files "$APP/firewall-owned.json"\nopen_firewall\nupdate_firewall_ownership\nTRANSACTION=""')
        self.assertEqual(result.returncode,0,result.stderr)
        candidate=json.loads(json.dumps(config['inbounds'][0]))
        candidate['users'][0].pop('flow')
        candidate['tls']=json.loads(json.dumps(config['inbounds'][1]['tls']))
        candidate['transport']={'type':'quic'}
        path=self.root/'quic.json';path.write_text(json.dumps(candidate))
        result=self.run_bash(f'stage_changes edit_protocol vless "{path}"\napply_changes\nnode_config summary')
        self.assertEqual(result.returncode,0,result.stderr)
        rules=json.loads(self.firewall_state.read_text())['ufw']
        self.assertIn('ALLOW 8443/udp',rules)
        self.assertNotIn('ALLOW 8443/tcp',rules)
        self.assertIn('VLESS：UDP 8443',result.stdout)
        queries=(self.root/'service.log').read_text()
        self.assertIn('restart sing-box.service',queries)
        self.assertTrue((self.app/'client/EXPORT-ERROR.txt').exists())

    def test_legacy_protocol_tags_do_not_impersonate_optional_protocols(self):
        config=self.managed_node()
        candidate=json.loads(json.dumps(config['inbounds'][0]));candidate['tag']='anytls'
        path=self.root/'tag.json';path.write_text(json.dumps(candidate))
        result=self.run_bash(f'stage_changes edit_protocol vless "{path}"\napply_changes')
        self.assertEqual(result.returncode,0,result.stderr)
        result=self.run_bash('stage_changes set_node add-anytls',ANYTLS_PORT='10443')
        self.assertEqual(result.returncode,0,result.stderr)
        pending=json.loads((self.app/'pending/config.json').read_text())
        self.assertEqual(pending['inbounds'][0]['tag'],'anytls')
        self.assertEqual(pending['inbounds'][2]['type'],'anytls')
        self.assertNotEqual(pending['inbounds'][2]['tag'],'anytls')

    def test_full_editor_allows_plain_vless_with_null_optional_tls(self):
        config=self.managed_node()
        candidate=json.loads(json.dumps(config['inbounds'][0]));candidate['tls']=None;candidate['users'][0].pop('flow')
        path=self.root/'plain.json';path.write_text(json.dumps(candidate))
        result=self.run_bash(f'stage_changes edit_protocol vless "{path}"\napply_changes')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIsNone(json.loads(self.config.read_text())['inbounds'][0]['tls'])
        self.assertTrue((self.app/'client/EXPORT-ERROR.txt').exists())

    def test_disjoint_listeners_sharing_new_port_add_one_firewall_rule(self):
        config=self.managed_node(anytls=True)
        self.setup_firewall('ufw',ufw=['ALLOW 22/tcp'])
        v=json.loads(json.dumps(config['inbounds'][0]));v.update(listen='127.0.0.1',listen_port=28443)
        a=json.loads(json.dumps(config['inbounds'][2]));a.update(listen='127.0.0.2',listen_port=28443)
        vp=self.root/'v.json';vp.write_text(json.dumps(v))
        ap=self.root/'a.json';ap.write_text(json.dumps(a))
        result=self.run_bash(f'stage_changes edit_protocol vless "{vp}"\nstage_changes edit_protocol anytls "{ap}"\napply_changes')
        self.assertEqual(result.returncode,0,result.stderr)
        rules=json.loads(self.firewall_state.read_text())['ufw']
        self.assertEqual(rules.count('ALLOW 28443/tcp'),1)
        ledger=json.loads((self.app/'firewall-owned.json').read_text())
        self.assertEqual(sum(r['proto']=='tcp' and r['port']==28443 for r in ledger),1)

    def test_tuic_cannot_be_redirected_by_hy2_hopping_range(self):
        self.managed_node()
        self.setup_nat()
        result=self.run_bash('stage_changes set_hopping',HY2_HOP_PORTS='20000:20005')
        self.assertEqual(result.returncode,0,result.stderr)
        before=self.file_snapshot();nat=self.nat_state.read_bytes()
        result=self.run_bash('stage_changes set_node add-tuic',TUIC_PORT='20003')
        self.assertNotEqual(result.returncode,0)
        self.assertIn('跳跃端口冲突',result.stderr)
        self.assertEqual(self.file_snapshot(),before)
        self.assertEqual(self.nat_state.read_bytes(),nat)

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
        self.assertIn('TCP 12345', result.stdout)
        self.assertIn('UDP 23456', result.stdout)
        queries = (self.root/'ss.log').read_text()
        self.assertIn(':12345', queries)
        self.assertIn(':23456', queries)
        self.assertNotIn(':8443', queries)

    def managed_node(self, anytls=False, tuic=False):
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
if [[ -n "$TUIC_PORT" ]]; then
  TUIC_SNI="$REALITY_DOMAIN"
  make_tls_certificate tuic "$TUIC_SNI"
fi
write_jsons
''', ANYTLS_PORT='10443' if anytls else '', TUIC_PORT='11443' if tuic else '')
        self.assertEqual(result.returncode, 0, result.stderr)
        # The generated configuration references these downloaded bootstrap resources.
        for name in ('ai','google','youtube'):
            (self.app/'rules'/f'{name}.srs').write_bytes(b'test-rule-'+name.encode())
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
        for cmd in ('set_node ports','stage_changes set_node ports'):
            result=self.run_bash(f"ss() {{ echo occupied; }}\n{cmd}",VLESS_PORT='12345')
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
if [[ $1 == generate ]]; then printf 'PrivateKey: XasIfmJKikt54X-Lg4AO5m87sSkmGLb9HC-LJ_-I4Os\\nPublicKey: 3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08\\n'; fi
''')
        result=self.run_bash('set_node rotate')
        self.assertEqual(result.returncode,0,result.stderr)
        after=json.loads(self.config.read_text())
        self.assertNotEqual(before['inbounds'][0]['users'][0]['uuid'],after['inbounds'][0]['users'][0]['uuid'])
        self.assertNotEqual(before['inbounds'][1]['users'][0]['password'],after['inbounds'][1]['users'][0]['password'])
        self.assertEqual(after['inbounds'][0]['tls']['reality']['private_key'],'XasIfmJKikt54X-Lg4AO5m87sSkmGLb9HC-LJ_-I4Os')
        client=json.loads((self.app/'client/vless-reality.outbound.json').read_text())
        self.assertEqual(client['tls']['reality']['public_key'],'3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08')
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
                         [('vless',443),('hysteria2',443),('anytls',8443),('tuic',10443)])
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
if tool=='ufw' and a[:1]==['status']:
    done(text='Status: inactive')
if tool=='firewall-cmd' and a==['--state']:
    done(252,'not running')
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
        for tool in ('ufw','firewall-cmd','nft','iptables'):(fake/tool).symlink_to(script)
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

    def test_backup_restore_config_only_without_app_or_hysteria2(self):
        import tarfile
        self.config.parent.mkdir(parents=True)
        config={'inbounds':[{'type':'socks','tag':'local-socks','listen':'127.0.0.1','listen_port':1080}],
                'outbounds':[{'type':'direct','tag':'direct'}]}
        self.config.write_text(json.dumps(config));original=self.config.read_bytes()
        result=self.run_bash('backup_cmd')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertFalse(self.app.exists());self.assertEqual(self.config.read_bytes(),original)
        archive=next((self.root/'backups').glob('*.tar.gz'))
        with tarfile.open(archive) as f:
            self.assertEqual(set(f.getnames()),{'config.json','manifest.json'})
        config['inbounds'][0]['listen_port']=1081;self.config.write_text(json.dumps(config))
        result=self.run_bash('restore_backup "'+str(archive)+'"')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(self.config.read_text())['inbounds'][0]['listen_port'],1080)
        self.assertFalse((self.app/'hopping.json').exists())
        self.assertFalse((self.root/'units/sing-box-hopping.service').exists())

    def test_backup_copies_external_cert_symlink_and_rule_bytes_without_touching_sources(self):
        import tarfile
        self.config.parent.mkdir(parents=True);external=self.root/'external';external.mkdir()
        cert=external/'fullchain.pem';key=external/'privkey.pem'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
                        '-subj','/CN=example.com','-keyout',str(key),'-out',str(cert)],check=True,capture_output=True)
        link=external/'cert.pem';link.symlink_to(cert)
        local=external/'local.json';initial=external/'initial.json'
        local.write_text('{"version":3,"rules":[{"domain":["example.com"]}]}')
        initial.write_text('{"version":3,"rules":[{"domain":["initial.example.com"]}]}')
        config={'inbounds':[{'type':'anytls','tag':'custom-anytls','listen':'::','listen_port':10443,
                            'users':[{'password':'external-auth'}],
                            'tls':{'enabled':True,'server_name':'example.com','certificate_path':str(link),'key_path':str(key)}}],
                'outbounds':[{'type':'direct','tag':'direct'}],
                'route':{'rule_set':[{'type':'local','tag':'local','format':'source','path':str(local)},
                                     {'type':'remote','tag':'remote','format':'source','url':'https://example.com/rules.json','initial_path':str(initial)}]}}
        self.config.write_text(json.dumps(config));before=self.config.read_bytes()
        expected={path:path.read_bytes() for path in (cert,key,local,initial)}
        result=self.run_bash('backup_cmd')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertFalse(self.app.exists());self.assertEqual(self.config.read_bytes(),before)
        self.assertTrue(link.is_symlink())
        for path,data in expected.items(): self.assertEqual(path.read_bytes(),data)
        archive=next((self.root/'backups').glob('*.tar.gz'))
        with tarfile.open(archive) as f:
            archived=json.load(f.extractfile('config.json'))
            self.assertEqual(len([n for n in f.getnames() if n.startswith('tls/imported-')]),2)
            self.assertEqual(len([n for n in f.getnames() if n.startswith('rules/imported-')]),2)
            self.assertNotEqual(archived['inbounds'][0]['tls']['certificate_path'],str(link))
            self.assertTrue(all(member.isfile() for member in f.getmembers()))
        # Prove that restore uses archived copies, never writes to the original external locations.
        for path in expected: path.unlink()
        result=self.run_bash('restore_backup "'+str(archive)+'"')
        self.assertEqual(result.returncode,0,result.stderr)
        restored=json.loads(self.config.read_text());tls=restored['inbounds'][0]['tls']
        self.assertEqual(Path(tls['certificate_path']).read_bytes(),expected[cert])
        self.assertEqual(Path(tls['key_path']).read_bytes(),expected[key])
        rules=restored['route']['rule_set']
        self.assertEqual(Path(rules[0]['path']).read_bytes(),expected[local])
        self.assertEqual(Path(rules[1]['initial_path']).read_bytes(),expected[initial])
        self.assertTrue(link.is_symlink())
        for path in expected: self.assertFalse(path.exists())

    def test_restore_without_hy2_stops_owned_hopping_without_fake_metadata(self):
        import shutil
        self.config.parent.mkdir(parents=True)
        config={'inbounds':[{'type':'socks','tag':'only-socks','listen':'127.0.0.1','listen_port':1080}],
                'outbounds':[{'type':'direct'}]}
        self.config.write_text(json.dumps(config))
        result=self.run_bash('backup_cmd');self.assertEqual(result.returncode,0,result.stderr)
        archive=next((self.root/'backups').glob('*.tar.gz'))
        shutil.rmtree(self.config.parent)
        self.managed_node();self.setup_nat()
        result=self.run_bash('set_hopping',HY2_HOP_PORTS='20000:20005')
        self.assertEqual(result.returncode,0,result.stderr)
        result=self.run_bash('restore_backup "'+str(archive)+'"')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(self.config.read_text()),config)
        self.assertEqual(json.loads(self.nat_state.read_text())['batch'],'')
        self.assertFalse((self.app/'hopping.json').exists())
        self.assertFalse((self.root/'units/sing-box-hopping.service').exists())
        self.assertFalse((self.root/'hop-enabled').exists());self.assertFalse((self.root/'hop-active').exists())

    def test_config_only_restore_failure_rolls_back_without_leaving_app(self):
        self.config.parent.mkdir(parents=True)
        config={'inbounds':[{'type':'socks','tag':'local','listen':'127.0.0.1','listen_port':1080}],
                'outbounds':[{'type':'direct'}]}
        self.config.write_text(json.dumps(config));(self.root/'active').touch()
        result=self.run_bash('backup_cmd');self.assertEqual(result.returncode,0,result.stderr)
        archive=next((self.root/'backups').glob('*.tar.gz'))
        config['inbounds'][0]['listen_port']=1081;self.config.write_text(json.dumps(config));before=self.config.read_bytes()
        (self.root/'fail-restart').touch()
        result=self.run_bash('restore_backup "'+str(archive)+'"')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(self.config.read_bytes(),before);self.assertFalse(self.app.exists())
        self.assertTrue((self.root/'active').exists())

    def test_backup_missing_external_resource_fails_without_modifying_config(self):
        self.config.parent.mkdir(parents=True)
        self.config.write_text(json.dumps({'inbounds':[{'type':'anytls','tls':{'certificate_path':str(self.root/'missing.pem')}}]}))
        before=self.config.read_bytes();result=self.run_bash('backup_cmd')
        self.assertNotEqual(result.returncode,0)
        self.assertIn('备份引用的资源不存在',result.stderr)
        self.assertEqual(self.config.read_bytes(),before);self.assertFalse(self.app.exists())
        self.assertEqual(list((self.root/'backups').glob('*.tar.gz')),[])

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
        original['inbounds'][1]['tag']='renamed-hy2'
        self.config.write_text(json.dumps(original))
        result=self.run_bash('backup_cmd');self.assertEqual(result.returncode,0,result.stderr)
        archive=next((self.root/'backups').glob('*.tar.gz'))
        self.config.write_text('broken json')
        self.setup_firewall('none')
        result=self.run_bash('restore_backup "'+str(archive)+'"')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(self.config.read_text()),original)

    def test_restore_validates_hopping_against_backup_config(self):
        original=self.managed_node();self.setup_nat()
        result=self.run_bash('set_hopping',HY2_HOP_PORTS='20000:20005')
        self.assertEqual(result.returncode,0,result.stderr)
        result=self.run_bash('backup_cmd');self.assertEqual(result.returncode,0,result.stderr)
        archive=next((self.root/'backups').glob('*.tar.gz'))
        self.config.write_text('broken json')
        result=self.run_bash('restore_backup "'+str(archive)+'"')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(self.config.read_text()),original)
        self.assertTrue(json.loads((self.app/'hopping.json').read_text())['enabled'])

    def test_backup_rejects_links_and_does_not_overwrite_existing_target(self):
        self.managed_node()
        target=self.root/'existing.tar.gz';target.write_text('keep')
        result=self.run_bash('backup_cmd "'+str(target)+'"')
        self.assertNotEqual(result.returncode,0);self.assertEqual(target.read_text(),'keep')
        (self.app/'rules/symlink').symlink_to(self.config)
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
        original=json.loads(self.config.read_text())
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
            self.assertFalse(any(name.startswith('client/') for name in names))
            self.assertEqual(json.load(archive.extractfile('config.json')),original)
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

    def test_firewall_automation_off_preserves_rules_and_later_enable_reconciles_ports(self):
        self.managed_node()
        initial=self.setup_firewall('ufw',ufw=['ALLOW 22/tcp'])
        ledger=self.app/'firewall-owned.json';ledger.write_text('[]')
        result=self.run_bash('''set_firewall_auto false
begin_transaction update "$APP/firewall-owned.json"
VLESS_PORT=8443 HY2_PORT=9443 open_firewall 443 443
VLESS_PORT=8443 HY2_PORT=9443 update_firewall_ownership 443 443
TRANSACTION=''
''')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(self.firewall_state.read_text()),initial)
        self.assertFalse((self.root/'firewall.log').exists())
        self.assertEqual(json.loads(ledger.read_text()),[])
        settings=self.app/'firewall-settings.json'
        self.assertEqual(settings.stat().st_mode&0o777,0o600)
        self.assertFalse(json.loads(settings.read_text())['automatic_ports'])
        result=self.run_bash('''set_firewall_auto true
begin_transaction update "$APP/firewall-owned.json"
VLESS_PORT=8443 HY2_PORT=9443 open_firewall 8443 9443
VLESS_PORT=8443 HY2_PORT=9443 update_firewall_ownership 8443 9443
TRANSACTION=''
''')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(set(json.loads(self.firewall_state.read_text())['ufw']),{'ALLOW 22/tcp','ALLOW 8443/tcp','ALLOW 9443/udp'})
        self.assertEqual(len(json.loads(ledger.read_text())),2)

    def test_firewall_malformed_automation_setting_fails_before_rule_mutation(self):
        self.managed_node();initial=self.setup_firewall('ufw')
        (self.app/'firewall-settings.json').write_text('{"automatic_ports":"false"}')
        result=self.run_bash('open_firewall')
        self.assertNotEqual(result.returncode,0)
        self.assertIn('设置格式无效',result.stderr)
        self.assertEqual(json.loads(self.firewall_state.read_text()),initial)
        self.assertFalse((self.root/'firewall.log').exists())

    def test_firewall_status_details_are_read_only_and_show_owned_rules(self):
        self.managed_node();initial=self.setup_firewall('ufw',ufw=['ALLOW 22/tcp'])
        result=self.run_bash('firewall_status details')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('UFW：已开启',result.stdout)
        self.assertIn('22/tcp',result.stdout)
        self.assertIn('自动放行端口：true',result.stdout)
        self.assertIn('本脚本记录的放行规则：0 条',result.stdout)
        self.assertEqual(json.loads(self.firewall_state.read_text()),initial)

    def test_system_firewall_requires_confirmation_and_verifies_ufw_toggle(self):
        mocks='''ufw() {
  if [[ "$1" == status ]]; then
    if [[ -f "$TEST_ROOT/ufw-active" ]]; then echo 'Status: active'; else echo 'Status: inactive'; fi
  elif [[ "$*" == '--force enable' ]]; then touch "$TEST_ROOT/ufw-active"
  elif [[ "$*" == '--force disable' ]]; then rm -f "$TEST_ROOT/ufw-active"
  else return 99; fi
}
firewall-cmd() { echo 'not running';return 252; }
'''
        result=self.run_bash(mocks+'firewall_system enable ufw')
        self.assertNotEqual(result.returncode,0)
        self.assertFalse((self.root/'ufw-active').exists())
        result=self.run_bash(mocks+'firewall_system enable ufw',FIREWALL_CONFIRM='YES')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertTrue((self.root/'ufw-active').exists())
        result=self.run_bash(mocks+'firewall_system disable ufw',FIREWALL_CONFIRM='YES')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertFalse((self.root/'ufw-active').exists())

    def test_system_firewall_firewalld_toggle_is_persistent_and_verified(self):
        mocks='''ufw() { echo 'Status: inactive'; }
firewall-cmd() {
  if [[ -f "$TEST_ROOT/firewalld-active" ]]; then echo running;else echo 'not running';return 252;fi
}
systemctl() {
  echo "$*" >> "$TEST_ROOT/firewalld-service.log"
  case "$*" in
    'enable --now firewalld.service') touch "$TEST_ROOT/firewalld-active" ;;
    'disable --now firewalld.service') rm -f "$TEST_ROOT/firewalld-active" ;;
    *) return 99 ;;
  esac
}
'''
        result=self.run_bash(mocks+'firewall_system enable firewalld',FIREWALL_CONFIRM='YES')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertTrue((self.root/'firewalld-active').exists())
        result=self.run_bash(mocks+'firewall_system disable firewalld',FIREWALL_CONFIRM='YES')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertFalse((self.root/'firewalld-active').exists())
        self.assertEqual((self.root/'firewalld-service.log').read_text().splitlines(),['enable --now firewalld.service','disable --now firewalld.service'])

    def test_system_firewall_refuses_enabling_second_active_manager(self):
        result=self.run_bash('''firewall-cmd() { echo running; }
ufw() { echo mutation >> "$TEST_ROOT/ufw-mutations"; }
firewall_system enable ufw
''',FIREWALL_CONFIRM='YES')
        self.assertNotEqual(result.returncode,0)
        self.assertIn('firewalld 已运行',result.stderr)
        self.assertFalse((self.root/'ufw-mutations').exists())

    def test_system_firewall_does_not_report_success_when_command_fails(self):
        result=self.run_bash('''firewall-cmd() { echo 'not running';return 252; }
ufw() { if [[ "$1" == '--force' ]]; then return 9;fi;echo 'Status: inactive'; }
firewall_system enable ufw
''',FIREWALL_CONFIRM='YES')
        self.assertEqual(result.returncode,9)
        self.assertNotIn('已执行',result.stderr)

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
