"""Real HY2 hopping test, always inside a fresh user/network namespace.

Run: python3 tests/hopping_integration.py --sing-box /usr/bin/sing-box
Requires Linux user namespaces, iproute2, nftables, iptables, curl and nsenter.
"""
import argparse
import http.server
import importlib.util
import json
import os
import shlex
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--sing-box', required=True)
parser.add_argument('--inside-netns', action='store_true', help=argparse.SUPPRESS)
args = parser.parse_args()
binary = str(Path(args.sing_box).resolve())
if not os.path.isfile(binary) or not os.access(binary, os.X_OK):
    parser.error('--sing-box must name an executable')
namespace = os.readlink('/proc/self/ns/net')
if not args.inside_netns:
    env = {**os.environ, '_SB_TEST_PARENT_NETNS': namespace}
    result = subprocess.run(['unshare', '-Urn', sys.executable, '-B', str(Path(__file__).resolve()), '--inside-netns', '--sing-box', binary], env=env)
    sys.exit(result.returncode)
if not os.environ.get('_SB_TEST_PARENT_NETNS') or namespace == os.environ['_SB_TEST_PARENT_NETNS']:
    parser.error('refusing to configure the host network namespace')
subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
subprocess.run(['ip', 'link', 'add', 'dummy0', 'type', 'dummy'], check=True)
subprocess.run(['ip', 'addr', 'add', '192.0.2.1/24', 'dev', 'dummy0'], check=True)
subprocess.run(['ip', 'link', 'set', 'dummy0', 'up'], check=True)
subprocess.run(['ip', 'route', 'add', 'default', 'dev', 'dummy0'], check=True)
spec = importlib.util.spec_from_file_location('deploytests', str(Path(__file__).with_name('test_deploy.py')))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
t = m.DeployTests()
t.setUp()
# Unit fixtures mask firewall commands and ss. Integration must use real tools
# inside the namespace established above; retain only its file/service isolation.
t.prelude += '\nexport PATH=' + shlex.quote(os.environ['PATH']) + '\nunset -f ss\n'
processes = []
clientns = None
httpd = None
sniffer = None
running = True
observed = set()
try:
    t.config.parent.mkdir(parents=True)
    for name in ('tls', 'client', 'rules'):
        (t.app / name).mkdir(parents=True)
    for name in ('ai', 'google', 'youtube'):
        p = t.root / f'{name}.json'
        p.write_text(json.dumps({'version': 3, 'rules': [{'domain': ['example.com']}]}))
        subprocess.run([binary, 'rule-set', 'compile', str(p), '-o', str(t.app / f'rules/{name}.srs')], check=True, capture_output=True)
    r = t.run_bash(f'''BIN={shlex.quote(binary)}
export SERVER_IP=8.8.8.8 VLESS_PORT=18443 HY2_PORT=19443
export AI_SOCKS_HOST=localhost AI_SOCKS_PORT=1080 AI_SOCKS_USER=user AI_SOCKS_PASS=secret
export GOOGLE_SOCKS_HOST=localhost GOOGLE_SOCKS_PORT=1081 GOOGLE_SOCKS_USER=user GOOGLE_SOCKS_PASS=secret
export OTHER_SOCKS_HOST=localhost OTHER_SOCKS_PORT=1082 OTHER_SOCKS_USER=user OTHER_SOCKS_PASS=secret
new_credentials
make_hy2_certificate
write_jsons
HY2_HOP_PORTS=25000:25255 HY2_HOP_INTERVAL=5s prepare_hopping
cp "$TEMP/hopping-plan.json" "$APP/hopping.json"
node_config export
hopping_runtime start
''')
    assert r.returncode == 0, r.stderr
    c = json.loads(t.config.read_text())
    h = c['inbounds'][1]
    outbound = json.loads((t.app / 'client/hysteria2.outbound.json').read_text())
    outbound['server'] = '10.200.1.1'
    assert outbound['server_ports'] == ['25000:25255'] and 'server_port' not in outbound
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        socks_port = s.getsockname()[1]
    server = t.root / 'server.json'
    server.write_text(json.dumps({'inbounds': [h], 'outbounds': [{'type': 'direct'}]}))
    client = t.root / 'client.json'
    client.write_text(json.dumps({'inbounds': [{'type': 'socks', 'listen': '127.0.0.1', 'listen_port': socks_port}], 'outbounds': [outbound]}))
    subprocess.run([binary, 'check', '-c', str(client)], check=True, capture_output=True)

    class Handler(http.server.BaseHTTPRequestHandler):

        def do_GET(self):
            self.send_response(200)
            self.send_header('Content-Length', str(130 * 1024))
            self.end_headers()
            for i in range(130):
                self.wfile.write(b'x' * 1024)
                self.wfile.flush()
                time.sleep(0.1)

        def log_message(self, *args):
            pass
    httpd = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(2048))
    sniffer.settimeout(0.2)

    def sniff():
        while running:
            try:
                frame = sniffer.recv(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            if len(frame) < 42 or frame[23] != 17:
                continue
            off = 14 + (frame[14] & 15) * 4
            dst = struct.unpack('!H', frame[off + 2:off + 4])[0]
            if 25000 <= dst <= 25255:
                observed.add(dst)
    thread = threading.Thread(target=sniff, daemon=True)
    thread.start()
    clientns = subprocess.Popen(['unshare', '-n', 'sleep', '120'])
    for _ in range(100):
        if os.readlink(f'/proc/{clientns.pid}/ns/net') != os.readlink('/proc/self/ns/net'):
            break
        time.sleep(0.01)
    else:
        raise RuntimeError('client network namespace did not start')
    prefix = ['nsenter', '-t', str(clientns.pid), '-n', '--']
    subprocess.run(['ip', 'link', 'add', 'veth-server', 'type', 'veth', 'peer', 'name', 'veth-client'], check=True)
    subprocess.run(['ip', 'link', 'set', 'veth-client', 'netns', str(clientns.pid)], check=True)
    subprocess.run(['ip', 'addr', 'add', '10.200.1.1/24', 'dev', 'veth-server'], check=True)
    subprocess.run(['ip', 'link', 'set', 'veth-server', 'up'], check=True)
    subprocess.run(prefix + ['ip', 'link', 'set', 'lo', 'up'], check=True)
    subprocess.run(prefix + ['ip', 'addr', 'add', '10.200.1.2/24', 'dev', 'veth-client'], check=True)
    subprocess.run(prefix + ['ip', 'link', 'set', 'veth-client', 'up'], check=True)
    subprocess.run(prefix + ['ip', 'route', 'add', 'default', 'via', '10.200.1.1'], check=True)
    sniffer.bind(('veth-server', 0))
    for p in (server, client):
        log = open(t.root / (p.stem + '.log'), 'w')
        processes.append(subprocess.Popen((prefix if p == client else []) + [binary, 'run', '-c', str(p)], stdout=log, stderr=log))
        log.close()
    time.sleep(0.5)
    r = subprocess.run(prefix + ['curl', '--silent', '--show-error', '--max-time', '25', '--noproxy', '', '--socks5-hostname', f'127.0.0.1:{socks_port}', f'http://127.0.0.1:{httpd.server_port}/'], capture_output=True)
    assert r.returncode == 0 and len(r.stdout) == 130 * 1024, (r.stderr, (t.root / 'client.log').read_text(), (t.root / 'server.log').read_text())
    assert len(observed) >= 2, observed
    print('PASS: real sing-box streaming across ' + str(len(observed)) + ' hopping UDP ports with real nftables REDIRECT (isolated network namespace)')
    r = t.run_bash('hopping_runtime stop')
    assert r.returncode == 0, r.stderr
    tables = json.loads(subprocess.check_output(['nft', '-j', 'list', 'tables'], text=True))
    assert not any((x.get('table', {}).get('name') == 'sing_box_hy2_hop' for x in tables['nftables']))
    print('PASS: owned NAT table removed on stop')
    hop = json.loads((t.app / 'hopping.json').read_text())
    hop['backend'] = 'iptables'
    (t.app / 'hopping.json').write_text(json.dumps(hop))
    r = t.run_bash('hopping_runtime start\nhopping_runtime stop')
    assert r.returncode == 0, r.stderr
    assert 'SB_HY2_HOP' not in subprocess.check_output(['iptables', '-t', 'nat', '-S'], text=True)
    print('PASS: real iptables fallback creates/removes only its private NAT chain')
finally:
    running = False
    if sniffer:
        sniffer.close()
    for p in processes:
        if p.poll() is None:
            p.terminate()
    for p in processes:
        p.wait(timeout=5)
    if httpd:
        httpd.shutdown()
    if clientns is not None:
        clientns.terminate()
        clientns.wait(timeout=5)
    t.doCleanups()
