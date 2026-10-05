"""使用真实 Podman 容器、测试 CA 和 Xray 客户端验证 HTTPS 代理数据。"""
import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import threading
import time
import uuid

def run(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True, **kwargs).stdout

def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]

def wait_for(test, seconds=20):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            if test():
                return
        except (OSError, ValueError, subprocess.CalledProcessError):
            pass
        time.sleep(0.2)
    raise AssertionError('等待服务状态超时')

class Target(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'msproxy-real-vless-xhttp-data\n'
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--image', default='localhost/msproxy:dev')
    parser.add_argument('-o', '--output', required=True)
    args = parser.parse_args()
    root = Path(args.output).resolve()
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    root.chmod(0o700)
    data, certs = root / 'data', root / 'certs'
    data.mkdir(exist_ok=True)
    certs.mkdir(exist_ok=True)
    https_port, xray_port, socks_port = free_port(), free_port(), free_port()
    name = 'msproxy-test-' + uuid.uuid4().hex[:10]
    client = None
    target = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Target)
    threading.Thread(target=target.serve_forever, daemon=True).start()
    try:
        # 测试自签证书作为显式信任锚，客户端 TLS 校验保持开启。
        run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
             '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
             '-keyout', str(certs / 'key.pem'), '-out', str(certs / 'cert.pem')])
        (certs / 'key.pem').chmod(0o600)
        run(['podman', 'run', '--rm', '-v', str(data) + ':/config', args.image, 'init', '-d', 'localhost',
             '-p', str(https_port), '-s', str(socks_port), '-a', str(certs / 'cert.pem')])
        original = (data / 'server.json').read_bytes()
        # 再初始化必须失败，且既有凭据保持。
        duplicate = subprocess.run(['podman', 'run', '--rm', '-v', str(data) + ':/config', args.image,
                                    'init', '-d', 'localhost'], capture_output=True)
        assert duplicate.returncode != 0 and (data / 'server.json').read_bytes() == original
        def start():
            run(['podman', 'run', '-d', '--name', name, '--network', 'host',
                 '-v', str(data) + ':/config:ro', '-v', str(certs) + ':/certs:ro',
                 '-e', 'MSPROXY_CONFIG_FILE=/config/server.json', '-e', f'MSPROXY_HTTPS_PORT={https_port}',
                 '-e', f'MSPROXY_XRAY_PORT={xray_port}', args.image])
            wait_for(lambda: run(['podman', 'exec', name, 'python3', '/opt/msproxy/msproxy.py', 'healthcheck']) == '')
        start()
        context = ssl.create_default_context(cafile=str(certs / 'cert.pem'))
        with socket.create_connection(('127.0.0.1', https_port), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname='localhost') as tls:
                tls.sendall(b'GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n')
                assert b' 200 ' in tls.recv(1024)
        run(['podman', 'cp', name + ':/usr/local/bin/xray', str(root / 'xray-client')])
        (root / 'xray-client').chmod(0o700)
        client_config = json.loads((data / 'client.json').read_text())
        assert client_config['outbounds'][0]['streamSettings']['tlsSettings']['allowInsecure'] is False
        log = (root / 'client.log').open('w')
        client = subprocess.Popen([str(root / 'xray-client'), 'run', '-c', str(data / 'client.json')], stdout=log, stderr=log)
        def transfer():
            text = run(['curl', '--noproxy', '', '--proxy', f'socks5h://127.0.0.1:{socks_port}',
                        '--fail', '--silent', '--show-error', '--max-time', '10', f'http://127.0.0.1:{target.server_port}/'])
            (root / 'last-response.txt').write_text(text)
            return text == 'msproxy-real-vless-xhttp-data\n'
        wait_for(transfer)
        # 错误 UUID 必须被拒绝，证明业务成功依赖真实 VLESS 用户认证。
        bad = json.loads((data / 'client.json').read_text())
        bad_port = free_port()
        bad['inbounds'][0]['port'] = bad_port
        bad['outbounds'][0]['settings']['vnext'][0]['users'][0]['id'] = str(uuid.uuid4())
        bad_path = root / 'bad-client.json'
        bad_path.write_text(json.dumps(bad))
        bad_path.chmod(0o600)
        bad_process = subprocess.Popen([str(root / 'xray-client'), 'run', '-c', str(bad_path)], stdout=log, stderr=log)
        try:
            def bad_ready():
                with socket.create_connection(('127.0.0.1', bad_port), timeout=1):
                    return True
            wait_for(bad_ready)
            rejected = subprocess.run(['curl', '--noproxy', '', '--proxy', f'socks5h://127.0.0.1:{bad_port}',
                                      '--fail', '--silent', '--max-time', '3', f'http://127.0.0.1:{target.server_port}/'], capture_output=True)
            assert rejected.returncode != 0
        finally:
            bad_process.terminate()
            bad_process.wait(timeout=5)
        # 删除测试容器后重建，从只读挂载读取同一凭据，并再次传输真实数据。
        run(['podman', 'stop', '-t', '8', name])
        run(['podman', 'rm', name])
        start()
        assert (data / 'server.json').read_bytes() == original
        wait_for(transfer)
        # 单独终止 Xray：容器应退出，并停止 Nginx，而不是继续半失效运行。
        run(['podman', 'exec', name, 'python3', '-c',
             "import json,os,signal;os.kill(json.load(open('/run/msproxy/pids.json'))[0],signal.SIGTERM)"])
        wait_for(lambda: run(['podman', 'inspect', '--format', '{{.State.Running}}', name]).strip() == 'false')
        assert run(['podman', 'inspect', '--format', '{{.State.ExitCode}}', name]).strip() == '1'
        result = {'image': args.image, 'tls_verification': True, 'vless_encryption': True,
                  'xhttp_mode': 'packet-up', 'real_proxy_data': True, 'recreate_preserves_credentials': True,
                  'duplicate_init_rejected': True, 'wrong_uuid_rejected': True, 'child_failure_stops_container': True,
                  'source_binary_sha256': hashlib.sha256((root / 'xray-client').read_bytes()).hexdigest()}
        (root / 'verification.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result, indent=2))
    finally:
        logs = subprocess.run(['podman', 'logs', name], capture_output=True, text=True)
        (root / 'container.log').write_text(logs.stdout + logs.stderr)
        if client is not None:
            client.terminate()
            try:
                client.wait(timeout=5)
            except subprocess.TimeoutExpired:
                client.kill()
                client.wait()
        target.shutdown()
        subprocess.run(['podman', 'stop', '-t', '5', name], capture_output=True)
        subprocess.run(['podman', 'rm', name], capture_output=True)

if __name__ == '__main__':
    main()
