"""msproxy 配置、初始化和双进程管理，仅依赖 Python 标准库。"""
import argparse
import base64
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import signal
import socket
import ssl
import string
import subprocess
import sys
import time
import uuid

BASE = Path(__file__).resolve().parent
RUN = Path('/run/msproxy')
XRAY = os.environ.get('MSPROXY_XRAY_BIN', '/usr/local/bin/xray')
DEFAULTS = {'https_port': 8443, 'xray_port': 10086, 'public_port': 443, 'socks_port': 1080,
            'log_level': 'warning', 'tls_cert_file': '/certs/cert.pem', 'tls_key_file': '/certs/key.pem'}
FIELDS = set(DEFAULTS) | {'domain', 'xhttp_path', 'uuid', 'vless_decryption', 'tls_ca_file'}

def load_config():
    config = dict(DEFAULTS)
    name = os.environ.get('MSPROXY_CONFIG_FILE')
    if name:
        data = json.loads(Path(name).read_text())
        if not isinstance(data, dict) or set(data) - FIELDS:
            raise ValueError('配置必须是对象，且只能使用文档中的字段')
        config.update(data)
    # 显式环境变量覆盖配置；普通变量与 _FILE 同时出现时拒绝启动。
    for field in FIELDS:
        variable = 'MSPROXY_' + field.upper()
        file_variable = variable + '_FILE'
        if variable in os.environ and file_variable in os.environ:
            raise ValueError(variable + ' 与 ' + file_variable + ' 只能设置一个')
        if file_variable in os.environ:
            config[field] = Path(os.environ[file_variable]).read_text().strip()
        elif variable in os.environ:
            config[field] = os.environ[variable]
    return validate(config)

def validate(config):
    c = dict(config)
    domain = c.get('domain', '')
    if not isinstance(domain, str) or not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', domain):
        raise ValueError('domain 必须是有效的 ASCII 域名或 IPv4 地址')
    path = c.get('xhttp_path', '')
    if not isinstance(path, str) or not re.fullmatch(r'/[A-Za-z0-9/_-]+', path) or path in ('/', '/healthz'):
        raise ValueError('xhttp_path 必须是独立的非根 HTTP 路径')
    if not isinstance(c.get('uuid'), str):
        raise ValueError('uuid 必须是 UUID 字符串')
    c['uuid'] = str(uuid.UUID(c.get('uuid', '')))
    if not isinstance(c.get('vless_decryption'), str) or not c['vless_decryption'].startswith('mlkem768x25519plus.'):
        raise ValueError('必须提供 VLESS Encryption decryption 参数')
    for field in ('https_port', 'xray_port', 'public_port', 'socks_port'):
        value = c.get(field, DEFAULTS[field])
        if isinstance(value, bool) or not re.fullmatch(r'[0-9]+', str(value)) or not 1 <= int(value) <= 65535:
            raise ValueError(field + ' 必须在 1 到 65535 之间')
        c[field] = int(value)
    if c['https_port'] == c['xray_port']:
        raise ValueError('https_port 和 xray_port 必须不同')
    if c.get('log_level') not in ('debug', 'info', 'warning', 'error', 'none'):
        raise ValueError('log_level 无效')
    for field in ('tls_cert_file', 'tls_key_file', 'tls_ca_file'):
        if field in c and (not isinstance(c[field], str) or not c[field].startswith('/') or any(x in c[field] for x in '\n\r\x00')):
            raise ValueError(field + ' 必须为绝对文件路径')
    return c

def command(args):
    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode:
        # Xray 的错误可能包含密钥，禁止将原始验证输出回显到日志。
        raise ValueError(Path(args[0]).name + ' 检查失败，请核对配置和证书')
    return result.stdout

def write_private(path, data):
    path = Path(path)
    with open(path, 'w', opener=lambda p, f: os.open(p, f, 0o600)) as file:
        file.write(json.dumps(data, ensure_ascii=False, indent=2) + '\n')
    path.chmod(0o600)

def server_config(c):
    return {'log': {'loglevel': c['log_level']}, 'inbounds': [{
        'tag': 'msproxy', 'listen': '127.0.0.1', 'port': c['xray_port'], 'protocol': 'vless',
        'settings': {'clients': [{'id': c['uuid']}], 'decryption': c['vless_decryption']},
        'streamSettings': {'network': 'xhttp', 'security': 'none', 'xhttpSettings': {'path': c['xhttp_path'], 'mode': 'packet-up'}}}],
        'outbounds': [{'tag': 'direct', 'protocol': 'freedom'}]}

def client_config(c, ca_file=None):
    fields = c['vless_decryption'].split('.')
    public = []
    # 公钥从服务端密钥推导；导出的客户端 JSON 不含服务端私钥。
    for key in fields[3:]:
        if len(key) < 20:
            public.append(key)
            continue
        size = len(base64.urlsafe_b64decode(key + '=' * (-len(key) % 4)))
        if size not in (32, 64):
            raise ValueError('VLESS 服务端密钥长度无效')
        text = command([XRAY, 'mlkem768' if size == 64 else 'x25519', '-i', key])
        entries = dict(line.split(': ', 1) for line in text.splitlines() if ': ' in line)
        public.append(entries['Client' if size == 64 else 'Password (PublicKey)'])
    encryption = '.'.join(fields[:2] + ['0rtt'] + public)
    tls = {'serverName': c['domain'], 'allowInsecure': False, 'alpn': ['h2', 'http/1.1']}
    if ca_file or c.get('tls_ca_file'):
        tls['certificates'] = [{'certificateFile': ca_file or c['tls_ca_file'], 'usage': 'verify'}]
    return {'log': {'loglevel': 'warning'}, 'inbounds': [{'tag': 'socks', 'listen': '127.0.0.1', 'port': c['socks_port'],
        'protocol': 'socks', 'settings': {'auth': 'noauth', 'udp': True}}],
        'outbounds': [{'tag': 'msproxy', 'protocol': 'vless', 'settings': {'vnext': [{'address': c['domain'],
        'port': c['public_port'], 'users': [{'id': c['uuid'], 'encryption': encryption}]}]},
        'streamSettings': {'network': 'xhttp', 'security': 'tls', 'tlsSettings': tls,
        'xhttpSettings': {'host': c['domain'], 'path': c['xhttp_path'], 'mode': 'packet-up'}}}]}

def render(c):
    RUN.mkdir(parents=True, exist_ok=True)
    RUN.chmod(0o755)
    for name in ('body', 'proxy'):
        p = RUN / name
        p.mkdir(exist_ok=True)
        if os.geteuid() == 0:
            account = pwd.getpwnam('nginx')
            os.chown(p, account.pw_uid, account.pw_gid)
    for field in ('tls_cert_file', 'tls_key_file'):
        if not Path(c[field]).is_file():
            raise ValueError(field + ' 不存在或不是文件')
    cert = command(['openssl', 'x509', '-in', c['tls_cert_file'], '-pubkey', '-noout'])
    key = command(['openssl', 'pkey', '-in', c['tls_key_file'], '-pubout'])
    if cert != key:
        raise ValueError('TLS 证书与私钥不匹配')
    command(['openssl', 'x509', '-in', c['tls_cert_file'], '-noout', '-checkend', '0'])
    if 'does match certificate' not in command(['openssl', 'x509', '-in', c['tls_cert_file'], '-noout', '-checkhost', c['domain']]):
        raise ValueError('TLS 证书不覆盖 domain')
    write_private(RUN / 'xray.json', server_config(c))
    values = dict(c)
    for field in ('tls_cert_file', 'tls_key_file'):
        values[field] = '"' + c[field].replace('\\', '\\\\').replace('"', '\\"').replace('$', '\\$') + '"'
    (RUN / 'nginx.conf').write_text(string.Template((BASE / 'templates/nginx.conf').read_text()).substitute(values))
    write_private(RUN / 'state.json', {'https_port': c['https_port'], 'xray_port': c['xray_port']})
    command([XRAY, 'run', '-test', '-c', str(RUN / 'xray.json')])
    command(['nginx', '-t', '-c', str(RUN / 'nginx.conf')])

def serve():
    render(load_config())
    children = []
    stopping = False
    def stop(signum, frame):
        nonlocal stopping
        stopping = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        children.append(subprocess.Popen([XRAY, 'run', '-c', str(RUN / 'xray.json')]))
        children.append(subprocess.Popen(['nginx', '-c', str(RUN / 'nginx.conf'), '-g', 'daemon off;']))
        write_private(RUN / 'pids.json', [p.pid for p in children])
        while not stopping:
            if any(p.poll() is not None for p in children):
                print('msproxy: 子进程退出，停止整个容器', file=sys.stderr)
                return 1
            time.sleep(0.2)
        return 0
    finally:
        # 两个进程作为整体退出，避免只剩 Nginx 或 Xray 的半失效状态。
        for p in children:
            if p.poll() is None:
                p.terminate()
        deadline = time.monotonic() + 5
        for p in children:
            try:
                p.wait(timeout=max(0.1, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()

def health():
    state = json.loads((RUN / 'state.json').read_text())
    for pid in json.loads((RUN / 'pids.json').read_text()):
        os.kill(pid, 0)
    # 只验证本机服务存活；业务链路由端到端测试验证。
    with socket.create_connection(('127.0.0.1', state['xray_port']), timeout=2):
        pass
    context = ssl._create_unverified_context()
    with socket.create_connection(('127.0.0.1', state['https_port']), timeout=2) as sock:
        with context.wrap_socket(sock, server_hostname='localhost') as tls:
            tls.sendall(b'GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n')
            if b' 200 ' not in tls.recv(1024):
                raise ValueError('Nginx 健康检查失败')

def main():
    parser = argparse.ArgumentParser(description='msproxy 初始化、客户端导出和服务管理')
    subs = parser.add_subparsers(dest='action', required=True)
    for name in ('serve', 'check', 'healthcheck'):
        subs.add_parser(name)
    init = subs.add_parser('init', help='生成持久配置和客户端，已有文件时拒绝覆盖')
    init.add_argument('-d', '--domain', required=True)
    init.add_argument('-o', '--output', default='/config')
    init.add_argument('-c', '--tls-cert', default=DEFAULTS['tls_cert_file'])
    init.add_argument('-k', '--tls-key', default=DEFAULTS['tls_key_file'])
    init.add_argument('-p', '--public-port', type=int, default=443)
    init.add_argument('-s', '--socks-port', type=int, default=1080)
    init.add_argument('-x', '--xhttp-path')
    init.add_argument('-a', '--tls-ca', help='客户端额外信任 CA 的文件路径')
    client = subs.add_parser('client', help='从已有配置导出客户端 JSON')
    client.add_argument('-o', '--output', required=True)
    client.add_argument('-a', '--tls-ca')
    args = parser.parse_args()
    try:
        if args.action == 'init':
            output = Path(args.output)
            output.mkdir(parents=True, exist_ok=True)
            if any((output / name).exists() for name in ('server.json', 'client.json')):
                raise ValueError('配置已存在，拒绝覆盖')
            pairs = command([XRAY, 'vlessenc'])
            decryption = re.findall(r'"decryption": "([^"]+)"', pairs)[-1].replace('.native.', '.random.')
            c = validate(dict(DEFAULTS, domain=args.domain, uuid=str(uuid.uuid4()), vless_decryption=decryption,
                xhttp_path=args.xhttp_path or '/xh-' + secrets.token_hex(12), public_port=args.public_port,
                socks_port=args.socks_port, tls_cert_file=args.tls_cert, tls_key_file=args.tls_key))
            write_private(output / 'server.json', c)
            write_private(output / 'client.json', client_config(c, args.tls_ca))
            print('已生成 server.json 和 client.json；证书由挂载提供')
        elif args.action == 'client':
            output = Path(args.output)
            if output.exists():
                raise ValueError('客户端文件已存在，拒绝覆盖')
            write_private(output, client_config(load_config(), args.tls_ca))
        elif args.action == 'check':
            render(load_config())
            print('Nginx、Xray、TLS 配置检查通过')
        elif args.action == 'healthcheck':
            health()
        else:
            return serve()
        return 0
    except (ValueError, OSError, KeyError, IndexError) as error:
        # 外部输入的异常只报告类型；字段错误使用预定义消息，避免泄漏凭据。
        message = str(error) if type(error) is ValueError and not isinstance(error, json.JSONDecodeError) else type(error).__name__
        if len(message) > 200 or 'mlkem768x25519plus.' in message:
            message = '输入配置无效'
        print('msproxy: ' + message, file=sys.stderr)
        return 1

if __name__ == '__main__':
    sys.exit(main())
