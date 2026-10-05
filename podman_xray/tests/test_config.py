import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('msproxy', Path(__file__).resolve().parents[1] / 'msproxy.py')
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)

def config():
    return dict(app.DEFAULTS, domain='example.com', uuid='11111111-1111-4111-8111-111111111111',
                xhttp_path='/xh-example', vless_decryption='mlkem768x25519plus.random.600s.' + 'A' * 86)

class ConfigurationTests(unittest.TestCase):
    def test_file_environment_and_secret_file(self):
        # 文件提供基础配置，环境变量覆盖非敏感参数，_FILE 提供密钥。
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'config.json').write_text(json.dumps(config()))
            secret = config()['vless_decryption']
            (root / 'key').write_text(secret + '\n')
            env = {'MSPROXY_CONFIG_FILE': str(root / 'config.json'), 'MSPROXY_DOMAIN': 'other.example.com',
                   'MSPROXY_VLESS_DECRYPTION_FILE': str(root / 'key')}
            with patch.dict(os.environ, env, clear=True):
                loaded = app.load_config()
            self.assertEqual(loaded['domain'], 'other.example.com')
            self.assertEqual(loaded['vless_decryption'], secret)

    def test_conflicting_secret_sources_rejected(self):
        with patch.dict(os.environ, {'MSPROXY_UUID': config()['uuid'], 'MSPROXY_UUID_FILE': '/not-read'}, clear=True):
            with self.assertRaisesRegex(ValueError, '只能设置一个'):
                app.load_config()

    def test_nginx_injection_rejected(self):
        for field, value in [('domain', 'example.com; return 200;'), ('xhttp_path', '/xh { return 200; }'),
                             ('tls_key_file', '/certs/key.pem\ninclude /evil;')]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                app.validate(dict(config(), **{field: value}))

    def test_reserved_path_and_port_collision(self):
        for changes in [{'xhttp_path': '/'}, {'xhttp_path': '/healthz'}, {'xray_port': 8443}, {'https_port': 0}, {'https_port': True}]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                app.validate(dict(config(), **changes))

    def test_unknown_config_keys_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'bad.json'
            path.write_text(json.dumps(dict(config(), typo='value')))
            with patch.dict(os.environ, {'MSPROXY_CONFIG_FILE': str(path)}, clear=True), self.assertRaises(ValueError):
                app.load_config()

    def test_xray_error_does_not_expose_secret(self):
        with patch('subprocess.run') as run:
            run.return_value.returncode = 1
            run.return_value.stderr = 'private-secret'
            with self.assertRaises(ValueError) as error:
                app.command(['xray', 'run', '-test'])
            self.assertNotIn('private-secret', str(error.exception))

if __name__ == '__main__':
    unittest.main()
