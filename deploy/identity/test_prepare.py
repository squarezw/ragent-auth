"""Offline checks with reserved example infrastructure only."""
import copy
import importlib.util
import json
from pathlib import Path
import stat
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('prepare', Path(__file__).with_name('prepare.py'))
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)


def fixture():
    return json.loads(Path(__file__).with_name('config.example.json').read_text())


class PrepareTests(unittest.TestCase):
    def test_two_independent_configurations_propagate(self):
        for alternate in (False, True):
            c = fixture()
            if alternate:
                for k in ('issuer', 'frontend_origin', 'account_base_url'):
                    c[k] = c[k].replace('example.invalid', 'second.example.invalid')
                c['frontend_origin'] += ':8443'
                c.update(cloudbase_env_id='second-env', database_host='db.second.example.invalid', database_port=5433,
                         database_name='second_db', database_role='second_role', docker_network='second-network',
                         bridge_gateway='198.51.100.1', trusted_bridge_cidrs=['198.51.100.0/24'], secret_dir='/etc/second/secrets',
                         identity_upstream='http://127.0.0.1:18020', bridge_upstream='http://127.0.0.1:18010')
                for app in c['apps']:
                    app['origin'] = app['origin'].replace('example.invalid', 'second.example.invalid')
                    app['redirect_uri'] = app['redirect_uri'].replace('example.invalid', 'second.example.invalid')
            with tempfile.TemporaryDirectory() as tmp:
                output = Path(tmp) / 'candidate'
                prepare.generate(output, c)
                clients = json.loads((output / 'secrets/clients.json').read_text())
                self.assertEqual([x['redirect_uris'][0] for x in clients], [a['redirect_uri'] for a in c['apps']])
                for file in output.rglob('*'):
                    self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o600 if file.is_file() else 0o700)
                    if file.is_file():
                        self.assertNotIn('{{', file.read_text())
                for env in output.glob('*.env'):
                    self.assertIn('ENABLED=false', env.read_text())
                env = (output / 'compose.env').read_text()
                for key in ('issuer', 'account_base_url', 'cloudbase_env_id', 'docker_network', 'bridge_gateway', 'secret_dir'):
                    self.assertIn(c[key], env)
                self.assertIn('IDENTITY_PUBLISH_PORT=' + str(prepare.urlsplit(c['identity_upstream']).port), env)
                db = (output / 'secrets/database-url').read_text()
                self.assertIn('@' + c['database_host'] + ':' + str(c['database_port']) + '/' + c['database_name'], db)
                sql = (output / 'provision.sql').read_text()
                self.assertIn('CREATE ROLE ' + c['database_role'], sql)
                self.assertIn('ON DATABASE ' + c['database_name'], sql)
                self.assertNotIn('GRANT ALL', sql)
                nginx = (output / 'nginx/auth-https.conf').read_text()
                self.assertIn(c['identity_upstream'], nginx)
                self.assertIn('$request_uri', nginx)
                bridge = (output / 'nginx/api-bridge-location.conf').read_text()
                self.assertIn(c['bridge_upstream'], bridge)
                self.assertIn('allow ' + c['trusted_bridge_cidrs'][0] + ';', bridge)
                self.assertIn('deny all;', bridge)
                frontend = (output / 'nginx/frontend.conf').read_text()
                self.assertIn('proxy_ssl_verify on;', frontend)
                self.assertIn(c['frontend_origin'], frontend)
                self.assertIn('proxy_ssl_name ' + prepare.urlsplit(c['frontend_origin']).hostname + ';', frontend)
                self.assertIn(c['issuer'].split('://')[1], (output / 'certbot-deploy-hook.sh').read_text())
                with self.assertRaises(SystemExit):
                    prepare.generate(output, c)

    def test_missing_and_injection_rejected_before_output(self):
        invalid = []
        for key in fixture():
            c = fixture(); del c[key]; invalid.append(c)
        for key, value in [('issuer', 'https://auth.example.invalid\nINJECT=1'), ('issuer', 'https://auth.example.invalid:8443'), ('database_role', 'bad; DROP ROLE x'),
                           ('secret_dir', '/tmp/../bad'), ('cloudbase_env_id', 'bad\nX=1'),
                           ('frontend_origin', 'https://app.example.invalid;'), ('trusted_bridge_cidrs', ['0.0.0.0/0']),
                           ('trusted_bridge_cidrs', ['192.0.2.0/24; deny all']), ('bridge_gateway', 'host-gateway\nBAD=1'),
                           ('identity_upstream', 'http://127.0.0.1:8020;'), ('image', 'image\nX=1')]:
            c = fixture(); c[key] = value; invalid.append(c)
        for uri in ['https://evil.example.invalid/api/auth/oidc/callback', 'https://app.example.invalid/*',
                    'https://app.example.invalid/api/auth/oidc/callback?x=1', 'https://a:b@app.example.invalid/api/auth/oidc/callback']:
            c = fixture(); c['apps'][0]['redirect_uri'] = uri; invalid.append(c)
        for c in invalid:
            with tempfile.TemporaryDirectory() as tmp:
                output = Path(tmp) / 'candidate'
                with self.assertRaises((ValueError, KeyError, TypeError)):
                    prepare.generate(output, c)
                self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
