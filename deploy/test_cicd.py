"""Offline CI policy and release rollback checks; no Docker daemon or SSH."""
import json
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('wrapper', ROOT/'scripts/ssh-deploy-wrapper.py')
wrapper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wrapper)
IMAGE = 'registry.example.invalid/team/auth@sha256:' + 'a' * 64
OLD = 'sha256:' + 'b' * 64
DOCKER = '''#!/usr/bin/env python3
import json, os, pathlib, sys
p=pathlib.Path(os.environ['FAKE_STATE']); s=json.loads(p.read_text()); a=sys.argv[1:]
s['calls'].append(a)
def save(): p.write_text(json.dumps(s))
if a[0]=='pull': save(); sys.exit(0)
if a[0]=='inspect':
 if 'Config.Image' in a[2] or a[2] == '{{.Image}}': print(s['image'])
 else: print('running unhealthy' if s.get('fail') and '@sha256:' in s['image'] else 'running healthy')
 save(); sys.exit(0)
if a[0]=='compose':
 if 'ps' in a: print('identity-test'); save(); sys.exit(0)
 if 'up' in a:
  f=[a[i+1] for i,x in enumerate(a) if x=='-f'][-1]
  for line in pathlib.Path(f).read_text().splitlines():
   if line.strip().startswith('image:'): s['image']=line.split('image:',1)[1].strip().strip('"')
  save(); sys.exit(0)
save(); sys.exit(2)
'''


class ReleaseTests(unittest.TestCase):
    def run_release(self, fail=False, marker=True, image=IMAGE):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = Path(tmp.name)
        bindir = base / 'bin'; bindir.mkdir()
        for name, body in [('docker', DOCKER), ('flock', '#!/bin/sh\nexit 0\n')]:
            f=bindir/name; f.write_text(body); f.chmod(0o700)
        deploy = base / 'target'; deploy.mkdir()
        (deploy/'compose.env').write_text('IDENTITY_ENABLED=true\nPRIVATE=unchanged\n')
        (deploy/'compose.production.yml').write_text('services:\n  identity:\n    image: ignored\n')
        previous = 'services:\n  identity:\n    image: "'+OLD+'"\n'
        if marker: (deploy/'.identity-release.yml').write_text(previous)
        state=base/'state'; state.write_text(json.dumps({'image':OLD, 'fail':fail, 'calls':[]}))
        env=dict(os.environ, PATH=str(bindir)+os.pathsep+os.environ['PATH'], FAKE_STATE=str(state))
        result=subprocess.run(['bash',str(ROOT/'scripts/deploy-release.sh'), image,str(deploy)],env=env,capture_output=True,text=True)
        return result, deploy, json.loads(state.read_text()), previous

    def test_success_uses_digest_only_identity_and_retains_configuration(self):
        result, deploy, state, _ = self.run_release()
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(state['image'],IMAGE)
        self.assertIn(IMAGE,(deploy/'.identity-release.yml').read_text())
        self.assertEqual((deploy/'compose.env').read_text(),'IDENTITY_ENABLED=true\nPRIVATE=unchanged\n')
        up=[c for c in state['calls'] if 'up' in c]
        self.assertEqual(len(up),1)
        self.assertEqual(up[0][-5:],['up','-d','--no-deps','--no-build','identity'])

    def test_failed_health_restores_image_and_existing_marker(self):
        result, deploy, state, previous=self.run_release(fail=True)
        self.assertEqual(result.returncode,1)
        self.assertEqual(state['image'],OLD)
        self.assertEqual((deploy/'.identity-release.yml').read_text(),previous)
        self.assertIn('restored and healthy',result.stderr)

    def test_failed_health_restores_missing_marker(self):
        result, deploy, state, _=self.run_release(fail=True,marker=False)
        self.assertEqual(result.returncode,1)
        self.assertEqual(state['image'],OLD)
        self.assertFalse((deploy/'.identity-release.yml').exists())

    def test_mutable_or_injected_image_rejected_without_docker(self):
        for image in ['registry.example.invalid/team/auth:latest', IMAGE+'\nBAD=1', '$(touch /tmp/unwanted)']:
            result, _, state, _=self.run_release(image=image)
            self.assertEqual(result.returncode,2)
            self.assertEqual(state['calls'],[])

    def test_forced_command_restricts_command_repository_and_paths(self):
        config = {'image_repository': 'registry.example.invalid/team/auth',
                  'deploy_dir': '/srv/example-identity', 'release_script': '/opt/example-deploy/release.sh'}
        self.assertEqual(wrapper.command(config, 'auth-deploy ' + IMAGE),
                         ['bash', config['release_script'], IMAGE, config['deploy_dir']])
        for original in ['scp -t /tmp/file', 'bash -s', '', 'auth-deploy ' + IMAGE + '; id',
                         'auth-deploy ' + IMAGE + ' extra', 'auth-deploy $(id)',
                         'auth-deploy registry.example.invalid/other/auth@sha256:' + 'a'*64,
                         'auth-deploy registry.example.invalid/team/auth:latest']:
            with self.assertRaises(ValueError): wrapper.command(config, original)
        with tempfile.TemporaryDirectory() as tmp:
            untrusted = Path(tmp)/'config'; untrusted.write_text('{}'); untrusted.chmod(0o666)
            with self.assertRaises(ValueError): wrapper.protected_regular_file(untrusted)
            link = Path(tmp)/'link'; link.symlink_to(untrusted)
            with self.assertRaises(ValueError): wrapper.protected_regular_file(link)

    def test_publish_boundary_exports_only_validated_digest(self):
        workflow=(ROOT/'.github/workflows/ci.yml').read_text()
        self.assertIn('digest: ${{ steps.image.outputs.digest }}', workflow)
        self.assertNotIn('needs.publish.outputs.image', workflow)
        self.assertIn('vars.REGISTRY_USERNAME || secrets.REGISTRY_USERNAME || github.actor', workflow)
        start=workflow.index('      - id: image\n')
        end=workflow.index('\n  deploy:', start)
        step=workflow[start:end]
        self.assertNotIn('IMAGE_NAME', step)
        self.assertNotIn('AUTH_IMAGE', step)
        self.assertNotIn('REGISTRY_USERNAME', step)
        script=step.split('        run: |\n',1)[1]
        script='\n'.join(line[10:] for line in script.splitlines())
        with tempfile.TemporaryDirectory() as tmp:
            output=Path(tmp)/'output'
            digest='sha256:'+'a'*64
            result=subprocess.run(['bash','-c',script],env=dict(os.environ,DIGEST=digest,GITHUB_OUTPUT=str(output)),capture_output=True)
            self.assertEqual(result.returncode,0)
            self.assertEqual(output.read_text(),'digest='+digest+'\n')
            for invalid in [IMAGE, 'latest', digest+'\nusername=example']:
                output.unlink(missing_ok=True)
                result=subprocess.run(['bash','-c',script],env=dict(os.environ,DIGEST=invalid,GITHUB_OUTPUT=str(output)),capture_output=True)
                self.assertNotEqual(result.returncode,0)
                self.assertFalse(output.exists())

    def test_workflow_branch_gates_and_no_untrusted_secrets(self):
        workflow=(ROOT/'.github/workflows/ci.yml').read_text()
        self.assertIn('branches: [dev, main]',workflow)
        self.assertEqual(workflow.count("if: github.event_name == 'push' && github.ref == 'refs/heads/dev'"),2)
        self.assertIn('needs: test',workflow)
        self.assertIn('needs: publish',workflow)
        self.assertIn('cancel-in-progress: false',workflow)
        self.assertIn('branch.data.commit.sha === context.sha',workflow)
        self.assertIn("if: steps.current.outputs.deploy == 'true'",workflow)
        self.assertIn('StrictHostKeyChecking=yes',workflow)
        self.assertNotIn('ssh-keyscan',workflow)
        self.assertNotIn('pull_request_target',workflow)
        self.assertNotIn('secrets.',workflow.split('  publish:')[0])
        # Execute the actual branch policy shell for each promotion direction.
        start=workflow.index('          if [ "$BASE" = main ]; then')
        end=workflow.index('\n  test:',start)
        policy='\n'.join(line[10:] for line in workflow[start:end].splitlines())
        for base,head,same,allowed in [('main','dev',True,True),('main','feat/x',True,False),
                                      ('main','dev',False,False),('dev','feat/x',False,True),('dev','main',True,False)]:
            result=subprocess.run(['bash','-c',policy],env=dict(os.environ,BASE=base,HEAD=head,SOURCE_REPO='target' if same else 'fork',TARGET_REPO='target'),capture_output=True)
            self.assertEqual(result.returncode==0,allowed)


if __name__=='__main__': unittest.main()
