#!/usr/bin/env python3
"""Root-installed forced-command entry point. No shell evaluation or secret input."""
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys


def protected_regular_file(path):
    p = Path(path)
    info = p.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError('Untrusted deployment file')
    # Every parent must also be root-owned and not writable by the SSH user/group.
    for parent in p.parents:
        info = parent.stat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('Untrusted deployment parent')
    return p


def command(config, original):
    repository = config['image_repository']
    if not isinstance(repository, str) or not re.fullmatch(r'[a-z0-9][a-z0-9./:_-]*', repository):
        raise ValueError('Invalid allowed repository')
    args = shlex.split(original, posix=True)
    if len(args) != 2 or args[0] != 'auth-deploy':
        raise ValueError('Unsupported SSH command')
    if not re.fullmatch(re.escape(repository) + r'@sha256:[a-f0-9]{64}', args[1]):
        raise ValueError('Unsupported release image')
    for key in ('deploy_dir', 'release_script'):
        value = config[key]
        if not isinstance(value, str) or not re.fullmatch(r'/[a-zA-Z0-9_./-]+', value) or '..' in Path(value).parts:
            raise ValueError('Invalid fixed deployment path')
    return ['bash', config['release_script'], args[1], config['deploy_dir']]


def main():
    try:
        if len(sys.argv) != 2:
            raise ValueError('Fixed wrapper configuration required')
        config = json.loads(protected_regular_file(sys.argv[1]).read_text())
        args = command(config, os.environ.get('SSH_ORIGINAL_COMMAND', ''))
        protected_regular_file(config['release_script'])
        # Never propagate client-supplied shell initialization or Docker redirection.
        env = {'PATH': '/usr/bin:/bin', 'HOME': os.environ['HOME']}
        result = subprocess.run(args, env=env, check=False)
        return result.returncode
    except (ValueError, KeyError, TypeError, OSError):
        print('SSH deployment command rejected', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
