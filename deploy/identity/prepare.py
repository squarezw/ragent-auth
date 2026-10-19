#!/usr/bin/env python3
"""Generate OFFLINE production candidates. No deployment or database connection."""

import argparse
import base64
import json
import os
from pathlib import Path
import secrets

from cryptography.hazmat.primitives.asymmetric import rsa

import ipaddress
import re
from urllib.parse import urlsplit


def validate(config):
    def text(value, pattern):
        if not isinstance(value, str) or not re.fullmatch(pattern, value):
            raise ValueError("Invalid deployment configuration")
        return value
    def origin(value):
        text(value, r"https://[a-zA-Z0-9.-]+(?::[0-9]+)?")
        u = urlsplit(value)
        text(u.hostname, r"[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?")
        if u.port is not None and not 1 <= u.port <= 65535:
            raise ValueError("Invalid port")
        return value
    def path(value):
        text(value, r"/[a-zA-Z0-9_./-]+")
        if '..' in Path(value).parts:
            raise ValueError("Invalid path")
        return value
    for k in ('issuer', 'frontend_origin', 'account_base_url'):
        origin(config[k])
    if urlsplit(config['issuer']).port not in (None, 443):
        raise ValueError("Issuer proxy requires standard HTTPS port")
    for k in ('cloudbase_env_id', 'docker_network', 'database_host'):
        text(config[k], r"[a-zA-Z0-9][a-zA-Z0-9_.-]*")
    for k in ('database_name', 'database_role'):
        text(config[k], r"[a-z_][a-z0-9_]{0,62}")
    if type(config['database_port']) is not int or not 1 <= config['database_port'] <= 65535:
        raise ValueError('Invalid database port')
    for k in ('secret_dir', 'certificate_dir', 'webroot', 'ca_bundle', 'frontend_snippet'):
        path(config[k])
    for k in ('identity_upstream', 'bridge_upstream'):
        text(config[k], r"http://(?:127\.0\.0\.1|[a-zA-Z0-9.-]+):[0-9]+")
        if not 1 <= urlsplit(config[k]).port <= 65535:
            raise ValueError('Invalid upstream port')
    if urlsplit(config['identity_upstream']).hostname != '127.0.0.1':
        raise ValueError('Identity upstream must remain loopback')
    text(config['image'], r'[a-zA-Z0-9][a-zA-Z0-9_./:@-]*')
    gateway = config['bridge_gateway']
    if gateway != 'host-gateway':
        ipaddress.ip_address(gateway)
    if not config['trusted_bridge_cidrs']:
        raise ValueError('At least one explicitly trusted source required')
    for cidr in config['trusted_bridge_cidrs']:
        if not isinstance(cidr, str) or ipaddress.ip_network(cidr, strict=True).prefixlen == 0:
            raise ValueError('Invalid trusted network')
    if not config['apps']:
        raise ValueError('At least one client required')
    ids = set()
    for app in config['apps']:
        text(app['client_id'], r'[a-zA-Z0-9][a-zA-Z0-9_-]*')
        if app['client_id'] in ('backend', 'compose') or app['client_id'] in ids or app['kind'] not in ('ragent', 'mt'):
            raise ValueError('Invalid client')
        ids.add(app['client_id'])
        origin(app['origin'])
        # Exact callbacks, no query, fragment, wildcard or credentials.
        u = urlsplit(app['redirect_uri'])
        origin('https://' + u.netloc)
        if u.scheme != 'https' or u.query or u.fragment or u.path != '/api/auth/oidc/callback':
            raise ValueError('Invalid callback')
        if 'https://' + u.netloc != app['origin']:
            raise ValueError('Callback origin mismatch')
    return config


def generate(output: Path, config):
    config = validate(config)
    issuer = config["issuer"]
    apps = config["apps"]
    if output.exists():
        raise SystemExit("Refusing to overwrite an existing candidate directory")
    output.mkdir(parents=True, mode=0o700)
    secret_dir = output / "secrets"
    secret_dir.mkdir(mode=0o700)

    def write(path, value):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(value + "\n")

    token = secrets.token_urlsafe(48)
    db_password = secrets.token_urlsafe(48)
    keys = rsa.generate_private_key(
        public_exponent=65537, key_size=3072
    ).private_numbers()

    def encode(n):
        return (
            base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, "big"))
            .decode()
            .rstrip("=")
        )

    jwk = {
        k: encode(v)
        for k, v in {
            "n": keys.public_numbers.n,
            "e": keys.public_numbers.e,
            "d": keys.d,
            "p": keys.p,
            "q": keys.q,
            "dp": keys.dmp1,
            "dq": keys.dmq1,
            "qi": keys.iqmp,
        }.items()
    }
    jwk.update(kty="RSA", kid="prod-" + secrets.token_hex(8), use="sig", alg="RS256")
    clients = [
        {
            "client_id": app["client_id"],
            "client_secret": secrets.token_urlsafe(48),
            "redirect_uris": [app["redirect_uri"]],
        }
        for app in apps
    ]
    write(secret_dir / "service-token", token)
    write(secret_dir / "cookie-keys.json", json.dumps([secrets.token_urlsafe(48)]))
    write(secret_dir / "private-jwks.json", json.dumps({"keys": [jwk]}))
    write(secret_dir / "clients.json", json.dumps(clients, indent=2))
    write(
        secret_dir / "database-url",
        f"postgresql://{config['database_role']}:{db_password}@{config['database_host']}:{config['database_port']}/{config['database_name']}",
    )
    for client in clients:
        app = next(a for a in apps if a["client_id"] == client["client_id"])
        origin = app["origin"]
        env = {
            "OIDC_ENABLED": "false",
            "OIDC_ISSUER": issuer,
            "OIDC_CLIENT_ID": client["client_id"],
            "OIDC_CLIENT_SECRET": client["client_secret"],
        }
        if app["kind"] == "ragent":
            env.update(
                OIDC_REDIRECT_URI=app["redirect_uri"],
                OIDC_TRANSACTION_KEY=secrets.token_hex(32),
            )
        else:
            env.update(OIDC_APP_ORIGIN=origin, OIDC_ALLOW_NEW_USERS="false")
        write(
            output / (client["client_id"] + ".env"),
            "\n".join(k + "=" + v for k, v in env.items()),
        )
    write(output / "backend.env", "\n".join([
        "IDENTITY_ENABLED=false", "IDENTITY_SERVICE_TOKEN=" + token,
        "IDENTITY_RATE_LIMIT_REDIS_URL=REPLACE_WITH_AUTHENTICATED_REDIS_URL",
        "CLOUDBASE_ENV_ID=" + config['cloudbase_env_id']]))
    values = {
        'IDENTITY_ENABLED': 'false', 'IDENTITY_IMAGE': config['image'],
        'IDENTITY_PUBLISH_PORT': str(urlsplit(config['identity_upstream']).port),
        'IDENTITY_ISSUER': issuer, 'IDENTITY_ACCOUNT_BASE_URL': config['account_base_url'],
        'IDENTITY_SECRET_DIR': config['secret_dir'], 'IDENTITY_DOCKER_NETWORK': config['docker_network'],
        'IDENTITY_BRIDGE_HOST': urlsplit(config['account_base_url']).hostname,
        'IDENTITY_BRIDGE_GATEWAY': config['bridge_gateway'], 'CLOUDBASE_ENV_ID': config['cloudbase_env_id']}
    write(output / 'compose.env', '\n'.join(k + '=' + v for k, v in values.items()))
    replacements = {
        'ISSUER_HOST': urlsplit(issuer).hostname, 'ISSUER_ORIGIN': issuer,
        'FRONTEND_HOST': urlsplit(config['frontend_origin']).netloc,
        'FRONTEND_ORIGIN': config['frontend_origin'],
        'FRONTEND_TLS_NAME': urlsplit(config['frontend_origin']).hostname,
        'BRIDGE_HOST': urlsplit(config['account_base_url']).netloc,
        'IDENTITY_UPSTREAM': config['identity_upstream'], 'BRIDGE_UPSTREAM': config['bridge_upstream'],
        'CERTIFICATE_DIR': config['certificate_dir'], 'WEBROOT': config['webroot'],
        'CA_BUNDLE': config['ca_bundle'], 'FRONTEND_SNIPPET': config['frontend_snippet'],
        'BRIDGE_ALLOW': '\n    '.join('allow ' + c + ';' for c in config['trusted_bridge_cidrs'])}
    template_dir = Path(__file__).parent
    (output / 'nginx').mkdir(mode=0o700)
    for template in [*sorted((template_dir / 'nginx').glob('*.conf')), template_dir / 'certbot-deploy-hook.sh']:
        rendered = template.read_text()
        for key, value in replacements.items():
            rendered = rendered.replace('{{' + key + '}}', value)
        if '{{' in rendered or '}}' in rendered:
            raise ValueError('Unresolved deployment template')
        target = output / 'nginx' / template.name if template.suffix == '.conf' else output / template.name
        write(target, rendered.rstrip())
    migration = (
        Path(__file__).resolve().parents[2]
        / "migrations/001-artifacts.sql"
    )
    ddl = migration.read_text().replace("BEGIN;", "").replace("COMMIT;", "")
    sql = (
        "BEGIN;\nCREATE ROLE " + config["database_role"] + " LOGIN PASSWORD '"
        + db_password
        + "';\n"
        + ddl
        + f"\nGRANT CONNECT ON DATABASE {config['database_name']} TO {config['database_role']};\nGRANT USAGE ON SCHEMA identity_oidc TO {config['database_role']};\nGRANT SELECT,INSERT,UPDATE,DELETE ON identity_oidc.artifacts TO {config['database_role']};\nCOMMIT;"
    )
    write(output / "provision.sql", sql)
    write(
        output / "manifest.json",
        json.dumps(
            {
                "issuer": issuer,
                "enabled": False,
                "callbacks": {c["client_id"]: c["redirect_uris"] for c in clients},
                "status": "offline candidate; not provisioned or deployed",
            },
            indent=2,
        ),
    )
    print("Offline candidate generated at", output)
    print(
        "All enablement flags are false. Secrets were not printed. No server or database was contacted."
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--config-file", required=True, type=Path)
    args = parser.parse_args()
    output = args.output_dir.expanduser().resolve()
    repo = Path(__file__).resolve().parents[2]
    if output == repo or repo in output.parents:
        raise SystemExit("Output must be outside the repository")
    try:
        generate(output, json.loads(args.config_file.read_text()))
    except (ValueError, KeyError, TypeError, OSError):
        raise SystemExit("Invalid or incomplete external deployment configuration")
