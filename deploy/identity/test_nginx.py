"""Opt-in local Nginx parser checks with ephemeral synthetic certificates."""

from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import shutil
from test_prepare import fixture, prepare
import subprocess
import tempfile
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


@unittest.skipUnless(
    os.environ.get("IDENTITY_TEST_NGINX") == "1",
    "Set IDENTITY_TEST_NGINX=1 with local nginx:1.24-alpine image",
)
class NginxTests(unittest.TestCase):
    def test_bootstrap_and_https_bridge_parse(self):
        source = None
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            candidate = base / "candidate"
            prepare.generate(candidate, fixture())
            source = candidate / "nginx"
            conf = base / "nginx"
            (conf / "conf.d").mkdir(parents=True)
            (conf / "snippets").mkdir()
            (conf / "nginx.conf").write_text(
                "worker_processes 1; events { worker_connections 64; } http { include /etc/nginx/conf.d/*.conf; }"
            )
            shutil.copyfile(
                source / "frontend.conf",
                conf / "snippets/example-identity-frontend.conf",
            )
            shutil.copyfile(
                source / "api-bridge-location.conf", conf / "snippets/bridge.conf"
            )
            certdir = base / "certs"
            certdir.mkdir()
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subject = x509.Name(
                [x509.NameAttribute(NameOID.COMMON_NAME, "auth.example.invalid")]
            )
            now = datetime.now(timezone.utc)
            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(subject)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=1))
                .not_valid_after(now + timedelta(days=1))
                .add_extension(
                    x509.SubjectAlternativeName(
                        [
                            x509.DNSName("auth.example.invalid"),
                            x509.DNSName("api.example.invalid"),
                        ]
                    ),
                    critical=False,
                )
                .sign(key, hashes.SHA256())
            )
            (certdir / "fullchain.pem").write_bytes(
                cert.public_bytes(serialization.Encoding.PEM)
            )
            (certdir / "privkey.pem").write_bytes(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
            (conf / "conf.d/api.conf").write_text(
                "server { listen 443 ssl; server_name api.example.invalid; ssl_certificate /etc/letsencrypt/live/auth.example.invalid/fullchain.pem; ssl_certificate_key /etc/letsencrypt/live/auth.example.invalid/privkey.pem; include /etc/nginx/snippets/bridge.conf; location / {return 404;} }"
            )
            for file in ["auth-http.conf", "auth-https.conf"]:
                shutil.copyfile(source / file, conf / "conf.d/ragent-auth.conf")
                result = subprocess.run(
                    [
                        "docker",
                        "run",
                        "--rm",
                        "--network",
                        "none",
                        "--add-host",
                        "app.example.invalid:127.0.0.1",
                        "-v",
                        str(conf) + ":/etc/nginx:ro",
                        "-v",
                        str(certdir) + ":/etc/letsencrypt/live/auth.example.invalid:ro",
                        "--entrypoint",
                        "nginx",
                        "nginx:1.24-alpine",
                        "-t",
                    ],
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(result.returncode, 0, file + ": " + result.stderr)


if __name__ == "__main__":
    unittest.main()
