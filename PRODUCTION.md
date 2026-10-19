# Standalone production packaging

Build from this repository root. The image contains code only; deployment endpoints, network identifiers, environment IDs and secrets are supplied externally. Use the [offline generator](deploy/identity/README.md) with a protected external JSON to render all deployment templates. Never commit the real configuration or generated output.

`compose.production.yml` requires explicit HTTPS issuer/account bridge, existing database network, bridge hostname/gateway and absolute secret-directory values. It publishes only loopback port8020, runs UID/GID1000 with a read-only filesystem, dropped capabilities, no privilege escalation and bounded resources/logs. The container bind address is internal only. It does not create or replace PostgreSQL, Redis or the backend. Use an inspected gateway IP or Docker's supported `host-gateway` feature; never disable TLS verification to accommodate routing.

The secret directory contains five protected regular files: `service-token`, `cookie-keys.json`, `private-jwks.json`, `clients.json` and `database-url`. Give UID1000 read access deliberately with root:1000 directories0750/files0440 or owner1000/files0400. The loader rejects symlinks, nonregular/oversized/empty/NUL files, unsafe ownership/modes and competing direct/file values. Disabled startup does not read secrets or open a listener. No shell evaluation is used.

From the repository root, supply the external generated Compose environment:

```sh
docker compose --env-file "$COMPOSE_ENV" -f compose.production.yml config --quiet
docker compose --env-file "$COMPOSE_ENV" -f compose.production.yml build identity
```

Record the immutable image digest and scan result before deployment. Initial protocol DDL is an explicit backed-up administrator step; startup never performs DDL. Runtime credentials need only CONNECT, schema USAGE and protocol-artifact table SELECT/INSERT/UPDATE/DELETE. Review secrets and configuration before explicitly enabling and starting the service. Do not regenerate initial provisioning material for an upgrade.

Nginx terminates issuer HTTPS, overwrites forwarded headers and restricts machine account routes with the externally configured CIDRs plus independent bearer authentication. The central UI upstream uses verified HTTPS with Host/SNI matching its configured origin; never expose all business APIs through the issuer hostname. The healthcheck verifies local discovery against the exact configured HTTPS issuer; it does not prove database, bridge, public TLS or browser SSO readiness. Validate those independently using the deployment checklist.
