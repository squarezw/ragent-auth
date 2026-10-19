# ADR: independent issuer repository

Status: implemented repository extraction; existing production remains unchanged.

The issuer already runs as an independent Node container. Its protocol library, migration, tests and release templates now have an independent source repository so downstream projects can pin and reuse it. The backend consumes it as an HTTPS Git submodule at `identity-provider`, preserving the existing build path and avoiding duplicated issuer implementations. Python-only backend builds do not need to initialize it. Auth releases build this repository root directly.

Alternative: copying the issuer into each consumer would drift. An npm dependency would imply embedding the issuer inside an application process and would not represent the existing independent deployment. A submodule requires explicit initialization and reviewed pointer updates but gives a reproducible dependency without changing the runtime architecture.

The account database, stable subject mapping, password/phone verification, roles and tenant permissions remain owned by ragent-service. The existing RAgent login UI remains a frontend dependency behind the same-origin proxy. Application OIDC clients stay in their application repositories. The protocol schema `identity_oidc` and its migration belong here; the backend account mapping schema does not.

No automatic production deployment, signing-key rotation, schema migration or secret transfer is part of extraction. Existing production paths/images are kept until an explicit release. Preserve the existing gateway mapping, trusted proxy TLS configuration and external secret mount when deploying this source. CI uses only synthetic fixtures; optional real database/bridge tests need isolated external fixtures.

Public history starts with the reviewed extracted snapshot from the extracted ragent-service issuer snapshot. Do not merge private backend history into this repository. Never commit environment overlays, generated candidates, private JWKS, database dumps or customer configuration.

Deployment templates contain placeholders rather than environment-specific hosts or ACLs. An external operator configuration supplies those values; generated candidates stay outside the checkout. This does not change the existing running service or migrate production credentials.
