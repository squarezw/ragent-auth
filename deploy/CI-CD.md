# Branches and delivery

`dev` is the integration branch. Open feature/fix PRs against `dev`; CI checks tests and container build without secrets. Promote a reviewed `dev` PR into `main` for a stable source baseline. CI rejects any other source branch into `main` and reverse `main` into `dev` PRs. Configure required branch-policy/test checks and block direct/force pushes on both branches in repository settings; workflow checks alone do not prevent direct pushes. Main pushes are tested but never deploy.

A push to `dev`, after successful tests, builds `linux/amd64`, publishes an image tagged with the full Git commit SHA, and deploys its immutable registry digest. The `auth-dev` GitHub environment names the **dev branch deployment target**; configure its environment protection/reviewers according to the intended host, which may be production infrastructure. Enabling these credentials makes every merged `dev` commit deploy automatically. Pull requests and other branches cannot enter publishing/deployment jobs or receive their credentials. No deployment target or registry account is embedded here.

## External repository/environment settings

Configure variables in GitHub, never commit their real values:

| Variable | Meaning |
| --- | --- |
| AUTH_REGISTRY | Registry hostname, optionally port; GHCR or Docker Hub supported |
| AUTH_IMAGE | Lowercase repository path relative to registry, including namespace |
| REGISTRY_USERNAME | Public registry publishing username; GHCR can use GitHub actor |

Configure secrets (deployment topology is secret too, so public workflow environment rendering does not disclose host/user/port):

| Secret | Meaning |
| --- | --- |
| REGISTRY_TOKEN | Limited publish token; GHCR can use ephemeral GITHUB_TOKEN with packages:write |
| AUTH_DEPLOY_HOST | Private deployment SSH hostname/IP |
| AUTH_DEPLOY_USER | Dedicated deployment account |
| AUTH_DEPLOY_PORT | SSH port, default22 |
| AUTH_DEPLOY_KEY | Authorized SSH private key for the deployment account |
| AUTH_DEPLOY_KNOWN_HOSTS | Host public key verified out of band, including `[host]:port` syntax for a nondefault port |

Docker Hub requires an explicit registry username variable and token secret. The username resolves from `vars.REGISTRY_USERNAME`, then the legacy secret for compatibility, then GitHub actor. Migrate legacy username secrets to a variable: usernames are public artifact metadata and secret masking can suppress image names in job outputs. Only the validated digest crosses the publish/deploy job boundary; the deploy job reconstructs the image from public registry/image variables. Never reuse a broader personal credential if a repository-scoped token is available. Configure private image **read** authentication out of band in the deployment user's Docker credential store, ideally using a credential helper. CI does not send registry credentials to the host, place them in SSH arguments, or rewrite its Docker login. Public images need no pull credential. Host keys are pinned; live `ssh-keyscan` discovery is not trust establishment.

## Existing host contract

The host needs Bash, Docker Compose v2, `flock`, outbound registry access and sufficient permissions to update the existing identity container. The directory fixed in the protected host wrapper configuration already contains protected `compose.env` and `compose.production.yml`, with optional existing `compose.override.yml`. These retain all account URLs, source ACL/gateway/network, enabled flags, external secret mounts and resource settings. Provision those separately through the external configuration workflow. CI neither copies these files nor reads/sources their secret values. Ensure the configured service name is `identity`, exactly one container already exists, and its image healthcheck genuinely verifies readiness. First-time installation is deliberately outside this release script.

CI invokes a fixed, administrator-installed `auth-deploy` launcher that constructs `SSH_ORIGINAL_COMMAND` from its argument array and calls the root-installed `ssh-deploy-wrapper.py` with a fixed external JSON configuration path. The wrapper configuration supplies `image_repository`, `deploy_dir` and `release_script`; it is nonsecret but root-owned and not group/world writable, as are the release script, wrapper, launcher and all parent directories. Do not place them in a deployment-user-writable checkout. Install/update these reviewed host scripts explicitly with administrator approval; CI cannot replace them. The wrapper accepts only `auth-deploy REPOSITORY@sha256:DIGEST` for the one configured repository, rejects extra arguments, mutable tags, other repositories and shell syntax, and executes the fixed release script with an argument array. The deploy directory is fixed on the host. The wrapper retains only fixed PATH and account HOME for existing Docker credentials.

An existing SSH key may be reused when explicitly authorized. That shared key retains its original SSH/account permissions; the fixed launcher constrains the deployment command, **not the key's ability to run other commands**. Do not change its existing authorized_keys entry or claim it is restricted to authentication deployments. A separately provisioned dedicated key can instead use an authorized_keys `restrict,command="..."` forced wrapper, preserving other operators' entries; this stricter mode is optional and requires separate authorization.

The release script takes only an immutable image digest and deployment directory from that wrapper. Superseded dev commits are skipped before SSH so an older, slower build cannot overwrite a newer deployment. It serializes on a host lock as well as the GitHub deployment concurrency group, pulls before modifying state and writes `.identity-release.yml` containing only the selected image. That final Compose override changes only `identity.image`; the command uses `up -d --no-deps --no-build identity`, never other services, migrations, volumes or secrets. Existing underlying overrides must not select an unrelated identity service. Readiness requires a running container whose image healthcheck is healthy; missing/unhealthy healthchecks fail closed.

Failed startup/health checks automatically recreate the prior image using local image layers, verify its health and restore the prior release marker (or its prior absence). CI still fails and prints a generic rollback outcome, without dumping environment, Compose configuration, tokens or service logs. If rollback itself cannot become healthy, operator intervention is required; inspect protected runtime state locally without publishing secrets. GitHub cancellation can interrupt a job, so deployment concurrency uses `cancel-in-progress: false`; the host script also handles normal ERR/INT/TERM. Host/power loss or SIGKILL can require manual recovery.

## Validation and release evidence

```sh
python -m unittest discover -s deploy -p 'test_cicd.py'
bash -n scripts/deploy-release.sh
```

Offline fake-Docker tests exercise digest validation, identity-only changes, configuration preservation, failed-health rollback with/without an existing marker and actual branch policy behavior. They do not claim live SSH or registry readiness. After configuring a target, record the workflow run, full source SHA, published digest and healthy deployed container. Do not print secrets or raw signed callbacks in CI evidence. No credentials or infrastructure are configured merely by merging these files.
