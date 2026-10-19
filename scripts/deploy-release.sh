#!/usr/bin/env bash
# Run through pinned-host-key SSH. Never source configuration or log secrets.
set -Eeuo pipefail
image=${1:?immutable image required}
deploy_dir=${2:?deployment directory required}
[[ "$image" =~ ^[a-z0-9][a-z0-9./:_-]*@sha256:[a-f0-9]{64}$ ]] || { echo 'Invalid immutable image reference' >&2; exit 2; }
[[ "$deploy_dir" =~ ^/[a-zA-Z0-9_./-]+$ && ! "$deploy_dir" =~ (^|/)\.\.(/|$) ]] || { echo 'Invalid deployment directory' >&2; exit 2; }
cd -- "$deploy_dir"
umask 077
exec 9>.identity-deploy.lock
flock -x 9
[[ -f compose.env && -f compose.production.yml ]] || { echo 'Existing protected Compose configuration required' >&2; exit 2; }
base=(docker compose --env-file compose.env -f compose.production.yml)
[[ ! -f compose.override.yml ]] || base+=(-f compose.override.yml)
marker=.identity-release.yml
[[ ! -L "$marker" ]] || { echo 'Release marker cannot be a symlink' >&2; exit 2; }
current=("${base[@]}")
[[ ! -f "$marker" ]] || current+=(-f "$marker")
cid=$("${current[@]}" ps -q identity)
[[ -n "$cid" && "$cid" != *$'\n'* ]] || { echo 'Exactly one existing identity container required' >&2; exit 2; }
old_image=$(docker inspect --format '{{.Image}}' "$cid")
[[ "$old_image" =~ ^sha256:[a-f0-9]{64}$ ]] || { echo 'Cannot identify rollback image' >&2; exit 2; }
# Existing authenticated Docker credentials are provisioned out of band on this host.
docker pull "$image" >/dev/null
backup=$(mktemp .identity-release.backup.XXXXXX)
candidate=$(mktemp .identity-release.candidate.XXXXXX)
had_marker=false
if [[ -f "$marker" ]]; then cp -- "$marker" "$backup"; had_marker=true; fi
write_override() { printf 'services:\n  identity:\n    image: "%s"\n' "$1" > "$2"; }
write_override "$image" "$candidate"
release=("${base[@]}" -f "$marker")
wait_healthy() {
  local id state actual i
  local expected=$1
  for ((i=0; i<60; i++)); do
    id=$("${release[@]}" ps -q identity) || return 1
    [[ -n "$id" ]] || return 1
    actual=$(docker inspect --format '{{.Config.Image}}' "$id") || return 1
    [[ "$actual" == "$expected" ]] || return 1
    state=$(docker inspect --format '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' "$id") || return 1
    [[ "$state" != 'running healthy' ]] || return 0
    [[ "$state" != *unhealthy* && "$state" != *missing* && "$state" != exited* && "$state" != dead* ]] || return 1
    sleep 2
  done
  return 1
}
rollback() {
  trap - ERR INT TERM
  echo 'Identity deployment failed; restoring previous image' >&2
  write_override "$old_image" "$marker"
  if "${release[@]}" up -d --no-deps --no-build identity >/dev/null && wait_healthy "$old_image"; then
    echo 'Previous identity image restored and healthy' >&2
  else
    echo 'Rollback readiness failed; operator intervention required' >&2
  fi
  if "$had_marker"; then mv -f -- "$backup" "$marker"; else rm -f -- "$marker"; fi
  rm -f -- "$candidate" "$backup"
  exit 1
}
trap rollback ERR INT TERM
mv -f -- "$candidate" "$marker"
"${release[@]}" up -d --no-deps --no-build identity >/dev/null
wait_healthy "$image"
trap - ERR INT TERM
rm -f -- "$backup"
echo 'Identity image deployed and healthy'
