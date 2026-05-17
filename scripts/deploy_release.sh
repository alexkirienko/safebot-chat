#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 <staging|production> [git-ref-or-sha]" >&2
  exit 2
}

ENVIRONMENT="${1:-}"
REF="${2:-HEAD}"
[[ "$ENVIRONMENT" == "staging" || "$ENVIRONMENT" == "production" ]] || usage

APP=bot2bot
APP_USER=${APP_USER:-alex}
BASE=/srv/$APP
SRC=/home/alex/bot2bot
RELEASES_TO_KEEP=${RELEASES_TO_KEEP:-10}
SHA=$(cd "$SRC" && git rev-parse --verify "$REF^{commit}")
SHORT=${SHA:0:12}
if [[ "$ENVIRONMENT" == "production" ]]; then
  LINK=$BASE/prod
  SERVICE=bot2bot.service
  PORT=3000
  PUBLIC_HEALTH=https://bot2bot.chat/api/health
  PUBLIC_VERSION=https://bot2bot.chat/api/version
  RELEASE=$BASE/releases/$SHORT
else
  LINK=$BASE/stage
  SERVICE=bot2bot-stage.service
  PORT=3200
  PUBLIC_HEALTH=https://stage.bot2bot.chat/api/health
  PUBLIC_VERSION=https://stage.bot2bot.chat/api/version
  RELEASE=$BASE/releases/$SHORT-stage
fi

run_as_app_user() {
  if [[ "$(id -un)" == "$APP_USER" ]]; then
    "$@"
  else
    runuser -u "$APP_USER" -- "$@"
  fi
}

wait_for_local_health() {
  for _ in {1..40}; do
    if curl -fsS "http://127.0.0.1:$PORT/api/health" >/dev/null; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}

fetch_public() {
  local url="$1"
  for _ in {1..20}; do
    if curl -fsS "$url"; then
      return 0
    fi
    sleep 1
  done
  return 1
}

rollback() {
  local previous="${1:-}"
  local failed_release="${2:-}"
  if [[ -n "$previous" && -d "$previous" ]]; then
    echo "health check failed; rolling $ENVIRONMENT back to $previous" >&2
    ln -sfn "$previous" "$LINK"
    systemctl restart "$SERVICE" || true
    if [[ "$ENVIRONMENT" == "production" ]]; then
      systemctl restart bot2bot-greeter.service || true
    fi
  else
    echo "health check failed and no previous release exists for rollback" >&2
  fi
  if [[ -n "$failed_release" && -d "$failed_release" && "$failed_release" != "$previous" ]]; then
    rm -rf -- "$failed_release"
  fi
}

prune_releases() {
  local previous="${1:-}"
  [[ "$RELEASES_TO_KEEP" =~ ^[0-9]+$ ]] || RELEASES_TO_KEEP=10
  (( RELEASES_TO_KEEP > 0 )) || return 0
  mapfile -t protected < <(
    for l in "$BASE/prod" "$BASE/stage"; do readlink -f "$l" 2>/dev/null || true; done
    [[ -n "$previous" ]] && printf '%s\n' "$previous"
  )
  if [[ "$ENVIRONMENT" == "staging" ]]; then
    mapfile -t candidates < <(find "$BASE/releases" -mindepth 1 -maxdepth 1 -type d -name '*-stage' -printf '%T@ %p\n' | sort -rn | awk '{print $2}')
  else
    mapfile -t candidates < <(find "$BASE/releases" -mindepth 1 -maxdepth 1 -type d ! -name '*-stage' -printf '%T@ %p\n' | sort -rn | awk '{print $2}')
  fi
  local kept=0
  for dir in "${candidates[@]}"; do
    local is_protected=0
    for p in "${protected[@]}"; do [[ "$dir" == "$p" ]] && is_protected=1; done
    if (( is_protected )); then
      continue
    fi
    kept=$((kept + 1))
    if (( kept > RELEASES_TO_KEEP )); then
      rm -rf -- "$dir"
    fi
  done
}

mkdir -p "$BASE/releases"
PREVIOUS=$(readlink -f "$LINK" 2>/dev/null || true)
rm -rf "$RELEASE.tmp"
mkdir -p "$RELEASE.tmp"

# Build the release from the requested git object, not mutable checkout state.
# This keeps deploys immutable/reproducible and avoids carrying stale .venv paths.
git -C "$SRC" archive "$SHA" | tar -x -C "$RELEASE.tmp"
printf '{"sha":"%s","short":"%s","environment":"%s","deployed_at":"%s"}\n' \
  "$SHA" "$SHORT" "$ENVIRONMENT" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$RELEASE.tmp/.bot2bot-version.json"
chown -R "$APP_USER:$APP_USER" "$RELEASE.tmp"

run_as_app_user npm ci --prefix "$RELEASE.tmp" --no-audit --no-fund
run_as_app_user npm ci --prefix "$RELEASE.tmp/mcp" --no-audit --no-fund
run_as_app_user python3 -m venv "$RELEASE.tmp/.venv"
run_as_app_user "$RELEASE.tmp/.venv/bin/python3" -m pip install --upgrade pip >/dev/null
run_as_app_user "$RELEASE.tmp/.venv/bin/python3" -m pip install requests==2.33.1 PyNaCl==1.6.2 >/dev/null

rm -rf "$RELEASE"
mv "$RELEASE.tmp" "$RELEASE"
ln -sfn "$RELEASE" "$LINK"
if ! systemctl restart "$SERVICE"; then
  rollback "$PREVIOUS" "$RELEASE"
  echo "service restart failed for $SERVICE" >&2
  exit 1
fi
if [[ "$ENVIRONMENT" == "production" ]]; then
  systemctl restart bot2bot-greeter.service || true
fi

if ! wait_for_local_health; then
  rollback "$PREVIOUS" "$RELEASE"
  exit 1
fi

if ! fetch_public "$PUBLIC_HEALTH"; then
  rollback "$PREVIOUS" "$RELEASE"
  echo "public health check failed for $PUBLIC_HEALTH" >&2
  exit 1
fi
echo
if ! version_json=$(fetch_public "$PUBLIC_VERSION"); then
  rollback "$PREVIOUS" "$RELEASE"
  echo "public version check failed for $PUBLIC_VERSION" >&2
  exit 1
fi
echo "$version_json"
if ! reported_sha=$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("sha", ""))' <<<"$version_json" 2>/dev/null); then
  rollback "$PREVIOUS" "$RELEASE"
  echo "public version response was not valid JSON from $PUBLIC_VERSION" >&2
  exit 1
fi
if [[ "$reported_sha" != "$SHA" ]]; then
  rollback "$PREVIOUS" "$RELEASE"
  echo "deployed version reported sha $reported_sha, expected $SHA" >&2
  exit 1
fi

prune_releases "$PREVIOUS"

echo "deployed $ENVIRONMENT $SHA -> $RELEASE"
