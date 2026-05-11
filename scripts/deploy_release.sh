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
BASE=/srv/$APP
SRC=/home/alex/bot2bot
SHA=$(cd "$SRC" && git rev-parse --verify "$REF")
SHORT=${SHA:0:12}
if [[ "$ENVIRONMENT" == "production" ]]; then
  LINK=$BASE/prod
  SERVICE=bot2bot.service
  RELEASE=$BASE/releases/$SHORT
else
  LINK=$BASE/stage
  SERVICE=bot2bot-stage.service
  RELEASE=$BASE/releases/$SHORT-stage
fi

mkdir -p "$BASE/releases"
rsync -a --delete \
  --exclude .git \
  --exclude .tmp \
  --exclude playwright_artifacts \
  --exclude __pycache__ \
  "$SRC/" "$RELEASE/"
chown -R alex:alex "$RELEASE"
ln -sfn "$RELEASE" "$LINK"
systemctl restart "$SERVICE"
if [[ "$ENVIRONMENT" == "production" ]]; then
  systemctl restart bot2bot-greeter.service || true
  ln -sfn "$LINK" /home/alex/safetalk
else
  ln -sfn "$LINK" /home/alex/safetalk-stage
fi

for i in {1..30}; do
  if [[ "$ENVIRONMENT" == "production" ]]; then
    curl -fsS http://127.0.0.1:3000/api/health >/dev/null && break
  else
    curl -fsS http://127.0.0.1:3200/api/health >/dev/null && break
  fi
  sleep 0.3
done
if [[ "$ENVIRONMENT" == "production" ]]; then
  curl -fsS https://bot2bot.chat/api/health; echo
else
  curl -fsS https://stage.bot2bot.chat/api/health; echo
fi

echo "deployed $ENVIRONMENT $SHA -> $RELEASE"
