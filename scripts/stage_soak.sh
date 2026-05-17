#!/usr/bin/env bash
set -euo pipefail

BASE="${BOT2BOT_BASE:-https://stage.bot2bot.chat}"
DURATION_SECONDS="${DURATION_SECONDS:-10800}"
HEALTH_INTERVAL_SECONDS="${HEALTH_INTERVAL_SECONDS:-30}"
SMOKE_INTERVAL_SECONDS="${SMOKE_INTERVAL_SECONDS:-300}"
REGRESSION_INTERVAL_SECONDS="${REGRESSION_INTERVAL_SECONDS:-900}"
OUT_DIR="${OUT_DIR:-/srv/bot2bot/stage/.tmp/stage-soak-$(date -u +%Y%m%dT%H%M%SZ)}"
PYTHON="${PYTHON:-/srv/bot2bot/stage/.venv/bin/python3}"

mkdir -p "$OUT_DIR"
LOG="$OUT_DIR/soak.log"
SUMMARY="$OUT_DIR/summary.json"
start_epoch="$(date +%s)"
end_epoch="$((start_epoch + DURATION_SECONDS))"
last_smoke=0
last_regression=0
health_count=0
smoke_count=0
regression_count=0

log() {
  printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "$LOG"
}

fail() {
  log "FAIL: $*"
  jq -n \
    --arg ok "false" \
    --arg base "$BASE" \
    --arg reason "$*" \
    --arg log "$LOG" \
    '{ok:($ok=="true"), base:$base, reason:$reason, log:$log}' > "$SUMMARY"
  exit 1
}

run_health() {
  curl -fsS "$BASE/api/health" | jq -e '.ok == true' >/dev/null
  curl -fsS "$BASE/agents.json" | jq -e '.schema == "bot2bot.agent_directory.v1"' >/dev/null
  health_count=$((health_count + 1))
}

run_smoke() {
  BOT2BOT_BASE="$BASE" "$PYTHON" tests/agent_directory/stage_smoke.py >/tmp/bot2bot-stage-smoke.json
  jq -e '.ok == true' /tmp/bot2bot-stage-smoke.json >/dev/null
  cat /tmp/bot2bot-stage-smoke.json >> "$LOG"
  smoke_count=$((smoke_count + 1))
}

run_regression_subset() {
  BOT2BOT_BASE="$BASE" BASE="$BASE" "$PYTHON" tests/room_signed.py >/dev/null
  BOT2BOT_BASE="$BASE" BASE="$BASE" "$PYTHON" tests/room_claim.py >/dev/null
  BASE="$BASE" "$PYTHON" tests/dm.py >/dev/null
  BASE="$BASE" node tests/reconnect.js "$BASE" >/dev/null
  regression_count=$((regression_count + 1))
}

log "stage soak start base=$BASE duration=${DURATION_SECONDS}s"
run_health || fail "initial health failed"
run_smoke || fail "initial directory smoke failed"
run_regression_subset || fail "initial regression subset failed"
last_smoke="$(date +%s)"
last_regression="$last_smoke"
log "initial checks clean"

while [ "$(date +%s)" -lt "$end_epoch" ]; do
  now="$(date +%s)"
  run_health || fail "health probe failed"
  if [ "$((now - last_smoke))" -ge "$SMOKE_INTERVAL_SECONDS" ]; then
    run_smoke || fail "directory smoke failed"
    last_smoke="$now"
    log "directory smoke clean count=$smoke_count"
  fi
  if [ "$((now - last_regression))" -ge "$REGRESSION_INTERVAL_SECONDS" ]; then
    run_regression_subset || fail "regression subset failed"
    last_regression="$now"
    log "regression subset clean count=$regression_count"
  fi
  sleep "$HEALTH_INTERVAL_SECONDS"
done

jq -n \
  --arg base "$BASE" \
  --arg log "$LOG" \
  --argjson health "$health_count" \
  --argjson smoke "$smoke_count" \
  --argjson regression "$regression_count" \
  '{ok:true, base:$base, health_count:$health, smoke_count:$smoke, regression_count:$regression, log:$log}' > "$SUMMARY"
log "stage soak clean summary=$SUMMARY"
cat "$SUMMARY"
