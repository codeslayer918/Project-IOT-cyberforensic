#!/usr/bin/env bash
# Shared helpers for the ICS forensics lab orchestration scripts.
# Every script sources this, prints UTC timestamps, and appends to the
# operator action log (part of the forensic timeline).

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EVID="$ROOT/evidence"
OPLOG="$EVID/operator_actions.log"
DC="docker compose"
export COMPOSE_PROJECT_NAME="ics-forensics"

mkdir -p "$EVID" "$EVID/pcap" "$EVID/baseline" "$EVID/acquisition" "$EVID/live" "$EVID/attack"

utc() { date -u +%Y-%m-%dT%H:%M:%S.%3NZ; }

# log <message>  -> stdout + operator_actions.log
log() {
  local line="[$(utc)] $*"
  echo "$line"
  echo "$line" >> "$OPLOG"
}

# banner <title>  -> visually separated section, also logged
banner() {
  local msg="$*"
  echo ""
  echo "=================================================================="
  echo "  $msg"
  echo "=================================================================="
  echo "[$(utc)] ===== $msg =====" >> "$OPLOG"
}

# pause <seconds> <reason>
pause() {
  local s="$1"; shift || true
  log "pause ${s}s: $*"
  sleep "$s"
}

# sha256 of a file -> prints "hash  path"
sha_of() { sha256sum "$1"; }

# run a command inside a running compose service
dexec() { $DC exec -T "$@"; }

cd "$ROOT"
