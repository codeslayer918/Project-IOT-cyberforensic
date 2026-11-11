#!/usr/bin/env bash
# =============================================================================
# 01_baseline.sh -- let the lab run normally, then snapshot a clean baseline:
#   legitimate .st, OpenPLC database, config files + SHA-256 hashes.
# Duration is configurable:  BASELINE_SECONDS=120 ./scripts/01_baseline.sh
# =============================================================================
source "$(dirname "$0")/lib.sh"

BASELINE_SECONDS="${BASELINE_SECONDS:-600}"
BDIR="$EVID/baseline"
PLC=ics-plc

banner "BASELINE: ensure the lab + capture are running"
$DC up -d
log "capture file: $EVID/pcap/ics_capture.pcap"

banner "BASELINE: run the plant normally for ${BASELINE_SECONDS}s"
log "observe http://127.0.0.1:8080 and the HMI historian (hmi/historian.csv)"
sleep "$BASELINE_SECONDS"

banner "BASELINE: capture clean baseline evidence"
cp -f "$ROOT/plc/programs/water_tank_legit.st" "$BDIR/water_tank_legit.st"
log "saved source: $BDIR/water_tank_legit.st"

# OpenPLC state lives on the container's /docker_persistent volume
for item in openplc.db active_program mbconfig.cfg dnp3.cfg; do
  if docker cp "$PLC:/docker_persistent/$item" "$BDIR/$item" 2>/dev/null; then
    log "copied $item from PLC"
  else
    log "note: $item not present (skipped)"
  fi
done
docker cp "$PLC:/docker_persistent/st_files" "$BDIR/st_files" 2>/dev/null \
  && log "copied st_files/ from PLC"

# a quick live register snapshot for the baseline record
dexec attacker python3 -c "from modbus_io import connect, snapshot; c=connect(); print(snapshot(c)); c.close()" \
  > "$BDIR/baseline_modbus_snapshot.txt" 2>&1 && log "saved baseline Modbus snapshot"

banner "BASELINE: compute SHA-256 hashes"
( cd "$BDIR" && find . -type f ! -name hashes.sha256 -print0 | sort -z \
    | xargs -0 sha256sum ) > "$BDIR/hashes.sha256"
log "wrote $BDIR/hashes.sha256 ($(wc -l < "$BDIR/hashes.sha256") files)"

banner "BASELINE COMPLETE"
log "Next: run scripts/02_attack.sh"
