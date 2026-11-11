#!/usr/bin/env bash
# =============================================================================
# 00_setup.sh -- build & start the lab, then configure OpenPLC over HTTP:
#   login (default creds) -> upload water_tank_legit.st -> compile -> start PLC.
# The sniffer starts capturing as soon as the stack comes up. The legitimate
# configuration is driven from the HOST (the "engineering workstation", seen in
# the pcap as the bridge gateway 172.28.0.1), NOT from the attacker.
# =============================================================================
source "$(dirname "$0")/lib.sh"

WEB="http://127.0.0.1:8080"
LEGIT_ST="$ROOT/plc/programs/water_tank_legit.st"

banner "SETUP: build images"
log "building lab images (OpenPLC build can take several minutes the first time)"
$DC build

banner "SETUP: start the lab stack (plc, hmi, attacker, sniffer)"
$DC up -d
log "stack started; packet capture is now running -> $EVID/pcap/ics_capture.pcap"

banner "SETUP: wait for the OpenPLC runtime to become healthy"
for i in $(seq 1 60); do
  st="$(docker inspect --format '{{.State.Health.Status}}' ics-plc 2>/dev/null || echo none)"
  log "plc health: $st"
  [ "$st" = "healthy" ] && break
  sleep 5
done

banner "SETUP: configure OpenPLC (login, upload legit program, compile, start)"
python3 "$ROOT/attacker/openplc_web.py" --base "$WEB" --wait \
    --user openplc --password openplc \
    --upload "$LEGIT_ST" \
    --name "Water Tank Control v1.0" \
    --descr "Baseline legitimate control logic for tank level with safety cutoff." \
    --start | tee -a "$OPLOG"

banner "SETUP: verify Modbus is answering with sensible values"
pause 6 "let the runtime settle and the physics start"
dexec attacker python3 -c "from modbus_io import connect, snapshot; c=connect(); print('MODBUS SNAPSHOT:', snapshot(c)); c.close()" | tee -a "$OPLOG"

banner "SETUP COMPLETE"
log "OpenPLC web UI: http://127.0.0.1:8080  (openplc/openplc)"
log "Next: run scripts/01_baseline.sh"
