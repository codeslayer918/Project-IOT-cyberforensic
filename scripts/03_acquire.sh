#!/usr/bin/env bash
# =============================================================================
# 03_acquire.sh -- forensic acquisition in ORDER OF VOLATILITY.
#   1. live PLC state (incl. the hidden true-level register)
#   2. finalize the packet capture
#   3. docker diff / logs / inspect
#   4. copy the OpenPLC DB, uploaded .st files, compiled program
#   5. docker export the PLC filesystem (tar)
#   6. copy the HMI historian
#   7. SHA-256 every artifact + chain-of-custody.csv
#   8. make the evidence read-only
# =============================================================================
source "$(dirname "$0")/lib.sh"

A="$EVID/acquisition"
PLC=ics-plc
ACQUIRER="Achraf"
mkdir -p "$A"

banner "ACQUIRE 1/8: LIVE PLC STATE (most volatile first)"
dexec attacker python3 -c "
import json
from modbus_io import connect, snapshot
c = connect(); s = snapshot(c); c.close()
print(json.dumps(s, indent=2))
" | tee "$A/live_registers.json" | tee -a "$OPLOG"
log "live registers (incl. hidden %MW10 true level) saved: $A/live_registers.json"

banner "ACQUIRE 2/8: FINALIZE PACKET CAPTURE"
log "stopping sniffer (SIGTERM flushes tcpdump and closes the pcap cleanly)"
$DC stop sniffer
cp -f "$EVID/pcap/ics_capture.pcap" "$A/ics_capture.pcap" && log "pcap copied to acquisition set"

banner "ACQUIRE 3/8: CONTAINER FORENSICS (diff / logs / inspect)"
docker diff "$PLC" > "$A/docker_diff_plc.txt" 2>&1 && log "docker diff plc saved"
for c in ics-plc ics-hmi ics-attacker ics-sniffer; do
  docker logs "$c" > "$A/logs_${c}.txt" 2>&1 && log "logs $c saved"
done
docker inspect ics-plc ics-hmi ics-attacker ics-sniffer > "$A/docker_inspect.json" 2>&1 \
  && log "docker inspect saved"

banner "ACQUIRE 4/8: COPY OPENPLC DB, .st FILES, COMPILED PROGRAM"
docker cp "$PLC:/docker_persistent/openplc.db" "$A/openplc.db" 2>/dev/null && log "openplc.db copied"
docker cp "$PLC:/docker_persistent/active_program" "$A/active_program" 2>/dev/null && log "active_program copied"
docker cp "$PLC:/docker_persistent/st_files" "$A/st_files" 2>/dev/null && log "st_files/ copied"
# compiled artifacts (generated C + runtime binary)
mkdir -p "$A/compiled"
for f in openplc Res0.c Config0.c POUS.c LOCATED_VARIABLES.h VARIABLES.csv; do
  docker cp "$PLC:/workdir/webserver/core/$f" "$A/compiled/$f" 2>/dev/null \
    && log "compiled/$f copied"
done

banner "ACQUIRE 5/8: DOCKER EXPORT PLC FILESYSTEM (tar)"
log "exporting full PLC container filesystem (this can be large / take a while)"
docker export "$PLC" -o "$A/plc_filesystem.tar" && log "plc_filesystem.tar written ($(du -h "$A/plc_filesystem.tar" | cut -f1))"

banner "ACQUIRE 6/8: COPY HMI HISTORIAN"
for f in historian.csv ground_truth.csv; do
  [ -f "$ROOT/hmi/$f" ] && cp -f "$ROOT/hmi/$f" "$A/$f" && log "copied hmi/$f"
done

banner "ACQUIRE 7/8: SHA-256 + CHAIN OF CUSTODY"
( cd "$A" && find . -type f ! -name hashes.sha256 ! -name chain_of_custody.csv -print0 \
    | sort -z | xargs -0 sha256sum ) > "$A/hashes.sha256"
log "wrote $A/hashes.sha256 ($(wc -l < "$A/hashes.sha256") artifacts)"

COC="$A/chain_of_custody.csv"
NOW="$(utc)"
echo "item_id,description,source,acquisition_method,utc_timestamp,sha256,acquired_by,storage_location" > "$COC"
n=0
while IFS= read -r line; do
  h="${line%% *}"
  p="${line#*  }"; p="${p#./}"
  n=$((n+1))
  id=$(printf "EV-%03d" "$n")
  base="$(basename "$p")"
  case "$base" in
    live_registers.json) d="Live Modbus register snapshot incl. hidden true level"; src="PLC 172.28.0.10:502"; m="Live Modbus read (pymodbus)";;
    ics_capture.pcap)    d="Full network packet capture (Modbus + HTTP)"; src="sniffer on PLC netns"; m="tcpdump -i any";;
    docker_diff_plc.txt) d="Changed files in PLC container vs image"; src="PLC container"; m="docker diff";;
    logs_*.txt)          d="Container stdout/stderr logs"; src="$base"; m="docker logs";;
    docker_inspect.json) d="Container runtime metadata"; src="all containers"; m="docker inspect";;
    openplc.db)          d="OpenPLC SQLite DB (programs, users, settings)"; src="PLC /docker_persistent"; m="docker cp";;
    active_program)      d="Name of the currently active program"; src="PLC /docker_persistent"; m="docker cp";;
    plc_filesystem.tar)  d="Full PLC container filesystem image"; src="PLC container"; m="docker export";;
    historian.csv)       d="HMI historian (operator-visible level)"; src="HMI container"; m="file copy";;
    ground_truth.csv)    d="Ground-truth level log (lab instrumentation)"; src="HMI container"; m="file copy";;
    *.st)                d="Structured Text program file"; src="PLC st_files"; m="docker cp";;
    openplc|Res0.c|Config0.c|POUS.c|LOCATED_VARIABLES.h|VARIABLES.csv) d="Compiled program artifact"; src="PLC core"; m="docker cp";;
    *)                   d="Evidence artifact"; src="PLC/lab"; m="file copy";;
  esac
  echo "$id,\"$d\",\"$src\",\"$m\",$NOW,$h,$ACQUIRER,\"evidence/acquisition/$p\"" >> "$COC"
done < "$A/hashes.sha256"
log "wrote chain of custody: $COC ($n items)"

banner "ACQUIRE 8/8: MAKE EVIDENCE READ-ONLY"
find "$A" -type f -exec chmod 0440 {} \;
find "$A" -type d -exec chmod 0550 {} \;
log "acquisition set is now read-only (integrity preserved after hashing)"

banner "ACQUISITION COMPLETE"
log "evidence directory: $A"
log "Next: analysis in analysis/ (see README)."
