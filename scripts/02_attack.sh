#!/usr/bin/env bash
# =============================================================================
# 02_attack.sh -- run the attack campaign against the lab, in three phases,
# all from the attacker container (172.28.0.66), with banners and pauses so the
# phases are clearly separable in the pcap and the timeline.
#   Phase 1: reconnaissance (nmap + Modbus enumeration)
#   Phase 2: process manipulation (unauthorized Modbus writes)
#   Phase 3: logic tampering (malicious program via the web UI) + overflow
# =============================================================================
source "$(dirname "$0")/lib.sh"

GAP="${ATTACK_GAP:-10}"

banner "ATTACK CAMPAIGN START"
log "attacker = 172.28.0.66 ; target PLC = 172.28.0.10 ; HMI = 172.28.0.20"

banner "ATTACK PHASE 1 / 3 : RECONNAISSANCE"
dexec attacker python3 /app/attack_1_recon.py | tee -a "$OPLOG"
pause "$GAP" "between recon and process manipulation"

banner "ATTACK PHASE 2 / 3 : PROCESS MANIPULATION (unauthorized Modbus writes)"
dexec attacker python3 /app/attack_2_process_manipulation.py | tee -a "$OPLOG"
pause "$GAP" "between process manipulation and logic tampering"

banner "ATTACK PHASE 3 / 3 : LOGIC TAMPERING (malicious program upload)"
dexec attacker python3 /app/attack_3_logic_tampering.py | tee -a "$OPLOG"

banner "ATTACK CAMPAIGN COMPLETE"
log "HMI now shows a normal-looking tank; the TRUE level has overflowed."
log "Next: run scripts/03_acquire.sh"
