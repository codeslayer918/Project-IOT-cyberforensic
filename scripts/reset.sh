#!/usr/bin/env bash
# =============================================================================
# reset.sh -- tear the lab down to a clean state so the experiment can be run
# again from zero. Removes containers AND the OpenPLC anonymous volume (wiping
# the database, uploaded programs and runtime state) and clears generated
# evidence. Source programs, scripts and docs are left intact.
# =============================================================================
source "$(dirname "$0")/lib.sh"

banner "RESET: stopping and removing containers + volumes"
$DC down -v --remove-orphans || true

banner "RESET: clearing generated evidence"
# acquisition was made read-only; restore write permission before deleting
chmod -R u+w "$EVID/acquisition" 2>/dev/null || true
rm -rf "$EVID/pcap" "$EVID/baseline" "$EVID/acquisition" "$EVID/live" "$EVID/attack" \
       "$EVID/analysis"
rm -f "$EVID/operator_actions.log"
rm -f "$ROOT/hmi/historian.csv" "$ROOT/hmi/ground_truth.csv"
rm -f "$ROOT/docs/forensic_findings.md"
mkdir -p "$EVID/pcap" "$EVID/baseline" "$EVID/acquisition" "$EVID/live" "$EVID/attack"

echo ""
echo "Lab reset. Run ./scripts/00_setup.sh to start a fresh experiment."
