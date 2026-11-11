#!/usr/bin/env python3
"""
HMI + historian for the ICS water-tank lab.

Role (what the plant operator sees): every POLL_INTERVAL seconds this process
reads the PLC over Modbus/TCP exactly like a real HMI/SCADA front-end would and
appends one row to historian.csv with a UTC ISO-8601 timestamp.

It reads ONLY operator-visible points:
  - Holding register 0      (%QW0)  -> level displayed on the HMI
  - Holding register 1024   (%MW0)  -> configured HIGH setpoint
  - Coils 0..3              (%QX0.0..0.3) -> pump, drain, alarm, overflow

In parallel it runs a second, independent "ground-truth" probe that reads the
PLC's hidden true-level register (%MW10 / holding register 1034) into
ground_truth.csv. This represents LAB INSTRUMENTATION of the simulated process,
NOT something the operator can see. Under the legitimate program the two match;
under the tampered (malicious) program they diverge -- that gap is the whole
point of the investigation. See docs/LIMITATIONS.md: a real investigation would
not have this parallel ground-truth feed, only the single live-acquisition
snapshot of the hidden register.
"""
import csv
import os
import sys
import time
from datetime import datetime, timezone

from pymodbus.client import ModbusTcpClient

# ---- Register / coil map (verified against OpenPLC_v3 modbus.cpp) -----------
HR_LEVEL_HMI   = 0      # %QW0  : level reported to the HMI
HR_SP_HIGH     = 1024   # %MW0  : HIGH setpoint (pump stop level)
HR_TRUE_LEVEL  = 1034   # %MW10 : hidden true level (ground-truth probe only)
COIL_PUMP      = 0      # %QX0.0
COIL_DRAIN     = 1      # %QX0.1
COIL_ALARM     = 2      # %QX0.2
COIL_OVERFLOW  = 3      # %QX0.3

PLC_HOST = os.environ.get("PLC_HOST", "172.28.0.10")
PLC_PORT = int(os.environ.get("PLC_PORT", "502"))
POLL     = float(os.environ.get("POLL_INTERVAL", "1"))
CSV_PATH = os.environ.get("HISTORIAN_CSV", "/app/historian.csv")
GT_PATH  = os.environ.get("GROUND_TRUTH_CSV", "/app/ground_truth.csv")
UNIT     = 1


def utc_now_iso():
    # e.g. 2026-11-11T13:24:05.123Z  (UTC, ISO-8601)
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def open_csv(path, header):
    new = not os.path.exists(path) or os.path.getsize(path) == 0
    f = open(path, "a", newline="")
    w = csv.writer(f)
    if new:
        w.writerow(header)
        f.flush()
    return f, w


def read_word(client, address):
    rr = client.read_holding_registers(address=address, count=1, slave=UNIT)
    if rr is None or rr.isError():
        return None
    return rr.registers[0]


def read_bits(client, address, count):
    rc = client.read_coils(address=address, count=count, slave=UNIT)
    if rc is None or rc.isError():
        return None
    return rc.bits


def main():
    print(f"[HMI] starting; PLC={PLC_HOST}:{PLC_PORT} poll={POLL}s", flush=True)
    hist_f, hist_w = open_csv(
        CSV_PATH,
        ["utc_time", "level_hmi", "pump", "drain", "alarm", "overflow", "sp_high"],
    )
    gt_f, gt_w = open_csv(GT_PATH, ["utc_time", "true_level"])

    client = ModbusTcpClient(PLC_HOST, port=PLC_PORT, timeout=3)

    while True:
        ts = utc_now_iso()
        try:
            if not client.connected:
                client.connect()

            level_hmi = read_word(client, HR_LEVEL_HMI)
            sp_high   = read_word(client, HR_SP_HIGH)
            true_lvl  = read_word(client, HR_TRUE_LEVEL)   # ground-truth probe
            bits      = read_bits(client, COIL_PUMP, 4)

            if level_hmi is None or bits is None:
                print(f"[HMI] {ts} read error / PLC not running yet", flush=True)
            else:
                pump     = int(bool(bits[0]))
                drain    = int(bool(bits[1]))
                alarm    = int(bool(bits[2]))
                overflow = int(bool(bits[3]))
                hist_w.writerow([ts, level_hmi, pump, drain, alarm, overflow,
                                 sp_high if sp_high is not None else ""])
                hist_f.flush()
                if true_lvl is not None:
                    gt_w.writerow([ts, true_lvl])
                    gt_f.flush()
                print(f"[HMI] {ts} level_hmi={level_hmi} true={true_lvl} "
                      f"pump={pump} alarm={alarm} overflow={overflow} sp_high={sp_high}",
                      flush=True)
        except Exception as e:  # noqa: BLE001  (keep the historian alive no matter what)
            print(f"[HMI] {ts} exception: {e}", flush=True)
            try:
                client.close()
            except Exception:
                pass
        time.sleep(POLL)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
