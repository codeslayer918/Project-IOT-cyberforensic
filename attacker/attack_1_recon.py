#!/usr/bin/env python3
"""
ATTACK PHASE 1 -- RECONNAISSANCE
  1. nmap host discovery of the ICS subnet
  2. nmap -p 502 --script modbus-discover against the PLC
  3. pymodbus: enumerate every coil and register (incl. the hidden true level)
Outputs are printed and saved under /evidence/attack/ for the forensic record.
"""
import os
import subprocess
from modbus_io import connect, snapshot, log, PLC_HOST

SUBNET = os.environ.get("SUBNET", "172.28.0.0/24")
OUTDIR = "/evidence/attack"


def run(cmd):
    log("$ " + " ".join(cmd))
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        out = p.stdout + p.stderr
    except Exception as e:  # noqa: BLE001
        out = f"(command failed: {e})"
    print(out, flush=True)
    return out


def save(name, content):
    os.makedirs(OUTDIR, exist_ok=True)
    path = os.path.join(OUTDIR, name)
    with open(path, "w") as f:
        f.write(content)
    log(f"saved {path}")


def main():
    log("=== PHASE 1: RECON — host discovery ===")
    out1 = run(["nmap", "-sn", SUBNET])
    save("recon_nmap_hostdiscovery.txt", out1)

    log("=== PHASE 1: RECON — Modbus service discovery on port 502 ===")
    out2 = run(["nmap", "-Pn", "-p", "502", "--script", "modbus-discover",
                "--script-args", "modbus-discover.aggressive=true", PLC_HOST])
    save("recon_nmap_modbus_discover.txt", out2)

    log("=== PHASE 1: RECON — raw Modbus register/coil enumeration ===")
    c = connect()
    snap = snapshot(c)
    c.close()
    lines = ["Modbus enumeration of PLC %s:502" % PLC_HOST, ""]
    for k, v in snap.items():
        lines.append(f"  {k:12s} = {v}")
    text = "\n".join(lines)
    print(text, flush=True)
    save("recon_modbus_enumeration.txt", text + "\n")
    log("NOTE: 'true_level' (%MW10/HR1034) is already readable — the attacker "
        "has full unauthenticated visibility of the process.")
    log("=== PHASE 1 complete ===")


if __name__ == "__main__":
    main()
