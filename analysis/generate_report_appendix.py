#!/usr/bin/env python3
"""
generate_report_appendix.py -- assemble docs/forensic_findings.md, a professional
incident-investigation summary that gathers all findings, tables and figure
paths produced by the other analyzers. Written in English, ready to adapt into
the university report. Standard library only; run it LAST.
"""
import csv
import json
import os
from datetime import datetime, timezone

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
EVID = os.path.join(ROOT, "evidence")
AN = os.path.join(EVID, "analysis")
DOCS = os.path.join(ROOT, "docs")


def read_csv(name, base=AN):
    p = os.path.join(base, name)
    if not os.path.exists(p):
        return []
    with open(p, newline="") as f:
        return list(csv.DictReader(f))


def read_text(path):
    return open(path, errors="replace").read() if os.path.exists(path) else ""


def count_lines(path):
    return sum(1 for _ in open(path, errors="replace")) if os.path.exists(path) else 0


def main():
    os.makedirs(DOCS, exist_ok=True)
    unauth = read_csv("modbus_unauthorized_writes.csv")
    http = read_csv("http_requests.csv")
    progs = read_csv("plc_programs.csv")
    timeline = read_csv("timeline.csv")
    coc = read_csv("chain_of_custody.csv", base=os.path.join(EVID, "acquisition"))
    uploads = [r for r in http if r.get("kind") in ("program-upload", "upload-metadata")]
    logins = [r for r in http if r.get("kind") == "login"]

    live = {}
    lp = os.path.join(EVID, "acquisition", "live_registers.json")
    if os.path.exists(lp):
        try:
            live = json.load(open(lp))
        except Exception:
            live = {}

    malicious = None
    for p in progs:
        if "mainten" in (p.get("name", "").lower()) or "update" in (p.get("name", "").lower()):
            malicious = p
    if not malicious and progs:
        malicious = progs[-1]

    diff_auth = read_text(os.path.join(AN, "program_diff_authoring.txt")).strip()
    gen = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")

    L = []
    L += [f"# Forensic Findings — ICS Water-Tank Incident", "",
          f"*Investigator: Achraf — generated {gen}*", "",
          "## 1. Executive summary", "",
          "A digital-forensics investigation was carried out on a simulated "
          "Industrial Control System (ICS) consisting of an OpenPLC v3 soft-PLC "
          "controlling a water tank, an HMI/historian, and an isolated network. "
          "The investigation reconstructed a three-stage attack:", "",
          "1. **Reconnaissance** — the adversary scanned the control subnet and "
          "enumerated the PLC's Modbus coils and registers.",
          "2. **Process manipulation** — the adversary issued unauthorized Modbus "
          "write commands (force pump, raise setpoint) from a non-HMI host.",
          "3. **Logic tampering (Stuxnet-style)** — the adversary logged into the "
          "OpenPLC web interface with default credentials and uploaded a tampered "
          "control program that disabled the safety cut-off and spoofed the level "
          "reported to the operator while the tank silently overflowed.", "",
          f"The network capture contains **{len(unauth)} unauthorized Modbus "
          f"write operations** from a non-HMI source and **{len(uploads)} program "
          f"upload transactions**. The acquired PLC database shows the tampered "
          f"program stored under an innocuous name"
          + (f" (*{malicious.get('name')}*, uploaded {malicious.get('date_upload_utc')})"
             if malicious else "") + ".", ""]

    if live:
        L += ["## 2. Live-acquisition snapshot (ground truth)", "",
              "At acquisition time the hidden true-level register (%MW10 / HR1034) "
              "and the operator-visible register (%QW0 / HR0) were read directly "
              "from the live PLC:", "",
              "| Point | Value |", "|---|---|"]
        for k in ("level_hmi", "true_level", "sp_high", "manual", "pump",
                  "alarm", "overflow"):
            if k in live:
                L.append(f"| `{k}` | {live[k]} |")
        gap = None
        if "level_hmi" in live and "true_level" in live:
            gap = abs(int(live["true_level"]) - int(live["level_hmi"]))
        if gap is not None:
            L += ["", f"**The operator-visible level differs from the true level "
                  f"by {gap} units** — direct evidence of sensor-value spoofing.", ""]

    L += ["## 3. Network evidence", "",
          f"- Unauthorized Modbus writes (not from the HMI): **{len(unauth)}**",
          f"- OpenPLC web logins observed: **{len(logins)}**",
          f"- Program upload transactions: **{len(uploads)}**",
          "", "See `evidence/analysis/network_summary.md` for the full list and "
          "the exact Wireshark display filters.", ""]
    if unauth:
        L += ["Representative unauthorized writes:", "",
              "| UTC time | src | function | address (IEC) | value |",
              "|---|---|---|---|---|"]
        for r in unauth[:12]:
            L.append(f"| {r['utc_time']} | {r['src']} | {r['func_code']} "
                     f"{r['func_name']} | {r['address']} ({r['iec']}) | {r['value']} |")
        L.append("")

    L += ["## 4. PLC logic-tampering evidence", "",
          "The uploaded program is byte-for-byte identical to the legitimate one "
          "except for the safety/reporting logic. Unified diff (legitimate → "
          "malicious):", "", "```diff", diff_auth or "(diff unavailable)", "```", "",
          "See `evidence/analysis/plc_summary.md` and `program_diff_onplc.txt`.", ""]

    L += ["## 5. Unified incident timeline", "",
          f"A merged, UTC-sorted timeline of **{len(timeline)} events** across all "
          "sources is in `evidence/analysis/timeline.md` / `timeline.csv`. Key "
          "milestones:", ""]
    for r in timeline:
        if r.get("event_type") in ("milestone", "recon_scan", "program_upload",
                                   "spoofing_detected", "overflow_shown",
                                   "http_program-upload"):
            L.append(f"- `{r['timestamp']}` **{r['source']}/{r['event_type']}** — "
                     f"{r['description']}")
    L.append("")

    L += ["## 6. Figures", "",
          "- `evidence/analysis/figures/operator_view_vs_reality.png` — HMI level "
          "vs. true level (the deception).",
          "- `evidence/analysis/figures/operator_digital_signals.png` — pump / "
          "alarm / overflow as seen by the operator.",
          "- `evidence/analysis/figures/timeline.png` — incident timeline.", ""]

    L += ["## 7. Evidence integrity & chain of custody", "",
          f"- Acquired artifacts recorded in the chain of custody: **{len(coc)}**",
          "- Every artifact is SHA-256 hashed (`evidence/acquisition/hashes.sha256`) "
          "and the acquisition set was made read-only after hashing.",
          "- Full custody record: `evidence/acquisition/chain_of_custody.csv`.", ""]

    L += ["## 8. Conclusions & recommendations", "",
          "- Modbus/TCP provides **no authentication or integrity**; any host on "
          "the control network can read and write process variables. Segment the "
          "control network and restrict write access.",
          "- The OpenPLC web interface used **default credentials**; enforce strong "
          "credentials and restrict management-plane access.",
          "- Safety logic running on the same PLC can be overwritten; use "
          "independent, hard-wired safety instrumented systems (SIS).",
          "- Operators relied solely on PLC-reported values; add out-of-band / "
          "independent instrumentation and anomaly detection (e.g. pump energized "
          "while level appears steady).", "",
          "*See docs/LIMITATIONS.md for the limitations of this simulated lab "
          "versus a real ICS.*", ""]

    out = os.path.join(DOCS, "forensic_findings.md")
    with open(out, "w") as f:
        f.write("\n".join(L))
    print(f"[*] wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
