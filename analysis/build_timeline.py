#!/usr/bin/env python3
"""
build_timeline.py -- merge every evidence source into ONE unified, UTC-sorted
incident timeline: operator action log, pcap-derived events (unauthorized Modbus
writes, HTTP uploads/logins, recon scan), OpenPLC DB upload times, container
start times, and historian anomalies (spoofing divergence, alarm, overflow).

Run AFTER analyze_network.py / analyze_plc.py (it reuses their CSVs).
Outputs timeline.csv, timeline.md and timeline.png under evidence/analysis/.
"""
import json
import os
import re
import sys
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import pandas as pd

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
EVID = os.path.join(ROOT, "evidence")
AN = os.path.join(EVID, "analysis")
EV = []  # list of dicts


def add(ts, source, etype, desc, ref):
    t = pd.to_datetime(ts, utc=True, errors="coerce")
    if pd.isna(t):
        return
    EV.append({"timestamp": t, "source": source, "event_type": etype,
               "description": str(desc)[:160], "evidence_reference": ref})


def first_existing(*p):
    for x in p:
        if x and os.path.exists(x):
            return x
    return None


def from_operator_log():
    path = os.path.join(EVID, "operator_actions.log")
    if not os.path.exists(path):
        return
    pat = re.compile(r"\[(\d{4}-\d\d-\d\dT[\d:.]+Z)\]\s+(.*)")
    for line in open(path, errors="replace"):
        m = pat.search(line)
        if not m:
            continue
        ts, msg = m.group(1), m.group(2)
        if msg.startswith("====="):
            add(ts, "operator_log", "milestone", msg.strip("= "), "operator_actions.log")
        elif "state " in msg or "plc health" in msg or msg.startswith("pause "):
            continue  # skip per-second monitoring snapshots / noise
        elif any(k in msg for k in ("FC05", "FC06", "FC16", "force PUMP",
                                    "raise HIGH", "uploading", "server stored",
                                    "compilation finished", "runtime START",
                                    "runtime STOP", "Re-applying", "login OK",
                                    "MODBUS SNAPSHOT", "HIGH alarm")):
            add(ts, "operator_log", "action", msg, "operator_actions.log")


def from_csv(name, builder):
    path = os.path.join(AN, name)
    if not os.path.exists(path):
        return
    try:
        df = pd.read_csv(path)
    except Exception:
        return
    builder(df)


def from_network():
    def unauth(df):
        # group consecutive identical writes to keep the timeline readable
        if df.empty:
            return
        df = df.sort_values("utc_time")
        key = df[["func_name", "iec", "src"]].astype(str).agg("|".join, axis=1)
        seen = set()
        for _, r in df.iterrows():
            k = f"{r.get('func_name')}|{r.get('iec')}|{r.get('src')}"
            if k in seen:
                continue
            seen.add(k)
            add(r["utc_time"], "pcap", "modbus_write_unauthorized",
                f"{r.get('func_name')} {r.get('iec')}={r.get('value')} from {r.get('src')}",
                "modbus_unauthorized_writes.csv")
    from_csv("modbus_unauthorized_writes.csv", unauth)

    def http(df):
        for _, r in df.iterrows():
            if r.get("kind") in ("login", "program-upload", "upload-metadata",
                                 "compile", "runtime-start", "runtime-stop"):
                add(r["utc_time"], "pcap", f"http_{r.get('kind')}",
                    f"{r.get('method')} {r.get('uri')} from {r.get('src')}",
                    "http_requests.csv")
    from_csv("http_requests.csv", http)

    def scan(df):
        for _, r in df.iterrows():
            add(r["first_seen"], "pcap", "recon_scan",
                f"scan from {r.get('src')}: {r.get('distinct_hosts')} hosts, "
                f"{r.get('syn_packets')} SYNs", "scan_findings.csv")
    from_csv("scan_findings.csv", scan)


def from_db():
    def progs(df):
        for _, r in df.iterrows():
            add(r["date_upload_utc"], "openplc_db", "program_upload",
                f"program '{r.get('name')}' ({r.get('file')}) uploaded", "plc_programs.csv")
    from_csv("plc_programs.csv", progs)


def from_docker_inspect():
    path = os.path.join(EVID, "acquisition", "docker_inspect.json")
    if not os.path.exists(path):
        return
    try:
        data = json.load(open(path))
    except Exception:
        return
    for c in data:
        name = c.get("Name", "").lstrip("/")
        started = c.get("State", {}).get("StartedAt")
        if started:
            add(started, "docker", "container_start", f"container {name} started",
                "docker_inspect.json")


def from_historian():
    hist = first_existing(os.path.join(EVID, "acquisition", "historian.csv"),
                          os.path.join(ROOT, "hmi", "historian.csv"))
    gt = first_existing(os.path.join(EVID, "acquisition", "ground_truth.csv"),
                        os.path.join(ROOT, "hmi", "ground_truth.csv"))
    if not hist:
        return
    h = pd.read_csv(hist)
    h["utc_time"] = pd.to_datetime(h["utc_time"], utc=True, errors="coerce")
    # first alarm, first overflow (operator-visible)
    if "alarm" in h:
        al = h[h["alarm"] == 1]
        if not al.empty:
            add(al.iloc[0]["utc_time"], "historian", "alarm_raised",
                "operator-visible HIGH alarm raised", "historian.csv")
    if "overflow" in h:
        ov = h[h["overflow"] == 1]
        if not ov.empty:
            add(ov.iloc[0]["utc_time"], "historian", "overflow_shown",
                "operator-visible overflow bit set", "historian.csv")
    # spoofing divergence: |hmi - true| large
    if gt:
        g = pd.read_csv(gt)
        g["utc_time"] = pd.to_datetime(g["utc_time"], utc=True, errors="coerce")
        merged = pd.merge_asof(h.sort_values("utc_time"),
                               g.sort_values("utc_time"), on="utc_time",
                               direction="nearest", tolerance=pd.Timedelta("2s"))
        merged["gap"] = (merged["level_hmi"] - merged["true_level"]).abs()
        div = merged[merged["gap"] >= 150]
        if not div.empty:
            r = div.iloc[0]
            add(r["utc_time"], "historian", "spoofing_detected",
                f"HMI/true level divergence >=150 (hmi={int(r['level_hmi'])}, "
                f"true={int(r['true_level'])}) — level spoofing", "ground_truth.csv")


def main():
    os.makedirs(AN, exist_ok=True)
    from_operator_log()
    from_network()
    from_db()
    from_docker_inspect()
    from_historian()

    if not EV:
        print("ERROR: no timeline events gathered (run the analyzers first)",
              file=sys.stderr)
        return 2

    df = pd.DataFrame(EV).sort_values("timestamp").reset_index(drop=True)
    df_out = df.copy()
    df_out["timestamp"] = df_out["timestamp"].dt.strftime("%Y-%m-%dT%H:%M:%S.%f").str[:-3] + "Z"
    df_out.to_csv(os.path.join(AN, "timeline.csv"), index=False)

    with open(os.path.join(AN, "timeline.md"), "w") as f:
        f.write("# Unified Incident Timeline\n\n")
        f.write("| UTC timestamp | source | event type | description | evidence |\n")
        f.write("|---|---|---|---|---|\n")
        for _, r in df_out.iterrows():
            f.write(f"| {r['timestamp']} | {r['source']} | {r['event_type']} "
                    f"| {r['description']} | {r['evidence_reference']} |\n")

    # figure: events on a time axis, colored by source
    fig, ax = plt.subplots(figsize=(13, 5), dpi=160)
    sources = list(df["source"].unique())
    ymap = {s: i for i, s in enumerate(sources)}
    palette = ["#1f77b4", "#d62728", "#2ca02c", "#9467bd", "#ff7f0e", "#17becf"]
    for s in sources:
        d = df[df["source"] == s]
        ax.scatter(d["timestamp"], [ymap[s]] * len(d), s=40,
                   color=palette[ymap[s] % len(palette)], label=s, zorder=3)
    ax.set_yticks(range(len(sources)))
    ax.set_yticklabels(sources)
    ax.set_title("Unified incident timeline (events by source)")
    ax.set_xlabel("UTC time")
    ax.grid(True, axis="x", alpha=0.3)
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M:%S"))
    fig.autofmt_xdate()
    fig.tight_layout()
    fig.savefig(os.path.join(AN, "figures", "timeline.png"))

    print(f"[*] timeline events: {len(df)}")
    print(f"[*] wrote timeline.csv, timeline.md, figures/timeline.png to {AN}")
    return 0


if __name__ == "__main__":
    os.makedirs(os.path.join(AN, "figures"), exist_ok=True)
    sys.exit(main())
