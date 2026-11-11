#!/usr/bin/env python3
"""
analyze_historian.py -- visualize the deception.

Plots the HMI-displayed tank level over time and overlays the TRUE level
(from the ground-truth probe / live acquisition), with the three attack phases
marked. The gap between the two lines during the logic-tampering phase is the
headline figure: "what the operator saw" vs "what really happened".

Reads historian.csv + ground_truth.csv (prefers the acquired copies) and the
phase timestamps from evidence/operator_actions.log. Saves high-res PNGs.
"""
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
OUT = os.path.join(EVID, "analysis", "figures")


def first_existing(*paths):
    for p in paths:
        if p and os.path.exists(p):
            return p
    return None


def load_csv(path, time_col="utc_time"):
    df = pd.read_csv(path)
    df[time_col] = pd.to_datetime(df[time_col], utc=True, errors="coerce")
    return df.dropna(subset=[time_col])


def parse_phases(oplog):
    """Return list of (utc_time, label) for the attack phase banners."""
    phases = []
    if not os.path.exists(oplog):
        return phases
    pat = re.compile(r"\[(?P<ts>\d{4}-\d\d-\d\dT[\d:.]+Z)\]\s+=====\s+(?P<msg>.*?)\s+=====")
    for line in open(oplog, errors="replace"):
        m = pat.search(line)
        if not m:
            continue
        msg = m.group("msg")
        if "ATTACK PHASE" in msg or "ATTACK CAMPAIGN" in msg or "ACQUISITION" in msg:
            phases.append((pd.to_datetime(m.group("ts"), utc=True), msg))
    return phases


def main():
    os.makedirs(OUT, exist_ok=True)
    hist_path = first_existing(
        os.path.join(EVID, "acquisition", "historian.csv"),
        os.path.join(ROOT, "hmi", "historian.csv"))
    gt_path = first_existing(
        os.path.join(EVID, "acquisition", "ground_truth.csv"),
        os.path.join(ROOT, "hmi", "ground_truth.csv"))
    if not hist_path:
        print("ERROR: historian.csv not found", file=sys.stderr)
        return 2

    hist = load_csv(hist_path)
    gt = load_csv(gt_path) if gt_path else None
    phases = parse_phases(os.path.join(EVID, "operator_actions.log"))
    print(f"[*] historian rows: {len(hist)}; "
          f"ground-truth rows: {0 if gt is None else len(gt)}; "
          f"phases: {len(phases)}")

    # ---------- Figure 1: operator view vs reality ----------
    fig, ax = plt.subplots(figsize=(13, 6.5), dpi=160)
    ax.plot(hist["utc_time"], hist["level_hmi"], color="#1f77b4", lw=1.8,
            label="Level shown to operator (HMI)")
    if gt is not None and "true_level" in gt:
        ax.plot(gt["utc_time"], gt["true_level"], color="#d62728", lw=1.8,
                label="TRUE tank level (ground truth)")
    ax.axhline(950, color="#ff7f0e", ls="--", lw=1, label="Critical level (950)")
    ax.axhline(1000, color="#8c564b", ls=":", lw=1, label="Overflow (1000)")

    # alarm shading (operator-visible alarm == 1)
    if "alarm" in hist:
        al = hist[hist["alarm"] == 1]
        for t in al["utc_time"]:
            ax.axvspan(t, t, color="red", alpha=0.02)

    colors = ["#2ca02c", "#9467bd", "#e377c2", "#7f7f7f", "#17becf"]
    for i, (t, msg) in enumerate(phases):
        ax.axvline(t, color=colors[i % len(colors)], ls="-.", lw=1.2, alpha=0.9)
        ax.text(t, ax.get_ylim()[1] * 0.98, " " + msg.replace("ATTACK ", ""),
                rotation=90, va="top", ha="left", fontsize=7,
                color=colors[i % len(colors)])

    ax.set_title("ICS water tank — what the operator saw vs. what really happened")
    ax.set_xlabel("UTC time")
    ax.set_ylabel("Tank level (0–1000)")
    ax.legend(loc="upper left", fontsize=8)
    ax.grid(True, alpha=0.3)
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M:%S", tz=None))
    fig.autofmt_xdate()
    fig.tight_layout()
    f1 = os.path.join(OUT, "operator_view_vs_reality.png")
    fig.savefig(f1)
    print(f"[*] saved {f1}")

    # ---------- Figure 2: discrete signals ----------
    fig2, ax2 = plt.subplots(figsize=(13, 4.5), dpi=160)
    for col, off, color in [("pump", 0, "#1f77b4"), ("alarm", 1.2, "#d62728"),
                            ("overflow", 2.4, "#8c564b")]:
        if col in hist:
            ax2.step(hist["utc_time"], hist[col] + off, where="post",
                     label=col, color=color, lw=1.4)
    ax2.set_yticks([0, 1, 1.2, 2.2, 2.4, 3.4])
    ax2.set_yticklabels(["pump0", "pump1", "alarm0", "alarm1", "ovf0", "ovf1"],
                        fontsize=7)
    for i, (t, msg) in enumerate(phases):
        ax2.axvline(t, color=colors[i % len(colors)], ls="-.", lw=1.0, alpha=0.8)
    ax2.set_title("Operator-visible digital signals (pump / alarm / overflow)")
    ax2.set_xlabel("UTC time")
    ax2.legend(loc="upper left", fontsize=8)
    ax2.grid(True, alpha=0.3)
    ax2.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M:%S"))
    fig2.autofmt_xdate()
    fig2.tight_layout()
    f2 = os.path.join(OUT, "operator_digital_signals.png")
    fig2.savefig(f2)
    print(f"[*] saved {f2}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
