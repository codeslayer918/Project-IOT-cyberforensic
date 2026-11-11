#!/usr/bin/env python3
"""
analyze_plc.py -- forensic analysis of the PLC/host artifacts.

  * query the acquired OpenPLC SQLite DB: Programs (with upload dates), Users,
    Settings -> CSVs
  * diff the legitimate vs malicious program (clean authoring diff) AND the
    baseline vs acquired on-PLC program (forensic diff) -> saved to files
  * compare baseline vs acquired SHA-256 hashes -> what changed
  * summarize `docker diff` of the PLC container

Standard library only. Writes to evidence/analysis/.
"""
import csv
import difflib
import os
import sqlite3
import sys
from datetime import datetime, timezone

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
EVID = os.path.join(ROOT, "evidence")
OUT = os.path.join(EVID, "analysis")


def iso(epoch):
    try:
        return datetime.fromtimestamp(int(epoch), timezone.utc)\
            .strftime("%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError):
        return str(epoch)


def query_db(dbpath):
    out = {"programs": [], "users": [], "settings": []}
    if not os.path.exists(dbpath):
        return out
    con = sqlite3.connect(dbpath)
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    try:
        for r in cur.execute("SELECT Prog_ID,Name,Description,File,Date_upload "
                             "FROM Programs ORDER BY Date_upload"):
            out["programs"].append({
                "prog_id": r["Prog_ID"], "name": r["Name"],
                "description": r["Description"], "file": r["File"],
                "date_upload_utc": iso(r["Date_upload"]),
                "date_upload_epoch": r["Date_upload"]})
    except sqlite3.Error as e:
        print("programs query error:", e)
    try:
        for r in cur.execute("SELECT username,name,email FROM Users"):
            out["users"].append({"username": r["username"], "name": r["name"],
                                 "email": r["email"]})
    except sqlite3.Error as e:
        print("users query error:", e)
    try:
        for r in cur.execute("SELECT Key,Value FROM Settings"):
            out["settings"].append({"key": r["Key"], "value": r["Value"]})
    except sqlite3.Error as e:
        print("settings query error:", e)
    con.close()
    return out


def write_csv(path, rows, cols):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in cols})


def unified(a_path, b_path, a_label, b_label):
    def readlines(p):
        if not os.path.exists(p):
            return [f"(missing: {p})\n"]
        with open(p, "r", errors="replace") as f:
            return f.readlines()
    return "".join(difflib.unified_diff(
        readlines(a_path), readlines(b_path),
        fromfile=a_label, tofile=b_label))


def load_hashes(path):
    d = {}
    if not os.path.exists(path):
        return d
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            h, _, p = line.partition("  ")
            d[p.strip().lstrip("./")] = h
    return d


def summarize_docker_diff(path):
    counts = {"C": 0, "A": 0, "D": 0}
    highlights = []
    if not os.path.exists(path):
        return counts, highlights
    with open(path, errors="replace") as f:
        for line in f:
            line = line.rstrip()
            if not line or line[0] not in "CAD":
                continue
            tag = line[0]
            counts[tag] = counts.get(tag, 0) + 1
            p = line[2:]
            if any(k in p for k in ("st_files", "openplc.db", "active_program",
                                    "/core/", "webserver")):
                highlights.append(line)
    return counts, highlights


def main():
    os.makedirs(OUT, exist_ok=True)
    acq_db = os.path.join(EVID, "acquisition", "openplc.db")
    base_db = os.path.join(EVID, "baseline", "openplc.db")

    acq = query_db(acq_db)
    write_csv(os.path.join(OUT, "plc_programs.csv"), acq["programs"],
              ["prog_id", "name", "description", "file",
               "date_upload_utc", "date_upload_epoch"])
    write_csv(os.path.join(OUT, "plc_users.csv"), acq["users"],
              ["username", "name", "email"])
    write_csv(os.path.join(OUT, "plc_settings.csv"), acq["settings"],
              ["key", "value"])

    # --- clean authoring diff: legit vs malicious source ---
    legit_src = os.path.join(ROOT, "plc", "programs", "water_tank_legit.st")
    mal_src = os.path.join(ROOT, "plc", "programs", "water_tank_malicious.st")
    diff_auth = unified(legit_src, mal_src,
                        "water_tank_legit.st", "water_tank_malicious.st")
    with open(os.path.join(OUT, "program_diff_authoring.txt"), "w") as f:
        f.write(diff_auth)

    # --- forensic diff: baseline active program vs acquired active program ---
    def active_file_content(scope):
        ap = os.path.join(EVID, scope, "active_program")
        stdir = os.path.join(EVID, scope, "st_files")
        if os.path.exists(ap):
            name = open(ap).read().strip()
            cand = os.path.join(stdir, name)
            if os.path.exists(cand):
                return cand
        # fallback: newest .st in the scope's st_files
        if os.path.isdir(stdir):
            sts = [os.path.join(stdir, x) for x in os.listdir(stdir)
                   if x.endswith(".st")]
            if sts:
                return max(sts, key=os.path.getmtime)
        return os.path.join(stdir, "MISSING.st")

    diff_onplc = unified(active_file_content("baseline"),
                         active_file_content("acquisition"),
                         "baseline/active_program", "acquired/active_program")
    with open(os.path.join(OUT, "program_diff_onplc.txt"), "w") as f:
        f.write(diff_onplc)

    # --- hash comparison baseline vs acquired ---
    bh = load_hashes(os.path.join(EVID, "baseline", "hashes.sha256"))
    ah = load_hashes(os.path.join(EVID, "acquisition", "hashes.sha256"))
    changed, added, removed = [], [], []
    for k, v in ah.items():
        if k in bh and bh[k] != v:
            changed.append(k)
        elif k not in bh:
            added.append(k)
    for k in bh:
        if k not in ah:
            removed.append(k)

    # --- docker diff summary ---
    counts, highlights = summarize_docker_diff(
        os.path.join(EVID, "acquisition", "docker_diff_plc.txt"))

    md = ["# PLC / Host Forensics Summary", "",
          f"Generated {datetime.now(timezone.utc).isoformat()}", "",
          "## Programs in the acquired OpenPLC database", "",
          "| Prog_ID | Name | Description | File | Uploaded (UTC) |",
          "|---|---|---|---|---|"]
    for p in acq["programs"]:
        md.append(f"| {p['prog_id']} | {p['name']} | {p['description'][:50]} "
                  f"| {p['file']} | {p['date_upload_utc']} |")
    md += ["", "The tampered program typically appears here under an innocent "
           "name (e.g. *Maintenance update v1.2*) with the latest upload time.",
           "", "## Baseline vs acquired program (on-PLC forensic diff)", "",
           "See `program_diff_onplc.txt`. Clean authoring diff (legit vs "
           "malicious logic) in `program_diff_authoring.txt`:", "",
           "```diff", diff_auth.strip() or "(no differences found)", "```", "",
           "## Hash comparison (baseline vs acquired)", "",
           f"- changed files: {len(changed)} -> {', '.join(changed) or 'none'}",
           f"- new files: {len(added)} -> {', '.join(added) or 'none'}",
           f"- removed files: {len(removed)} -> {', '.join(removed) or 'none'}",
           "", "## docker diff (PLC container)", "",
           f"- Changed: {counts.get('C',0)}  Added: {counts.get('A',0)}  "
           f"Deleted: {counts.get('D',0)}", "",
           "Relevant changed paths:", "", "```"]
    md += highlights[:40] or ["(none captured)"]
    md += ["```"]
    with open(os.path.join(OUT, "plc_summary.md"), "w") as f:
        f.write("\n".join(md))

    print(f"[*] programs in acquired DB: {len(acq['programs'])}")
    print(f"[*] hash changes: {len(changed)} changed, {len(added)} added")
    print(f"[*] wrote plc_*.csv, program_diff_*.txt, plc_summary.md to {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
