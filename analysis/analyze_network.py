#!/usr/bin/env python3
"""
analyze_network.py -- forensic analysis of the captured network traffic.

From the pcap it extracts:
  * every Modbus/TCP transaction (time, src, dst, function code, address, value)
    and FLAGS write function codes (5,6,15,16) coming from any IP other than the
    HMI -- i.e. unauthorized control writes.
  * HTTP requests to the OpenPLC web UI (logins, program uploads, compile, start).
  * the attacker's nmap host sweep / port probe.

Outputs CSVs + a markdown summary under evidence/analysis/, and prints the exact
Wireshark display filters to reproduce each finding by hand (for screenshots).
"""
import argparse
import os
import sys
from datetime import datetime, timezone

from tshark_util import run_tshark, tshark_available

# --- lab topology ---
HMI_IP      = os.environ.get("HMI_IP", "172.28.0.20")
ATTACKER_IP = os.environ.get("ATTACKER_IP", "172.28.0.66")
PLC_IP      = os.environ.get("PLC_IP", "172.28.0.10")
GATEWAY_IP  = os.environ.get("GATEWAY_IP", "172.28.0.1")

FUNC = {
    "1": "ReadCoils", "2": "ReadDiscreteInputs", "3": "ReadHoldingRegisters",
    "4": "ReadInputRegisters", "5": "WriteSingleCoil", "6": "WriteSingleRegister",
    "15": "WriteMultipleCoils", "16": "WriteMultipleRegisters",
}
WRITE_FUNCS = {"5", "6", "15", "16"}


def iec_for(func, addr):
    """Map a Modbus function+address to the OpenPLC IEC located variable."""
    try:
        a = int(addr)
    except (TypeError, ValueError):
        return ""
    if func in ("1", "5", "15"):
        return f"%QX{a // 8}.{a % 8}"       # coils
    if func == "2":
        return f"%IX{a // 8}.{a % 8}"       # discrete inputs
    if func == "4":
        return f"%IW{a}"                    # input registers
    if func in ("3", "6", "16"):
        if a < 1024:
            return f"%QW{a}"
        if a < 2048:
            return f"%MW{a - 1024}"
    return ""


def iso(epoch):
    try:
        return datetime.fromtimestamp(float(epoch), timezone.utc)\
            .strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    except (TypeError, ValueError):
        return epoch


def extract_modbus(pcap):
    fields = ["frame.time_epoch", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport",
              "mbtcp.trans_id", "modbus.func_code", "modbus.reference_num",
              "modbus.regval_uint16", "modbus.bitval", "modbus.word_cnt",
              "modbus.bit_cnt"]
    args = ["-Y", "mbtcp", "-T", "fields", "-E", "separator=\t"]
    for f in fields:
        args += ["-e", f]
    out = run_tshark(pcap, args)
    rows = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) < len(fields):
            parts += [""] * (len(fields) - len(parts))
        (t, src, dst, sp, dp, tid, fc, ref, regv, bitv, wc, bc) = parts[:12]
        if not fc:
            continue
        # a func_code appears in both request and response; keep requests
        # (to the PLC on port 502) so addresses/values are meaningful
        fc = fc.split(",")[0]
        value = regv or bitv
        rows.append({
            "utc_time": iso(t), "src": src, "dst": dst,
            "func_code": fc, "func_name": FUNC.get(fc, "?"),
            "address": ref, "iec": iec_for(fc, ref), "value": value,
            "is_write": fc in WRITE_FUNCS,
            "unauthorized": (fc in WRITE_FUNCS and src and src != HMI_IP
                             and dst == PLC_IP),
        })
    return rows


def extract_http(pcap):
    fields = ["frame.time_epoch", "ip.src", "ip.dst",
              "http.request.method", "http.request.uri", "http.host"]
    args = ["-Y", "http.request", "-T", "fields", "-E", "separator=\t"]
    for f in fields:
        args += ["-e", f]
    out = run_tshark(pcap, args)
    rows = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) < len(fields):
            parts += [""] * (len(fields) - len(parts))
        t, src, dst, method, uri, host = parts[:6]
        if not method:
            continue
        kind = "other"
        u = uri.lower()
        if "/login" in u:
            kind = "login"
        elif "/upload-program-action" in u:
            kind = "upload-metadata"
        elif "/upload-program" in u:
            kind = "program-upload"
        elif "/compile-program" in u:
            kind = "compile"
        elif "/start_plc" in u:
            kind = "runtime-start"
        elif "/stop_plc" in u:
            kind = "runtime-stop"
        rows.append({"utc_time": iso(t), "src": src, "dst": dst,
                     "method": method, "uri": uri, "kind": kind})
    return rows


def detect_scan(pcap):
    by_src = {}
    first = {}

    def slot(src):
        by_src.setdefault(src, {"tcp_dsts": set(), "ports": set(), "syns": 0,
                                "arp_targets": set()})
        return by_src[src]

    # (1) TCP SYN scans (port scan / multi-host TCP connect)
    out = run_tshark(pcap, ["-Y", "tcp.flags.syn==1 && tcp.flags.ack==0",
                            "-T", "fields", "-E", "separator=\t",
                            "-e", "frame.time_epoch", "-e", "ip.src",
                            "-e", "ip.dst", "-e", "tcp.dstport"])
    for line in out.splitlines():
        p = line.split("\t")
        if len(p) < 4 or not p[1]:
            continue
        t, src, dst, dport = p[:4]
        s = slot(src)
        s["tcp_dsts"].add(dst)
        s["ports"].add(dport)
        s["syns"] += 1
        first.setdefault(src, t)

    # (2) ARP sweeps (nmap -sn on a local subnet uses ARP, not TCP)
    out2 = run_tshark(pcap, ["-Y", "arp.opcode==1", "-T", "fields",
                             "-E", "separator=\t", "-e", "frame.time_epoch",
                             "-e", "arp.src.proto_ipv4", "-e", "arp.dst.proto_ipv4"])
    for line in out2.splitlines():
        p = line.split("\t")
        if len(p) < 3 or not p[1]:
            continue
        t, src, tgt = p[:3]
        s = slot(src)
        s["arp_targets"].add(tgt)
        first.setdefault(src, t)

    findings = []
    for src, d in by_src.items():
        # a scan sweeps many distinct hosts (ARP or TCP) or probes many ports.
        # raw SYN count alone is NOT used: a chatty legit client (e.g. the web
        # config opening many short-lived connections) would false-trigger.
        host_sweep = len(d["arp_targets"]) >= 10 or len(d["tcp_dsts"]) >= 5
        port_scan = len(d["ports"]) >= 10
        if host_sweep or port_scan:
            findings.append({
                "src": src, "first_seen": iso(first.get(src)),
                "distinct_hosts": max(len(d["tcp_dsts"]), len(d["arp_targets"])),
                "distinct_ports": len(d["ports"]),
                "syn_packets": d["syns"],
                "note": ("ARP host sweep " if len(d["arp_targets"]) >= 10 else "")
                        + ("TCP port scan " if port_scan else "")
                        + ("(nmap-like)" if src == ATTACKER_IP else "[unexpected src]"),
            })
    return findings


def write_csv(path, rows, cols):
    import csv
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in cols})


DISPLAY_FILTERS = f"""## Wireshark display filters (reproduce each finding for screenshots)

| Finding | Display filter |
|---|---|
| All Modbus traffic | `mbtcp` |
| Unauthorized Modbus WRITES (not from HMI) | `mbtcp && modbus.func_code in {{5 6 15 16}} && ip.src != {HMI_IP}` |
| Force pump coil (FC5) | `modbus.func_code == 5` |
| Raise setpoint / force manual (FC6/FC16) | `modbus.func_code == 6 || modbus.func_code == 16` |
| Attacker -> PLC only | `ip.addr == {ATTACKER_IP} && ip.addr == {PLC_IP}` |
| OpenPLC web logins | `http.request.uri contains "/login"` |
| Malicious program upload | `http.request.uri contains "upload-program"` |
| Compile / start runtime | `http.request.uri contains "compile-program" || http.request.uri contains "start_plc"` |
| nmap SYN sweep from attacker | `tcp.flags.syn==1 && tcp.flags.ack==0 && ip.src == {ATTACKER_IP}` |
| Modbus discovery probe (port 502) | `tcp.port == 502 && tcp.flags.syn==1` |
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap")
    ap.add_argument("--outdir")
    args = ap.parse_args()

    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    pcap = args.pcap
    if not pcap:
        for cand in ("evidence/acquisition/ics_capture.pcap",
                     "evidence/pcap/ics_capture.pcap"):
            if os.path.exists(os.path.join(root, cand)):
                pcap = os.path.join(root, cand)
                break
    if not pcap or not os.path.exists(pcap):
        print("ERROR: pcap not found; pass --pcap", file=sys.stderr)
        return 2
    if not tshark_available():
        print("ERROR: tshark not available locally or via the netshoot image.",
              file=sys.stderr)
        return 3

    outdir = args.outdir or os.path.join(root, "evidence", "analysis")
    os.makedirs(outdir, exist_ok=True)
    print(f"[*] analyzing {pcap}")

    modbus = extract_modbus(pcap)
    http = extract_http(pcap)
    scan = detect_scan(pcap)

    write_csv(os.path.join(outdir, "modbus_transactions.csv"), modbus,
              ["utc_time", "src", "dst", "func_code", "func_name", "address",
               "iec", "value", "is_write", "unauthorized"])
    unauth = [r for r in modbus if r["unauthorized"]]
    write_csv(os.path.join(outdir, "modbus_unauthorized_writes.csv"), unauth,
              ["utc_time", "src", "dst", "func_code", "func_name", "address",
               "iec", "value"])
    write_csv(os.path.join(outdir, "http_requests.csv"), http,
              ["utc_time", "src", "dst", "method", "uri", "kind"])
    write_csv(os.path.join(outdir, "scan_findings.csv"), scan,
              ["src", "first_seen", "distinct_hosts", "distinct_ports",
               "syn_packets", "note"])

    uploads = [r for r in http if r["kind"] in ("program-upload", "upload-metadata")]
    logins = [r for r in http if r["kind"] == "login"]

    md = [f"# Network Forensics Summary", "",
          f"Generated {datetime.now(timezone.utc).isoformat()}  ",
          f"Source pcap: `{os.path.relpath(pcap, root)}`", "",
          "## Key findings", "",
          f"- Total Modbus transactions parsed: **{len(modbus)}**",
          f"- **Unauthorized Modbus writes (not from HMI {HMI_IP}): {len(unauth)}**",
          f"- HTTP requests to OpenPLC web UI: **{len(http)}** "
          f"(logins: {len(logins)}, program uploads: {len(uploads)})",
          f"- Scan sources detected: **{len(scan)}**", ""]

    if unauth:
        md += ["## Unauthorized Modbus writes (smoking gun)", "",
               "| UTC time | src | func | address (IEC) | value |",
               "|---|---|---|---|---|"]
        for r in unauth[:50]:
            md.append(f"| {r['utc_time']} | {r['src']} | {r['func_code']} "
                      f"{r['func_name']} | {r['address']} ({r['iec']}) | {r['value']} |")
        md.append("")
    if uploads:
        md += ["## OpenPLC program uploads", "",
               "| UTC time | src | method | uri |", "|---|---|---|---|"]
        for r in uploads:
            md.append(f"| {r['utc_time']} | {r['src']} | {r['method']} | {r['uri']} |")
        md.append("")
    if scan:
        md += ["## Reconnaissance (scan)", "",
               "| src | first seen | hosts | ports | SYNs | note |",
               "|---|---|---|---|---|---|"]
        for r in scan:
            md.append(f"| {r['src']} | {r['first_seen']} | {r['distinct_hosts']} "
                      f"| {r['distinct_ports']} | {r['syn_packets']} | {r['note']} |")
        md.append("")
    md.append(DISPLAY_FILTERS)

    with open(os.path.join(outdir, "network_summary.md"), "w") as f:
        f.write("\n".join(md))

    print(f"[*] wrote CSVs + network_summary.md to {outdir}")
    print(f"[*] unauthorized writes: {len(unauth)} | uploads: {len(uploads)} | scans: {len(scan)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
