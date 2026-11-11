#!/usr/bin/env python3
"""
tshark_util -- run tshark whether or not it is installed in WSL.

Preference order:
  1. a local `tshark` on PATH
  2. tshark inside the nicolaka/netshoot container (same image as the sniffer)
Returns decoded stdout text. The pcap directory is bind-mounted into the
container for the fallback path.
"""
import os
import shutil
import subprocess

NETSHOOT = "nicolaka/netshoot:latest"


def have_local_tshark():
    return shutil.which("tshark") is not None


def run_tshark(pcap_path, args):
    """args: list of tshark arguments AFTER '-r <pcap>'."""
    pcap_path = os.path.abspath(pcap_path)
    if have_local_tshark():
        cmd = ["tshark", "-r", pcap_path] + args
        return subprocess.run(cmd, capture_output=True, text=True).stdout

    # fallback: run tshark in a container, bind-mounting the pcap's directory
    d = os.path.dirname(pcap_path)
    f = os.path.basename(pcap_path)
    cmd = [
        "docker", "run", "--rm", "-v", f"{d}:/caps:ro",
        "--entrypoint", "tshark", NETSHOOT,
        "-r", f"/caps/{f}",
    ] + args
    return subprocess.run(cmd, capture_output=True, text=True).stdout


def tshark_available():
    if have_local_tshark():
        return True
    # is the netshoot image present?
    out = subprocess.run(["docker", "images", "-q", NETSHOOT],
                         capture_output=True, text=True).stdout.strip()
    return bool(out)
