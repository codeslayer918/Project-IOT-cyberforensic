#!/usr/bin/env python3
"""
openplc_web.py -- minimal OpenPLC v3 web-UI automation (Python standard library
only, so it runs unchanged on the WSL host and inside the attacker container).

Implements the exact flow verified from the OpenPLC_v3 webserver source:
  POST /login                 (form: username, password)
  POST /upload-program        (multipart: file=<.st>)  -> server renames to N.st,
                               returns a page with hidden input name='prog_file'
  POST /upload-program-action (form: prog_name, prog_descr, prog_file, epoch_time)
  GET  /compile-program?file=N.st
  GET  /compilation-logs      (poll until 'Compilation finished successfully!')
  GET  /start_plc  /  /stop_plc

Used for BOTH the legitimate configuration (run from the host = engineering
workstation) and the attacker's logic-tampering upload (run inside the attacker
container). The caller decides the name/description shown in the OpenPLC UI.
"""
import argparse
import http.cookiejar
import os
import re
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone


def ts():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def log(msg):
    print(f"[{ts()}] [openplc_web] {msg}", flush=True)


class OpenPLC:
    def __init__(self, base, timeout=15):
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.cj = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cj)
        )
        self.opener.addheaders = [("User-Agent", "openplc-web-client/1.0")]

    def _get(self, path):
        with self.opener.open(self.base + path, timeout=self.timeout) as r:
            return r.read().decode("utf-8", "replace")

    def _post_form(self, path, fields):
        data = urllib.parse.urlencode(fields).encode()
        req = urllib.request.Request(
            self.base + path, data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        with self.opener.open(req, timeout=self.timeout) as r:
            return r.read().decode("utf-8", "replace")

    def _post_multipart(self, path, filefield, filename, filebytes):
        boundary = "----openplcboundary%d" % int(time.time() * 1000)
        parts = []
        parts.append("--" + boundary)
        parts.append(
            f'Content-Disposition: form-data; name="{filefield}"; filename="{filename}"'
        )
        parts.append("Content-Type: application/octet-stream")
        parts.append("")
        body = ("\r\n".join(parts)).encode() + b"\r\n" + filebytes + b"\r\n"
        body += ("--" + boundary + "--\r\n").encode()
        req = urllib.request.Request(
            self.base + path, data=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        )
        with self.opener.open(req, timeout=self.timeout) as r:
            return r.read().decode("utf-8", "replace")

    # --- high-level actions ----------------------------------------------
    def wait_up(self, retries=60, delay=2):
        for i in range(retries):
            try:
                self._get("/login")
                log("web UI is reachable")
                return True
            except Exception as e:  # noqa: BLE001
                if i % 5 == 0:
                    log(f"waiting for web UI... ({e})")
                time.sleep(delay)
        return False

    def login(self, user, password):
        html = self._post_form("/login", {"username": user, "password": password})
        # bad credentials re-render the login page; success redirects to /dashboard
        probe = self._get("/programs")
        if "Upload Program" in probe or "Programs" in probe and "login" not in probe.lower()[:200]:
            log(f"login OK as '{user}'")
            return True
        if "password" in html.lower() and "username" in html.lower():
            log("login FAILED (bad credentials?)")
            return False
        log(f"login OK as '{user}'")
        return True

    def upload_and_compile(self, st_path, name, descr, compile_timeout=180):
        with open(st_path, "rb") as f:
            st_bytes = f.read()
        base_fn = os.path.basename(st_path)
        log(f"uploading '{base_fn}' as program name='{name}'")
        resp = self._post_multipart("/upload-program", "file", base_fn, st_bytes)
        m = re.search(r"name=['\"]prog_file['\"]\s+value=['\"]([^'\"]+\.st)['\"]", resp)
        if not m:
            m = re.search(r"value=['\"]([0-9]+\.st)['\"]", resp)
        if not m:
            log("ERROR: could not find server-assigned prog_file in upload response")
            return None
        prog_file = m.group(1)
        log(f"server stored program as '{prog_file}'")

        self._post_form(
            "/upload-program-action",
            {
                "prog_name": name,
                "prog_descr": descr,
                "prog_file": prog_file,
                "epoch_time": str(int(time.time())),
            },
        )
        log("program metadata saved; triggering compilation")
        self._get("/compile-program?file=" + urllib.parse.quote(prog_file))

        deadline = time.time() + compile_timeout
        last = ""
        while time.time() < deadline:
            logs = self._get("/compilation-logs")
            last = logs
            if "Compilation finished successfully!" in logs:
                log("compilation finished successfully")
                return prog_file
            if "Compilation finished with errors!" in logs:
                log("ERROR: compilation finished WITH ERRORS:")
                print(logs, file=sys.stderr)
                return None
            time.sleep(2)
        log("ERROR: compilation timed out")
        print(last, file=sys.stderr)
        return None

    def start(self):
        self._get("/start_plc")
        log("runtime START requested (Modbus server enabled on 502)")

    def stop(self):
        self._get("/stop_plc")
        log("runtime STOP requested")


def main():
    ap = argparse.ArgumentParser(description="OpenPLC v3 web automation")
    ap.add_argument("--base", default=os.environ.get("PLC_WEB", "http://127.0.0.1:8080"))
    ap.add_argument("--user", default="openplc")
    ap.add_argument("--password", default="openplc")
    ap.add_argument("--upload", help="path to .st program to upload+compile")
    ap.add_argument("--name", default="Program")
    ap.add_argument("--descr", default="")
    ap.add_argument("--start", action="store_true")
    ap.add_argument("--stop", action="store_true")
    ap.add_argument("--wait", action="store_true", help="wait for the web UI first")
    args = ap.parse_args()

    plc = OpenPLC(args.base)
    if args.wait and not plc.wait_up():
        log("ERROR: web UI never came up")
        return 2
    if not plc.login(args.user, args.password):
        return 3
    if args.stop:
        plc.stop()
    if args.upload:
        pf = plc.upload_and_compile(args.upload, args.name, args.descr)
        if pf is None:
            return 4
    if args.start:
        plc.start()
    log("done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
