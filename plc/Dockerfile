# OpenPLC Runtime v3, built from the official GitHub repo.
# We clone INSIDE the image (reliable container ext4) at a pinned commit instead
# of vendoring the 2800-file repo on the Windows drive, then run the project's
# own installer + the same persistent-volume setup as upstream's Dockerfile.
FROM debian:trixie-20251020

# Pin the exact OpenPLC_v3 commit for reproducibility (override with --build-arg).
ARG OPENPLC_REF=b5d41356dab4aeadca0dd7ca64ba542f870b595d

RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

# Full clone so an exact commit can be checked out, then pin + fetch submodules.
RUN git clone https://github.com/thiagoralves/OpenPLC_v3.git /workdir \
 && cd /workdir \
 && git checkout "${OPENPLC_REF}" \
 && (git submodule update --init --recursive || true)

WORKDIR /workdir

RUN mkdir /docker_persistent
VOLUME /docker_persistent

# --- identical to upstream OpenPLC_v3/Dockerfile: build + persistent setup -----
RUN ./install.sh docker \
    && touch /docker_persistent/mbconfig.cfg \
    && touch /docker_persistent/persistent.file \
    && mkdir /docker_persistent/st_files \
    && cp /workdir/webserver/openplc.db /docker_persistent/openplc.db \
    && mv /workdir/webserver/openplc.db /workdir/webserver/openplc_default.db \
    && cp /workdir/webserver/dnp3.cfg /docker_persistent/dnp3.cfg \
    && mv /workdir/webserver/dnp3.cfg /workdir/webserver/dnp3_default.cfg \
    && cp -r /workdir/webserver/st_files/ /docker_persistent/st_files/ \
    && mv /workdir/webserver/st_files /workdir/webserver/st_files_default \
    && cp /workdir/webserver/active_program /docker_persistent/active_program \
    && mv /workdir/webserver/active_program /workdir/webserver/active_program_default \
    && ln -s /docker_persistent/mbconfig.cfg /workdir/webserver/mbconfig.cfg \
    && ln -s /docker_persistent/persistent.file /workdir/webserver/persistent.file \
    && ln -s /docker_persistent/openplc.db /workdir/webserver/openplc.db \
    && ln -s /docker_persistent/dnp3.cfg /workdir/webserver/dnp3.cfg \
    && ln -s /docker_persistent/st_files /workdir/webserver/st_files \
    && ln -s /docker_persistent/active_program /workdir/webserver/active_program

# --- Fix: OpenPLC's web UI (Dashboard/Monitoring/Programs) asks the runtime for
# its status over an internal command socket (localhost:43628) on every page
# load, with NO socket timeout. If that socket is slow/wedged (which happens on
# this build after a few connections, e.g. the auto-refreshing Monitoring page),
# the Flask page blocks forever and the browser "hangs".
#  (1) add a 3s socket timeout in openplc.py::_rpc so a page never waits forever;
#  (2) when the command socket is unreachable, report "Running" if the runtime
#      process is still alive, so the Dashboard status stays correct.
# Self-validated with ast.parse + anchor asserts so the build fails loudly if
# upstream OpenPLC changes these lines.
RUN python3 - <<'PYEOF'
p = '/workdir/webserver/openplc.py'
s = open(p).read()

a1 = "            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
assert a1 in s, "anchor 1 (socket create) not found"
if "s.settimeout" not in s:
    s = s.replace(a1, a1 + "            s.settimeout(3)\n", 1)

a2 = ("        if not self._rpc('exec_time()', 10000):\n"
      "            self.runtime_status = \"Stopped\"\n")
assert a2 in s, "anchor 2 (status block) not found"
repl2 = ("        if not self._rpc('exec_time()', 10000):\n"
         "            try:\n"
         "                if getattr(self, 'theprocess', None) is not None and self.theprocess.poll() is None:\n"
         "                    return \"Running\"\n"
         "            except Exception:\n"
         "                pass\n"
         "            self.runtime_status = \"Stopped\"\n")
s = s.replace(a2, repl2, 1)

open(p, 'w').write(s)
import ast; ast.parse(open(p).read())
assert "s.settimeout(3)" in open(p).read()
assert "theprocess" in open(p).read()
print("openplc.py web-UI hardening patch OK (timeout + status fallback)")
PYEOF

EXPOSE 8080 502
ENTRYPOINT ["./start_openplc.sh"]
