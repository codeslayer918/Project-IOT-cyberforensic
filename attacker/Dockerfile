FROM python:3.12-slim

ENV TZ=UTC \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# Attacker toolkit: nmap (+ NSE modbus-discover), curl, ping, ip tooling.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        nmap curl iproute2 iputils-ping ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# pymodbus for crafted Modbus writes; requests for the OpenPLC web UI attack.
RUN pip install --no-cache-dir pymodbus==3.6.9 requests==2.32.3

WORKDIR /app
# /app is bind-mounted in compose (attack scripts). Idle until driven by docker exec.
CMD ["sleep", "infinity"]
