FROM python:3.12-slim

ENV TZ=UTC \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# pymodbus 3.6.9: stable sync client API (read_holding_registers(address, count=, slave=))
RUN pip install --no-cache-dir pymodbus==3.6.9

WORKDIR /app
COPY hmi.py /app/hmi.py

# /app is bind-mounted in compose so the historian CSV is visible on the host.
CMD ["python3", "/app/hmi.py"]
