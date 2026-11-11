#!/usr/bin/env python3
"""
modbus_io.py -- shared Modbus/TCP helpers for the attacker scripts.
Register/coil map verified against OpenPLC_v3 core/modbus.cpp (see README).
pymodbus 3.6.9 sync client.
"""
import os
from datetime import datetime, timezone
from pymodbus.client import ModbusTcpClient

PLC_HOST = os.environ.get("PLC_HOST", "172.28.0.10")
PLC_PORT = int(os.environ.get("PLC_PORT", "502"))
UNIT = 1

# ---- Address map ----
COIL_PUMP, COIL_DRAIN, COIL_ALARM, COIL_OVERFLOW = 0, 1, 2, 3
HR_LEVEL_HMI  = 0       # %QW0
HR_SP_HIGH    = 1024    # %MW0
HR_SP_LOW     = 1025    # %MW1
HR_MANUAL     = 1026    # %MW2
HR_TRUE_LEVEL = 1034    # %MW10 (hidden true level)


def ts():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def log(msg):
    print(f"[{ts()}] {msg}", flush=True)


def connect():
    c = ModbusTcpClient(PLC_HOST, port=PLC_PORT, timeout=4)
    c.connect()
    return c


def snapshot(c):
    """Read everything (including the hidden true-level register)."""
    out = {}
    rc = c.read_coils(address=0, count=4, slave=UNIT)
    if not rc.isError():
        out["pump"]     = int(bool(rc.bits[0]))
        out["drain"]    = int(bool(rc.bits[1]))
        out["alarm"]    = int(bool(rc.bits[2]))
        out["overflow"] = int(bool(rc.bits[3]))
    r0 = c.read_holding_registers(address=0, count=2, slave=UNIT)
    if not r0.isError():
        out["level_hmi"] = r0.registers[0]
    rm = c.read_holding_registers(address=1024, count=11, slave=UNIT)
    if not rm.isError():
        out["sp_high"]    = rm.registers[0]       # HR1024 %MW0
        out["sp_low"]     = rm.registers[1]       # HR1025 %MW1
        out["manual"]     = rm.registers[2]       # HR1026 %MW2
        out["true_level"] = rm.registers[10]      # HR1034 %MW10
    return out
