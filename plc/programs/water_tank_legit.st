(*
  =====================================================================
   water_tank_legit.st   --  LEGITIMATE water-tank control
   IEC 61131-3 Structured Text, OpenPLC Runtime v3
  =====================================================================
   Simulated process (physics runs inside the PLC scan cycle):
     - Tank level 0..1000 (integer units).
     - Pump adds water (inflow) when ON; drain valve removes water (outflow).
     - Pump hysteresis: starts below LOW setpoint, stops above HIGH setpoint.
     - HIGH setpoint is configurable over Modbus (holding register %MW0).
     - Critical-level SAFETY cutoff forces the pump OFF above 950.
     - Alarm bit set above the critical level; overflow bit latched at 1000.

   Register / coil map (verified against OpenPLC_v3 core/modbus.cpp):
     Coils  (FC1 read / FC5,15 write):
       %QX0.0 coil0  Pump running
       %QX0.1 coil1  Drain valve open
       %QX0.2 coil2  HIGH-level alarm (shown to HMI)
       %QX0.3 coil3  Overflow latched (shown to HMI)
     Holding registers (FC3 read / FC6,16 write):
       %QW0  HR0     Level reported to the HMI
       %MW0  HR1024  HIGH setpoint (pump stop)      [operator/engineer writes]
       %MW1  HR1025  LOW setpoint  (pump start)     [operator/engineer writes]
       %MW2  HR1026  Manual pump command 0/1        [operator/engineer writes]
       %MW10 HR1034  TRUE tank level (ground truth) [PLC writes]
  =====================================================================
*)

PROGRAM prog0
  VAR
    (* ---- Process outputs (coils) ---- *)
    Pump       AT %QX0.0 : BOOL;
    Drain      AT %QX0.1 : BOOL;
    Alarm      AT %QX0.2 : BOOL;
    Overflow   AT %QX0.3 : BOOL;

    (* ---- HMI-visible analog value (holding register %QW0 / HR0) ---- *)
    LevelHMI   AT %QW0   : INT;

    (* ---- Setpoints & commands (%MW0..2 / HR1024..1026) ---- *)
    SpHigh     AT %MW0   : INT;
    SpLow      AT %MW1   : INT;
    ManualPump AT %MW2   : INT;

    (* ---- Ground-truth level (hidden register %MW10 / HR1034) ---- *)
    TrueLevel  AT %MW10  : INT;

  END_VAR

  VAR
    (* ---- Internal state (non-located; matiec needs a separate VAR block) ---- *)
    Initialized : BOOL := FALSE;
    PumpCmd     : BOOL := FALSE;
    Tick        : TON;              (* 1-second physics tick *)
    SpoofPhase  : INT  := 0;        (* used only by the tampered program *)
    SpoofDir    : INT  := 1;        (* kept here so both programs share layout *)
  END_VAR

  (* ----- one-time initialisation ----- *)
  IF NOT Initialized THEN
    IF SpHigh = 0 THEN SpHigh := 800; END_IF;
    IF SpLow  = 0 THEN SpLow  := 200; END_IF;
    TrueLevel   := 300;
    Initialized := TRUE;
  END_IF;

  (* ===== CONTROL : sense -> decide ===== *)
  (* pump hysteresis on the TRUE level *)
  IF TrueLevel <= SpLow  THEN PumpCmd := TRUE;  END_IF;
  IF TrueLevel >= SpHigh THEN PumpCmd := FALSE; END_IF;
  (* manual override forces the pump ON *)
  IF ManualPump >= 1 THEN PumpCmd := TRUE; END_IF;

  (* >>> SAFETY (critical-level cutoff): forces the pump OFF above 950 <<< *)
  IF TrueLevel >= 950 THEN PumpCmd := FALSE; END_IF;

  Pump  := PumpCmd;
  Drain := TRUE;                    (* drain continuously open -> steady outflow *)

  (* overflow latch (true state reported to the HMI) *)
  IF TrueLevel >= 1000 THEN Overflow := TRUE; END_IF;

  (* >>> REPORTING: tell the HMI the TRUTH <<< *)
  Alarm    := (TrueLevel >= 950);
  LevelHMI := TrueLevel;

  (* spoof phase is advanced in both programs (unused here) *)
  (* ===== PHYSICS : actuate -> integrate (~once per second) ===== *)
  Tick(IN := NOT Tick.Q, PT := T#1000ms);
  IF Tick.Q THEN
    IF Pump  THEN TrueLevel := TrueLevel + 12; END_IF;   (* inflow  *)
    IF Drain THEN TrueLevel := TrueLevel - 7;  END_IF;    (* outflow *)
    IF TrueLevel < 0    THEN TrueLevel := 0;    END_IF;
    IF TrueLevel > 1000 THEN TrueLevel := 1000; END_IF;

    (* advance the plausible-looking spoof oscillation (dead code in legit) *)
    SpoofPhase := SpoofPhase + (SpoofDir * 7);
    IF SpoofPhase >= 180 THEN SpoofDir := -1; END_IF;
    IF SpoofPhase <= 0   THEN SpoofDir :=  1; END_IF;
  END_IF;

END_PROGRAM

CONFIGURATION Config0
  RESOURCE Res0 ON PLC
    TASK Main(INTERVAL := T#50ms, PRIORITY := 0);
    PROGRAM Inst0 WITH Main : prog0;
  END_RESOURCE
END_CONFIGURATION
