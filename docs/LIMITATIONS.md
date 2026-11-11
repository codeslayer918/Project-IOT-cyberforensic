# Limitations of this lab vs a real ICS

This lab is a faithful *functional* model of an ICS attack and investigation, but
it is a simulation on a single host. The following limitations should be stated in
the discussion section of the report; several of them are the reason specific
forensic techniques used here would differ in the field.

## Platform / hardware
- **Soft-PLC, not real hardware.** OpenPLC runs as a Linux process in a container.
  A real PLC (Siemens, Allen-Bradley, Schneider…) has proprietary firmware, a
  real-time OS, dedicated I/O modules and vendor tooling. There is no firmware
  image, no proprietary memory layout, and no vendor forensic interface here.
- **No physical I/O.** The process physics is simulated inside the PLC scan cycle.
  There are no real sensors/actuators, no 4–20 mA loops, and the `%IW` input
  registers (physical inputs) are therefore unused. In a real plant the "true
  level" would come from an independent instrument, not a hidden PLC register.
- **No field-bus diversity.** Only Modbus/TCP and HTTP are exercised. Real sites
  also run PROFINET, EtherNet/IP, DNP3, OPC-UA, serial Modbus/RTU, etc.

## Acquisition realism
- **Container-based acquisition.** We acquire with `docker cp`, `docker diff`,
  `docker export` and live Modbus reads. On real hardware you would use PLC memory
  dumps, program uploads via engineering software (e.g. TIA Portal), firmware
  extraction (JTAG/chip-off), and vendor logs — none of which exist for a soft-PLC.
- **Ground-truth feed is artificial.** To produce the "operator view vs reality"
  figure we run a parallel ground-truth probe that reads the hidden `%MW10`
  register every second. A real investigation would **not** have this continuous
  true-state log — only the single live-acquisition snapshot of the hidden
  register plus whatever the historian recorded. The time-series gap shown here is
  a teaching aid, not something normally available post-incident.
- **The attacker reads/writes without authentication** because Modbus has none;
  this is realistic, but the lab does not model network ACLs, firewalls, data
  diodes or an IDS that a mature site might have.

## Time & scale
- **Single host clock.** Every container shares the host clock (UTC), so there are
  no clock-skew or time-synchronisation problems between evidence sources. In the
  field, correlating timestamps across PLCs, HMIs, historians and network taps
  (often with drifting or differently-zoned clocks) is a real challenge.
- **Compressed, scripted timeline.** The whole attack runs in minutes with scripted
  pauses. Real intrusions unfold over days/weeks with dwell time and noise.
- **Tiny, clean network.** Four hosts on an isolated /24 with almost no background
  traffic make the malicious packets trivial to find. Real captures are far larger
  and noisier.

## Scope
- **No malware persistence / lateral movement / C2.** The "logic tampering" is a
  direct program upload with default credentials; there is no dropper, no
  persistence mechanism, no exfiltration channel and no pivot from IT to OT.
- **No safety instrumented system (SIS).** A real critical process has an
  independent hard-wired safety layer that the PLC cannot override; here the only
  safety is software on the same PLC, which is exactly why the tampering is so
  effective.
- **Credentials/defaults are intentionally weak** to keep the lab runnable in a day.

Despite these limitations, the lab correctly demonstrates the *forensic process*:
order-of-volatility acquisition, hashing and chain of custody, network/Modbus
analysis, PLC program diffing, historian reconstruction, and building a unified,
timestamped incident timeline.
