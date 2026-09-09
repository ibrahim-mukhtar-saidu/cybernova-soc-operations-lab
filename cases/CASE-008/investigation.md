# CASE-008 — Investigation

## Case Summary

CASE-008 documents a synthetic SOC laboratory investigation into suspicious process execution on `lab-ws-02`.

The detection engine generated:

- Alert ID: `ALERT-CASE-008-DET-MALWARE-001`
- Detection: `DET-MALWARE-001`
- Severity: High
- Confidence: High
- Host: `lab-ws-02`
- User: `analyst`
- Process: `invoice_viewer.exe`
- File: `/tmp/invoice_viewer.exe`

## Initial Triage

The alert was generated because `EVT-008001` contained five independent suspicious execution indicators:

- executable from a user-writable path
- suspicious executable extension
- known malware indicator
- high-entropy executable
- suspicious process name

The combination warrants malware-focused investigation and evidence preservation.

The detection does **not** independently establish that the executable is malicious. A malware verdict requires additional analysis, such as file hashing, static analysis, YARA analysis, sandboxing, or trusted threat-intelligence correlation.

## Evidence Review

### EVT-008001

`invoice_viewer.exe` executed successfully from `/tmp/`.

The telemetry associated the execution with:

- `malware_indicator: true`
- `high_entropy: true`
- `suspicious_name: true`

This event is the direct supporting evidence for the alert.

### EVT-008002

`backup_agent.exe` executed successfully from `/opt/backup/`.

Its malware-related metadata was negative:

- `malware_indicator: false`
- `high_entropy: false`
- `suspicious_name: false`

No alert was generated for this event.

## Investigation Assessment

The available telemetry supports treating `EVT-008001` as suspicious and worthy of containment-oriented investigation.

However, the current evidence does not prove:

- malware family
- persistence
- command-and-control activity
- privilege escalation
- data theft
- successful compromise
- malicious user intent

Those conclusions require additional evidence.

## Recommended Investigation Pivots

1. Calculate SHA-256 for `/tmp/invoice_viewer.exe`.
2. Preserve the executable and relevant metadata.
3. Perform static analysis in the isolated malware-analysis laboratory.
4. Run YARA analysis using approved laboratory rules.
5. Review file entropy and PE/ELF characteristics as applicable.
6. Search for the file hash across available laboratory telemetry.
7. Review process ancestry and parent process information if available.
8. Review network activity associated with the process.
9. Check for persistence mechanisms.
10. Correlate execution time with authentication and endpoint events.

## Containment Consideration

If this were a real incident, the endpoint could require isolation while evidence preservation and analysis are performed.

For this laboratory case, containment is documented as a simulated response action only.

## Confidence Boundary

The alert has high detection confidence because multiple configured indicators were observed.

High detection confidence must not be interpreted as proof that the file is malware. Detection confidence describes confidence in the detection logic, not a confirmed malware verdict.

## Laboratory Limitation

This case uses synthetic telemetry and does not represent a production incident, confirmed compromise, or real malware sample.
