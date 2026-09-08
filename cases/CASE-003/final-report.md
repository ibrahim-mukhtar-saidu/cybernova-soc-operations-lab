# CASE-003 Final Report

## Executive Summary

CASE-003 demonstrates detection and triage of suspicious PowerShell execution in synthetic endpoint telemetry.

The detection generated two high-severity alerts involving PowerShell launched by `winword.exe` with encoded-command indicators.

The second event additionally contained hidden-window execution, correlated outbound HTTPS activity, and a correlated child `cmd.exe` process.

## Findings

### Finding 1 — Suspicious PowerShell Execution

**Status:** Confirmed in synthetic telemetry.

EVT-003006 and EVT-003007 satisfy the DET-ENDPOINT-001 detection logic.

### Finding 2 — Correlated Network Activity

**Status:** Observed.

EVT-003008 correlates with PowerShell PID `4638`.

The destination is a documentation/test address and does not establish malicious infrastructure.

### Finding 3 — Correlated Child Process

**Status:** Observed.

EVT-003009 identifies `cmd.exe` PID `4671` as a child of PowerShell PID `4638`.

## Detection Results

- Telemetry events: 10
- Alerts generated: 2
- High-severity alerts: 2
- EVT-003006 risk score: 100
- EVT-003007 risk score: 100
- Correlated network event: EVT-003008
- Correlated child event: EVT-003009
- Benign baseline events: 5

## Determination

**Suspicious endpoint activity is confirmed in the synthetic dataset. Compromise is not confirmed.**

The available evidence does not independently establish:

- Successful malware execution
- Persistence
- Credential theft
- Privilege escalation
- Data exfiltration
- Real-world command-and-control
- Real-world attribution

## Recommended Next Steps

1. Validate authorization for the execution.
2. Identify the originating Word document.
3. Safely decode the PowerShell commands.
4. Review full process and network telemetry.
5. Search for related execution patterns across the environment.
6. Escalate or contain only if additional evidence confirms unauthorized activity.

## Scope

This report documents a controlled cybersecurity laboratory exercise using synthetic telemetry.

No production systems were investigated or remediated.
