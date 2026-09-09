# CASE-005 — Investigation Timeline

## Timeline Summary

This timeline reconstructs the relevant network and process activity from the synthetic CASE-005 telemetry.

All timestamps are UTC.

| Timestamp | Event ID | Event Type | Host / Process | Destination | Assessment |
|---|---|---|---|---|---|
| 2026-09-08 11:10:10Z | EVT-005007 | network_connection | lab-ws-01 / svchost_update.exe | 198.51.100.77:8443 | First observed suspicious outbound connection |
| 2026-09-08 11:11:10Z | EVT-005008 | network_connection | lab-ws-01 / svchost_update.exe | 198.51.100.77:8443 | Repeated connection; 60-second interval |
| 2026-09-08 11:12:10Z | EVT-005009 | network_connection | lab-ws-01 / svchost_update.exe | 198.51.100.77:8443 | Repeated connection; 60-second interval |
| 2026-09-08 11:13:10Z | EVT-005010 | network_connection | lab-ws-01 / svchost_update.exe | 198.51.100.77:8443 | Repeated connection; 60-second interval |
| 2026-09-08 11:14:10Z | EVT-005011 | network_connection | lab-ws-01 / svchost_update.exe | 198.51.100.77:8443 | Repeated connection; 60-second interval |
| 2026-09-08 11:15:10Z | EVT-005012 | network_connection | lab-ws-01 / svchost_update.exe | 198.51.100.77:8443 | Repeated connection; 60-second interval |
| 2026-09-08 11:15:20Z | EVT-005013 | process_network_correlation | lab-ws-01 / svchost_update.exe | 198.51.100.77:8443 | Correlation confirms suspicious process/network relationship |
| 2026-09-08 11:16:10Z | EVT-005014 | network_connection | lab-ws-01 / svchost_update.exe | 198.51.100.77:8443 | Seventh repeated connection; alert generated |
| 2026-09-08 11:16:10Z | ALERT-CASE-005-DET-NET-001 | detection_alert | lab-ws-01 / svchost_update.exe | 198.51.100.77:8443 | High-severity, high-confidence alert; risk score 100 |

## Supporting Process Evidence

| Timestamp | Event ID | Event Type | Process | Path | Assessment |
|---|---|---|---|---|---|
| 2026-09-08 11:09:50Z | EVT-005006 | process_start | svchost_update.exe | C:\Users\Public\svchost_update.exe | Unsigned process executing from a user-writable path |

EVT-005006 predates the first network connection and provides process context for the subsequent network activity. It is supporting investigation evidence rather than a supporting event explicitly listed in the generated alert.

## Baseline and Negative Evidence

| Event IDs | Activity | Assessment |
|---|---|---|
| EVT-005001–EVT-005005 | Chrome HTTPS traffic to 93.184.216.34:443 | Benign browser baseline; no alert generated |
| EVT-005015 | windows_update.exe to 203.0.113.80:443 | Expected update traffic; signed process and no alert generated |

These events demonstrate that the detection scenario contains both suspicious and benign network activity.

## Correlation Analysis

The suspicious network sequence from EVT-005007 through EVT-005014 contains seven network connections.

The intervals between the seven network connections are consistently 60 seconds:

- EVT-005007 → EVT-005008: 60 seconds
- EVT-005008 → EVT-005009: 60 seconds
- EVT-005009 → EVT-005010: 60 seconds
- EVT-005010 → EVT-005011: 60 seconds
- EVT-005011 → EVT-005012: 60 seconds
- EVT-005012 → EVT-005014: 60 seconds

The resulting regularity ratio is 1.0 (100%).

EVT-005013 occurs 10 seconds before the final network connection and provides process/network correlation evidence.

## Detection Point

The seventh connection, EVT-005014 at 11:16:10Z, completes the repeated connection pattern used by DET-NET-001.

The detection engine generated:

- Alert ID: ALERT-CASE-005-DET-NET-001
- Severity: high
- Confidence: high
- Risk score: 100

## Timeline Conclusion

The available telemetry shows a progression from suspicious process execution to repeated, highly regular outbound network communication and process/network correlation.

The timeline supports the assessment that the activity is consistent with automated beaconing behavior.

The timeline does not independently establish successful remote command execution, data exfiltration, persistence, host compromise, or attribution to a real-world threat actor.
