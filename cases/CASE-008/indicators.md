# CASE-008 — Indicators

## Confirmed Laboratory Indicators

| Indicator | Value | Source | Assessment |
|---|---|---|---|
| Event ID | `EVT-008001` | Telemetry | Supporting event |
| Host | `lab-ws-02` | Telemetry | Affected laboratory host |
| User | `analyst` | Telemetry | Execution context |
| Process | `invoice_viewer.exe` | Telemetry | Suspicious process |
| File path | `/tmp/invoice_viewer.exe` | Telemetry | User-writable execution path |
| File extension | `.exe` | Telemetry | Suspicious execution indicator |
| Malware indicator | `true` | Telemetry metadata | Detection indicator |
| High entropy | `true` | Telemetry metadata | Detection indicator |
| Suspicious name | `true` | Telemetry metadata | Detection indicator |
| Command line | `/tmp/invoice_viewer.exe --open invoice.pdf` | Telemetry | Execution context |

## Detection Indicators

The detection engine identified five indicators for `EVT-008001`:

1. `executable_from_user_writable_path`
2. `suspicious_file_extension`
3. `known_malware_indicator`
4. `high_entropy_executable`
5. `suspicious_process_name`

## Comparison Event

`EVT-008002` executed `/opt/backup/backup_agent.exe` with negative malware-related metadata and did not trigger the detection.

## Indicator Boundary

These indicators are suspicious execution signals, not confirmed malware verdicts.

No malware family, cryptographic hash, network indicator, persistence mechanism, or confirmed compromise indicator is asserted by the current telemetry.

## Recommended Additional Indicators

Further investigation could produce:

- SHA-256 file hash
- file type and format
- signer information
- parent process
- child processes
- network destinations
- DNS queries
- persistence artifacts
- YARA matches
- sandbox observations

These are investigation pivots and are not currently observed CASE-008 evidence.
