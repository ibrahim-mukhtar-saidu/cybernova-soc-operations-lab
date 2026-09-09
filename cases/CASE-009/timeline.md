# CASE-009 — Investigation Timeline

## Evidence Timeline

All timestamps are represented in UTC and originate from the synthetic CASE-009 telemetry fixture.

| Timestamp (UTC) | Event ID | Host | User | Activity | Assessment |
|---|---|---|---|---|---|
| 2026-09-09 13:00:00 | `EVT-009001` | `lab-linux-02` | `analyst` | `bash` executed a shell pipeline retrieving a payload and redirecting it into `/etc/cron.d/system-update` | Suspicious; generated `ALERT-CASE-009-DET-LINUX-001` |
| 2026-09-09 13:01:00 | `EVT-009002` | `lab-linux-02` | `admin` | `crontab -e` used against `/var/spool/cron/crontabs/admin` | Legitimate administrative activity; did not trigger the detection |

## Detection Point

At `2026-09-09 13:00:00 UTC`, `EVT-009001` satisfied the minimum two-indicator threshold for `DET-LINUX-001`.

Observed indicators:

1. `cron_persistence_path`
2. `shell_download_execution`
3. `hidden_or_tmp_payload`

The detection generated:

- Alert ID: `ALERT-CASE-009-DET-LINUX-001`
- Severity: High
- Confidence: High
- Supporting event: `EVT-009001`

## Benign Comparison

`EVT-009002` occurred one minute later and represents a useful benign comparison.

Although it references a cron persistence location and uses `crontab -e`, it did not satisfy the suspicious-indicator threshold and therefore produced no alert.

This comparison provides evidence that ordinary interactive cron administration is not automatically classified as suspicious by the current detection logic.

## Evidence Boundary

The timeline establishes what was observed in the supplied laboratory telemetry.

It does not establish:

- successful persistence,
- successful payload execution,
- malware classification,
- compromise,
- attacker identity,
- persistence duration,
- or real-world impact.

Those conclusions would require additional host, process, file, and network evidence.
