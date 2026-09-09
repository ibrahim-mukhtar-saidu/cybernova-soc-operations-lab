# CASE-008 — Timeline

| Time (UTC) | Event ID | Event | Host | User | Assessment |
|---|---|---|---|---|---|
| 2026-09-09 12:00:00 | EVT-008001 | `invoice_viewer.exe` executed successfully from `/tmp/` | lab-ws-02 | analyst | Suspicious; five configured indicators |
| 2026-09-09 12:01:00 | EVT-008002 | `backup_agent.exe` executed successfully from `/opt/backup/` | lab-ws-02 | analyst | Benign laboratory comparison event |

## Detection Point

At `2026-09-09T12:00:00Z`, `EVT-008001` satisfied the configured minimum of two suspicious indicators.

Observed indicators:

1. `executable_from_user_writable_path`
2. `suspicious_file_extension`
3. `known_malware_indicator`
4. `high_entropy_executable`
5. `suspicious_process_name`

This produced:

`ALERT-CASE-008-DET-MALWARE-001`

## Temporal Assessment

The two events occurred one minute apart on the same host and user.

Only `EVT-008001` satisfied the malware detection conditions.

The one-minute proximity is contextual evidence only; it does not establish that the benign comparison event and suspicious event were causally related.

## Evidence Boundary

The timeline contains only telemetry present in the CASE-008 laboratory dataset. No undocumented events are inferred.
