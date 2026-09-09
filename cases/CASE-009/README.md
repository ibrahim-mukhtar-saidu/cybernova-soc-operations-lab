# CASE-009 — Linux Security Incident

## Scenario

This laboratory case investigates suspicious Linux cron persistence activity observed on a synthetic Linux endpoint.

The detection engine identified multiple independent indicators associated with a cron persistence path, shell-based payload retrieval and execution, and a hidden payload context.

## Detection

- Detection ID: `DET-LINUX-001`
- Detection name: Suspicious Linux Cron Persistence Detection
- Detection version: `1.0`
- Alert ID: `ALERT-CASE-009-DET-LINUX-001`
- Severity: High
- Confidence: High
- MITRE ATT&CK: `T1053.003` — Cron

## Affected Laboratory Asset

- Host: `lab-linux-02`
- User: `analyst`
- Process: `bash`
- Observed file: `/etc/cron.d/system-update`

## Evidence

The case is based on synthetic laboratory telemetry:

- `EVT-009001` — suspicious cron persistence activity
- `EVT-009002` — legitimate `crontab -e` administrative activity

The detection generated one alert from the supplied telemetry.

## Observed Indicators

The alert identified:

1. `cron_persistence_path`
2. `shell_download_execution`
3. `hidden_or_tmp_payload`

## Investigation Objective

Determine whether the observed activity is consistent with suspicious Linux persistence, preserve the available evidence, identify relevant indicators, assess the likely attack technique, and document appropriate response and detection-improvement actions.

## Evidence Boundary

The telemetry demonstrates suspicious activity consistent with Linux cron persistence indicators. It does **not**, by itself, prove successful persistence, malware execution, compromise, attribution, or real-world impact.

Further validation would require examination of the resulting cron configuration, process activity, downloaded artifacts, file hashes, network telemetry, and host state.

## Laboratory Limitations

This case uses synthetic telemetry in an authorized defensive laboratory environment.

No production system, real credential, real victim, or real incident is represented.

## Case Artifacts

- `alert.json` — generated detection alert
- `investigation.md` — investigation narrative
- `timeline.md` — chronological evidence timeline
- `indicators.md` — indicators and observables
- `threat-intelligence.md` — threat-intelligence assessment
- `hunting.md` — threat-hunting queries and pivots
- `response.md` — response actions
- `final-report.md` — investigation conclusion
- `lessons-learned.md` — lessons and detection improvements
