# CASE-005 — Final Incident Report

## Executive Summary

CASE-005 documents a synthetic laboratory investigation of suspicious outbound network activity detected by `DET-NET-001 — Suspicious C2 Beaconing Activity`.

The detection identified seven outbound connections from `svchost_update.exe` on `lab-ws-01` to `198.51.100.77:8443` at approximately 60-second intervals.

The activity was accompanied by suspicious process characteristics, including an unsigned executable running from a user-writable path, and a process/network correlation event.

The detection generated a high-severity, high-confidence alert with a risk score of 100.

The observed behavior is highly consistent with automated C2-style beaconing in the laboratory scenario. However, the evidence does not independently establish confirmed compromise, malware execution, persistence, data exfiltration, or threat-actor attribution.

## Case Information

| Field | Value |
|---|---|
| Case ID | CASE-005 |
| Detection ID | DET-NET-001 |
| Alert ID | ALERT-CASE-005-DET-NET-001 |
| Detection | Suspicious C2 Beaconing Activity |
| Severity | High |
| Confidence | High |
| Risk Score | 100 |
| Host | lab-ws-01 |
| Source IP | 192.0.2.50 |
| Process | svchost_update.exe |
| Process Path | C:\Users\Public\svchost_update.exe |
| Destination | 198.51.100.77:8443 |
| First Suspicious Connection | 2026-09-08T11:10:10Z |
| Last Suspicious Connection | 2026-09-08T11:16:10Z |
| Average Interval | 60 seconds |
| Regularity Ratio | 100% |
| Environment | Synthetic laboratory |

## Alert Validation

The alert was generated after the telemetry satisfied the configured DET-NET-001 conditions:

- minimum repeated connections reached;
- connections occurred within the configured detection window;
- outbound network direction was observed;
- the same process and destination were repeatedly correlated;
- connection timing matched the configured beaconing interval;
- suspicious process characteristics increased the risk score.

The alert is considered valid against the current laboratory detection contract.

## Evidence Summary

### Suspicious Process Evidence

`EVT-005006` records:

- process: `svchost_update.exe`;
- path: `C:\Users\Public\svchost_update.exe`;
- PID: `7331`;
- parent process: `services.exe`;
- signed: false;
- classification: suspicious process.

### Network Evidence

The suspicious network sequence consists of:

- `EVT-005007`
- `EVT-005008`
- `EVT-005009`
- `EVT-005010`
- `EVT-005011`
- `EVT-005012`
- `EVT-005014`

These events represent seven outbound connections to:

`198.51.100.77:8443`

The connections occur at consistent approximately 60-second intervals.

### Correlation Evidence

`EVT-005013` provides process/network correlation evidence including:

- connection count: 6;
- interval: 60 seconds;
- unsigned binary: true;
- user-writable path: true;
- classification: high-confidence suspicious.

## Timeline Summary

| Time | Event | Significance |
|---|---|---|
| 11:09:50 | EVT-005006 | Suspicious process observed |
| 11:10:10 | EVT-005007 | First suspicious outbound connection |
| 11:11:10 | EVT-005008 | Repeated connection |
| 11:12:10 | EVT-005009 | Repeated connection |
| 11:13:10 | EVT-005010 | Repeated connection |
| 11:14:10 | EVT-005011 | Repeated connection |
| 11:15:10 | EVT-005012 | Repeated connection |
| 11:15:20 | EVT-005013 | Process/network correlation |
| 11:16:10 | EVT-005014 | Seventh connection and alert generation |

## Baseline and Negative Evidence

The case contains benign comparison traffic.

Chrome generated HTTPS traffic to:

`93.184.216.34:443`

An expected Windows update process generated HTTPS traffic to:

`203.0.113.80:443`

These events provide useful negative evidence because they differ from the suspicious activity in process identity, process path, signing status, destination port, and behavioral regularity.

The presence of benign network traffic demonstrates why outbound communication alone should not be treated as malicious.
## Hunting Results

Retrospective hunting produced positive pivots across:

- process name;
- process path;
- source host;
- source IP;
- destination IP;
- destination port;
- destination domain;
- process/network correlation;
- periodic connection behavior.

The available CASE-005 telemetry did not demonstrate:

- additional affected hosts;
- lateral movement;
- data exfiltration;
- confirmed remote command execution;
- persistence;
- real-world threat infrastructure;
- threat-actor attribution.

## Threat Intelligence Assessment

The network indicators use documentation/test values:

- `198.51.100.77`;
- `192.0.2.50`;
- `cdn-update.example`.

External reputation or attribution was not established from this laboratory case.

The primary intelligence value is behavioral: repeated periodic connections combined with suspicious process characteristics provide useful detection and hunting pivots.
## MITRE ATT&CK Assessment

The detection provides analytical mappings to:

- `T1071 — Application Layer Protocol`;
- `T1071.001 — Web Protocols`;
- `T1573 — Encrypted Channel`.

These mappings represent hypotheses based on observed network characteristics. They should not be interpreted as confirmed adversary techniques solely from the available telemetry.

## Incident Response Assessment

The recommended response priority is high.

For an equivalent authorized production investigation, responders should:

1. preserve relevant evidence;
2. assess host scope;
3. investigate the suspicious process;
4. capture executable hash and process ancestry;
5. consider host/network containment;
6. investigate persistence;
7. assess credential and lateral-movement exposure;
8. eradicate confirmed malicious artifacts;
9. recover the host under monitoring;
10. validate detection improvements.

No production containment, process termination, infrastructure blocking, credential rotation, eradication, or recovery is claimed for this laboratory case.
## Root Cause Assessment

The available telemetry does not establish a definitive root cause.

Observed evidence indicates that a suspicious process, `svchost_update.exe`, generated repeated outbound connections to the same destination at a highly regular interval. The process was also located in a user-writable path and was correlated with the network activity.

Further endpoint evidence would be required to determine how the process was introduced, executed, or persisted.

## Impact Assessment

No confirmed production impact can be established from this synthetic laboratory dataset.

The observed activity demonstrates a potentially significant security pattern because periodic outbound communication from a suspicious process could represent command-and-control behavior. However, the telemetry does not establish successful compromise, data loss, credential theft, lateral movement, or persistence.

## Detection Feedback

CASE-005 identifies several opportunities for future detection engineering improvements:

- correlate process ancestry and executable hash;
- incorporate DNS and proxy telemetry where available;
- establish historical prevalence for process and destination combinations;
- track host and process prevalence across the environment;
- enrich network detections with endpoint execution context;
- preserve deterministic correlation identifiers for investigation.

These improvements can reduce ambiguity and provide stronger evidence during subsequent investigations.
## Final Assessment

CASE-005 demonstrates a valid high-severity, high-confidence detection of suspicious C2-style beaconing behavior within the synthetic SOC laboratory.

The alert is supported by seven repeated outbound connections from the same process to the same destination, approximately 60-second intervals, suspicious process characteristics, and process/network correlation.

The evidence is sufficient to validate the detection and justify investigation and response planning. It is not sufficient to establish confirmed compromise, attribution, malware identity, or production impact.

## Evidence Chain

The investigation follows the CYBERNOVA SOC evidence chain:

Event → Detection → Alert → Triage → Evidence Validation → Investigation → Timeline → Indicators → Threat Intelligence → Hunting → MITRE ATT&CK Assessment → Severity → Response Planning → Impact Assessment → Final Report → Detection Feedback.

The resulting evidence is preserved across the CASE-005 alert, investigation, timeline, indicators, threat-intelligence, hunting, response, and final-report artifacts.

## Laboratory Limitation

All CASE-005 telemetry is synthetic laboratory data created for defensive security engineering and SOC investigation practice.

The IP addresses use documentation/test ranges and the domain uses the `.example` namespace. No real-world malicious infrastructure, attribution, compromise, or production incident is claimed.

The case demonstrates detection engineering and investigation methodology rather than evidence of a real-world security incident.
