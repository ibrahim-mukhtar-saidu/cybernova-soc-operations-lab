# CASE-010 — Multi-Stage Attack Investigation

## Case Summary

CASE-010 is a synthetic SOC laboratory investigation demonstrating end-to-end correlation of multiple independent security detections into a single multi-stage attack sequence.

The scenario correlates:

1. SSH brute-force authentication activity.
2. Successful authentication followed by privileged post-authentication activity.
3. Suspicious Linux cron persistence activity involving download-and-execute behavior.

The correlation occurs on the same laboratory host and user within the configured 30-minute correlation window.

## Investigation Classification

* **Case ID:** CASE-010
* **Scenario:** Multi-Stage Attack
* **Environment:** Synthetic SOC laboratory
* **Host:** `lab-linux-10`
* **User:** `root`
* **Source IP:** `198.51.100.90`
* **Correlation Detection:** `DET-CORR-001`
* **Severity:** Critical
* **Confidence:** High
* **Stage Count:** 3
* **Supporting Alerts:** 3
* **Supporting Events:** 13

## Correlated Detection Stages

| Order | Detection       | Stage                        | Timestamp                   |
| ----- | --------------- | ---------------------------- | --------------------------- |
| 1     | `DET-AUTH-001`  | Credential access            | `2026-09-09T10:02:03Z`      |
| 2     | `DET-AUTH-003`  | Post-authentication activity | `2026-09-09T10:03:21+00:00` |
| 3     | `DET-LINUX-001` | Persistence                  | `2026-09-09T10:12:00Z`      |

## Evidence Chain

```text
Authentication failures
        ↓
Successful SSH authentication
        ↓
Privileged / discovery-oriented commands
        ↓
Suspicious cron persistence activity
        ↓
Download-and-execute behavior
        ↓
DET-CORR-001 multi-stage correlation
```

## Detection Evidence

### Stage 1 — Authentication Attack

Detection:

`DET-AUTH-001 — SSH Brute-Force Authentication Detection`

Observed evidence includes six failed SSH authentication attempts from the same source IP against the laboratory host, followed by a successful authentication event.

Supporting telemetry:

* `EVT-010001`
* `EVT-010002`
* `EVT-010003`
* `EVT-010004`
* `EVT-010005`
* `EVT-010006`
* `EVT-010007`

The detection threshold was five failed attempts within five minutes.

### Stage 2 — Post-Authentication Activity

Detection:

`DET-AUTH-003 — Suspicious Post-Authentication Privileged Session`

The successful authentication was followed by a session start and four post-authentication commands.

Observed commands include:

* `whoami`
* `id`
* `sudo -l`
* `uname -a`

The activity occurred under the same laboratory host and user and originated from the same source IP.

Supporting telemetry extends through:

`EVT-010012`

### Stage 3 — Linux Persistence

Detection:

`DET-LINUX-001 — Suspicious Linux Cron Persistence Detection`

The detected persistence event involved:

* Cron persistence path: `/etc/cron.d/system-update`
* Process: `bash`
* Download-and-execute behavior using `curl`
* Shell execution through `sh`
* Hidden payload indicator
* Successful Linux persistence event

Supporting telemetry:

`EVT-010013`

The benign `crontab -e` event at `EVT-010014` was not included in the correlated alert.

## Correlation Result

The correlation engine generated:

* **Alert:** `ALERT-CASE-010-DET-CORR-001`
* **Detection:** `DET-CORR-001`
* **Severity:** Critical
* **Confidence:** High
* **Stages:** 3
* **Supporting alerts:** 3
* **Supporting events:** 13
* **Correlation window:** 30 minutes

The correlated sequence begins at:

`2026-09-09T10:02:03Z`

and ends at:

`2026-09-09T10:12:00Z`

The observed sequence therefore spans approximately ten minutes.

## Analyst Interpretation

The available laboratory telemetry shows a correlated sequence of authentication attack activity, successful authentication, post-authentication privileged/discovery activity, and suspicious Linux cron persistence on the same host and user.

The evidence supports investigation of a multi-stage attack sequence.

The correlation does not independently prove compromise.

The observed activity must be evaluated against authorization, expected administrative behavior, host context, and additional evidence before a final compromise determination is made.

## MITRE ATT&CK Mapping

The correlated detection references the following techniques:

| Tactic                                      | Technique | Description                               |
| ------------------------------------------- | --------- | ----------------------------------------- |
| Credential Access                           | T1110     | Brute Force                               |
| Credential Access / Defense Evasion context | T1078     | Valid Accounts                            |
| Discovery                                   | T1087     | Account Discovery                         |
| Discovery                                   | T1069.001 | Permission Groups Discovery: Local Groups |
| Persistence                                 | T1053.003 | Scheduled Task/Job: Cron                  |

The mappings describe behaviors represented by the laboratory telemetry and should not be interpreted as proof of attacker intent.

## Investigation Objectives

The investigation will:

1. Validate the correlated alert.
2. Reconstruct the chronological event sequence.
3. Preserve and classify supporting evidence.
4. Identify relevant indicators.
5. Evaluate threat-intelligence context where applicable.
6. Perform targeted hunting against available telemetry.
7. Map observed behavior to MITRE ATT&CK.
8. Assess severity and investigative priority.
9. Develop an appropriate response strategy.
10. Assess root cause and potential impact using available evidence.
11. Produce a final investigation report.
12. Identify detection-engineering improvements and future validation requirements.

## Evidence Files

* `alert.json` — final correlated alert
* `auth-001-alerts.json` — DET-AUTH-001 detection output
* `auth-003-alerts.json` — DET-AUTH-003 detection output
* `linux-001-alerts.json` — DET-LINUX-001 detection output
* `investigation.md` — investigation record
* `timeline.md` — chronological reconstruction
* `indicators.md` — indicators and investigative pivots
* `threat-intelligence.md` — threat-intelligence assessment
* `hunting.md` — threat-hunting activity
* `response.md` — response actions and recommendations
* `final-report.md` — final investigation report
* `lessons-learned.md` — lessons learned and detection improvements

Source telemetry:

`telemetry/correlation/CASE-010-multi-stage-attack.jsonl`

## Evidence Classification

Evidence in this case should be distinguished between:

* **Observed evidence** — directly represented in synthetic telemetry or generated detection output.
* **Analyst interpretation** — conclusions or hypotheses derived from observed evidence.
* **Recommended action** — proposed response or validation activity that has not necessarily been executed.

No unobserved activity should be presented as confirmed fact.

## Laboratory Limitations

This case uses synthetic telemetry in an isolated SOC laboratory environment.

The scenario does not represent:

* a real-world production incident;
* a real customer environment;
* a confirmed real credential compromise;
* a confirmed malicious actor;
* professional SOC employment experience; or
* production detection performance.

The IP addresses and telemetry identifiers are laboratory data.

The correlation engine is limited to detection alerts supplied to it. Missing telemetry, manipulated timestamps, incomplete evidence, legitimate administrative activity, or conflicting investigative context can affect the result.

## Engineering Evidence

CASE-010 demonstrates:

* independent detection execution;
* normalized alert generation;
* multi-stage alert correlation;
* chronological sequence validation;
* host and user pivoting;
* source-IP consistency checking where available;
* correlation-window enforcement;
* supporting alert preservation;
* supporting event preservation;
* MITRE ATT&CK mapping; and
* explicit separation between observed evidence and analyst interpretation.

The correlation layer does not replace individual detections. It operates above the detection engine to combine independently generated evidence into an investigation-oriented sequence.

## Case Status

**Investigation in progress.**

The correlated alert has been successfully generated from the real outputs of the three underlying detection workflows.

Further investigation artifacts will document validation, timeline reconstruction, indicators, threat intelligence, hunting, response, final assessment, and lessons learned.
