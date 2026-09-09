# PB-003 — Suspicious PowerShell Execution

## 1. Purpose

This playbook provides a repeatable SOC analyst workflow for investigating suspicious PowerShell execution alerts within the CYBERNOVA SOC Operations Laboratory.

The playbook is built around:

```text
Detection: DET-ENDPOINT-001
Detection Name: Suspicious PowerShell Execution
Related Investigation: CASE-003
```

The objective is to help an analyst:

* Validate the alert.
* Confirm the observed PowerShell execution.
* Reconstruct the execution timeline.
* Identify the initiating user, host, process, and command line.
* Determine whether suspicious execution was followed by additional activity.
* Preserve supporting evidence.
* Investigate encoded, obfuscated, downloaded, or otherwise suspicious commands.
* Identify parent and child process relationships where telemetry supports them.
* Assess whether the activity represents legitimate administration, security testing, or potentially malicious execution.
* Pivot into related authentication, network, malware, persistence, and file-integrity telemetry.
* Evaluate detection coverage and evasion opportunities.
* Document response considerations.
* Feed investigation findings back into detection engineering.

This playbook is designed for authorized laboratory telemetry and does not represent production SOC employment or production incident-response experience.

---

## 2. Scope

This playbook covers suspicious PowerShell execution observed in Windows endpoint telemetry.

Primary detection:

```text
DET-ENDPOINT-001
Suspicious PowerShell Execution
```

Primary investigation:

```text
CASE-003
Suspicious PowerShell
```

The workflow is applicable to PowerShell activity involving potentially suspicious:

* Command-line execution.
* Encoded commands.
* Download activity.
* Script execution.
* Child-process creation.
* Privilege-related activity.
* Persistence-related activity.
* Security-control modification.
* Lateral-movement preparation.
* Post-authentication activity.

The presence of PowerShell alone does not establish malicious activity.

PowerShell is a legitimate administrative and automation tool and therefore requires contextual analysis.

---

## 3. Trigger

Begin this playbook when `DET-ENDPOINT-001` generates an alert.

The current detection correlates suspicious PowerShell execution with supporting endpoint activity within its configured correlation window.

The analyst must validate the exact conditions represented by the alert rather than assuming that every PowerShell command is malicious.

Potential legitimate causes include:

* System administration.
* Software deployment.
* Endpoint management.
* Configuration management.
* Security testing.
* Developer automation.
* Monitoring agents.
* Software installation.
* Troubleshooting.

The alert is therefore an investigation trigger, not a compromise verdict.

---

## 4. Severity Guidance

Initial severity should follow the detection output and available contextual evidence.

Increase investigative priority when PowerShell execution is associated with:

* Encoded commands.
* Obfuscation.
* Download-and-execute behavior.
* Suspicious remote resources.
* Temporary-directory execution.
* Security-control modification.
* Credential access.
* Privilege escalation.
* Persistence.
* Suspicious child processes.
* Unusual parent processes.
* Network connections.
* Malware indicators.
* File-integrity violations.
* Multiple related alerts.
* A suspicious user or account.
* Execution immediately after suspicious authentication.

A high-confidence PowerShell alert does not independently prove compromise.

Severity should reflect the complete evidence available to the analyst.

---

## 5. Initial Alert Validation

Confirm the following fields where available:

* `alert_id`
* `detection_id`
* `detection_name`
* `detection_version`
* `status`
* `severity`
* `confidence`
* `event_type`
* `host`
* `user`
* `process`
* `command_line`
* `timestamp`
* `first_seen`
* `last_seen`
* correlation window
* supporting event IDs
* suspicious indicators
* MITRE ATT&CK context
* evidence classification

Confirm:

```text
detection_id = DET-ENDPOINT-001
```

Confirm that the alert came from the expected detection-engineering path.

Do not modify the original alert artifact.

---

## 6. Evidence Authenticity

Before interpreting the command line, validate the underlying telemetry.

Confirm:

1. The referenced event IDs exist.
2. The event timestamps are valid.
3. The host is consistent.
4. The user is consistent.
5. The process information is available.
6. The command line is preserved exactly where possible.
7. The alert conditions are reproducible from the supporting evidence.
8. The correlation window was respected.
9. Duplicate events did not distort the result.
10. No malformed telemetry caused an incorrect detection.

If a field is missing, record the limitation.

Do not silently infer missing process, user, or network information.

---

## 7. Command-Line Preservation

PowerShell investigations depend heavily on command-line evidence.

Preserve the original command line before creating an analyst-normalized interpretation.

Maintain two separate concepts:

```text
Observed command line
```

and:

```text
Analyst interpretation
```

Do not replace the original command line with a decoded or simplified version.

If decoding or normalization is performed, preserve the derived result separately and document how it was obtained.

---

## 8. PowerShell Command Analysis

Review the command for:

* `-EncodedCommand`
* `-enc`
* `-e`
* `-Command`
* `-c`
* Script paths
* Download commands
* Web requests
* Remote execution
* Reflection
* Memory-loading behavior
* Credential-related commands
* Process creation
* Scheduled tasks
* Registry modification
* Service creation
* Security-control changes
* Temporary files
* Hidden files
* Obfuscation
* String concatenation
* Base64 content
* Suspicious URLs
* Suspicious IP addresses
* Archive extraction
* File creation
* Execution from unusual directories

Do not assume that the presence of one keyword is sufficient to classify the execution as malicious.

---

## 9. Encoded PowerShell

Encoded PowerShell commands require careful analysis.

Common indicators include:

```text
-EncodedCommand
-enc
```

The analyst should determine:

* Whether encoding is actually present.
* What encoding mechanism is used.
* Whether the decoded content contains executable logic.
* Whether the content references files, URLs, credentials, or persistence.
* Whether the encoded content is consistent with legitimate software.

If decoding is performed:

1. Preserve the original command.
2. Create a separate decoded representation.
3. Record the decoding method.
4. Avoid executing the decoded payload.
5. Treat decoded content as evidence.
6. Record uncertainty when decoding is incomplete.

Do not execute unknown commands merely to determine what they do.

---

## 10. Obfuscation Review

Review suspicious command construction including:

* Excessive string concatenation.
* Character substitution.
* Environment-variable expansion.
* Escaped characters.
* Unusual whitespace.
* Fragmented commands.
* Base64 strings.
* Dynamically constructed command names.
* Reflection.
* Encoded script blocks.
* Multiple nested interpreters.

Potential obfuscation should be documented as an indicator rather than automatically treated as proof of maliciousness.

Legitimate software may also use complex command construction.

---

## 11. Parent Process Investigation

Identify the parent process when endpoint telemetry provides process lineage.

Review:

* Parent process name.
* Parent process path.
* Parent process command line.
* Parent process user.
* Parent process timestamp.
* Child process relationship.

Examples of useful context include:

```text
explorer.exe
cmd.exe
services.exe
taskeng.exe
wmiprvse.exe
office applications
browser processes
security-management software
```

No parent process should be automatically classified as malicious.

The analyst should determine whether the parent-child relationship is expected for the environment and scenario.

---

## 12. Child Process Investigation

Search for processes created by PowerShell.

Look for:

* `cmd.exe`
* `rundll32.exe`
* `regsvr32.exe`
* `mshta.exe`
* `wscript.exe`
* `cscript.exe`
* `bitsadmin.exe`
* Archive utilities.
* Network utilities.
* Credential-related tools.
* Unknown executables.

Document:

* Process name.
* Full path.
* Command line.
* User.
* Timestamp.
* Parent process.
* Child process.
* Supporting event ID.

A suspicious child process may increase priority but still requires contextual validation.

---

## 13. User Investigation

Identify the account responsible for execution.

Review:

* Username.
* Privilege level.
* Logon type.
* Session ID.
* Authentication events.
* Earlier activity.
* Later activity.
* Whether the user normally performs administrative tasks.

Pay particular attention when PowerShell execution follows:

```text
authentication anomaly
        +
successful authentication
        +
new session
        +
PowerShell execution
```

This sequence may justify additional investigation.

It does not independently prove account compromise.

---

## 14. Host Investigation

Review the affected host.

Record:

* Hostname.
* Operating-system context where available.
* User.
* Process.
* PowerShell version where available.
* First observed event.
* Last observed event.
* Related detections.
* Related network activity.
* Related file activity.
* Related authentication events.

Determine whether the host is:

* A normal laboratory endpoint.
* An administrative system.
* A server.
* A workstation.
* A security-testing host.

Host context can materially affect interpretation.

---

## 15. Timeline Construction

Construct a chronological timeline.

At minimum include:

| Time        | Event                            | User | Process    | Command/Activity | Evidence |
| ----------- | -------------------------------- | ---- | ---------- | ---------------- | -------- |
| Initial     | Parent process                   | User | Parent     | Command          | Event ID |
| Execution   | PowerShell start                 | User | PowerShell | Command line     | Event ID |
| Correlation | Supporting activity              | User | Process    | Activity         | Event ID |
| Follow-up   | Child process/network/file event | User | Process    | Activity         | Event ID |

Separate:

```text
Observed telemetry
```

from:

```text
Detection output
```

and:

```text
Analyst interpretation
```

The timeline should not introduce events that were not observed.

---

## 16. Network Investigation

PowerShell may interact with network resources.

Search for:

* Source host.
* Destination IP.
* Destination domain.
* Destination port.
* URL.
* Protocol.
* Timestamp.
* User-agent where available.
* Related DNS activity.
* Related network connections.

Potentially suspicious patterns include:

* Downloading scripts.
* Connecting to unusual external infrastructure.
* Repeated connections.
* Connections immediately before or after execution.
* Download-and-execute behavior.
* Communication with known laboratory simulation endpoints.

Do not claim that a network request succeeded unless supporting telemetry proves it.

A URL appearing in a command line is not itself proof that the resource was reached.

---

## 17. File Investigation

Search for files created, modified, or executed around the PowerShell event.

Review:

* File path.
* Filename.
* Extension.
* Hash where available.
* Creation time.
* Modification time.
* User.
* Process.
* Parent process.
* File-integrity events.

Prioritize:

* Temporary directories.
* User profile directories.
* Startup locations.
* Script directories.
* Unusual executable locations.
* Hidden files.

If a hash exists, preserve it as an indicator.

Do not execute an unknown file as part of routine triage.

---

## 18. Persistence Investigation

PowerShell may create or modify persistence mechanisms.

Search for:

* Scheduled tasks.
* Services.
* Registry run keys.
* Startup folders.
* WMI persistence.
* Scheduled scripts.
* PowerShell profiles.
* Other authorized persistence telemetry.

Related detections may include:

```text
DET-HOST-001
File Integrity Violation Detection

DET-LINUX-001
Suspicious Linux Cron Persistence Detection
```

The Linux persistence detector should only be used as a conceptual cross-project pivot where relevant.

Do not imply that Linux persistence occurred on a Windows host without supporting evidence.

---

## 19. Malware Investigation

If PowerShell execution references:

* Executables.
* Scripts.
* Payloads.
* Suspicious hashes.
* Downloaded files.
* Temporary files.

consider pivoting into the CYBERNOVA malware-analysis workflow.

Relevant detection:

```text
DET-MALWARE-001
Suspicious Malware Execution Detection
```

The analyst should preserve:

* File hash.
* File path.
* Parent process.
* Command line.
* Timestamp.
* Supporting event IDs.

Do not execute potentially malicious samples outside an isolated authorized malware-analysis environment.

---

## 20. Authentication Correlation

Search authentication telemetry before the PowerShell event.

Look for:

* Failed authentication.
* Successful authentication.
* Source IP.
* Target user.
* Session creation.
* Privileged login.

Potential sequence:

```text
Authentication anomaly
        ↓
Successful authentication
        ↓
Session creation
        ↓
PowerShell execution
        ↓
Additional activity
```

When multiple independent detections support such a sequence, consider whether a broader investigation is warranted.

---

## 21. Related Detection Investigation

Consider related detections when evidence supports the pivot.

Potential detections include:

```text
DET-AUTH-001
SSH Brute-Force Authentication Detection

DET-AUTH-002
Password Spraying Authentication Detection

DET-AUTH-003
Suspicious Post-Authentication Privileged Session

DET-MALWARE-001
Suspicious Malware Execution Detection

DET-NET-001
Suspicious C2 Beaconing Activity

DET-HOST-001
File Integrity Violation Detection

DET-WEB-001
Suspicious SQL Injection Activity
```

These are investigation pivots.

Do not claim that related alerts exist unless actual evidence confirms them.

---

## 22. Evidence Preservation

Preserve:

* Original alert JSON.
* Supporting endpoint events.
* Process IDs where available.
* Parent/child process relationships.
* User.
* Host.
* Command line.
* Timestamps.
* File paths.
* Hashes.
* Network indicators.
* Related alert IDs.
* Supporting event IDs.

Derived artifacts should remain separate from original evidence.

Recommended investigation artifacts include:

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

---

## 23. Indicators

Record indicators such as:

### Endpoint

* Host.
* User.
* Process.
* Parent process.
* Child process.
* Process ID.
* Command line.
* Script path.
* File path.

### Network

* Source IP.
* Destination IP.
* Domain.
* URL.
* Destination port.

### File

* Filename.
* Path.
* SHA-256 hash.
* File type.

### Detection

* Alert ID.
* Detection ID.
* Supporting event IDs.
* First seen.
* Last seen.

Every indicator should remain traceable to evidence.

Do not label synthetic laboratory infrastructure as a real-world IOC.

---

## 24. Threat-Intelligence Assessment

Threat intelligence may be used for enrichment where appropriate.

Potential enrichment targets include:

* IP addresses.
* Domains.
* URLs.
* File hashes.
* User-agents.

If external enrichment is performed, record:

* Indicator.
* Source.
* Query time.
* Result.
* Confidence.
* Limitations.

If no enrichment was performed, state:

```text
No external threat-intelligence enrichment was performed.
```

Do not invent:

* Reputation.
* Ownership.
* Attribution.
* Malware family.
* Threat actor.
* Geolocation.
* Blacklist status.

Synthetic laboratory indicators must remain clearly identified as laboratory data.

---

## 25. MITRE ATT&CK Context

PowerShell is commonly represented by:

```text
T1059.001 — PowerShell
```

Additional techniques should only be mapped when supported by observed behavior.

Possible contextual techniques may include:

```text
T1105 — Ingress Tool Transfer
T1027 — Obfuscated Files or Information
T1053 — Scheduled Task/Job
T1078 — Valid Accounts
```

These mappings require evidence.

Do not add ATT&CK techniques merely because they are theoretically possible.

ATT&CK mapping describes observed or supported behavior; it does not independently establish malicious intent.

---

## 26. False-Positive Review

PowerShell is widely used legitimately.

Investigate legitimate explanations such as:

* IT administration.
* Endpoint-management systems.
* Software deployment.
* Patch management.
* Security tooling.
* Configuration management.
* Developer automation.
* Troubleshooting.
* Authorized penetration testing.
* Laboratory exercises.

Ask:

1. Is the user expected to run PowerShell?
2. Is the host expected to execute PowerShell?
3. Is the parent process expected?
4. Is the command line expected?
5. Is the execution time expected?
6. Is the destination expected?
7. Was a file created?
8. Was a child process created?
9. Did persistence occur?
10. Did authentication anomalies precede execution?
11. Did additional detections follow?

The final assessment should explain the evidence supporting the conclusion.

---

## 27. Obfuscated and Encoded Content

When encoded or obfuscated PowerShell is detected:

1. Preserve the original command.
2. Determine the encoding or obfuscation mechanism.
3. Decode without executing the resulting content.
4. Record the decoded representation separately.
5. Identify referenced files and network resources.
6. Search for corresponding telemetry.
7. Determine whether the behavior is expected.
8. Record unresolved content when decoding is incomplete.

Do not equate encoding alone with maliciousness.

Encoding may be used by legitimate automation.

---

## 28. Download-and-Execute Review

If the command contains network retrieval followed by execution, investigate:

* URL.
* Domain.
* Destination IP.
* Download timestamp.
* File path.
* File hash.
* Process lineage.
* Subsequent execution.
* Related network activity.

Potential pattern:

```text
PowerShell
    ↓
Remote resource request
    ↓
File/script retrieval
    ↓
Execution
    ↓
Child process
    ↓
Persistence/network activity
```

Each step must be supported independently.

Do not assume that the presence of a URL means a successful download.

---

## 29. Security-Control Modification

Investigate commands that appear to:

* Disable security controls.
* Modify logging.
* Change execution policy.
* Alter firewall settings.
* Stop security services.
* Modify endpoint protection configuration.

Record the exact command and supporting evidence.

Determine whether the activity was:

* Authorized administration.
* Security testing.
* Configuration management.
* Potential defense-evasion behavior.

Do not claim that a security control was disabled unless telemetry supports the change.

---

## 30. Containment Decision

Containment should only be performed within an authorized environment.

Potential response options include:

* Isolating the endpoint.
* Restricting network access.
* Terminating a suspicious process.
* Disabling or restricting an affected account.
* Blocking malicious infrastructure.
* Preserving a forensic image.
* Restricting execution paths.

In the laboratory, these are response considerations unless the exercise explicitly authorizes and documents their execution.

Do not claim production containment.

---

## 31. Eradication Considerations

If malicious execution is established, investigate whether eradication may require:

* Removing malicious files.
* Removing persistence.
* Reverting unauthorized configuration changes.
* Rotating compromised credentials.
* Revoking unauthorized sessions.
* Removing scheduled tasks or services.
* Restoring modified security settings.

Do not claim eradication unless it was actually performed and verified.

---

## 32. Recovery Considerations

Recovery may include:

* Restoring endpoint configuration.
* Verifying security controls.
* Validating endpoint integrity.
* Confirming persistence removal.
* Rotating credentials.
* Continuing enhanced monitoring.
* Repeating detection tests.

Recovery should have measurable validation criteria where possible.

No production recovery claim should be made from this laboratory.

---

## 33. Detection Validation

Validate `DET-ENDPOINT-001` against its detection contract.

Confirm:

* Required event fields.
* PowerShell identification.
* Suspicious-condition logic.
* Correlation window.
* Alert generation.
* Alert severity.
* Alert confidence.
* Supporting event IDs.
* Timestamp behavior.
* Duplicate handling.
* Benign PowerShell behavior.

Test both:

```text
Suspicious PowerShell
```

and:

```text
Legitimate PowerShell
```

The detector should not treat every PowerShell command as malicious.

---

## 34. Detection Evasion Review

Consider potential evasion strategies.

### 34.1 Command obfuscation

An attacker may alter command syntax while retaining the same behavior.

Limitation:

```text
Simple string-based indicators may miss transformed commands.
```

Improvement:

```text
Use behavioral and normalized execution telemetry where available.
```

### 34.2 Encoding variation

An attacker may use different encodings or nested transformations.

Limitation:

```text
Static pattern matching may not identify every encoded representation.
```

Improvement:

```text
Add controlled decoding and behavioral analytics.
```

### 34.3 Alternate interpreters

An attacker may avoid PowerShell and use another execution mechanism.

Limitation:

```text
PowerShell-specific detection cannot provide complete endpoint coverage.
```

Improvement:

```text
Correlate with broader process-execution telemetry.
```

### 34.4 Execution from unusual paths

Payloads may be executed from temporary or user-controlled directories.

Improvement:

```text
Add path-based context while maintaining false-positive controls.
```

### 34.5 Parent-process variation

Different parent processes may launch PowerShell.

Limitation:

```text
Parent-process assumptions can create blind spots.
```

Improvement:

```text
Use process lineage as contextual evidence rather than a single hard-coded parent.
```

### 34.6 Slow execution

Activity may be distributed over time.

Limitation:

```text
A narrow correlation window may fail to connect related events.
```

Improvement:

```text
Use complementary longer-window analytics where justified.
```

### 34.7 Telemetry deletion or suppression

An attacker may attempt to interfere with endpoint telemetry.

Limitation:

```text
Missing telemetry can prevent reconstruction of the complete sequence.
```

Improvement:

```text
Monitor telemetry health and preserve independent evidence sources where available.
```

---

## 35. Adversarial Validation

Controlled laboratory testing should include:

* Normal PowerShell.
* Suspicious command strings.
* Encoded commands.
* Obfuscated commands.
* Long command lines.
* Unicode characters.
* Empty command lines.
* Missing command-line fields.
* Invalid timestamps.
* Duplicate events.
* Multiple users.
* Multiple hosts.
* Multiple parent processes.
* Download-like commands.
* Temporary-directory execution.
* Child-process creation.
* Security-control modification simulation.
* Slow activity across the correlation window.

Expected detection behavior should be recorded.

Do not claim successful evasion unless the test was actually executed.

---

## 36. Threat Hunting

Useful hunting pivots include:

### User

Search for additional PowerShell activity by the same user.

### Host

Search for PowerShell executions on the same endpoint.

### Process

Search for related parent and child processes.

### Command line

Search for:

* `-EncodedCommand`
* `-enc`
* `Invoke-Expression`
* `DownloadString`
* `WebClient`
* `Invoke-WebRequest`
* `Start-BitsTransfer`
* Suspicious script paths.

These strings are hunting pivots, not automatic maliciousness indicators.

### Network

Search for destinations contacted by PowerShell.

### File

Search for files created or executed around the event.

### Persistence

Search for scheduled tasks, services, registry changes, or startup artifacts.

---

## 37. Cross-Project Investigation

The CYBERNOVA portfolio contains complementary security projects that can support deeper analysis.

Potential pivots include:

```text
CYBERNOVA SIEM Detection Lab
        ↓
SOC Operations Lab
        ↓
Threat Hunting Toolkit
        ↓
Malware Analysis Sandbox
        ↓
Windows Security Monitoring Lab
```

The analyst should connect projects only when actual evidence supports the relationship.

A project being capable of performing a particular analysis does not mean that the analysis was executed.

---

## 38. Evidence Classification

Every important statement should be classified conceptually as one of:

```text
Observed evidence
Derived evidence
Analyst interpretation
Recommended action
Laboratory limitation
```

Examples:

```text
Observed:
PowerShell executed on lab endpoint.

Derived:
The command contained an encoded argument.

Interpretation:
The execution warrants additional investigation.

Recommendation:
Review process lineage and network telemetry.

Limitation:
No external enrichment was performed.
```

This separation prevents unsupported incident claims.

---

## 39. Escalation Criteria

Escalate when one or more of the following are supported:

* Malicious payload execution.
* Successful download and execution.
* Credential access.
* Persistence.
* Privilege escalation.
* Security-control modification.
* Suspicious network communication.
* Multiple related detections.
* Suspicious authentication preceding execution.
* Multiple affected hosts.
* Evidence of lateral movement.
* Malware indicators.
* Insufficient telemetry to determine scope.

Escalation should be evidence-driven.

---

## 40. Closure Criteria

Close the investigation only after:

* Alert validity is established.
* Supporting evidence is preserved.
* Command line is reviewed.
* User is identified.
* Host is identified.
* Process lineage is reviewed where available.
* Timeline is constructed.
* Network activity is reviewed.
* File activity is reviewed.
* Persistence is considered.
* Related detections are considered.
* False-positive analysis is documented.
* Threat-intelligence boundaries are documented.
* ATT&CK mapping is supported.
* Detection limitations are recorded.
* Response considerations are addressed.
* Required investigation artifacts are complete.
* Final disposition is supported by evidence.

A valid conclusion may be:

```text
Suspicious PowerShell execution observed; malicious intent or compromise not established.
```

when that is what the evidence supports.

---

## 41. Required Evidence Package

A complete CASE-003 investigation should contain:

```text
CASE-003/
├── README.md
├── alert.json
├── investigation.md
├── timeline.md
├── indicators.md
├── threat-intelligence.md
├── hunting.md
├── response.md
├── final-report.md
└── lessons-learned.md
```

The evidence package should remain internally traceable.

---

## 42. Laboratory Validation Scenario

A positive validation scenario should contain:

* PowerShell execution.
* Suspicious execution characteristics defined by the detection.
* Valid host.
* Valid user.
* Valid timestamp.
* Supporting endpoint telemetry.
* Correlation within the configured window.
* Unique event IDs.

A benign control should contain legitimate PowerShell execution that does not satisfy the suspicious detection conditions.

Additional test cases should include:

* Encoded commands.
* Obfuscated commands.
* Long command lines.
* Missing command lines.
* Invalid timestamps.
* Duplicate telemetry.
* Multiple users.
* Multiple hosts.
* Different parent processes.
* Download-like activity.
* Temporary-directory execution.
* Benign administrative automation.

Expected outcomes should be documented from actual test results.

---

## 43. Operational Checklist

### Alert validation

* [ ] Confirm `DET-ENDPOINT-001`.
* [ ] Confirm alert status.
* [ ] Confirm severity and confidence.
* [ ] Validate supporting event IDs.
* [ ] Validate timestamps.
* [ ] Validate host.
* [ ] Validate user.
* [ ] Validate process.
* [ ] Validate command line.
* [ ] Confirm correlation window.

### Command analysis

* [ ] Preserve original command line.
* [ ] Check for encoding.
* [ ] Check for obfuscation.
* [ ] Check for download behavior.
* [ ] Check for script execution.
* [ ] Check for suspicious paths.
* [ ] Check for security-control modification.
* [ ] Check for persistence indicators.

### Endpoint investigation

* [ ] Identify parent process.
* [ ] Identify child processes.
* [ ] Review user context.
* [ ] Review host context.
* [ ] Review file activity.
* [ ] Review network activity.
* [ ] Review authentication activity.

### Cross-detection investigation

* [ ] Check authentication detections.
* [ ] Check malware detection.
* [ ] Check network detection.
* [ ] Check file-integrity detection.
* [ ] Check relevant web or other telemetry where appropriate.

### Threat intelligence

* [ ] Record indicators.
* [ ] Separate synthetic indicators.
* [ ] Perform enrichment only where appropriate.
* [ ] Record enrichment sources.
* [ ] Do not invent reputation or attribution.

### Response

* [ ] Evaluate containment.
* [ ] Evaluate credential response.
* [ ] Evaluate eradication.
* [ ] Evaluate recovery.
* [ ] Escalate when criteria are met.

### Detection engineering

* [ ] Validate detection contract.
* [ ] Test benign PowerShell.
* [ ] Test suspicious PowerShell.
* [ ] Test encoded commands.
* [ ] Test obfuscation.
* [ ] Test duplicates.
* [ ] Test malformed telemetry.
* [ ] Test long commands.
* [ ] Test timing boundaries.
* [ ] Document detection limitations.
* [ ] Add regression tests for confirmed weaknesses.

### Closure

* [ ] Preserve evidence.
* [ ] Complete timeline.
* [ ] Complete indicators.
* [ ] Complete hunting assessment.
* [ ] Complete response assessment.
* [ ] Complete final report.
* [ ] Document uncertainty.
* [ ] Record final disposition.
* [ ] Feed findings back into detection engineering.

---

## 44. Analyst Conclusion

Suspicious PowerShell execution requires contextual endpoint investigation because PowerShell is both a legitimate administration technology and a commonly monitored execution mechanism.

The analyst should establish:

```text
What executed?
      ↓
Who executed it?
      ↓
Where did it execute?
      ↓
What launched it?
      ↓
What did the command contain?
      ↓
Did it create or execute anything else?
      ↓
Did it communicate with a network resource?
      ↓
Did authentication anomalies precede it?
      ↓
Did persistence or other detections follow?
      ↓
What evidence supports the assessment?
      ↓
What response is justified?
      ↓
What should detection engineering improve?
```

The strongest investigation connects process, identity, host, network, file, authentication, and persistence evidence without overstating what the telemetry proves.

PowerShell execution alone is not evidence of compromise.

---

## 45. Scope and Limitations

This playbook belongs to the CYBERNOVA SOC Operations Laboratory.

All examples and evidence must remain within authorized laboratory or defensive environments.

This playbook does not claim:

* Professional SOC employment.
* Production incident-response experience.
* Real-world compromise.
* Real-world attacker attribution.
* Real-world threat-intelligence reputation.
* Production containment.
* Production eradication.
* Production recovery.
* Complete endpoint visibility.

The purpose is to demonstrate repeatable SOC analysis, endpoint investigation, detection validation, threat hunting, response planning, and detection-engineering feedback.

---

## 46. Author

**Ibrahim Mukhtar Saidu**

CYBERNOVA SOC Operations Laboratory

Focus:

```text
SOC Operations
Detection Engineering
Endpoint Security
Threat Hunting
Incident Investigation
Security Monitoring
Security Automation
```
