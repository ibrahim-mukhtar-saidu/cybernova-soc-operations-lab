# CASE-005 — Suspicious Network Activity Investigation

## Case Metadata

- **Case ID:** CASE-005
- **Alert ID:** ALERT-CASE-005-DET-NET-001
- **Detection:** DET-NET-001 — Suspicious C2 Beaconing Activity
- **Detection Version:** 1.0
- **Severity:** High
- **Confidence:** High
- **Status:** Open
- **Host:** lab-ws-01
- **Source IP:** 192.0.2.50
- **Process:** svchost_update.exe
- **Process Path:** C:\Users\Public\svchost_update.exe
- **Destination:** 198.51.100.77:8443
- **Destination Domain:** cdn-update.example
- **Detection Timestamp:** 2026-09-08T11:16:10Z

## Investigation Objective

Determine whether the detected repeated outbound network activity is consistent with automated beaconing and assess the available evidence for suspicious process execution, network persistence, and potential command-and-control behavior.

The investigation is based exclusively on synthetic laboratory telemetry generated for this SOC operations laboratory.

## Alert Validation

The detection engine processed 15 telemetry events and generated one alert.

Observed alert characteristics:

- 7 outbound connections were associated with the same process and destination.
- Connections occurred at an average interval of 60 seconds.
- Interval regularity was 100%.
- The destination used TCP port 8443.
- The process executed from a user-writable path.
- The process was identified as `svchost_update.exe`.
- A process/network correlation event reported 6 connections and classified the activity as high-confidence suspicious.
- The calculated risk score was 100.

The alert is therefore supported by multiple independent telemetry characteristics rather than by connection frequency alone.

## Observed Evidence

### Network Activity

The following network events form the detected connection sequence:

- EVT-005007 — 11:10:10Z
- EVT-005008 — 11:11:10Z
- EVT-005009 — 11:12:10Z
- EVT-005010 — 11:13:10Z
- EVT-005011 — 11:14:10Z
- EVT-005012 — 11:15:10Z
- EVT-005014 — 11:16:10Z

The seven connections target the same destination and process and maintain a regular 60-second interval.

### Process Evidence

EVT-005006 records the process:

- Process name: `svchost_update.exe`
- Path: `C:\Users\Public\svchost_update.exe`
- PID: 7331
- Parent process: `services.exe`
- Signed: false
- Classification: suspicious_process

This event is supporting telemetry for the investigation. It is not listed as a supporting event in the generated alert itself.

### Correlation Evidence

EVT-005013 records process/network correlation:

- Process: `svchost_update.exe`
- Destination: `198.51.100.77:8443`
- Connection count: 6
- Interval: 60 seconds
- Unsigned binary: true
- User-writable path: true
- Classification: high_confidence_suspicious

## Baseline Comparison

Events EVT-005001 through EVT-005005 represent benign browser traffic from `lab-ws-01`.

The baseline traffic:

- Uses Chrome.
- Connects to `93.184.216.34:443`.
- Is classified as benign browser traffic.
- Uses expected HTTPS destination port 443.

EVT-005015 represents separate expected Windows update traffic:

- Process: `windows_update.exe`
- Path: `C:\Windows\System32\windows_update.exe`
- Destination: `203.0.113.80:443`
- Signed: true
- Classification: expected_update_traffic

The baseline and expected-update events provide negative evidence that the detector is not simply alerting on every outbound connection.

## Analyst Assessment

### Observed

The telemetry demonstrates a highly regular sequence of outbound connections from `svchost_update.exe` to a single destination. The process also has suspicious characteristics, including an unsigned binary executing from a user-writable directory.

### Interpretation

The combination of repeated fixed-interval communication, a consistent destination, a non-standard destination port, and suspicious process characteristics is consistent with automated beaconing behavior.

### Not Established

The available telemetry does not independently establish:

- successful command execution by a remote operator;
- data exfiltration;
- persistence beyond the observed process;
- compromise of the host;
- malicious ownership of the destination;
- the exact application-layer protocol;
- the identity of an external threat actor.

The case should therefore be treated as a high-priority suspicious network activity investigation rather than as confirmed compromise.

## MITRE ATT&CK Assessment

The detection engine associates the alert with:

- T1071 — Application Layer Protocol
- T1071.001 — Web Protocols
- T1573 — Encrypted Channel

These mappings require qualification.

The telemetry demonstrates network communication over a connection that includes TLS-related metadata, but it does not independently prove malicious application-layer protocol use or adversarial encrypted-channel usage.

Accordingly, these techniques should be treated as **suspected/analytical mappings**, not confirmed attacker behavior.

## Investigation Conclusion

The alert is valid and well-supported by the available synthetic telemetry.

The strongest evidence is the combination of:

1. Seven repeated outbound connections.
2. A consistent 60-second interval.
3. 100% interval regularity.
4. A single suspicious process.
5. Execution from a user-writable path.
6. Unsigned process characteristics.
7. Process/network correlation evidence.
8. Benign baseline traffic that was not detected.

The activity is highly consistent with automated C2-style beaconing in the laboratory scenario.

However, the available evidence does not establish confirmed host compromise or identify a real-world threat actor.

## Recommended Next Investigation Actions

1. Preserve the relevant telemetry and generated alert.
2. Review the process execution chain for `svchost_update.exe`.
3. Inspect the process file hash and binary metadata if available.
4. Search for additional network activity from the same host, process, and destination.
5. Search for the same process name across other laboratory hosts.
6. Review persistence-related telemetry if available.
7. Inspect DNS and proxy telemetry if available.
8. Determine whether any application-layer protocol can be established from additional evidence.
9. Continue containment and response decisions according to the laboratory response workflow.

## Evidence Limitations

This case uses synthetic laboratory telemetry and documentation/example network indicators. It is not evidence of a real-world compromise.

No production environment, real credential, personal information, or real-world threat actor attribution is claimed.
