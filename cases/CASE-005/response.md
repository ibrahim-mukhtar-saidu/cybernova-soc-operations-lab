# CASE-005 — Incident Response

## Response Objective

Define the appropriate SOC response to the suspicious network activity detected by DET-NET-001.

This document describes the response workflow for the synthetic laboratory scenario. It does not claim that containment, eradication, or recovery actions were executed against a production system.

## Initial Response Assessment

**Alert:** ALERT-CASE-005-DET-NET-001

**Severity:** High

**Confidence:** High

**Risk Score:** 100

**Primary Host:** lab-ws-01

**Process:** svchost_update.exe

**Destination:** 198.51.100.77:8443

The combination of repeated regular communication, suspicious process characteristics, and process/network correlation warrants high-priority investigation and containment consideration.

## Evidence Preservation

Before destructive response actions, preserve the available evidence.

Recommended evidence to preserve:

- generated alert JSON;
- original CASE-005 network telemetry;
- relevant process-start telemetry;
- process/network correlation event;
- detection configuration;
- investigation timeline;
- indicator inventory;
- hunting results.

Evidence should be retained in a manner that preserves event identifiers and timestamps.

The laboratory case currently preserves the generated alert and supporting investigation documents.

## Containment Decision

### Recommended Laboratory Action

For a real authorized environment, isolate the affected host from unnecessary network communication while maintaining approved forensic access.

For this laboratory scenario, containment is represented as a documented response decision rather than an executed production action.

### Containment Rationale

Containment would be justified by:

- high alert severity;
- high detection confidence;
- seven regular outbound connections;
- suspicious unsigned process;
- user-writable execution path;
- process/network correlation;
- risk score of 100.

The purpose of containment would be to prevent continued suspicious communication while preserving evidence.

## Network Containment

Recommended controls for an equivalent authorized environment:

1. Restrict outbound communication from the affected host.
2. Prevent communication with the identified destination.
3. Preserve required forensic and management access.
4. Monitor for attempted reconnection.
5. Record the time and scope of each containment action.

No real network blocking action is claimed for this laboratory case.

## Process Containment

The suspicious process should be investigated before termination when possible.

Recommended actions:

1. Identify the process owner.
2. Capture process metadata.
3. Capture the executable hash.
4. Review process ancestry.
5. Preserve relevant volatile evidence where authorized.
6. Determine whether the process is persistent.
7. Terminate or quarantine the process according to the approved response procedure.

The current case does not contain sufficient evidence to claim that the process was actually terminated or quarantined.

## Eradication

If additional evidence confirmed malicious execution in an equivalent real environment, eradication would include:

- removing the malicious executable;
- removing associated persistence mechanisms;
- identifying and removing related artifacts;
- rotating affected credentials if applicable;
- blocking confirmed malicious infrastructure;
- validating that the malicious process cannot restart.

These actions are recommendations only for the laboratory case.

## Recovery

After eradication, recovery should include:

1. Restore the host to a trusted state.
2. Apply required security updates.
3. Validate endpoint security controls.
4. Reconnect the host under monitoring.
5. Monitor for recurrence of the network pattern.
6. Verify that the suspicious process does not return.
7. Confirm that no related indicators remain active.

Recovery is not claimed as completed in this synthetic case.

## Escalation

Escalation would be appropriate if additional evidence established:

- confirmed malware execution;
- successful remote command execution;
- credential compromise;
- persistence;
- lateral movement;
- data exfiltration;
- multiple affected hosts;
- repeated communication after containment.

The current telemetry does not establish these conditions.

## Response Decision Matrix

| Condition | Recommended Response |
|---|---|
| Suspicious beaconing only | Continue investigation and increase monitoring |
| Suspicious process confirmed | Consider process containment |
| Confirmed malicious executable | Quarantine/remove according to approved procedure |
| Persistence identified | Eradicate persistence and investigate related activity |
| Multiple hosts affected | Expand scope and escalate |
| Confirmed data exfiltration | Escalate as a security incident and preserve additional evidence |
| Confirmed compromise | Execute full incident-response procedure |

## Closure Criteria

The case should not be closed solely because the beaconing alert stopped.

Recommended closure criteria:

- suspicious activity investigated;
- relevant evidence preserved;
- scope assessed;
- additional affected hosts considered;
- required containment completed;
- eradication completed where necessary;
- recovery validated;
- detection improvements identified;
- final report completed;
- lessons learned documented.

For this laboratory case, closure remains a documented workflow state rather than a claim of real-world remediation.

## Detection Feedback

The response process identifies useful defensive improvements:

- collect executable hashes;
- collect richer process ancestry;
- collect DNS/proxy telemetry;
- retain certificate metadata;
- improve cross-host correlation;
- maintain known-good destination baselines;
- correlate process reputation with network behavior.

Any detection changes should be tested against both positive and negative laboratory telemetry before adoption.

## Response Limitations

This case is based on synthetic laboratory telemetry.

No production host was isolated, no real process was terminated, no real infrastructure was blocked, and no real credentials were rotated as part of this case.

The response documentation demonstrates the decision-making workflow expected during an authorized SOC investigation.
