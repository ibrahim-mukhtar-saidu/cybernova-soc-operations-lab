# CASE-006 — Response and Containment

## Response Objective

Define a controlled defensive response to the detected SQL injection activity while avoiding unsupported claims of successful exploitation.

The response applies to the synthetic laboratory environment represented by CASE-006.

## Initial Classification

- Alert: `ALERT-CASE-006-DET-WEB-001`
- Detection: `DET-WEB-001`
- Severity: High
- Confidence: High
- Activity: Automated SQL injection probing
- Confirmed exploitation: No

The available telemetry demonstrates suspicious probing but does not establish unauthorized database access or application compromise.

## Immediate Actions

1. Preserve the original web telemetry.
2. Preserve the generated alert and investigation evidence.
3. Record the alert and supporting event IDs.
4. Review web-server and application logs.
5. Correlate suspicious requests with database audit telemetry.
6. Determine whether any suspicious requests resulted in unauthorized access or state changes.

## Containment

If equivalent activity were confirmed against an authorized production application, containment options could include:

- blocking or rate-limiting the source;
- enabling or strengthening WAF protections;
- restricting affected application endpoints where operationally safe;
- temporarily disabling vulnerable functionality if exploitation is confirmed;
- increasing monitoring for related requests.

Containment actions should be based on validated evidence and operational impact.

## Eradication

If successful exploitation were independently confirmed, eradication should include:

- correcting the vulnerable query construction;
- enforcing parameterized queries;
- reviewing affected application components;
- removing unauthorized changes;
- rotating affected credentials where compromise is established;
- validating application and database integrity.

No eradication of a confirmed compromise is claimed for this laboratory case.

## Recovery

Recovery should include:

- validating application functionality;
- confirming database integrity;
- reviewing security controls;
- monitoring for recurrence;
- validating that the detection remains effective after remediation.

## Escalation Conditions

Escalate the incident if investigation identifies:

- confirmed unauthorized database access;
- unauthorized data retrieval;
- database modification;
- credential compromise;
- persistent unauthorized access;
- exploitation of additional application components;
- related activity against other systems.

## Evidence Preservation

Preserve:

- original web requests;
- alert JSON;
- application logs;
- WAF events;
- database audit records;
- relevant timestamps;
- affected endpoint information;
- investigation notes.

Maintain the original evidence separately from analyst-generated interpretation.

## Detection Feedback

The investigation suggests improvements to `DET-WEB-001`, including:

- URL decoding before indicator matching;
- normalized parameter inspection;
- encoded SQL injection detection;
- correlation across applications;
- source rotation detection;
- low-and-slow attack detection;
- application and database correlation.

## Response Decision

Based on the current evidence, the appropriate laboratory response is:

**Suspicious SQL injection probing — validate and monitor; do not classify as confirmed compromise.**

## Closure Criteria

CASE-006 should only be closed after:

1. evidence has been preserved;
2. application and database telemetry has been reviewed;
3. exploitation status has been documented;
4. relevant indicators have been recorded;
5. required defensive improvements have been identified;
6. detection feedback has been documented.

## Laboratory Limitation

CASE-006 uses synthetic defensive telemetry. The response procedures demonstrate SOC investigation and incident-response methodology and do not represent actions performed against real production infrastructure.
