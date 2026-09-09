# CASE-002 — Incident Response

## Response Objective

The response objective is to contain and investigate the observed password-spraying activity while preserving evidence and avoiding unsupported conclusions.

The alert indicates high-confidence password-spraying behavior from `198.51.100.40` against multiple accounts on `lab-auth-01`.

The successful authentication for `alice` increases investigation priority, but the available telemetry does not establish account compromise.

## Initial Response Priority

**Severity:** High
**Confidence:** High
**Current Status:** Open

The response should prioritize:

1. Validation of whether the authentication activity was authorized.
2. Preservation of supporting authentication evidence.
3. Investigation of the successful authentication for `alice`.
4. Identification of any post-authentication activity.
5. Assessment of whether additional accounts or hosts were affected.

## Evidence Preservation

Preserve the following laboratory evidence:

- `cases/CASE-002/alert.json`
- `telemetry/authentication/CASE-002-authentication-events.jsonl`
- Supporting event IDs `EVT-002001` through `EVT-002014`
- Successful authentication `EVT-002008`
- Relevant authentication events before and after the detection window
- Detection configuration for `DET-AUTH-002`

Evidence should remain unchanged during analysis.

Analysts should record any derived artifacts separately from original telemetry.

## Containment

If the activity were confirmed unauthorized in an authorized operational environment, appropriate containment could include:

- temporarily blocking the identified source
- applying authentication rate limits
- enforcing account lockout or adaptive controls
- requiring additional authentication controls
- protecting affected accounts
- restricting exposed SSH access where appropriate

Containment actions should be proportional to validated risk and organizational policy.

For this laboratory case, no real system is being contained.

## Account Protection

Because `EVT-002008` records a successful password authentication for `alice`, investigators should validate:

- whether the login was expected
- whether the source was authorized
- whether the credential was legitimate
- whether the account owner recognizes the activity
- whether subsequent session activity occurred

If unauthorized access were confirmed, account protection could include:

- credential reset
- session termination
- token or key review
- MFA enforcement
- review of account permissions
- investigation of related authentication activity

## Investigation

The investigation should correlate:

- source IP `198.51.100.40`
- host `lab-auth-01`
- targeted accounts
- successful authentication `EVT-002008`
- SSH session telemetry
- command execution
- privilege escalation
- network activity
- file activity
- account changes
- authentication history

The supplied dataset does not contain sufficient post-authentication telemetry to complete these checks.

## Eradication

Eradication actions depend on confirmed findings.

If compromise were established, possible actions in an authorized environment could include:

- removing unauthorized persistence
- terminating malicious sessions
- resetting compromised credentials
- removing unauthorized keys
- correcting insecure authentication configuration
- addressing exposed services
- reviewing related systems for the same activity

No eradication action is claimed for this laboratory case because compromise has not been established.

## Recovery

If compromise were confirmed, recovery should include:

1. Restore affected services to a trusted state.
2. Validate authentication controls.
3. Confirm that unauthorized access has ended.
4. Monitor for recurrence.
5. Review related accounts and systems.
6. Document recovery validation.

For this case, recovery is not currently applicable.

## Escalation Criteria

Escalate the investigation if any of the following are confirmed:

- unauthorized successful authentication
- suspicious SSH session activity
- privilege escalation
- persistence
- lateral movement
- malicious command execution
- unauthorized account changes
- suspicious network connections
- evidence of data access or exfiltration
- additional hosts affected
- repeated password-spraying activity

## Closure Criteria

Do not close the case solely because the password-spraying alert is technically valid.

The case may be closed after appropriate investigation determines that:

- the activity was authorized, or
- unauthorized activity was contained and investigated, with no further evidence requiring escalation.

The closure record should document the evidence reviewed and the final determination.

## Detection Feedback

The response should feed detection engineering improvements.

Potential improvements include:

- account-centric correlation
- cross-host source correlation
- longer detection windows for low-and-slow spraying
- source rotation detection
- successful-authentication escalation
- post-authentication session correlation

Any detection change should be accompanied by regression tests using positive and negative laboratory telemetry.

## Response Limitations

This is a synthetic SOC laboratory case.

No real account, host, credential, source IP reputation, or production containment action is being claimed.

The available telemetry does not establish unauthorized access, account compromise, persistence, lateral movement, or data impact.
