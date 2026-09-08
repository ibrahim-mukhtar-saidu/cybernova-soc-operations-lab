# CASE-003 Response

## Response Objective

Define the appropriate response workflow for the suspicious PowerShell execution pattern while maintaining evidence integrity.

## Immediate Analyst Actions

1. Preserve the original telemetry and alert output.
2. Record alert IDs and supporting event IDs.
3. Validate the affected host and user context.
4. Confirm whether the PowerShell execution was authorized.
5. Preserve the relevant process tree.
6. Identify the originating Office document if available.
7. Review correlated network activity.
8. Decode the PowerShell command safely in an isolated analysis environment.

## Conditional Containment

If the activity is confirmed unauthorized and operational controls permit it:

- Isolate the affected endpoint.
- Restrict the affected account if compromise is confirmed.
- Block confirmed malicious infrastructure.
- Preserve forensic evidence before destructive remediation.
- Escalate according to incident severity.

Containment should be based on validated evidence rather than the detection alone.

## Recovery

After confirmation and evidence preservation:

- Remove confirmed malicious artifacts.
- Restore affected systems from trusted sources when required.
- Reset compromised credentials.
- Validate endpoint health.
- Monitor for recurrence.

## Response Status

No real-world containment, blocking, credential reset, or remediation was performed.

This is a controlled SOC operations laboratory case.
