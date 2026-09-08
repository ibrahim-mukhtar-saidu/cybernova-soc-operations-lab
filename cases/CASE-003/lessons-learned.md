# CASE-003 Lessons Learned

## Detection Engineering

Suspicious PowerShell activity is more useful when multiple contextual signals are correlated rather than relying on a single command-line keyword.

This case combines:

- Encoded-command indicators
- Office parent-process context
- Hidden-window execution
- Network correlation
- Child-process correlation

## Triage

The two alerts contain different levels of supporting context.

EVT-003006 contains encoded execution and a suspicious Office parent.

EVT-003007 contains those indicators plus hidden execution, network activity, and a child process.

This distinction helps analysts prioritize investigation.

## Negative Testing

Legitimate PowerShell activity was deliberately included in the dataset.

The detection must distinguish suspicious combinations from routine administrative PowerShell usage.

## Evidence Handling

The case reinforces separation between:

- Observed evidence
- Analyst interpretation
- Confirmed findings
- Hypotheses
- Recommended actions

This prevents synthetic evidence from being overstated as a confirmed real-world incident.

## Future Improvements

Future versions could add:

- PowerShell script-block telemetry
- Windows Event Log correlation
- File hashes
- Parent document metadata
- DNS telemetry
- EDR process lineage
- More benign Office automation
- Additional negative test cases
- More granular risk-score validation
