# CASE-003 Threat Intelligence

## Intelligence Assessment

CASE-003 uses synthetic laboratory telemetry and documentation/test network indicators.

No external threat-intelligence attribution is made from this dataset.

## Network Context

The observed network event contains:

- Source IP: `192.0.2.53`
- Destination IP: `203.0.113.80`
- Domain: `updates.example.test`
- Port: `443`
- Protocol: HTTPS

These values are intentionally represented as laboratory/test indicators.

## Intelligence Boundary

An HTTPS connection does not by itself establish command-and-control, malware delivery, or data exfiltration.

An encoded PowerShell command also does not independently establish malware execution.

The detection becomes more significant because multiple observable characteristics occur together:

1. PowerShell execution.
2. Encoded command indicators.
3. Microsoft Word as the parent process.
4. Hidden-window execution.
5. Correlated outbound HTTPS activity.
6. Correlated child-process activity.

## Recommended Enrichment

If the pattern occurred in an authorized production environment, analysts should:

1. Identify the originating Word document.
2. Review document provenance.
3. Decode the PowerShell command safely.
4. Inspect the complete process tree.
5. Review DNS, proxy, firewall, and EDR telemetry.
6. Validate the destination against approved infrastructure.
7. Search for the same command-line pattern across endpoints.
8. Review related authentication activity.
9. Compare relevant hashes and filenames against approved software and intelligence sources.

These are recommendations only. No real-world infrastructure was investigated.
