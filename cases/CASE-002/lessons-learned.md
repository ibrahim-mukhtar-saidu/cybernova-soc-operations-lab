# CASE-002 — Lessons Learned

## Summary

CASE-002 demonstrates a high-confidence password-spraying detection against a laboratory SSH service.

The investigation also demonstrates the importance of separating a confirmed behavioral detection from an unconfirmed compromise assessment.

## Key Lessons

### 1. Detection and compromise are different conclusions

The password-spraying behavior is confirmed within the laboratory telemetry.

The successful authentication for `alice` is observed evidence, but it does not independently prove compromise.

### 2. Successful authentication requires investigation

A successful login occurring during suspicious authentication activity should increase investigation priority.

The next step is to correlate session, endpoint, privilege, and network telemetry rather than immediately declaring compromise.

### 3. Short detection windows can miss distributed activity

The current detection uses a five-minute window.

An attacker could distribute authentication attempts over longer periods or across multiple sources.

Future detection engineering should consider longer-window and cross-source correlation.

### 4. Account-centric hunting is valuable

Source-based detection identifies concentrated spraying activity effectively, but account-centric analysis can reveal attacks distributed across multiple source addresses.

### 5. Evidence classification improves analytical discipline

Observed telemetry should remain separate from analyst interpretation.

This prevents assumptions about authorization, attribution, or compromise from becoming unsupported facts.

## Detection Engineering Improvements

Potential improvements identified during the investigation:

- cross-source password-spraying correlation
- longer behavioral windows
- account-centric aggregation
- successful-authentication escalation
- post-authentication session correlation
- source-rotation detection
- baseline-aware authentication analytics

Each improvement should be validated using positive and negative laboratory telemetry.

## Hunting Improvements

Future hunts should include:

- longer authentication history
- cross-host correlation
- repeated targeting of the same account set
- source rotation
- post-authentication activity
- privilege escalation
- network activity following successful authentication

## Response Improvements

Response procedures should explicitly distinguish:

1. suspicious authentication behavior
2. successful authentication
3. validated unauthorized access
4. confirmed account compromise

This allows containment and escalation decisions to remain proportional to the evidence.

## Evidence Improvements

Future laboratory cases could include:

- SSH session identifiers
- command execution telemetry
- privilege escalation events
- endpoint process telemetry
- network flow telemetry
- account-management events
- credential-reset events

These additions would allow the investigation to progress beyond authentication evidence.

## Portfolio Evidence

This case demonstrates practical capability in:

- authentication detection engineering
- alert validation
- SOC investigation
- timeline reconstruction
- indicator analysis
- threat intelligence assessment
- threat hunting
- incident response
- MITRE ATT&CK mapping
- evidence-based reporting
- detection feedback

## Final Lesson

The strongest SOC conclusion is not always the most severe conclusion.

For CASE-002, the defensible conclusion is:

**Password spraying confirmed; successful authentication observed; compromise not established.**

That distinction demonstrates evidence-driven SOC analysis.

## Laboratory Limitation

This case uses synthetic laboratory telemetry.

No real-world incident, attacker attribution, credential compromise, production containment, or employment experience is claimed.
