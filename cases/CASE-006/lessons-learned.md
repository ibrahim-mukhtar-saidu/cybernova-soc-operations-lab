# CASE-006 — Lessons Learned

## Investigation Summary

CASE-006 demonstrated a complete defensive workflow for investigating suspicious SQL injection activity:

**Telemetry → Detection → Alert → Triage → Evidence Validation → Timeline → Indicators → Threat Intelligence → Hunting → Response → Final Assessment**

The investigation confirmed that the detection accurately identified a concentrated sequence of automated SQL injection probing.

## Key Lessons

### 1. Multiple Indicators Increase Confidence

A single suspicious request may be ambiguous.

Confidence increased substantially because the activity combined:

- repeated requests;
- multiple SQL injection techniques;
- automated tooling;
- targeted application parameters;
- multiple endpoints;
- server errors.

Detection logic should therefore favor correlated behavioral evidence where practical.

### 2. Detection Does Not Equal Compromise

The alert identified suspicious behavior but did not prove successful exploitation.

This distinction is important for accurate SOC reporting.

Successful exploitation would require independent application or database evidence.

### 3. HTTP Status Codes Require Context

HTTP 500 responses can indicate application errors but do not independently prove SQL injection success.

HTTP 200 responses likewise do not prove that a malicious request succeeded.

Application response content and backend telemetry are necessary for stronger conclusions.

### 4. User-Agent Values Are Useful but Spoofable

The `sqlmap/1.8` user agent was a valuable supporting indicator.

However, user-agent strings should not independently establish attacker identity or maliciousness.

### 5. Negative Evidence Matters

Normal requests in the same telemetry set provided a baseline for comparison.

This helps distinguish suspicious behavior from ordinary application traffic.

### 6. Investigation Should Preserve Uncertainty

The final assessment deliberately separates:

- observed evidence;
- analyst interpretation;
- unestablished conclusions.

This prevents overclaiming and improves the defensibility of SOC reporting.

## Detection Engineering Improvements

Future versions of `DET-WEB-001` should consider:

- URL decoding before pattern inspection;
- parameter normalization;
- encoded SQL injection detection;
- source rotation detection;
- distributed low-and-slow detection;
- cross-application correlation;
- WAF integration;
- database audit correlation.

Each improvement should be accompanied by regression tests.

## Process Improvements

The investigation workflow should continue to emphasize:

1. preserve original evidence;
2. validate alert context;
3. establish a timeline;
4. separate facts from interpretation;
5. hunt for related activity;
6. assess scope;
7. determine exploitation status;
8. document limitations;
9. feed findings back into detection engineering.

## False-Positive Considerations

Future detection testing should include legitimate application requests containing:

- ordinary search parameters;
- encoded characters;
- error-generating but legitimate input;
- security-testing traffic in authorized environments;
- normal automated clients.

The objective is to improve detection sensitivity without treating every unusual parameter as malicious.

## Evidence Quality

CASE-006 demonstrates that strong investigation evidence should be:

- timestamped;
- attributable to source events;
- reproducible from telemetry;
- clearly classified;
- separated from analyst interpretation;
- preserved independently from derived reports.

## Final Lesson

The most important lesson from CASE-006 is that a strong SOC investigation does not simply identify suspicious activity.

It must establish **what the telemetry proves, what it strongly suggests, and what remains unproven**.

That distinction is essential for reliable detection engineering and professional incident reporting.

## Laboratory Limitation

CASE-006 uses synthetic defensive SOC telemetry and demonstrates investigation methodology. The lessons learned are intended for laboratory portfolio evidence and do not represent findings from a real production incident.
