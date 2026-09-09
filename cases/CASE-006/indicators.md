# CASE-006 — Indicators and Evidence

## Indicator Handling

All indicators in this case are derived from synthetic laboratory telemetry.

They should be treated as investigation pivots rather than confirmed real-world malicious infrastructure.

## Network Indicators

### Source IP

`203.0.113.50`

Observed as the source of all six suspicious web requests.

### Destination Host

`lab-web-01`

The suspicious activity targeted this laboratory web server.

## Web Indicators

### Targeted Paths

- `/products`
- `/login`

### SQL Injection Techniques

Observed indicators include:

- Boolean `OR` conditions.
- `UNION SELECT`.
- `AND 1=1`.
- `AND 1=2`.
- SQL comment markers.

These indicators appeared across `EVT-006003` through `EVT-006008`.

## Tooling Indicator

### User Agent

`sqlmap/1.8`

The user agent was present on all six suspicious requests.

This is a useful detection and hunting indicator, but user-agent strings can be spoofed and should not independently establish attacker identity.

## HTTP Response Indicators

The suspicious sequence produced:

- HTTP 500 responses on `EVT-006003` and `EVT-006004`.
- HTTP 200 responses on `EVT-006005` through `EVT-006008`.

Response status alone does not establish successful SQL injection.

## Benign Comparison Indicators

The following events provide negative evidence:

- `EVT-006001`
- `EVT-006002`
- `EVT-006009`
- `EVT-006010`

These requests originated from other source addresses, used `Mozilla/5.0`, and contained normal application parameters.

## Behavioral Indicators

The strongest behavioral indicators are:

- six requests from the same source;
- multiple SQL injection techniques;
- automated tooling identified by user agent;
- repeated targeting of `/products`;
- expansion to `/login`;
- server errors during initial probing;
- boolean differential testing.

## Evidence Classification

### Observed

The telemetry directly demonstrates the suspicious requests, payload patterns, source address, targeted paths, user agent, and HTTP response codes.

### Analyst Interpretation

The activity is strongly consistent with automated SQL injection probing.

### Not Established

The available evidence does not establish:

- successful SQL injection;
- unauthorized database access;
- data retrieval;
- database modification;
- web-server compromise;
- credential theft;
- persistence;
- lateral movement;
- attacker attribution.

## Intelligence Handling

The source IP uses a documentation/test range and the case domain is not a real-world infrastructure indicator.

No external reputation or attribution should be inferred from these laboratory values.

## Hunting Use

The indicators can be used to pivot across authorized telemetry by:

- source IP;
- targeted path;
- SQL injection pattern;
- user agent;
- host;
- response status;
- application parameter.

## Handling Recommendation

In a real authorized investigation, preserve the original request records and correlate them with application and database telemetry before determining whether exploitation occurred.

## Laboratory Limitation

CASE-006 is synthetic defensive SOC telemetry. The indicators demonstrate investigation methodology and detection engineering rather than evidence of a real-world attack.
