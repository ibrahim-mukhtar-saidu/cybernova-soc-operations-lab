# CASE-006 — Threat Hunting

## Hunting Objective

Identify additional web activity associated with the suspicious SQL injection sequence and determine whether the observed behavior extends beyond the original alert.

The hunting activity is limited to authorized laboratory telemetry.

## Primary Hunting Pivots

### Source IP

`203.0.113.50`

Search for all web requests originating from the source to identify additional targeted endpoints or applications.

### User Agent

`sqlmap/1.8`

Search for automated SQL injection tooling indicators across available web telemetry.

### Targeted Paths

- `/products`
- `/login`

Search for additional requests against these endpoints, including requests that did not trigger the detection threshold.

### SQL Injection Patterns

Search for:

- `UNION SELECT`
- `AND 1=1`
- `AND 1=2`
- `OR 1=1`
- SQL comment markers

### Response Status

Review HTTP 500 and HTTP 200 responses associated with suspicious requests.

Response codes should be correlated with application behavior rather than interpreted as proof of exploitation.

## Suggested Hunting Queries

### Source-Based Hunt

Search authorized web telemetry for:

`source_ip = 203.0.113.50`

Review:

- request count;
- targeted paths;
- timestamps;
- parameters;
- HTTP methods;
- response codes;
- user-agent values.

### User-Agent Hunt

Search for:

`user_agent contains "sqlmap"`

Compare matching events against the detection output.

### Endpoint Hunt

Search for:

`path = /products`

and:

`path = /login`

Review whether additional suspicious parameters or payloads were observed.

### Pattern Hunt

Search request URLs and query parameters for SQL injection indicators.

The search should be case-insensitive where appropriate and should account for URL encoding.

## Scope Expansion

If additional matching events are identified, pivot on:

1. source IP;
2. destination host;
3. targeted application;
4. targeted endpoint;
5. user-agent;
6. timestamp range;
7. related HTTP responses.

Then review application and database telemetry for evidence of successful exploitation.

## Negative Hunting Evidence

The current dataset contains normal requests from other source addresses using `Mozilla/5.0`.

These events provide a baseline for comparison and do not match the suspicious behavioral pattern.

## Hunting Assessment

The available telemetry supports a focused hunt around the source IP, SQL injection patterns, targeted endpoints, and automated tooling indicator.

No additional compromise evidence is established by the current dataset.

## Detection Improvement Opportunities

Future detection engineering should consider:

- URL-decoded pattern matching;
- normalization of HTTP parameters before inspection;
- detection of encoded SQL injection indicators;
- correlation across multiple web applications;
- source rotation detection;
- distributed low-and-slow probing;
- additional WAF and application-layer telemetry;
- database audit correlation.

These improvements can reduce evasion opportunities while avoiding classification based on a single user-agent string or payload.

## Laboratory Limitation

This hunting plan is designed for synthetic defensive SOC telemetry and demonstrates investigation methodology. It does not represent a hunt against real production infrastructure.
