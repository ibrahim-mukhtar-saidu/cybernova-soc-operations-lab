# CASE-006 — SQL Injection Investigation

## Case Objective

Investigate `ALERT-CASE-006-DET-WEB-001` and determine whether the observed web activity is consistent with SQL injection probing, whether exploitation can be established, and what additional evidence would be required.

## Alert Validation

The detection engine generated one high-severity, high-confidence alert:

- Detection: `DET-WEB-001`
- Alert: `ALERT-CASE-006-DET-WEB-001`
- Source IP: `203.0.113.50`
- Host: `lab-web-01`
- Suspicious requests: 6
- Targeted paths: `/login`, `/products`
- Risk score: 100
- First seen: `2026-09-09T09:01:00Z`
- Last seen: `2026-09-09T09:02:40Z`

The alert is supported by `EVT-006003` through `EVT-006008`.

## Observed Evidence

The suspicious source generated six requests using `sqlmap/1.8` as the user agent.

Observed SQL injection indicators include:

- Boolean `OR` conditions.
- `UNION SELECT` syntax.
- Boolean comparison tests using `AND 1=1` and `AND 1=2`.
- SQL comment markers.
- Automated SQL injection tooling identified by the user agent.

The requests targeted:

- `/products`
- `/login`

The first two suspicious requests returned HTTP 500 responses. Later requests returned HTTP 200 responses.

## Event Assessment

### EVT-006003

A request against `/products` contained a boolean-style SQL injection payload and returned HTTP 500. The user agent was `sqlmap/1.8`.

### EVT-006004

A request against `/products` contained `UNION SELECT` syntax and a SQL comment marker. The response was HTTP 500.

### EVT-006005

A request against `/products` tested `AND 1=1` and returned HTTP 200.

### EVT-006006

A request against `/products` tested `AND 1=2` and returned HTTP 200.

### EVT-006007

A request against `/products` used an `OR 1=1` condition and returned HTTP 200.

### EVT-006008

A request against `/login` used a SQL comment marker against an administrative username value and returned HTTP 200.

## Baseline and Negative Evidence

Normal web traffic was observed from other source addresses:

- `EVT-006001` — `/search?q=normal`, HTTP 200, Mozilla browser.
- `EVT-006002` — `/products?id=10`, HTTP 200, Mozilla browser.
- `EVT-006009` — `/products?id=25`, HTTP 200, Mozilla browser.
- `EVT-006010` — `/search?q=laptop`, HTTP 200, Mozilla browser.

These events provide a useful baseline because they do not contain the observed SQL injection indicators and use a normal browser user agent.

## Analyst Assessment

The six suspicious requests are strongly consistent with automated SQL injection probing.

Confidence is increased by:

- repeated requests from the same source;
- multiple distinct SQL injection techniques;
- use of `sqlmap/1.8`;
- targeting of application parameters;
- server errors associated with early probes;
- progression from boolean tests to `UNION SELECT` and comment-based payloads.

However, the available telemetry does not establish that SQL injection was successfully exploited.

HTTP 200 responses alone do not demonstrate unauthorized access, and HTTP 500 responses do not establish successful database interaction.

## Exploitation Assessment

Successful exploitation is **not established**.

Additional evidence would be required, including:

- application logs;
- database query logs;
- database audit records;
- response-body comparison;
- authenticated application activity;
- evidence of unauthorized data retrieval;
- evidence of modified application or database state.

## Scope Assessment

The available dataset demonstrates activity against `lab-web-01`.

It does not establish:

- compromise of the web server;
- compromise of the database;
- unauthorized data access;
- credential theft;
- persistence;
- lateral movement;
- data exfiltration;
- attacker attribution.

## MITRE ATT&CK Assessment

The activity is analytically mapped to:

- `T1190 — Exploit Public-Facing Application`

This mapping represents an investigation hypothesis based on observed web exploitation probing. It does not establish successful exploitation.

## Investigation Conclusion

`ALERT-CASE-006-DET-WEB-001` is valid.

The evidence strongly supports classification as suspicious SQL injection probing against the laboratory web application.

The evidence does not support classifying the application or database as compromised without additional independent validation.

## Recommended Next Actions

1. Preserve web-server and application logs.
2. Review database audit/query logs for corresponding requests.
3. Compare application responses for boolean-test behavior.
4. Determine whether any unauthorized records were returned.
5. Review the source IP across other authorized laboratory web services.
6. Inspect application parameter handling and SQL query construction.
7. Verify use of parameterized queries or equivalent safe database access controls.
8. Record any confirmed exploitation separately from the detection itself.

## Evidence Limitation

CASE-006 uses synthetic laboratory telemetry for defensive SOC engineering. The observed source and web activity should not be interpreted as a real-world attack or attribution.
