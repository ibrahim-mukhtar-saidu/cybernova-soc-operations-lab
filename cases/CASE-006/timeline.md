# CASE-006 — Investigation Timeline

## Timeline Summary

| Time (UTC) | Event | Activity |
|---|---|---|
| 09:00:00 | EVT-006001 | Normal `/search` request |
| 09:00:10 | EVT-006002 | Normal `/products` request |
| 09:01:00 | EVT-006003 | SQL injection boolean probe; HTTP 500 |
| 09:01:20 | EVT-006004 | `UNION SELECT` probe; HTTP 500 |
| 09:01:40 | EVT-006005 | `AND 1=1` boolean test; HTTP 200 |
| 09:02:00 | EVT-006006 | `AND 1=2` boolean test; HTTP 200 |
| 09:02:20 | EVT-006007 | `OR 1=1` probe; HTTP 200 |
| 09:02:40 | EVT-006008 | SQL comment-based `/login` probe; HTTP 200 |
| 09:03:00 | EVT-006009 | Normal `/products` request |
| 09:03:20 | EVT-006010 | Normal `/search` request |

## Suspicious Activity Sequence

The suspicious sequence began at `09:01:00Z` with a boolean-style SQL injection request against `/products`.

At `09:01:20Z`, the source attempted `UNION SELECT` syntax.

The following requests tested boolean conditions:

- `AND 1=1`
- `AND 1=2`
- `OR 1=1`

The sequence then expanded to the `/login` endpoint at `09:02:40Z`.

All six suspicious requests used the `sqlmap/1.8` user agent.

## Response Behavior

The first two suspicious requests returned HTTP 500 responses.

The subsequent four suspicious requests returned HTTP 200 responses.

Response status alone does not establish successful exploitation. Application response bodies, application logs, and database evidence would be required for that determination.

## Detection Point

`DET-WEB-001` correlated the six suspicious requests from:

- Source IP: `203.0.113.50`
- Host: `lab-web-01`

The detection window covered the suspicious sequence from `09:01:00Z` through `09:02:40Z`.

The resulting alert was:

`ALERT-CASE-006-DET-WEB-001`

## Baseline Activity

Normal requests were observed before and after the suspicious sequence.

The baseline requests used the `Mozilla/5.0` user agent and did not contain SQL injection indicators.

This provides negative evidence that normal web traffic was present in the same laboratory environment.

## Timeline Conclusion

The timeline demonstrates a concentrated sequence of automated SQL injection probing followed by normal comparison traffic.

The sequence is consistent with reconnaissance and exploitation probing, but the available telemetry does not establish successful compromise or unauthorized data access.
