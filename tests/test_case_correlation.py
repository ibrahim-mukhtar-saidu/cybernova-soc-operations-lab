import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from case_correlation import correlate_multi_stage_attack


def _alert(
    detection_id,
    alert_id,
    timestamp,
    *,
    host="lab-linux-10",
    user="root",
    source_ip="198.51.100.90",
    event_ids=None,
):
    return {
        "alert_id": alert_id,
        "detection_id": detection_id,
        "detection_name": detection_id,
        "detection_version": "1.0",
        "status": "open",
        "severity": "high",
        "confidence": "high",
        "timestamp": timestamp,
        "host": host,
        "user": user,
        "source_ip": source_ip,
        "supporting_event_ids": event_ids or [f"{alert_id}-EVENT"],
    }


def test_multi_stage_attack_correlates_required_sequence():
    alerts = [
        _alert(
            "DET-AUTH-001",
            "ALERT-CASE-010-AUTH-001",
            "2026-09-09T10:00:00Z",
            event_ids=["EVT-010001", "EVT-010002"],
        ),
        _alert(
            "DET-AUTH-003",
            "ALERT-CASE-010-AUTH-003",
            "2026-09-09T10:08:00Z",
            event_ids=["EVT-010003", "EVT-010004"],
        ),
        _alert(
            "DET-LINUX-001",
            "ALERT-CASE-010-LINUX-001",
            "2026-09-09T10:18:00Z",
            source_ip=None,
            event_ids=["EVT-010005"],
        ),
    ]

    correlations = correlate_multi_stage_attack(alerts)

    assert len(correlations) == 1

    alert = correlations[0]

    assert alert["alert_id"] == "ALERT-CASE-010-DET-CORR-001"
    assert alert["detection_id"] == "DET-CORR-001"
    assert alert["severity"] == "critical"
    assert alert["confidence"] == "high"
    assert alert["host"] == "lab-linux-10"
    assert alert["user"] == "root"
    assert alert["source_ip"] == "198.51.100.90"
    assert alert["stage_count"] == 3

    assert [stage["detection_id"] for stage in alert["stages"]] == [
        "DET-AUTH-001",
        "DET-AUTH-003",
        "DET-LINUX-001",
    ]

    assert alert["supporting_alert_ids"] == [
        "ALERT-CASE-010-AUTH-001",
        "ALERT-CASE-010-AUTH-003",
        "ALERT-CASE-010-LINUX-001",
    ]

    assert alert["supporting_event_ids"] == [
        "EVT-010001",
        "EVT-010002",
        "EVT-010003",
        "EVT-010004",
        "EVT-010005",
    ]


def test_multi_stage_attack_requires_all_stages():
    alerts = [
        _alert(
            "DET-AUTH-001",
            "ALERT-CASE-010-AUTH-001",
            "2026-09-09T10:00:00Z",
        ),
        _alert(
            "DET-AUTH-003",
            "ALERT-CASE-010-AUTH-003",
            "2026-09-09T10:08:00Z",
        ),
    ]

    assert correlate_multi_stage_attack(alerts) == []


def test_multi_stage_attack_rejects_events_outside_window():
    alerts = [
        _alert(
            "DET-AUTH-001",
            "ALERT-CASE-010-AUTH-001",
            "2026-09-09T10:00:00Z",
        ),
        _alert(
            "DET-AUTH-003",
            "ALERT-CASE-010-AUTH-003",
            "2026-09-09T10:08:00Z",
        ),
        _alert(
            "DET-LINUX-001",
            "ALERT-CASE-010-LINUX-001",
            "2026-09-09T10:31:00Z",
            source_ip=None,
        ),
    ]

    assert correlate_multi_stage_attack(alerts) == []


def test_multi_stage_attack_rejects_conflicting_source_ips():
    alerts = [
        _alert(
            "DET-AUTH-001",
            "ALERT-CASE-010-AUTH-001",
            "2026-09-09T10:00:00Z",
            source_ip="198.51.100.90",
        ),
        _alert(
            "DET-AUTH-003",
            "ALERT-CASE-010-AUTH-003",
            "2026-09-09T10:08:00Z",
            source_ip="198.51.100.91",
        ),
        _alert(
            "DET-LINUX-001",
            "ALERT-CASE-010-LINUX-001",
            "2026-09-09T10:18:00Z",
            source_ip=None,
        ),
    ]

    assert correlate_multi_stage_attack(alerts) == []


def test_multi_stage_attack_rejects_different_host_or_user():
    alerts = [
        _alert(
            "DET-AUTH-001",
            "ALERT-CASE-010-AUTH-001",
            "2026-09-09T10:00:00Z",
        ),
        _alert(
            "DET-AUTH-003",
            "ALERT-CASE-010-AUTH-003",
            "2026-09-09T10:08:00Z",
            host="lab-linux-11",
        ),
        _alert(
            "DET-LINUX-001",
            "ALERT-CASE-010-LINUX-001",
            "2026-09-09T10:18:00Z",
            source_ip=None,
        ),
    ]

    assert correlate_multi_stage_attack(alerts) == []

def test_multi_stage_attack_uses_first_seen_when_timestamp_is_missing():
    alerts = [
        {
            "alert_id": "ALERT-AUTH-001",
            "detection_id": "DET-AUTH-001",
            "status": "open",
            "confidence": "high",
            "host": "lab-linux-10",
            "user": "root",
            "timestamp": "2026-09-09T10:02:03Z",
            "source_ip": "198.51.100.90",
            "supporting_event_ids": ["EVT-010001"],
        },
        {
            "alert_id": "ALERT-AUTH-003",
            "detection_id": "DET-AUTH-003",
            "status": "open",
            "confidence": "high",
            "host": "lab-linux-10",
            "user": "root",
            "first_seen": "2026-09-09T10:03:00Z",
            "source_ip": "198.51.100.90",
            "supporting_event_ids": ["EVT-010007"],
        },
        {
            "alert_id": "ALERT-LINUX-001",
            "detection_id": "DET-LINUX-001",
            "status": "open",
            "confidence": "high",
            "host": "lab-linux-10",
            "user": "root",
            "timestamp": "2026-09-09T10:12:00Z",
            "supporting_event_ids": ["EVT-010013"],
        },
    ]

    correlations = correlate_multi_stage_attack(alerts)

    assert len(correlations) == 1
    assert correlations[0]["stage_count"] == 3
    assert correlations[0]["stages"][1]["timestamp"] == "2026-09-09T10:03:00Z"
