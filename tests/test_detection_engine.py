import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT / "src" / "detection_engine.py"

CASE001_TELEMETRY = (
    ROOT / "telemetry/authentication/CASE-001-authentication-events.jsonl"
)

CASE002_TELEMETRY = (
    ROOT / "telemetry/authentication/CASE-002-authentication-events.jsonl"
)

CASE003_TELEMETRY = (
    ROOT / "telemetry/endpoint/CASE-003-endpoint-events.jsonl"
)

CASE004_TELEMETRY = (
    ROOT / "telemetry/authentication/CASE-004-authentication-events.jsonl"
)


def run_detection(detection_id, input_path, output_path):
    result = subprocess.run(
        [
            sys.executable,
            str(ENGINE),
            "--detection",
            detection_id,
            "--input",
            str(input_path),
            "--output",
            str(output_path),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, (
        f"Detection engine failed.\n"
        f"STDOUT:\n{result.stdout}\n"
        f"STDERR:\n{result.stderr}"
    )

    return json.loads(output_path.read_text(encoding="utf-8"))


def test_auth_001_brute_force_detection(tmp_path):
    output = tmp_path / "auth001.json"

    document = run_detection(
        "DET-AUTH-001",
        CASE001_TELEMETRY,
        output,
    )

    assert document["detection_id"] == "DET-AUTH-001"
    assert document["alert_count"] == 1

    alert = document["alerts"][0]

    assert alert["alert_id"] == "ALERT-CASE-001-DET-AUTH-001"
    assert alert["severity"] == "high"
    assert alert["source_ip"] == "198.51.100.25"
    assert alert["host"] == "lab-auth-01"
    assert alert["user"] == "root"
    assert alert["failed_attempt_count"] == 8
    assert alert["successful_authentication_observed"] is True


def test_auth_002_password_spraying_detection(tmp_path):
    output = tmp_path / "auth002.json"

    document = run_detection(
        "DET-AUTH-002",
        CASE002_TELEMETRY,
        output,
    )

    assert document["detection_id"] == "DET-AUTH-002"
    assert document["alert_count"] == 1

    alert = document["alerts"][0]

    assert alert["alert_id"] == "ALERT-CASE-002-DET-AUTH-002"
    assert alert["severity"] == "high"
    assert alert["confidence"] == "high"
    assert alert["source_ip"] == "198.51.100.40"
    assert alert["host"] == "lab-auth-01"
    assert alert["targeted_user_count"] == 7
    assert alert["failed_attempt_count"] == 13
    assert alert["successful_authentication_observed"] is True


def test_auth_002_success_escalates_alert(tmp_path):
    output = tmp_path / "auth002-success.json"

    document = run_detection(
        "DET-AUTH-002",
        CASE002_TELEMETRY,
        output,
    )

    alert = document["alerts"][0]

    assert alert["successful_authentication_observed"] is True
    assert alert["severity"] == "high"
    assert alert["confidence"] == "high"
    assert alert["successful_authentication_event_id"] == "EVT-002008"
    assert alert["successful_authentication_user"] == "alice"


def test_auth_002_targeted_users_are_correlated(tmp_path):
    output = tmp_path / "auth002-users.json"

    document = run_detection(
        "DET-AUTH-002",
        CASE002_TELEMETRY,
        output,
    )

    alert = document["alerts"][0]

    assert set(alert["targeted_users"]) == {
        "alice",
        "bob",
        "carol",
        "david",
        "erin",
        "frank",
        "grace",
    }


def test_auth_002_supporting_events_exist_in_telemetry(tmp_path):
    output = tmp_path / "auth002-supporting.json"

    document = run_detection(
        "DET-AUTH-002",
        CASE002_TELEMETRY,
        output,
    )

    events = {
        json.loads(line)["event_id"]
        for line in CASE002_TELEMETRY.read_text(encoding="utf-8").splitlines()
        if line.strip()
    }

    alert = document["alerts"][0]

    for event_id in alert["supporting_event_ids"]:
        assert event_id in events


def test_auth_002_noise_does_not_trigger(tmp_path):
    output = tmp_path / "auth002-noise.json"
    noise_path = tmp_path / "auth002-noise.jsonl"

    events = [
        json.loads(line)
        for line in CASE002_TELEMETRY.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    noise = [
        event
        for event in events
        if event["source_ip"] in {
            "192.0.2.21",
            "192.0.2.22",
            "192.0.2.23",
            "203.0.113.45",
        }
    ]

    noise_path.write_text(
        "\n".join(json.dumps(event) for event in noise) + "\n",
        encoding="utf-8",
    )

    document = run_detection(
        "DET-AUTH-002",
        noise_path,
        output,
    )

    assert document["alert_count"] == 0
    assert document["alerts"] == []


def test_auth_002_requires_distinct_users(tmp_path):
    output = tmp_path / "auth002-distinct-users.json"
    reduced_path = tmp_path / "auth002-distinct-users.jsonl"

    events = [
        json.loads(line)
        for line in CASE002_TELEMETRY.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    primary = [
        event
        for event in events
        if event["source_ip"] == "198.51.100.40"
    ]

    reduced = [
        event
        for event in primary
        if event["user"] in {
            "alice",
            "bob",
            "carol",
            "david",
            "erin",
        }
    ]

    noise = [
        event
        for event in events
        if event["source_ip"] != "198.51.100.40"
    ]

    reduced.extend(noise)

    reduced_path.write_text(
        "\n".join(json.dumps(event) for event in reduced) + "\n",
        encoding="utf-8",
    )

    document = run_detection(
        "DET-AUTH-002",
        reduced_path,
        output,
    )

    assert document["alert_count"] == 0
    assert document["alerts"] == []


def test_invalid_telemetry_is_rejected(tmp_path):
    input_path = tmp_path / "invalid.jsonl"
    output_path = tmp_path / "invalid.json"

    invalid_event = {
        "event_id": "INVALID-001",
        "timestamp": "2026-09-08T10:00:00Z",
    }

    input_path.write_text(
        json.dumps(invalid_event) + "\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            str(ENGINE),
            "--detection",
            "DET-AUTH-001",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert not output_path.exists()


def test_missing_timestamp_is_rejected(tmp_path):
    input_path = tmp_path / "missing_timestamp.jsonl"
    output_path = tmp_path / "missing_timestamp.json"

    invalid_event = {
        "event_id": "INVALID-002",
        "event_type": "authentication",
    }

    input_path.write_text(
        json.dumps(invalid_event) + "\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            str(ENGINE),
            "--detection",
            "DET-AUTH-001",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "missing timestamp" in result.stderr
    assert not output_path.exists()


def test_endpoint_001_suspicious_powershell_detection(tmp_path):
    output = tmp_path / "endpoint001.json"

    document = run_detection(
        "DET-ENDPOINT-001",
        CASE003_TELEMETRY,
        output,
    )

    assert document["detection_id"] == "DET-ENDPOINT-001"
    assert document["alert_count"] == 2

    alert_ids = {
        alert["alert_id"]
        for alert in document["alerts"]
    }

    assert "ALERT-EVT-003006-DET-ENDPOINT-001" in alert_ids
    assert "ALERT-EVT-003007-DET-ENDPOINT-001" in alert_ids


def test_endpoint_001_encoded_powershell_alert(tmp_path):
    output = tmp_path / "endpoint001-encoded.json"

    document = run_detection(
        "DET-ENDPOINT-001",
        CASE003_TELEMETRY,
        output,
    )

    alerts = {
        alert["alert_id"]: alert
        for alert in document["alerts"]
    }

    first_alert = alerts["ALERT-EVT-003006-DET-ENDPOINT-001"]

    assert first_alert["severity"] == "high"
    assert first_alert["confidence"] == "high"
    assert first_alert["risk_score"] == 100
    assert "encoded_command" in first_alert["indicators"]
    assert "suspicious_parent" in first_alert["indicators"]


def test_endpoint_001_correlates_network_and_child_process(tmp_path):
    output = tmp_path / "endpoint001-correlation.json"

    document = run_detection(
        "DET-ENDPOINT-001",
        CASE003_TELEMETRY,
        output,
    )

    alerts = {
        alert["alert_id"]: alert
        for alert in document["alerts"]
    }

    second_alert = alerts["ALERT-EVT-003007-DET-ENDPOINT-001"]

    assert second_alert["network_event_id"] == "EVT-003008"
    assert second_alert["child_process_event_id"] == "EVT-003009"

    assert "correlated_network_activity" in second_alert["indicators"]
    assert "correlated_child_process" in second_alert["indicators"]


def test_endpoint_001_legitimate_powershell_does_not_trigger(tmp_path):
    output = tmp_path / "endpoint001-legitimate.json"
    legitimate_path = tmp_path / "endpoint001-legitimate.jsonl"

    events = [
        json.loads(line)
        for line in CASE003_TELEMETRY.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    legitimate = [
        event
        for event in events
        if event["event_id"] in {
            "EVT-003001",
            "EVT-003002",
            "EVT-003004",
            "EVT-003005",
            "EVT-003010",
        }
    ]

    legitimate_path.write_text(
        "\n".join(json.dumps(event) for event in legitimate) + "\n",
        encoding="utf-8",
    )

    document = run_detection(
        "DET-ENDPOINT-001",
        legitimate_path,
        output,
    )

    assert document["alert_count"] == 0
    assert document["alerts"] == []


def test_endpoint_001_supporting_events_exist_in_telemetry(tmp_path):
    output = tmp_path / "endpoint001-supporting.json"

    document = run_detection(
        "DET-ENDPOINT-001",
        CASE003_TELEMETRY,
        output,
    )

    events = {
        json.loads(line)["event_id"]
        for line in CASE003_TELEMETRY.read_text(encoding="utf-8").splitlines()
        if line.strip()
    }

    for alert in document["alerts"]:
        for event_id in alert["supporting_event_ids"]:
            assert event_id in events


def test_auth_003_privileged_session_detection(tmp_path):
    output = tmp_path / "auth003.json"

    document = run_detection(
        "DET-AUTH-003",
        CASE004_TELEMETRY,
        output,
    )

    assert document["detection_id"] == "DET-AUTH-003"
    assert document["alert_count"] == 1

    alert = document["alerts"][0]

    assert alert["alert_id"] == "ALERT-CASE-004-DET-AUTH-003"
    assert alert["severity"] == "high"
    assert alert["confidence"] == "high"
    assert alert["source_ip"] == "198.51.100.60"
    assert alert["host"] == "lab-linux-01"
    assert alert["user"] == "admin"


def test_auth_003_session_and_privileged_activity_correlation(tmp_path):
    output = tmp_path / "auth003-correlation.json"

    document = run_detection(
        "DET-AUTH-003",
        CASE004_TELEMETRY,
        output,
    )

    assert document["alert_count"] == 1

    alert = document["alerts"][0]

    assert alert["failed_authentication_count"] == 4
    assert alert["successful_authentication_event_id"] == "EVT-004007"
    assert alert["session_start_event_id"] == "EVT-004008"
    assert alert["post_authentication_command_count"] == 4
    assert alert["session_id"] == "SES-004-C"

    assert set(alert["privileged_activity_indicators"]) == {
        "id",
        "sudo -l",
    }

    assert set(alert["supporting_event_ids"]) == {
        "EVT-004003",
        "EVT-004004",
        "EVT-004005",
        "EVT-004006",
        "EVT-004007",
        "EVT-004008",
        "EVT-004009",
        "EVT-004010",
        "EVT-004011",
        "EVT-004012",
    }


def test_auth_003_benign_authentication_noise_does_not_trigger(tmp_path):
    output = tmp_path / "auth003-noise.json"
    noise_path = tmp_path / "auth003-noise.jsonl"

    events = [
        json.loads(line)
        for line in CASE004_TELEMETRY.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    noise = [
        event
        for event in events
        if event["event_id"] in {
            "EVT-004001",
            "EVT-004002",
            "EVT-004013",
            "EVT-004014",
            "EVT-004015",
        }
    ]

    noise_path.write_text(
        "\n".join(json.dumps(event) for event in noise) + "\n",
        encoding="utf-8",
    )

    document = run_detection(
        "DET-AUTH-003",
        noise_path,
        output,
    )

    assert document["alert_count"] == 0
    assert document["alerts"] == []


def test_auth_003_requires_four_failed_authentications(tmp_path):
    output = tmp_path / "auth003-threshold.json"
    reduced_path = tmp_path / "auth003-threshold.jsonl"

    events = [
        json.loads(line)
        for line in CASE004_TELEMETRY.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    reduced = [
        event
        for event in events
        if event["event_id"] != "EVT-004006"
    ]

    reduced_path.write_text(
        "\n".join(json.dumps(event) for event in reduced) + "\n",
        encoding="utf-8",
    )

    document = run_detection(
        "DET-AUTH-003",
        reduced_path,
        output,
    )

    assert document["alert_count"] == 0
    assert document["alerts"] == []


def test_host_001_file_integrity_detection(tmp_path):
    telemetry = tmp_path / "host.jsonl"
    telemetry.write_text(
        '{"event_id":"EVT-007001","timestamp":"2026-09-08T12:00:00Z",'
        '"event_type":"file_integrity","source":"fim","host":"lab-host-01",'
        '"user":"root","action":"file_change","status":"changed",'
        '"file_path":"/etc/ssh/sshd_config","change_type":"modified",'
        '"old_hash":"aaa","new_hash":"bbb","metadata":{}}\n'
        '{"event_id":"EVT-007002","timestamp":"2026-09-08T12:02:00Z",'
        '"event_type":"file_integrity","source":"fim","host":"lab-host-01",'
        '"user":"root","action":"file_change","status":"changed",'
        '"file_path":"/etc/passwd","change_type":"modified",'
        '"old_hash":"ccc","new_hash":"ddd","metadata":{}}\n'
    )

    output = tmp_path / "alert.json"

    document = run_detection(
        "DET-HOST-001",
        telemetry,
        output,
    )

    assert document["detection_id"] == "DET-HOST-001"
    assert len(document["alerts"]) == 1

    alert = document["alerts"][0]

    assert alert["alert_id"] == "ALERT-CASE-007-DET-HOST-001"
    assert alert["host"] == "lab-host-01"
    assert alert["violation_count"] == 2
    assert alert["affected_files"] == [
        "/etc/passwd",
        "/etc/ssh/sshd_config",
    ]
    assert alert["change_types"] == ["modified"]
    assert alert["supporting_event_ids"] == [
        "EVT-007001",
        "EVT-007002",
    ]


def test_host_001_single_violation_does_not_trigger(tmp_path):
    telemetry = tmp_path / "host.jsonl"
    telemetry.write_text(
        '{"event_id":"EVT-007003","timestamp":"2026-09-08T12:00:00Z",'
        '"event_type":"file_integrity","source":"fim","host":"lab-host-01",'
        '"user":"root","action":"file_change","status":"changed",'
        '"file_path":"/etc/ssh/sshd_config","change_type":"modified",'
        '"old_hash":"aaa","new_hash":"bbb","metadata":{}}\n'
    )

    output = tmp_path / "alert.json"

    document = run_detection(
        "DET-HOST-001",
        telemetry,
        output,
    )

    assert document["detection_id"] == "NONE"
    assert document["alerts"] == []
