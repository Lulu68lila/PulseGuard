"""Unit tests for PulseGuard local REST API server."""

import json
import time
import urllib.request
import urllib.error
from pathlib import Path

import pytest

from pulseguard.api.server import PulseGuardAPIServer

TEST_PORT = 48299
BASE_URL = f"http://127.0.0.1:{TEST_PORT}"


@pytest.fixture(scope="module")
def api_server():
    server = PulseGuardAPIServer(host="127.0.0.1", port=TEST_PORT)
    server.start(block=False)
    time.sleep(0.3)  # Allow server thread to bind
    yield server
    server.stop()
    time.sleep(0.1)


def make_request(method: str, path: str, data: dict = None) -> tuple:
    url = f"{BASE_URL}{path}"
    headers = {"Content-Type": "application/json"}
    body = json.dumps(data).encode("utf-8") if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    with urllib.request.urlopen(req) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8")), resp.headers


def test_cors_preflight(api_server):
    url = f"{BASE_URL}/api/status"
    req = urllib.request.Request(url, method="OPTIONS")
    with urllib.request.urlopen(req) as resp:
        assert resp.status == 204
        assert resp.headers.get("Access-Control-Allow-Origin") == "*"


def test_get_status(api_server):
    status, data, _ = make_request("GET", "/api/status")
    assert status == 200
    assert data["engine"] == "ONLINE"
    assert "signatures" in data
    assert "quarantine_count" in data


def test_post_scan_clean(api_server, tmp_path: Path):
    clean = tmp_path / "good.txt"
    clean.write_text("All good and benign\n", encoding="utf-8")

    status, data, _ = make_request("POST", "/api/scan", {"path": str(clean)})
    assert status == 200
    assert data["scanned_count"] == 1
    assert data["infected_count"] == 0
    assert data["results"][0]["status"] == "CLEAN"


def test_post_scan_infected_and_quarantine(api_server, tmp_path: Path):
    threat_file = tmp_path / "bad.bin"
    threat_file.write_bytes(b"PREFIX::PULSEGUARD_TEST_RANSOM_MARKER::SUFFIX")

    status, data, _ = make_request("POST", "/api/scan", {"path": str(threat_file), "quarantine": True})
    assert status == 200
    assert data["infected_count"] == 1
    assert data["results"][0]["is_infected"] is True
    assert data["results"][0]["quarantine_id"] is not None
    assert not threat_file.exists()


def test_get_quarantine_records(api_server):
    status, data, _ = make_request("GET", "/api/quarantine")
    assert status == 200
    assert "records" in data
    assert isinstance(data["records"], list)


def test_post_watch_toggle(api_server, tmp_path: Path):
    # Activate watcher
    status, data, _ = make_request("POST", "/api/watch/toggle", {"active": True, "path": str(tmp_path)})
    assert status == 200
    assert data["watcher_active"] is True

    # Deactivate watcher
    status, data, _ = make_request("POST", "/api/watch/toggle", {"active": False})
    assert status == 200
    assert data["watcher_active"] is False


def test_get_processes(api_server):
    status, data, _ = make_request("GET", "/api/processes?limit=5")
    assert status == 200
    assert "processes" in data
    assert data["scanned_count"] > 0
    assert len(data["processes"]) <= 5


def test_get_events(api_server):
    status, data, _ = make_request("GET", "/api/events")
    assert status == 200
    assert "events" in data
    assert isinstance(data["events"], list)


def test_quarantine_restore_and_delete_endpoints(api_server, tmp_path: Path):
    threat_file = tmp_path / "bad_to_restore.bin"
    threat_file.write_bytes(b"PREFIX::PULSEGUARD_TEST_RANSOM_MARKER::SUFFIX")

    # Scan and quarantine
    status, scan_data, _ = make_request("POST", "/api/scan", {"path": str(threat_file), "quarantine": True})
    assert status == 200
    q_id = scan_data["results"][0]["quarantine_id"]
    assert q_id is not None

    # Restore
    restored_dest = tmp_path / "restored.bin"
    status, r_data, _ = make_request("POST", "/api/quarantine/restore", {"record_id": q_id, "dest": str(restored_dest)})
    assert status == 200
    assert r_data["success"] is True
    assert restored_dest.exists()

    # Delete
    status, d_data, _ = make_request("POST", "/api/quarantine/delete", {"record_id": q_id})
    assert status == 200
    assert d_data["success"] is True


def test_api_error_handling(api_server):
    # 404 endpoint
    try:
        make_request("GET", "/api/nonexistent")
    except urllib.error.HTTPError as exc:
        assert exc.code == 404

    # Missing path in scan
    try:
        make_request("POST", "/api/scan", {})
    except urllib.error.HTTPError as exc:
        assert exc.code == 400
