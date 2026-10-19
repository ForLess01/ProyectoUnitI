"""Bounded HTTP integration cases for the local fixture-only lab."""

from __future__ import annotations

import http.client
import json
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from pathlib import Path
from threading import Thread
from typing import Any, Callable
from urllib.parse import urlsplit

from .app import _totp_matches, create_server
from .test_credentials import DEMO_PASSWORDS, RFC6238_SECRET, totp_code


MAX_REQUEST_BYTES = 65_536


@dataclass
class ApiResponse:
    status: int
    body: dict[str, Any]
    headers: http.client.HTTPMessage
    payload_bytes_sent: int
    payload_bytes_received: int
    duration_ms: float
    request_id: str | None


class ApiClient:
    def __init__(self, base_url: str):
        parsed = urlsplit(base_url)
        self.host = parsed.hostname or "127.0.0.1"
        self.port = parsed.port
        self.cookie_value: str | None = None
        self.request_count = 0
        self.payload_bytes_sent = 0
        self.payload_bytes_received = 0
        self.request_durations_ms: list[float] = []

    def request(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, Any] | None = None,
        raw_body: bytes | None = None,
        cookie_override: str | None = None,
    ) -> ApiResponse:
        if payload is not None and raw_body is not None:
            raise ValueError("Provide JSON payload or raw body, not both")
        if payload is not None:
            body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            content_type = "application/json"
        else:
            body = raw_body
            content_type = "application/octet-stream"

        headers: dict[str, str] = {"Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = content_type
        cookie = cookie_override
        if cookie is None and self.cookie_value is not None:
            cookie = f"lab_session={self.cookie_value}"
        if cookie:
            headers["Cookie"] = cookie

        connection = http.client.HTTPConnection(self.host, self.port, timeout=4)
        started = time.perf_counter()
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            response_body = response.read(131_072)
            duration_ms = (time.perf_counter() - started) * 1000
            response_headers = response.headers
            parsed_cookie = SimpleCookie()
            for value in response_headers.get_all("Set-Cookie", []):
                parsed_cookie.load(value)
            session_cookie = parsed_cookie.get("lab_session")
            if session_cookie is not None:
                if session_cookie["max-age"] == "0" or not session_cookie.value:
                    self.cookie_value = None
                else:
                    self.cookie_value = session_cookie.value
            try:
                parsed_body = json.loads(response_body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                parsed_body = {"_raw": response_body.decode("utf-8", errors="replace")[:500]}
            result = ApiResponse(
                status=response.status,
                body=parsed_body,
                headers=response_headers,
                payload_bytes_sent=len(body or b""),
                payload_bytes_received=len(response_body),
                duration_ms=duration_ms,
                request_id=response_headers.get("X-Request-ID"),
            )
            self.request_count += 1
            self.payload_bytes_sent += result.payload_bytes_sent
            self.payload_bytes_received += result.payload_bytes_received
            self.request_durations_ms.append(duration_ms)
            return result
        finally:
            connection.close()


class LabHarness:
    def __init__(self):
        self.temporary_directory = tempfile.TemporaryDirectory(prefix="unit-i-lab-")
        self.root = Path(self.temporary_directory.name)
        self.server = create_server(
            "127.0.0.1",
            0,
            self.root / "lab.sqlite3",
            self.root / "runtime",
        )
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.clients: list[ApiClient] = []

    def client(self) -> ApiClient:
        client = ApiClient(self.base_url)
        self.clients.append(client)
        return client

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temporary_directory.cleanup()


def _login(client: ApiClient, username: str) -> dict[str, Any]:
    password_response = client.request(
        "POST",
        "/api/login",
        payload={"username": username, "password": DEMO_PASSWORDS[username]},
    )
    assert password_response.status == 401, "Password-only login must not create a session"
    assert password_response.body.get("code") == "mfa_required"
    challenge_id = password_response.body.get("challenge_id")
    assert isinstance(challenge_id, str) and challenge_id
    assert client.cookie_value is None, "No session cookie may exist before TOTP succeeds"

    mfa_response = client.request(
        "POST",
        "/api/mfa",
        payload={"challenge_id": challenge_id, "code": totp_code(RFC6238_SECRET)},
    )
    assert mfa_response.status == 200, "Valid RFC 6238 TOTP should authenticate the fixture user"
    assert mfa_response.body.get("status") == "authenticated"
    assert isinstance(client.cookie_value, str) and client.cookie_value
    assert "httponly" in (mfa_response.headers.get("Set-Cookie", "").lower())
    return mfa_response.body["user"]


def case_invalid_credentials(harness: LabHarness, runtime_dir: Path) -> dict[str, Any]:
    client = harness.client()
    response = client.request(
        "POST",
        "/api/login",
        payload={"username": "lucia", "password": "incorrect-fixture-password"},
    )
    assert response.status == 401
    assert response.body.get("code") == "invalid_credentials"
    assert response.request_id == response.body.get("request_id")
    assert client.cookie_value is None
    return {
        "status": response.status,
        "code": response.body["code"],
        "request_id_present": bool(response.request_id),
        "session_created": client.cookie_value is not None,
    }


def case_password_without_totp(harness: LabHarness, runtime_dir: Path) -> dict[str, Any]:
    client = harness.client()
    response = client.request(
        "POST",
        "/api/login",
        payload={"username": "lucia", "password": DEMO_PASSWORDS["lucia"]},
    )
    assert response.status == 401, "Correct password without TOTP must remain denied"
    assert response.body.get("code") == "mfa_required"
    assert response.body.get("access_granted") is False
    assert client.cookie_value is None
    return {
        "status": response.status,
        "code": response.body["code"],
        "access_granted": response.body["access_granted"],
        "session_created": client.cookie_value is not None,
    }


def case_totp_authentication(harness: LabHarness, runtime_dir: Path) -> dict[str, Any]:
    assert totp_code(RFC6238_SECRET, timestamp=59) == "287082"
    assert _totp_matches("287082", RFC6238_SECRET, timestamp=59)
    user = _login(harness.client(), "lucia")
    assert user["role"] == "reader"
    return {
        "mfa_status": "authenticated",
        "role": user["role"],
        "session_cookie": "HttpOnly",
        "rfc6238_sha1_test_vector_verified": True,
        "totp_digits": 6,
        "totp_period_seconds": 30,
    }


def case_reader_admin_denied(harness: LabHarness, runtime_dir: Path) -> dict[str, Any]:
    client = harness.client()
    _login(client, "lucia")
    response = client.request("GET", "/api/admin")
    assert response.status == 403
    assert response.body.get("code") == "forbidden"
    return {"status": response.status, "code": response.body["code"], "role": "reader"}


def case_admin_allowed(harness: LabHarness, runtime_dir: Path) -> dict[str, Any]:
    client = harness.client()
    user = _login(client, "ana.admin")
    response = client.request("GET", "/api/admin")
    assert user["role"] == "admin"
    assert response.status == 200
    assert response.body.get("scope") == "synthetic-lab"
    return {"status": response.status, "role": user["role"], "scope": response.body["scope"]}


def case_cross_object_read_denied(harness: LabHarness, runtime_dir: Path) -> dict[str, Any]:
    client = harness.client()
    _login(client, "lucia")
    own_record = client.request("GET", "/api/objects/record-A")
    other_record = client.request("GET", "/api/objects/record-B")
    assert own_record.status == 200
    assert own_record.body.get("owner") == "lucia"
    assert other_record.status == 404
    assert other_record.body.get("code") == "not_found"
    assert "Synthetic record B" not in json.dumps(other_record.body)
    return {
        "own_object_status": own_record.status,
        "other_object_status": other_record.status,
        "other_object_content_disclosed": False,
    }


def case_reader_tampering_rejected(harness: LabHarness, runtime_dir: Path) -> dict[str, Any]:
    client = harness.client()
    _login(client, "lucia")
    before = client.request("GET", "/api/objects/record-A")
    denied = client.request(
        "POST",
        "/api/objects/record-A",
        payload={"content": "unauthorized-change"},
    )
    after = client.request("GET", "/api/objects/record-A")
    assert before.status == 200 and after.status == 200
    assert denied.status == 403
    assert before.body["content"] == after.body["content"]
    assert after.body["content"] != "unauthorized-change"
    return {
        "update_status": denied.status,
        "object_unchanged": before.body["content"] == after.body["content"],
    }


def case_editor_own_update_allowed(harness: LabHarness, runtime_dir: Path) -> dict[str, Any]:
    client = harness.client()
    user = _login(client, "mateo")
    updated = client.request(
        "POST",
        "/api/objects/record-B",
        payload={"content": "Synthetic record B updated by its editor"},
    )
    assert user["role"] == "editor"
    assert updated.status == 200
    assert updated.body.get("content") == "Synthetic record B updated by its editor"
    return {"status": updated.status, "role": user["role"], "own_object_update": True}


def case_audit_fields(harness: LabHarness, runtime_dir: Path) -> dict[str, Any]:
    anonymous = harness.client()
    denied = anonymous.request(
        "POST",
        "/api/login",
        payload={"username": "not-a-user", "password": "irrelevant-fixture-value"},
    )
    assert denied.status == 401 and denied.request_id

    administrator = harness.client()
    _login(administrator, "ana.admin")
    audit_response = administrator.request("GET", "/api/audit")
    assert audit_response.status == 200
    matching = [
        event
        for event in audit_response.body.get("events", [])
        if event.get("request_id") == denied.request_id
    ]
    assert len(matching) == 1
    event = matching[0]
    required = {"actor", "occurred_at_utc", "action", "result", "request_id"}
    assert required.issubset(event)
    assert event["actor"] == "anonymous"
    assert event["action"] == "auth.login"
    assert event["result"] == "denied"
    assert event["request_id"] == denied.request_id
    timestamp = datetime.fromisoformat(event["occurred_at_utc"].replace("Z", "+00:00"))
    assert timestamp.tzinfo == timezone.utc
    assert "irrelevant-fixture-value" not in json.dumps(event)
    return {
        "audit_fields_present": sorted(required),
        "actor": event["actor"],
        "action": event["action"],
        "result": event["result"],
        "utc_timestamp_valid": True,
        "request_id_matches": event["request_id"] == denied.request_id,
    }


def case_request_size_limit(harness: LabHarness, runtime_dir: Path) -> dict[str, Any]:
    client = harness.client()
    _login(client, "lucia")
    oversized = b"x" * (MAX_REQUEST_BYTES + 1)
    rejected = client.request("POST", "/api/requests", raw_body=oversized)
    assert rejected.status == 413
    assert rejected.body.get("max_bytes") == MAX_REQUEST_BYTES

    valid_payload = {"subject": "Synthetic lab request", "details": "Fictitious fixture record"}
    valid_body = json.dumps(valid_payload, separators=(",", ":")).encode("utf-8")
    accepted = client.request("POST", "/api/requests", payload=valid_payload)
    assert accepted.status == 201
    assert accepted.body.get("accepted_bytes") == len(valid_body)
    assert len(valid_body) <= MAX_REQUEST_BYTES
    return {
        "limit_bytes": MAX_REQUEST_BYTES,
        "oversized_bytes": len(oversized),
        "oversized_status": rejected.status,
        "normal_bytes": len(valid_body),
        "normal_status": accepted.status,
    }


def case_session_revocation(harness: LabHarness, runtime_dir: Path) -> dict[str, Any]:
    client = harness.client()
    _login(client, "lucia")
    assert client.cookie_value
    old_cookie = f"lab_session={client.cookie_value}"
    revoked = client.request("POST", "/api/session/revoke", payload={})
    assert revoked.status == 200
    after_revoke = client.request("GET", "/api/me", cookie_override=old_cookie)
    assert after_revoke.status == 401
    assert after_revoke.body.get("code") == "unauthenticated"
    return {
        "revoke_status": revoked.status,
        "reused_session_status": after_revoke.status,
        "old_session_rejected": True,
    }


def case_attack_fixture_monitoring(harness: LabHarness, runtime_dir: Path) -> dict[str, Any]:
    from .attack_sim import simulate_fixture_activity

    result = simulate_fixture_activity(runtime_dir / "attack")
    assert result["techniques"] == ["T1083", "T1005", "T1074.001"]
    assert result["enumerated_fixture_files"] >= 2
    assert result["copied_fixture_files"] == result["enumerated_fixture_files"]
    assert result["staged_fixture_files"] == result["enumerated_fixture_files"]
    assert result["alerts_generated"] == 1
    assert result["alert_rule_id"] == "LAB-DET-001"
    assert result["monitoring_rule"] == "self_contained_local_fixture_directory"
    assert result["fixture_only"] is True
    return result


def case_backup_restore_hashes(harness: LabHarness, runtime_dir: Path) -> dict[str, Any]:
    from .attack_sim import verify_fixture_backup_restore

    result = verify_fixture_backup_restore(runtime_dir / "backup")
    assert result["files_verified"] >= 2
    assert result["damage_detected"] is True
    assert result["source_unchanged_during_damage"] is True
    assert result["backup_unchanged_during_damage"] is True
    assert result["restoration_completed"] is True
    assert result["all_hashes_match"] is True
    assert result["algorithm"] == "SHA-256"
    assert result["fixture_only"] is True
    timings = result["timings_ms"]
    assert {"copy_to_working", "create_backup", "controlled_working_copy_damage", "restore_from_backup", "verify_final_hashes", "total"}.issubset(timings)
    assert all(isinstance(value, (int, float)) and value >= 0 for value in timings.values())
    assert timings["total"] >= max(value for key, value in timings.items() if key != "total")
    return result


CASE_DEFINITIONS: dict[str, tuple[str, Callable[[LabHarness, Path], dict[str, Any]]]] = {
    "AUTH-01": ("credencial incorrecta denegada", case_invalid_credentials),
    "AUTH-02": ("contraseña correcta sin TOTP denegada", case_password_without_totp),
    "AUTH-03": ("TOTP RFC 6238 válido permite acceso", case_totp_authentication),
    "RBAC-01": ("lector recibe denegación en panel admin", case_reader_admin_denied),
    "RBAC-02": ("admin autorizado accede a su panel", case_admin_allowed),
    "IDOR-01": ("objeto de otro usuario no se divulga", case_cross_object_read_denied),
    "INT-01": ("edición sin permiso se rechaza sin cambiar datos", case_reader_tampering_rejected),
    "RBAC-03": ("editor modifica su objeto permitido", case_editor_own_update_allowed),
    "AUDIT-01": ("auditoría contiene actor UTC acción resultado request_id", case_audit_fields),
    "INPUT-01": ("límite 64 KiB y solicitud normal posterior", case_request_size_limit),
    "SESSION-01": ("revocación invalida reutilización de sesión", case_session_revocation),
    "ATTACK-01": ("T1083 T1005 T1074.001 sólo con fixtures y alerta", case_attack_fixture_monitoring),
    "RECOVERY-01": ("prueba de restauración de archivos por SHA-256", case_backup_restore_hashes),
}

CASE_EXPECTATIONS = {
    "AUTH-01": "Invalid fixture password returns HTTP 401 invalid_credentials and creates no session.",
    "AUTH-02": "A correct password without TOTP returns HTTP 401 mfa_required and grants no access.",
    "AUTH-03": "Valid RFC 6238 TOTP creates an HttpOnly session for the reader role.",
    "RBAC-01": "Reader role receives HTTP 403 from the administrator panel.",
    "RBAC-02": "Admin role receives HTTP 200 from the synthetic administrator panel.",
    "IDOR-01": "Reader can read object A but receives a generic HTTP 404 without object B content.",
    "INT-01": "Reader update receives HTTP 403 and a subsequent read proves the object is unchanged.",
    "RBAC-03": "Editor can update the object assigned to that editor.",
    "AUDIT-01": "An audit event exposes actor, UTC timestamp, action, result, and matching request_id without the supplied password.",
    "INPUT-01": "A 65,537-byte request is rejected with HTTP 413 at the 65,536-byte limit; a later 73-byte request is accepted with HTTP 201.",
    "SESSION-01": "After revocation, reuse of the previous session token receives HTTP 401.",
    "ATTACK-01": "Only bundled fixtures are enumerated, copied, and staged; monitoring emits one LAB-DET-001 alert.",
    "RECOVERY-01": "A controlled byte change in one disposable working copy is detected, the backup remains unchanged, and restored copies match source/backup SHA-256.",
}


GROUPS: dict[str, tuple[str, ...]] = {
    "auth_mfa": ("AUTH-01", "AUTH-02", "AUTH-03"),
    "rbac_idor": ("RBAC-01", "RBAC-02", "IDOR-01"),
    "integrity_audit": ("INT-01", "RBAC-03", "AUDIT-01"),
    "size_revocation": ("INPUT-01", "SESSION-01"),
    "attack_backup": ("ATTACK-01", "RECOVERY-01"),
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
