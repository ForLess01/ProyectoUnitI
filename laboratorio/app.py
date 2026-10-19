"""Minimal local HTTP application for synthetic cybersecurity test cases."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import secrets
import sqlite3
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urlsplit


MAX_REQUEST_BYTES = 65_536
SESSION_LIFETIME_SECONDS = 900
CHALLENGE_LIFETIME_SECONDS = 120
PBKDF2_ITERATIONS = 120_000
COOKIE_NAME = "lab_session"
COOKIE_PATH = "/"

DEMO_USERS = {
    "lucia": {
        "display_name": "Lucia Reader",
        "role": "reader",
        "salt": "bG9jYWwtZGVtby1zYWx0LWx1Y2lhLTIwMjY=",
        "password_hash": "x/NVQ7pdfRYcN+R9ozwOhhFXwTxRoLqOI8truIAW4fw=",
    },
    "mateo": {
        "display_name": "Mateo Editor",
        "role": "editor",
        "salt": "bG9jYWwtZGVtby1zYWx0LW1hdGVvLTIwMjY=",
        "password_hash": "FD3XmAVdFaMy2FW/c6E+PXG/0hWfDMSr6zR+8DKUs4M=",
    },
    "ana.admin": {
        "display_name": "Ana Admin",
        "role": "admin",
        "salt": "bG9jYWwtZGVtby1zYWx0LWFuYS1hZG1pbi0yMDI2",
        "password_hash": "FVkutlI7JyumaL+VZyxfWK3h1JbVJkWL/eKjCVZEnjI=",
    },
}

DEMO_TOTP_SECRET = base64.b32decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
DUMMY_SALT_B64 = base64.b64encode(b"local-demo-unknown-salt").decode("ascii")
DUMMY_HASH_B64 = base64.b64encode(bytes(32)).decode("ascii")
WEB_ROOT = Path(__file__).resolve().parent / "web"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _password_matches(password: str, salt_b64: str, expected_b64: str) -> bool:
    salt = base64.b64decode(salt_b64)
    expected = base64.b64decode(expected_b64)
    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return hmac.compare_digest(actual, expected)


def _totp_matches(code: str, secret: bytes, timestamp: float | None = None) -> bool:
    if len(code) != 6 or not code.isascii() or not code.isdigit():
        return False
    now = time.time() if timestamp is None else timestamp
    current_counter = int(now // 30)
    valid_codes: list[str] = []
    for counter in (current_counter - 1, current_counter, current_counter + 1):
        digest = hmac.new(secret, counter.to_bytes(8, "big"), hashlib.sha1).digest()
        offset = digest[-1] & 0x0F
        number = int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFFFFFF
        valid_codes.append(f"{number % 1_000_000:06d}")
    return any(hmac.compare_digest(code, candidate) for candidate in valid_codes)


class LabState:
    def __init__(self, database_path: Path | str):
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize_database()

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(str(self.database_path), timeout=2)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _initialize_database(self) -> None:
        with self.connection() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    display_name TEXT NOT NULL,
                    role TEXT NOT NULL CHECK (role IN ('reader', 'editor', 'admin')),
                    salt_b64 TEXT NOT NULL,
                    password_hash_b64 TEXT NOT NULL,
                    totp_secret BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS objects (
                    object_id TEXT PRIMARY KEY,
                    owner_username TEXT NOT NULL REFERENCES users(username),
                    title TEXT NOT NULL,
                    content TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS mfa_challenges (
                    token_hash TEXT PRIMARY KEY,
                    username TEXT NOT NULL REFERENCES users(username),
                    expires_at REAL NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    token_hash TEXT PRIMARY KEY,
                    username TEXT NOT NULL REFERENCES users(username),
                    created_at_utc TEXT NOT NULL,
                    expires_at REAL NOT NULL,
                    revoked_at_utc TEXT
                );
                CREATE TABLE IF NOT EXISTS audit_log (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    actor TEXT NOT NULL,
                    occurred_at_utc TEXT NOT NULL,
                    action TEXT NOT NULL,
                    result TEXT NOT NULL,
                    request_id TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS requests (
                    request_id TEXT PRIMARY KEY,
                    actor TEXT NOT NULL REFERENCES users(username),
                    subject TEXT NOT NULL,
                    details TEXT NOT NULL,
                    created_at_utc TEXT NOT NULL
                );
                """
            )
            user_count = connection.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            if user_count == 0:
                for username, user in DEMO_USERS.items():
                    connection.execute(
                        """INSERT INTO users
                           (username, display_name, role, salt_b64, password_hash_b64, totp_secret)
                           VALUES (?, ?, ?, ?, ?, ?)""",
                        (
                            username,
                            user["display_name"],
                            user["role"],
                            user["salt"],
                            user["password_hash"],
                            DEMO_TOTP_SECRET,
                        ),
                    )
                connection.executemany(
                    "INSERT INTO objects (object_id, owner_username, title, content) VALUES (?, ?, ?, ?)",
                    (
                        (
                            "record-A",
                            "lucia",
                            "Synthetic record A",
                            "Synthetic record A — fictional laboratory data.",
                        ),
                        (
                            "record-B",
                            "mateo",
                            "Synthetic record B",
                            "Synthetic record B — fictional laboratory data.",
                        ),
                    ),
                )

    @staticmethod
    def hash_token(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def record_audit(
        self,
        actor: str,
        action: str,
        result: str,
        request_id: str,
    ) -> None:
        with self.connection() as connection:
            connection.execute(
                """INSERT INTO audit_log (actor, occurred_at_utc, action, result, request_id)
                   VALUES (?, ?, ?, ?, ?)""",
                (actor, utc_now(), action, result, request_id),
            )

    def session_user(self, cookie_header: str | None) -> sqlite3.Row | None:
        token = _session_token(cookie_header)
        if not token:
            return None
        token_hash = self.hash_token(token)
        now = time.time()
        with self.connection() as connection:
            row = connection.execute(
                """SELECT users.username, users.display_name, users.role, sessions.expires_at,
                          sessions.revoked_at_utc
                   FROM sessions JOIN users ON users.username = sessions.username
                   WHERE sessions.token_hash = ?""",
                (token_hash,),
            ).fetchone()
        if row is None or row["revoked_at_utc"] is not None or row["expires_at"] <= now:
            return None
        return row

    def audit_events(self) -> list[dict[str, Any]]:
        with self.connection() as connection:
            rows = connection.execute(
                """SELECT actor, occurred_at_utc, action, result, request_id
                   FROM audit_log ORDER BY event_id ASC LIMIT 200"""
            ).fetchall()
        return [dict(row) for row in rows]


def _session_token(cookie_header: str | None) -> str | None:
    if not cookie_header:
        return None
    cookie = SimpleCookie()
    try:
        cookie.load(cookie_header)
    except Exception:
        return None
    morsel = cookie.get(COOKIE_NAME)
    return morsel.value if morsel else None


class LabRequestHandler(BaseHTTPRequestHandler):
    server_version = "LocalFixtureLab/1.0"
    sys_version = ""

    @property
    def state(self) -> LabState:
        return self.server.state  # type: ignore[attr-defined]

    def log_message(self, format: str, *args: Any) -> None:
        # Request bodies, cookie headers, and credentials are deliberately not logged.
        return

    def log_error(self, format: str, *args: Any) -> None:
        return

    def _new_request_id(self) -> str:
        return uuid.uuid4().hex

    def _common_headers(self, content_type: str) -> None:
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; connect-src 'self'; "
            "img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        )

    def _respond_json(
        self,
        status: int,
        payload: dict[str, Any],
        request_id: str,
        *,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        body = dict(payload)
        body["request_id"] = request_id
        data = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self._common_headers("application/json; charset=utf-8")
        self.send_header("X-Request-ID", request_id)
        self.send_header("Content-Length", str(len(data)))
        if extra_headers:
            for name, value in extra_headers.items():
                self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def _respond_page(self, request_id: str) -> None:
        data = (WEB_ROOT / "index.html").read_bytes()
        self.send_response(200)
        self._common_headers("text/html; charset=utf-8")
        self.send_header("X-Request-ID", request_id)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _actor(self) -> sqlite3.Row | None:
        return self.state.session_user(self.headers.get("Cookie"))

    def _unauthenticated(self, request_id: str, action: str) -> None:
        self.state.record_audit("anonymous", action, "denied", request_id)
        self._respond_json(
            401,
            {"code": "unauthenticated", "message": "Se requiere una sesión válida."},
            request_id,
        )

    def _read_json_body(self, request_id: str) -> dict[str, Any] | None:
        if self.headers.get("Transfer-Encoding"):
            self.close_connection = True
            self._respond_json(
                400,
                {"code": "unsupported_transfer_encoding", "message": "Transfer-Encoding no está habilitado."},
                request_id,
            )
            return None
        raw_length = self.headers.get("Content-Length")
        try:
            length = int(raw_length) if raw_length is not None else 0
        except ValueError:
            length = -1
        if length < 0:
            self.close_connection = True
            self._respond_json(400, {"code": "invalid_content_length"}, request_id)
            return None
        if length > MAX_REQUEST_BYTES:
            actor = self._actor()
            self.state.record_audit(
                actor["username"] if actor else "anonymous",
                "request.create",
                "rejected_size",
                request_id,
            )
            self.close_connection = True
            self._respond_json(
                413,
                {
                    "code": "payload_too_large",
                    "max_bytes": MAX_REQUEST_BYTES,
                    "received_bytes": length,
                },
                request_id,
            )
            return None
        if length == 0:
            return {}
        data = self.rfile.read(length)
        if len(data) != length:
            self.close_connection = True
            self._respond_json(400, {"code": "incomplete_body"}, request_id)
            return None
        try:
            parsed = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._respond_json(400, {"code": "invalid_json"}, request_id)
            return None
        if not isinstance(parsed, dict):
            self._respond_json(400, {"code": "json_object_required"}, request_id)
            return None
        self._received_body_bytes = length
        return parsed

    def do_GET(self) -> None:
        request_id = self._new_request_id()
        path = urlsplit(self.path).path
        if path == "/":
            self._respond_page(request_id)
            return
        if path == "/api/me":
            user = self._actor()
            if user is None:
                self._unauthenticated(request_id, "auth.session.check")
                return
            self.state.record_audit(user["username"], "auth.session.check", "allowed", request_id)
            self._respond_json(
                200,
                {
                    "status": "authenticated",
                    "user": {
                        "username": user["username"],
                        "display_name": user["display_name"],
                        "role": user["role"],
                    },
                },
                request_id,
            )
            return
        if path == "/api/admin":
            user = self._actor()
            if user is None:
                self._unauthenticated(request_id, "admin.panel")
                return
            if user["role"] != "admin":
                self.state.record_audit(user["username"], "admin.panel", "denied", request_id)
                self._respond_json(403, {"code": "forbidden", "message": "Se requiere el rol admin."}, request_id)
                return
            self.state.record_audit(user["username"], "admin.panel", "allowed", request_id)
            self._respond_json(
                200,
                {"status": "allowed", "scope": "synthetic-lab", "message": "Panel ficticio de administración."},
                request_id,
            )
            return
        if path == "/api/audit":
            user = self._actor()
            if user is None:
                self._unauthenticated(request_id, "audit.read")
                return
            if user["role"] != "admin":
                self.state.record_audit(user["username"], "audit.read", "denied", request_id)
                self._respond_json(403, {"code": "forbidden"}, request_id)
                return
            self._respond_json(200, {"events": self.state.audit_events()}, request_id)
            return
        if path.startswith("/api/objects/"):
            self._get_object(path.rsplit("/", 1)[-1], request_id)
            return
        self._respond_json(404, {"code": "not_found"}, request_id)

    def _get_object(self, object_id: str, request_id: str) -> None:
        user = self._actor()
        if user is None:
            self._unauthenticated(request_id, "object.read")
            return
        with self.state.connection() as connection:
            record = connection.execute(
                "SELECT object_id, owner_username, title, content FROM objects WHERE object_id = ?",
                (object_id,),
            ).fetchone()
        if record is None or (record["owner_username"] != user["username"] and user["role"] != "admin"):
            self.state.record_audit(user["username"], "object.read", "denied", request_id)
            self._respond_json(404, {"code": "not_found", "message": "No se encontró el objeto."}, request_id)
            return
        self.state.record_audit(user["username"], "object.read", "allowed", request_id)
        self._respond_json(
            200,
            {
                "id": record["object_id"],
                "owner": record["owner_username"],
                "title": record["title"],
                "content": record["content"],
            },
            request_id,
        )

    def do_POST(self) -> None:
        request_id = self._new_request_id()
        path = urlsplit(self.path).path
        payload = self._read_json_body(request_id)
        if payload is None:
            return
        if path == "/api/login":
            self._login(payload, request_id)
            return
        if path == "/api/mfa":
            self._verify_mfa(payload, request_id)
            return
        if path == "/api/session/revoke":
            self._revoke_session(request_id)
            return
        if path.startswith("/api/objects/"):
            self._update_object(path.rsplit("/", 1)[-1], payload, request_id)
            return
        if path == "/api/requests":
            self._create_request(payload, request_id)
            return
        self._respond_json(404, {"code": "not_found"}, request_id)

    def _login(self, payload: dict[str, Any], request_id: str) -> None:
        username = payload.get("username")
        password = payload.get("password")
        if not isinstance(username, str) or not isinstance(password, str):
            self.state.record_audit("anonymous", "auth.login", "denied", request_id)
            self._respond_json(401, {"code": "invalid_credentials"}, request_id)
            return
        with self.state.connection() as connection:
            user = connection.execute(
                "SELECT username, salt_b64, password_hash_b64 FROM users WHERE username = ?",
                (username,),
            ).fetchone()
        password_is_bounded = len(username) <= 128 and len(password) <= 512
        salt_b64 = user["salt_b64"] if user is not None else DUMMY_SALT_B64
        password_hash_b64 = user["password_hash_b64"] if user is not None else DUMMY_HASH_B64
        password_matches = _password_matches(password[:512], salt_b64, password_hash_b64)
        if user is None or not password_is_bounded or not password_matches:
            self.state.record_audit("anonymous", "auth.login", "denied", request_id)
            self._respond_json(401, {"code": "invalid_credentials"}, request_id)
            return
        challenge = secrets.token_urlsafe(32)
        with self.state.connection() as connection:
            connection.execute(
                "INSERT INTO mfa_challenges (token_hash, username, expires_at) VALUES (?, ?, ?)",
                (self.state.hash_token(challenge), username, time.time() + CHALLENGE_LIFETIME_SECONDS),
            )
        self.state.record_audit(username, "auth.mfa.required", "denied_pending_mfa", request_id)
        self._respond_json(
            401,
            {"code": "mfa_required", "access_granted": False, "challenge_id": challenge},
            request_id,
        )

    def _verify_mfa(self, payload: dict[str, Any], request_id: str) -> None:
        challenge = payload.get("challenge_id")
        code = payload.get("code")
        if not isinstance(challenge, str) or not isinstance(code, str):
            self.state.record_audit("anonymous", "auth.mfa.verify", "denied", request_id)
            self._respond_json(401, {"code": "invalid_challenge"}, request_id)
            return
        challenge_hash = self.state.hash_token(challenge)
        with self.state.connection() as connection:
            row = connection.execute(
                """SELECT mfa_challenges.username, mfa_challenges.expires_at,
                          mfa_challenges.attempts, users.display_name, users.role, users.totp_secret
                   FROM mfa_challenges JOIN users ON users.username = mfa_challenges.username
                   WHERE mfa_challenges.token_hash = ?""",
                (challenge_hash,),
            ).fetchone()
        if row is None or row["expires_at"] <= time.time() or row["attempts"] >= 3:
            self.state.record_audit("anonymous", "auth.mfa.verify", "denied", request_id)
            self._respond_json(401, {"code": "invalid_challenge"}, request_id)
            return
        if not _totp_matches(code, row["totp_secret"]):
            with self.state.connection() as connection:
                connection.execute(
                    "UPDATE mfa_challenges SET attempts = attempts + 1 WHERE token_hash = ?",
                    (challenge_hash,),
                )
                connection.execute(
                    "DELETE FROM mfa_challenges WHERE token_hash = ? AND attempts >= 3",
                    (challenge_hash,),
                )
            self.state.record_audit(row["username"], "auth.mfa.verify", "denied", request_id)
            self._respond_json(401, {"code": "invalid_mfa"}, request_id)
            return
        session_token = secrets.token_urlsafe(32)
        with self.state.connection() as connection:
            connection.execute("DELETE FROM mfa_challenges WHERE token_hash = ?", (challenge_hash,))
            connection.execute(
                """INSERT INTO sessions (token_hash, username, created_at_utc, expires_at)
                   VALUES (?, ?, ?, ?)""",
                (
                    self.state.hash_token(session_token),
                    row["username"],
                    utc_now(),
                    time.time() + SESSION_LIFETIME_SECONDS,
                ),
            )
        self.state.record_audit(row["username"], "auth.login", "allowed", request_id)
        cookie = (
            f"{COOKIE_NAME}={session_token}; Path={COOKIE_PATH}; Max-Age={SESSION_LIFETIME_SECONDS}; "
            "HttpOnly; SameSite=Strict"
        )
        self._respond_json(
            200,
            {
                "status": "authenticated",
                "user": {
                    "username": row["username"],
                    "display_name": row["display_name"],
                    "role": row["role"],
                },
            },
            request_id,
            extra_headers={"Set-Cookie": cookie},
        )

    def _revoke_session(self, request_id: str) -> None:
        user = self._actor()
        token = _session_token(self.headers.get("Cookie"))
        if user is None or token is None:
            self._unauthenticated(request_id, "auth.session.revoke")
            return
        with self.state.connection() as connection:
            connection.execute(
                "UPDATE sessions SET revoked_at_utc = ? WHERE token_hash = ? AND revoked_at_utc IS NULL",
                (utc_now(), self.state.hash_token(token)),
            )
        self.state.record_audit(user["username"], "auth.session.revoke", "revoked", request_id)
        self._respond_json(
            200,
            {"status": "revoked"},
            request_id,
            extra_headers={"Set-Cookie": f"{COOKIE_NAME}=; Path={COOKIE_PATH}; Max-Age=0; HttpOnly; SameSite=Strict"},
        )

    def _update_object(self, object_id: str, payload: dict[str, Any], request_id: str) -> None:
        user = self._actor()
        if user is None:
            self._unauthenticated(request_id, "object.update")
            return
        content = payload.get("content")
        if not isinstance(content, str) or len(content) > 4096:
            self._respond_json(400, {"code": "invalid_content"}, request_id)
            return
        with self.state.connection() as connection:
            record = connection.execute(
                "SELECT object_id, owner_username FROM objects WHERE object_id = ?",
                (object_id,),
            ).fetchone()
            if record is not None and user["role"] in {"editor", "admin"} and (
                user["role"] == "admin" or record["owner_username"] == user["username"]
            ):
                connection.execute("UPDATE objects SET content = ? WHERE object_id = ?", (content, object_id))
        if record is None:
            self.state.record_audit(user["username"], "object.update", "denied", request_id)
            self._respond_json(404, {"code": "not_found"}, request_id)
            return
        if user["role"] not in {"editor", "admin"}:
            self.state.record_audit(user["username"], "object.update", "denied", request_id)
            self._respond_json(403, {"code": "forbidden"}, request_id)
            return
        if user["role"] != "admin" and record["owner_username"] != user["username"]:
            self.state.record_audit(user["username"], "object.update", "denied", request_id)
            self._respond_json(404, {"code": "not_found"}, request_id)
            return
        self.state.record_audit(user["username"], "object.update", "allowed", request_id)
        self._respond_json(200, {"id": object_id, "content": content}, request_id)

    def _create_request(self, payload: dict[str, Any], request_id: str) -> None:
        user = self._actor()
        if user is None:
            self._unauthenticated(request_id, "request.create")
            return
        subject = payload.get("subject")
        details = payload.get("details")
        if not isinstance(subject, str) or not isinstance(details, str):
            self._respond_json(400, {"code": "invalid_request"}, request_id)
            return
        with self.state.connection() as connection:
            connection.execute(
                "INSERT INTO requests (request_id, actor, subject, details, created_at_utc) VALUES (?, ?, ?, ?, ?)",
                (request_id, user["username"], subject, details, utc_now()),
            )
        self.state.record_audit(user["username"], "request.create", "allowed", request_id)
        self._respond_json(
            201,
            {"status": "accepted", "accepted_bytes": getattr(self, "_received_body_bytes", 0)},
            request_id,
        )


class LabHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], state: LabState):
        self.state = state
        super().__init__(address, LabRequestHandler)


def create_server(
    host: str,
    port: int,
    database_path: Path | str,
    runtime_dir: Path | str,
) -> LabHTTPServer:
    del runtime_dir  # Runtime fixture operations are invoked only by the explicit test runner.
    state = LabState(database_path)
    return LabHTTPServer((host, port), state)


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve the local synthetic cybersecurity lab.")
    parser.add_argument("--host", choices=("127.0.0.1", "0.0.0.0"), default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--database", type=Path, default=Path("evidencias/laboratorio/runtime/lab.sqlite3"))
    parser.add_argument("--runtime-dir", type=Path, default=Path("evidencias/laboratorio/runtime"))
    args = parser.parse_args()
    if args.host == "0.0.0.0" and __import__("os").environ.get("LAB_CONTAINER") != "1":
        parser.error("0.0.0.0 binding is permitted only inside the isolated lab container")
    if not 1024 <= args.port <= 65_535:
        parser.error("--port must be between 1024 and 65535")

    server = create_server(args.host, args.port, args.database, args.runtime_dir)
    print(f"LOCAL_LAB_READY host={args.host} port={args.port} database=ephemeral-or-fixture-only", flush=True)
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
