#!/usr/bin/env python3
"""Loopback-only PTY terminal for running a fixed set of isolated lab cases."""

from __future__ import annotations

import argparse
import errno
import fcntl
import hashlib
import json
import os
import pty
import re
import select
import shlex
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_EVIDENCE_ROOT = PROJECT_ROOT / "evidencias" / "laboratorio"
CONTAINER_NAME = "proyectouniti-lab-demo"
NETWORK_NAME = "proyectouniti-lab-isolated"
DEFAULT_RUNTIME_IMAGE = "marfil-pdf-test:latest"
DEFAULT_RUNTIME_IMAGE_ID = "sha256:4180697e2ec643227d99f19ffd95f4315e496e5db5192b9ce328a96ce6214310"
OFFICIAL_PYTHON_ARM64_REFERENCE = (
    "docker.io/library/python:3.12.13-slim@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36"
)
OFFICIAL_PYTHON_ARM64_IMAGE_ID = "sha256:0445c02b019cf3f9d61bac90acaac8e2d37ae6991b3384bd9d75fec93bcdfe98"
CAPTURE_PORT = 18_766
APP_PROXY_PORT = 18_765
MAX_OUTPUT_BYTES = 524_288
PROCESS_TIMEOUT_SECONDS = 90
MAX_PROXY_BODY_BYTES = 65_537
MAX_PROXY_RESPONSE_BYTES = 1_048_576
GROUP_LABELS = {
    "auth_mfa": "Autenticación y MFA",
    "rbac_idor": "RBAC y objeto A/B",
    "integrity_audit": "Integridad y auditoría",
    "size_revocation": "Límite 64 KiB y revocación",
    "attack_backup": "ATT&CK en fixtures y recuperación",
}
ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _validate_evidence_root(path: Path | str) -> Path:
    evidence_root = Path(path).resolve()
    expected_root = DEFAULT_EVIDENCE_ROOT.resolve()
    if evidence_root != expected_root:
        raise ValueError(f"Evidence output must be exactly {expected_root}")
    return evidence_root


def _docker_client_environment(evidence_root: Path) -> dict[str, str]:
    environment = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": os.environ.get("HOME", str(evidence_root / "work" / "capture-home")),
        "TMPDIR": str(evidence_root / "work" / "capture-tmp"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
    }
    for name in ("DOCKER_CONFIG", "DOCKER_HOST", "DOCKER_CONTEXT"):
        if os.environ.get(name):
            environment[name] = os.environ[name]
    return environment


def _docker_command(
    arguments: list[str], evidence_root: Path, timeout: int = 20
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["docker", *arguments],
        capture_output=True,
        timeout=timeout,
        check=False,
        env=_docker_client_environment(evidence_root),
    )


def _capture_server_startup_log(evidence_root: Path, timeout_seconds: float = 10) -> bool:
    log_path = evidence_root / "logs" / "server.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    if log_path.is_symlink():
        raise ValueError("Refusing a symlink at evidencias/laboratorio/logs/server.log")
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        logs = _docker_command(["logs", CONTAINER_NAME], evidence_root, timeout=5)
        raw = logs.stdout + logs.stderr
        if logs.returncode == 0 and b"LOCAL_LAB_READY " in raw:
            log_path.write_bytes(raw)
            print(
                f"SERVER_STARTUP_LOG_CAPTURED path={log_path.relative_to(PROJECT_ROOT)} bytes={len(raw)}",
                flush=True,
            )
            return True
        status = _docker_command(["inspect", "--format", "{{.State.Status}}", CONTAINER_NAME], evidence_root)
        if status.returncode == 0 and status.stdout.decode("utf-8", errors="replace").strip() != "running":
            return False
        time.sleep(0.2)
    return False


def start_container(evidence_root: Path) -> int:
    """Start the local-only lab only after verifying the configured local image ID."""
    runtime_image = os.environ.get("LAB_RUNTIME_IMAGE", DEFAULT_RUNTIME_IMAGE).strip()
    expected_image_id = os.environ.get("LAB_RUNTIME_IMAGE_ID", DEFAULT_RUNTIME_IMAGE_ID).strip()
    if not runtime_image or any(character.isspace() for character in runtime_image):
        print("LAB_START_FAILED invalid LAB_RUNTIME_IMAGE", flush=True)
        return 2
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", expected_image_id):
        print("LAB_START_FAILED LAB_RUNTIME_IMAGE_ID must be a sha256 config image ID", flush=True)
        return 2

    try:
        image = _docker_command(
            ["image", "inspect", "--format", "{{.Id}}", runtime_image], evidence_root
        )
        if image.returncode != 0:
            print(
                "LAB_START_FAILED configured image is not available locally; "
                "pull it explicitly by pinned digest first if authorized",
                flush=True,
            )
            return image.returncode or 1
        actual_image_id = image.stdout.decode("utf-8", errors="replace").strip()
        if actual_image_id != expected_image_id:
            print(
                f"LAB_START_FAILED image ID mismatch expected={expected_image_id} actual={actual_image_id}",
                flush=True,
            )
            return 2

        network = _docker_command(
            ["network", "inspect", "--format", "{{.Internal}}", NETWORK_NAME], evidence_root
        )
        network_created = False
        if network.returncode != 0:
            created = _docker_command(["network", "create", "--internal", NETWORK_NAME], evidence_root)
            if created.returncode != 0:
                print("LAB_START_FAILED could not create the internal Docker network", flush=True)
                return created.returncode or 1
            network_created = True
        elif network.stdout.decode("utf-8", errors="replace").strip().lower() != "true":
            print("LAB_START_FAILED refusing to use a Docker network that is not internal", flush=True)
            return 2

        existing = _docker_command(["container", "inspect", CONTAINER_NAME], evidence_root)
        if existing.returncode == 0:
            print(f"LAB_START_FAILED container {CONTAINER_NAME} already exists; refusing to replace it", flush=True)
            return 2

        source = os.environ.get("LAB_RUNTIME_IMAGE_SOURCE")
        if not source:
            if runtime_image == DEFAULT_RUNTIME_IMAGE:
                source = "preexisting-local-image"
            elif (
                runtime_image == OFFICIAL_PYTHON_ARM64_REFERENCE
                and actual_image_id == OFFICIAL_PYTHON_ARM64_IMAGE_ID
            ):
                source = "official-python-3.12.13-slim-pinned"
            else:
                source = "configured-local-image"
        manifest_match = re.search(r"@sha256:([0-9a-f]{64})$", runtime_image)
        manifest_digest = f"sha256:{manifest_match.group(1)}" if manifest_match else "none"
        capture_source_hash = hashlib.sha256(Path(__file__).resolve().read_bytes()).hexdigest()
        version = _docker_command(["version", "--format", "{{.Server.Version}}"], evidence_root)
        server_version = version.stdout.decode("utf-8", errors="replace").strip() if version.returncode == 0 else "unknown"
        startup_path = evidence_root / "runtime" / "startup.json"
        startup_path.parent.mkdir(parents=True, exist_ok=True)
        if startup_path.is_symlink() or (startup_path.exists() and not startup_path.is_file()):
            print("LAB_START_FAILED refusing a non-regular runtime/startup.json", flush=True)
            return 2
        helper_command = shlex.join(
            [
                f"LAB_RUNTIME_IMAGE={runtime_image}",
                f"LAB_RUNTIME_IMAGE_ID={actual_image_id}",
                f"LAB_RUNTIME_IMAGE_SOURCE={source}",
                "python3",
                "herramientas/lab_capture.py",
                "--start-container",
            ]
        )
        docker_argv = [
            "docker",
            "run",
            "--detach",
            "--pull=never",
            "--rm",
            "--name",
            CONTAINER_NAME,
            "--network",
            NETWORK_NAME,
            "--read-only",
            "--cpus=1",
            "--memory=256m",
            "--pids-limit=32",
            "--ulimit",
            "nofile=64:64",
            "--ulimit",
            "fsize=1048576:1048576",
            "--ulimit",
            "cpu=90:90",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=32m,mode=1777",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "--mount",
            f"type=bind,src={PROJECT_ROOT / 'laboratorio'},dst=/app/laboratorio,readonly",
            "--mount",
            f"type=bind,src={evidence_root},dst=/outputs",
            "--workdir",
            "/app",
            "--entrypoint=/usr/bin/env",
            runtime_image,
            "-i",
            *[
                "PATH=/usr/local/bin:/usr/bin:/bin",
                "HOME=/tmp",
                "TMPDIR=/tmp",
                "PYTHONPATH=/app",
                "PYTHONDONTWRITEBYTECODE=1",
                "LAB_OUTPUT_ROOT=/outputs",
                f"LAB_DOCKER_NETWORK={NETWORK_NAME}",
                "LAB_DOCKER_NETWORK_INTERNAL=true",
                f"LAB_RUNTIME_IMAGE={runtime_image}",
                f"LAB_RUNTIME_IMAGE_ID={actual_image_id}",
                f"LAB_RUNTIME_IMAGE_SOURCE={source}",
                f"LAB_RUNTIME_MANIFEST_DIGEST={manifest_digest}",
                f"LAB_CAPTURE_SOURCE_SHA256={capture_source_hash}",
                f"LAB_START_COMMAND={helper_command}",
                f"LAB_DOCKER_SERVER_VERSION={server_version}",
                "TZ=UTC",
            ],
            "python3",
            "-m",
            "laboratorio.app",
            "--host",
            "127.0.0.1",
            "--port",
            "8765",
            "--database",
            "/tmp/lab.sqlite3",
            "--runtime-dir",
            "/outputs/runtime",
        ]
        started = _docker_command(docker_argv[1:], evidence_root, timeout=30)
        if started.returncode != 0:
            print("LAB_START_FAILED docker run returned non-zero; no external pull was attempted", flush=True)
            return started.returncode or 1
        container_id = started.stdout.decode("utf-8", errors="replace").strip()
        startup_metadata = {
            "started_at_utc": _utc_now(),
            "container_name": CONTAINER_NAME,
            "container_id": container_id,
            "docker_server_version": server_version,
            "docker_network": NETWORK_NAME,
            "docker_network_internal": True,
            "docker_network_created_by_this_start": network_created,
            "runtime_image_reference": runtime_image,
            "runtime_image_id": actual_image_id,
            "runtime_image_source": source,
            "runtime_manifest_digest": manifest_digest,
            "lab_capture_source_sha256": capture_source_hash,
            "start_command": helper_command,
            "docker_run_argv": docker_argv,
            "docker_run_command": shlex.join(docker_argv),
        }
        try:
            startup_path.write_text(
                json.dumps(startup_metadata, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
        except OSError:
            _docker_command(["stop", CONTAINER_NAME], evidence_root, timeout=15)
            print("LAB_START_FAILED could not persist runtime/startup.json; container was stopped", flush=True)
            return 1
        if not _capture_server_startup_log(evidence_root):
            _docker_command(["stop", CONTAINER_NAME], evidence_root, timeout=15)
            print("LAB_START_FAILED local service did not produce its readiness log; container was stopped", flush=True)
            return 1
        print(
            f"LAB_CONTAINER_STARTED name={CONTAINER_NAME} container_id={container_id} "
            f"image={runtime_image} image_id={actual_image_id} image_source={source} "
            f"manifest_digest={manifest_digest} network_internal=true docker_server={server_version}",
            flush=True,
        )
        return 0
    except (OSError, subprocess.TimeoutExpired) as exception:
        print(f"LAB_START_FAILED {type(exception).__name__}", flush=True)
        return 1


class CaptureRegistry:
    def __init__(self, container: str, evidence_root: Path):
        if container != CONTAINER_NAME:
            raise ValueError(f"Only the dedicated lab container {CONTAINER_NAME} is allowed")
        self.container = container
        self.evidence_root = evidence_root
        self.lock = threading.Lock()
        self.states: dict[str, dict[str, Any]] = {
            group: {
                "group": group,
                "label": label,
                "status": "ready",
                "command": None,
                "stdout": "",
                "exit_status": None,
                "started_utc": None,
                "finished_utc": None,
                "duration_ms": None,
                "output_bytes": 0,
                "timed_out": False,
                "output_limited": False,
            }
            for group, label in GROUP_LABELS.items()
        }

    def command_argv(self, group: str) -> list[str]:
        if group not in GROUP_LABELS:
            raise ValueError("Unknown laboratory group")
        container_python_env = [
            "/usr/bin/env",
            "-i",
            "PATH=/usr/local/bin:/usr/bin:/bin",
            "PYTHONPATH=/app",
            "PYTHONDONTWRITEBYTECODE=1",
            "TZ=UTC",
            "TERM=dumb",
            "LAB_OUTPUT_ROOT=/outputs",
        ]
        runner_args = [
            "python3",
            "-m",
            "laboratorio.run_tests",
            "--group",
            group,
            "--artifact-dir",
            "/outputs",
            "--runtime-dir",
            "/outputs/runtime",
        ]
        return [
            "docker",
            "exec",
            "--interactive",
            "--tty",
            "--env",
            "TERM=dumb",
            self.container,
            *container_python_env,
            *runner_args,
        ]

    def state(self, group: str) -> dict[str, Any]:
        with self.lock:
            if group not in self.states:
                raise KeyError(group)
            return dict(self.states[group])

    def start(self, group: str) -> dict[str, Any]:
        with self.lock:
            if group not in self.states:
                raise KeyError(group)
            current = self.states[group]
            if current["status"] != "ready":
                return dict(current)
            argv = self.command_argv(group)
            current.update(
                {
                    "status": "running",
                    "command": shlex.join(argv),
                    "started_utc": _utc_now(),
                }
            )
        worker = threading.Thread(target=self._execute, args=(group, argv), daemon=True)
        worker.start()
        return self.state(group)

    def _execute(self, group: str, argv: list[str]) -> None:
        started = time.monotonic()
        master_fd, slave_fd = pty.openpty()
        fcntl.fcntl(master_fd, fcntl.F_SETFL, fcntl.fcntl(master_fd, fcntl.F_GETFL) | os.O_NONBLOCK)
        environment = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "HOME": os.environ.get("HOME", str(self.evidence_root / "work" / "capture-home")),
            "TMPDIR": str(self.evidence_root / "work" / "capture-tmp"),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "TZ": "UTC",
            "DOCKER_CLI_HINTS": "false",
        }
        for name in ("DOCKER_CONFIG", "DOCKER_HOST", "DOCKER_CONTEXT"):
            if os.environ.get(name):
                environment[name] = os.environ[name]
        Path(environment["HOME"]).mkdir(parents=True, exist_ok=True)
        Path(environment["TMPDIR"]).mkdir(parents=True, exist_ok=True)
        log_dir = self.evidence_root / "logs" / "terminal"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / f"{group}.log"
        raw_output = bytearray()
        process: subprocess.Popen[bytes] | None = None
        timed_out = False
        output_limited = False
        runner_error = None
        try:
            process = subprocess.Popen(
                argv,
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                close_fds=True,
                start_new_session=True,
                env=environment,
            )
            os.close(slave_fd)
            deadline = started + PROCESS_TIMEOUT_SECONDS
            with log_path.open("wb") as raw_log:
                while True:
                    if time.monotonic() >= deadline:
                        timed_out = True
                        break
                    readable, _, _ = select.select([master_fd], [], [], 0.1)
                    read_eof = False
                    if readable:
                        try:
                            chunk = os.read(master_fd, 8192)
                        except BlockingIOError:
                            chunk = b""
                        except OSError as exception:
                            chunk = b""
                            read_eof = exception.errno in {errno.EIO, errno.EBADF}
                        if chunk:
                            room = MAX_OUTPUT_BYTES - len(raw_output)
                            if room <= 0:
                                output_limited = True
                                break
                            kept = chunk[:room]
                            raw_output.extend(kept)
                            raw_log.write(kept)
                            raw_log.flush()
                            if len(kept) < len(chunk):
                                output_limited = True
                                break
                        elif not read_eof:
                            read_eof = True
                    if process.poll() is not None and (not readable or read_eof):
                        break
                    if read_eof and process.poll() is None:
                        break
            if process.poll() is None and not (timed_out or output_limited):
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    timed_out = True
            if timed_out or output_limited:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                    process.wait(timeout=2)
                except (ProcessLookupError, subprocess.TimeoutExpired):
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                process.wait(timeout=2)
        except Exception as exception:
            runner_error = f"{type(exception).__name__}: {exception}"
        finally:
            try:
                os.close(slave_fd)
            except OSError:
                pass
            try:
                os.close(master_fd)
            except OSError:
                pass
        finished = time.monotonic()
        exit_status = process.returncode if process is not None else 127
        if timed_out or output_limited:
            exit_status = 124 if timed_out else 125
        stdout = raw_output.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")
        stdout = ANSI_ESCAPE.sub("", stdout)
        with self.lock:
            self.states[group].update(
                {
                    "status": "finished",
                    "stdout": stdout,
                    "exit_status": exit_status,
                    "finished_utc": _utc_now(),
                    "duration_ms": round((finished - started) * 1000, 3),
                    "output_bytes": len(raw_output),
                    "timed_out": timed_out,
                    "output_limited": output_limited,
                    "runner_error": runner_error,
                }
            )
        self._annotate_group_result(group, argv, exit_status, started, finished, timed_out, output_limited)

    def _annotate_group_result(
        self,
        group: str,
        argv: list[str],
        exit_status: int,
        started: float,
        finished: float,
        timed_out: bool,
        output_limited: bool,
    ) -> None:
        result_path = self.evidence_root / "groups" / f"{group}.json"
        if not result_path.is_file():
            return
        try:
            result = json.loads(result_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        exact_command = shlex.join(argv)
        result["execution_command"] = exact_command
        result["terminal_capture"] = {
            "method": "pty_subprocess_docker_exec",
            "process_exit_status": exit_status,
            "duration_ms": round((finished - started) * 1000, 3),
            "timed_out": timed_out,
            "output_limited": output_limited,
        }
        for case in result.get("cases", []):
            case["command"] = exact_command
        result_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


PAGE = r"""<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Consola PTY · laboratorio local</title>
<style>
:root{color-scheme:dark;--bg:#101817;--panel:#172321;--line:#2b3d38;--ink:#e6eee8;--muted:#9db2a9;--green:#a9e2c2;--amber:#f2d89c;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;-webkit-font-smoothing:antialiased}
*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(circle at 92% 0%,#1c3932 0,transparent 31rem),var(--bg);color:var(--ink)}
main{max-width:1120px;margin:0 auto;padding:30px 26px 40px}.top{display:flex;justify-content:space-between;align-items:flex-start;gap:18px;padding-bottom:20px;border-bottom:1px solid var(--line)}
.eyebrow{margin:0 0 9px;color:var(--green);font-size:10px;letter-spacing:.14em;text-transform:uppercase}h1{margin:0;font:600 25px/1.2 "Avenir Next","Segoe UI",sans-serif;letter-spacing:-.03em}.scope{padding:8px 10px;border:1px solid var(--line);border-radius:7px;color:var(--muted);font-size:10px;white-space:nowrap}
.grid{display:grid;grid-template-columns:260px minmax(0,1fr);gap:17px;margin-top:20px}.groups,.terminal{border:1px solid var(--line);border-radius:12px;background:rgba(23,35,33,.92)}.groups{padding:14px}.groups h2{margin:2px 0 12px;color:var(--muted);font-size:10px;font-weight:500;letter-spacing:.1em;text-transform:uppercase}
.group{display:grid;gap:5px;width:100%;margin:0 0 8px;padding:11px 10px;border:1px solid transparent;border-radius:7px;color:var(--ink);background:transparent;text-align:left;cursor:pointer;font:inherit}
.group:hover{border-color:#47675d;background:#20332e}.group:focus-visible{outline:2px solid var(--green);outline-offset:2px}.group[aria-current=true]{border-color:#436b5c;background:#20352e}.group strong{font-size:11px}.group span{color:var(--muted);font-size:9px;line-height:1.4}
.terminal{min-width:0;overflow:hidden}.terminal-head{padding:13px 15px;border-bottom:1px solid var(--line);background:#1a2926}.lights{display:flex;align-items:center;gap:7px}.light{width:8px;height:8px;border-radius:50%;background:#40544d}.terminal-title{margin-left:7px;color:var(--muted);font-size:10px}
.command{min-height:49px;padding:13px 15px;border-bottom:1px solid #243631;color:#bad9c7;font-size:10px;line-height:1.55;overflow-wrap:anywhere}.command::before{color:var(--green);content:"$ ";white-space:pre}
pre{min-height:410px;max-height:58vh;overflow:auto;margin:0;padding:17px 15px;color:#dbe8df;background:#101817;font-size:11px;line-height:1.55;white-space:pre-wrap;overflow-wrap:anywhere}
.status{display:flex;justify-content:space-between;gap:10px;padding:11px 15px;border-top:1px solid var(--line);color:var(--muted);font-size:10px}.status strong{color:var(--amber);font-weight:600}.status[data-state=finished] strong{color:var(--green)}
.actions{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-top:16px;color:var(--muted);font:11px/1.5 "Avenir Next","Segoe UI",sans-serif}.run{min-height:39px;padding:0 14px;border:1px solid #4b7764;border-radius:7px;color:#e9f5ed;background:#21483a;cursor:pointer;font:600 11px "Avenir Next","Segoe UI",sans-serif}.run:hover:not(:disabled){background:#2b5e4a}.run:focus-visible{outline:2px solid var(--green);outline-offset:2px}.run:disabled{cursor:not-allowed;opacity:.6}
@media(max-width:700px){main{padding:20px 14px}.top{align-items:flex-start}.scope{white-space:normal;text-align:right}.grid{grid-template-columns:1fr}.groups{display:grid;grid-template-columns:1fr 1fr;gap:5px}.groups h2{grid-column:1/-1}.group{margin:0}.terminal pre{min-height:300px}}
</style></head><body><main>
<header class="top"><div><p class="eyebrow">PTY local · ejecución real</p><h1>Consola de pruebas aisladas</h1></div><span class="scope">127.0.0.1 · grupos allowlisted · salida del proceso</span></header>
<div class="grid"><nav class="groups" aria-label="Grupos de pruebas"><h2>Seleccionar grupo</h2><div id="group-list"></div></nav>
<section class="terminal" aria-label="Salida de terminal"><div class="terminal-head"><div class="lights"><i class="light"></i><i class="light"></i><i class="light"></i><span class="terminal-title">PTY · laboratorio local</span></div></div>
<div id="command" class="command">Elegí un grupo para mostrar el comando exacto.</div><pre id="output" aria-live="polite">No hay una ejecución activa. Al iniciar un grupo se crea un proceso conectado a PTY; esta vista recibe su salida en vivo.</pre>
<div id="status" class="status" data-state="ready"><span>Estado: listo</span><strong id="exit">sin proceso</strong></div></section></div>
<div class="actions"><span>La consola sólo ejecuta comandos fijos dentro del contenedor local sin salida a Internet.</span><button id="run" class="run" disabled>Ejecutar grupo</button></div>
</main><script>
const groups=["auth_mfa","rbac_idor","integrity_audit","size_revocation","attack_backup"];let selected=null;let polling=null;
const labels={auth_mfa:"Autenticación y MFA",rbac_idor:"RBAC y objeto A/B",integrity_audit:"Integridad y auditoría",size_revocation:"Límite 64 KiB y revocación",attack_backup:"ATT&CK en fixtures y recuperación"};
const list=document.querySelector("#group-list");for(const group of groups){const button=document.createElement("button");button.className="group";button.type="button";button.dataset.group=group;const title=document.createElement("strong");title.textContent=labels[group];const code=document.createElement("span");code.textContent=group;button.append(title,code);button.addEventListener("click",()=>selectGroup(group));list.append(button)}
function setState(state,exit){document.querySelector("#status").dataset.state=state;document.querySelector("#status span").textContent="Estado: "+(state==="finished"?"finalizado":state==="running"?"ejecutando":"listo");document.querySelector("#exit").textContent=exit}
function selectGroup(group){selected=group;for(const button of document.querySelectorAll(".group"))button.setAttribute("aria-current",String(button.dataset.group===group));document.querySelector("#command").textContent="Preparando comando allowlisted…";document.querySelector("#output").textContent="Sin salida todavía: el proceso se iniciará al pulsar Ejecutar grupo.";document.querySelector("#run").disabled=false;setState("ready","sin proceso");if(polling){clearInterval(polling);polling=null}}
async function poll(){if(!selected)return null;const response=await fetch("/api/state/"+selected,{cache:"no-store"});const state=await response.json();document.querySelector("#command").textContent=state.command||"Comando pendiente";document.querySelector("#output").textContent=state.stdout||"Esperando salida del proceso PTY…";document.querySelector("#output").scrollTop=document.querySelector("#output").scrollHeight;if(state.status==="finished"){clearInterval(polling);polling=null;document.querySelector("#run").disabled=true;setState("finished","exit status: "+state.exit_status);return state}setState(state.status,state.status==="running"?"proceso conectado a PTY":"sin proceso");return state}
document.querySelector("#run").addEventListener("click",async()=>{if(!selected)return;document.querySelector("#run").disabled=true;const response=await fetch("/api/run/"+selected,{method:"POST"});if(!response.ok){document.querySelector("#output").textContent="No se pudo iniciar el proceso allowlisted.";setState("finished","HTTP "+response.status);return}await poll();polling=setInterval(poll,180)});
</script></body></html>"""


class CaptureHandler(BaseHTTPRequestHandler):
    server_version = "LocalPTYCapture/1.0"
    sys_version = ""

    @property
    def registry(self) -> CaptureRegistry:
        return self.server.registry  # type: ignore[attr-defined]

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _json(self, status: int, data: dict[str, Any]) -> None:
        body = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/":
            body = PAGE.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path.startswith("/api/state/"):
            group = path.rsplit("/", 1)[-1]
            try:
                self._json(200, self.registry.state(group))
            except KeyError:
                self._json(404, {"error": "unknown_group"})
            return
        self._json(404, {"error": "not_found"})

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        if not path.startswith("/api/run/"):
            self._json(404, {"error": "not_found"})
            return
        group = path.rsplit("/", 1)[-1]
        try:
            state = self.registry.start(group)
        except KeyError:
            self._json(404, {"error": "unknown_group"})
            return
        if state["status"] != "running":
            self._json(409, {"error": "group_already_started", "state": state["status"]})
            return
        self._json(202, {"status": "started", "group": group})


class CaptureHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], registry: CaptureRegistry):
        self.registry = registry
        super().__init__(address, CaptureHandler)


class DockerLoopbackProxyHandler(BaseHTTPRequestHandler):
    """Relay one bounded loopback HTTP request through Docker exec stdin/stdout."""

    server_version = "LocalDockerLoopbackRelay/1.0"
    sys_version = ""
    protocol_version = "HTTP/1.0"

    @property
    def registry(self) -> CaptureRegistry:
        return self.server.registry  # type: ignore[attr-defined]

    def log_message(self, format: str, *args: Any) -> None:
        # Never log request bodies, MFA values, or session cookies.
        return

    def _error(self, status: int, code: str) -> None:
        body = json.dumps({"code": code}, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def _forward(self) -> None:
        if self.command not in {"GET", "POST"}:
            self._error(405, "method_not_allowed")
            return
        if self.headers.get("Transfer-Encoding"):
            self._error(400, "transfer_encoding_not_supported")
            return
        raw_length = self.headers.get("Content-Length", "0")
        try:
            body_length = int(raw_length)
        except ValueError:
            self._error(400, "invalid_content_length")
            return
        if body_length < 0:
            self._error(400, "invalid_content_length")
            return
        if body_length > MAX_PROXY_BODY_BYTES:
            self._error(413, "payload_too_large")
            return
        body = self.rfile.read(body_length) if body_length else b""
        if len(body) != body_length:
            self._error(400, "incomplete_body")
            return
        request_line = f"{self.command} {self.path} HTTP/1.0\r\n".encode("iso-8859-1")
        header_lines = bytearray()
        for name, value in self.headers.items():
            if name.lower() not in {"connection", "keep-alive", "proxy-connection", "transfer-encoding"}:
                header_lines.extend(f"{name}: {value}\r\n".encode("iso-8859-1"))
        header_lines.extend(b"Connection: close\r\n\r\n")
        request_bytes = request_line + bytes(header_lines) + body
        if len(request_bytes) > 131_072:
            self._error(413, "request_headers_too_large")
            return

        argv = [
            "docker",
            "exec",
            "--interactive",
            self.registry.container,
            "/usr/bin/env",
            "-i",
            "PATH=/usr/local/bin:/usr/bin:/bin",
            "PYTHONPATH=/app",
            "PYTHONDONTWRITEBYTECODE=1",
            "TZ=UTC",
            "python3",
            "-m",
            "laboratorio.bridge",
        ]
        environment = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "HOME": os.environ.get("HOME", str(self.registry.evidence_root / "work" / "capture-home")),
            "TMPDIR": str(self.registry.evidence_root / "work" / "capture-tmp"),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "TZ": "UTC",
        }
        for name in ("DOCKER_CONFIG", "DOCKER_HOST", "DOCKER_CONTEXT"):
            if os.environ.get(name):
                environment[name] = os.environ[name]
        try:
            relay = subprocess.run(
                argv,
                input=request_bytes,
                capture_output=True,
                timeout=12,
                check=False,
                env=environment,
            )
        except subprocess.TimeoutExpired:
            self._error(504, "local_container_relay_timeout")
            return
        except OSError:
            self._error(502, "local_container_relay_unavailable")
            return
        if relay.returncode != 0 or not relay.stdout or len(relay.stdout) > MAX_PROXY_RESPONSE_BYTES:
            self._error(502, "local_container_relay_failed")
            return
        self.close_connection = True
        self.wfile.write(relay.stdout)

    def do_GET(self) -> None:
        self._forward()

    def do_POST(self) -> None:
        self._forward()


class DockerLoopbackProxy(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], registry: CaptureRegistry):
        self.registry = registry
        super().__init__(address, DockerLoopbackProxyHandler)


def collect_server_log(evidence_root: Path, stop_container: bool) -> int:
    environment = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": os.environ.get("HOME", str(evidence_root / "work" / "capture-home")),
        "TMPDIR": str(evidence_root / "work" / "capture-tmp"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
    }
    for name in ("DOCKER_CONFIG", "DOCKER_HOST", "DOCKER_CONTEXT"):
        if os.environ.get(name):
            environment[name] = os.environ[name]
    try:
        logs = subprocess.run(
            ["docker", "logs", CONTAINER_NAME],
            capture_output=True,
            timeout=10,
            check=False,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as exception:
        print(f"SERVER_LOG_CAPTURE_FAILED {type(exception).__name__}", flush=True)
        return 1
    log_path = evidence_root / "logs" / "server.log"
    if logs.returncode != 0:
        if log_path.is_file() and not log_path.is_symlink() and b"LOCAL_LAB_READY " in log_path.read_bytes():
            print(
                f"SERVER_LOG_REUSED path={log_path.relative_to(PROJECT_ROOT)} "
                "container logs were already captured at startup",
                flush=True,
            )
            return 0
        print(f"SERVER_LOG_CAPTURE_FAILED docker_logs_exit={logs.returncode}; no error text was stored as server output", flush=True)
        return logs.returncode
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_bytes(logs.stdout + logs.stderr)
    print(
        f"SERVER_LOG_CAPTURED path={log_path.relative_to(PROJECT_ROOT)} "
        f"bytes={log_path.stat().st_size} docker_logs_exit={logs.returncode}",
        flush=True,
    )
    if logs.returncode != 0:
        return logs.returncode
    if stop_container:
        try:
            stopped = subprocess.run(
                ["docker", "stop", CONTAINER_NAME],
                capture_output=True,
                timeout=15,
                check=False,
                env=environment,
            )
        except (OSError, subprocess.TimeoutExpired) as exception:
            print(f"SERVER_STOP_FAILED {type(exception).__name__}", flush=True)
            return 1
        if stopped.returncode != 0:
            print("SERVER_STOP_FAILED docker stop returned non-zero", flush=True)
            return stopped.returncode
        print("SERVER_STOPPED container=proyectouniti-lab-demo", flush=True)
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve a loopback-only PTY terminal for fixed lab test groups.")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--start-container", action="store_true", help="Start the isolated lab with a verified local image ID")
    mode.add_argument("--serve", action="store_true", help="Start the local PTY-backed capture page")
    mode.add_argument("--collect-server-log", action="store_true", help="Save the dedicated lab container's raw startup log")
    parser.add_argument("--stop-container", action="store_true", help="Stop the dedicated lab container after saving its log")
    parser.add_argument("--container", default=CONTAINER_NAME, choices=(CONTAINER_NAME,))
    parser.add_argument("--port", type=int, default=CAPTURE_PORT, choices=(CAPTURE_PORT,))
    parser.add_argument("--proxy-port", type=int, default=APP_PROXY_PORT, choices=(APP_PROXY_PORT,))
    parser.add_argument("--evidence-dir", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    args = parser.parse_args()
    evidence_root = _validate_evidence_root(args.evidence_dir)
    if args.start_container:
        if args.stop_container:
            parser.error("--stop-container is valid only with --collect-server-log")
        sys.exit(start_container(evidence_root))
    if args.collect_server_log:
        sys.exit(collect_server_log(evidence_root, args.stop_container))
    if args.stop_container:
        parser.error("--stop-container is valid only with --collect-server-log")
    registry = CaptureRegistry(args.container, evidence_root)
    server = CaptureHTTPServer(("127.0.0.1", args.port), registry)
    proxy = DockerLoopbackProxy(("127.0.0.1", args.proxy_port), registry)
    proxy_thread = threading.Thread(target=proxy.serve_forever, kwargs={"poll_interval": 0.2}, daemon=True)
    proxy_thread.start()
    print(
        f"PTY_CAPTURE_READY url=http://127.0.0.1:{args.port}/ "
        f"app_proxy=http://127.0.0.1:{args.proxy_port}/ container={args.container}",
        flush=True,
    )
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()
        proxy.shutdown()
        proxy.server_close()
        proxy_thread.join(timeout=2)


if __name__ == "__main__":
    main()
