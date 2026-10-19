"""Aggregate observed test runs, screenshots, and a SHA-256 evidence manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .test_suite import CASE_DEFINITIONS, GROUPS


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_ROOT = PROJECT_ROOT / "evidencias" / "laboratorio"
EXPECTED_EVIDENCE_IDS = {
    "TERM-01",
    "TERM-02",
    "TERM-03",
    "TERM-04",
    "TERM-05",
    "BROWSER-01",
    "BROWSER-02",
    "BROWSER-03",
    "BROWSER-04",
}

NETWORK_COMMAND = "docker network create --internal proyectouniti-lab-isolated"
BROWSER_CAPTURE_COMMAND = (
    "env -i PATH=\"$PATH\" HOME=\"$HOME\" DOCKER_CONTEXT=desktop-linux "
    "node laboratorio/browser-tools/capture.js --base-url http://127.0.0.1:18765 "
    "--terminal-url http://127.0.0.1:18766 --output-dir evidencias/laboratorio/capturas"
)
OFFICIAL_PYTHON_RUNTIME = {
    "reference": "docker.io/library/python:3.12.13-slim@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36",
    "multi_platform_index_digest": "sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36",
    "linux_arm64_manifest_digest": "sha256:adbc7c33e0abc183557d1d14ce5eb5d261aaadff5451c81a8db636b3ebefcdf6",
    "linux_arm64_image_config_id": "sha256:0445c02b019cf3f9d61bac90acaac8e2d37ae6991b3384bd9d75fec93bcdfe98",
    "version": "Python 3.12.13 slim, Debian Trixie",
    "metadata_query": "docker manifest inspect --verbose docker.io/library/python:3.12.13-slim",
    "metadata_query_downloaded_layers": False,
    "executed_for_captured_evidence": False,
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def evidence_root(path: Path | str) -> Path:
    root = Path(path).resolve()
    allowed = Path(os.environ.get("LAB_OUTPUT_ROOT", DEFAULT_OUTPUT_ROOT)).resolve()
    if root != allowed:
        raise ValueError(f"Evidence root must be exactly {allowed}")
    return root


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object in {path}")
    return value


def validate_capture_file(root: Path, relative_path: str, expected_bytes: int | None = None) -> Path:
    path = (root / relative_path).resolve(strict=True)
    if not path.is_relative_to(root) or path.is_symlink() or not path.is_file():
        raise ValueError(f"Evidence path is not a regular file under the evidence root: {relative_path}")
    if expected_bytes is not None and path.stat().st_size != expected_bytes:
        raise ValueError(f"Screenshot byte count differs from capture metadata: {relative_path}")
    return path


def collect_functional_cases(root: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    cases: list[dict[str, Any]] = []
    group_summaries: list[dict[str, Any]] = []
    for group, expected_case_ids in GROUPS.items():
        path = root / "groups" / f"{group}.json"
        if not path.is_file():
            group_summaries.append(
                {"group": group, "status": "missing", "expected_case_ids": list(expected_case_ids), "cases": []}
            )
            continue
        summary = read_json(path)
        actual_cases = summary.get("cases", [])
        actual_ids = [case.get("case_id") for case in actual_cases]
        group_passed = (
            actual_ids == list(expected_case_ids)
            and summary.get("cases_total") == len(expected_case_ids)
            and summary.get("cases_failed") == 0
        )
        group_summaries.append(
            {
                "group": group,
                "status": "pass" if group_passed else "fail_or_incomplete",
                "command": summary.get("execution_command", summary.get("command")),
                "started_utc": summary.get("started_utc"),
                "finished_utc": summary.get("finished_utc"),
                "duration_ms": summary.get("duration_ms"),
                "cases_total": summary.get("cases_total"),
                "cases_passed": summary.get("cases_passed"),
                "cases_failed": summary.get("cases_failed"),
                "http_requests": summary.get("http_requests"),
                "request_payload_bytes_sent": summary.get("request_payload_bytes_sent"),
                "response_body_bytes_received": summary.get("response_body_bytes_received"),
                "request_duration_ms_total": summary.get("request_duration_ms_total"),
                "runtime": summary.get("runtime", {}),
                "cases": actual_ids,
            }
        )
        for item in actual_cases:
            cases.append(
                {
                    "case_id": item.get("case_id"),
                    "group": group,
                    "case": item.get("case"),
                    "expected": item.get("expected"),
                    "observed": item.get("observed"),
                    "pass": bool(item.get("passed")),
                    "passed": bool(item.get("passed")),
                    "command": item.get("command", summary.get("execution_command", summary.get("command"))),
                    "started_utc": item.get("started_utc"),
                    "finished_utc": item.get("finished_utc"),
                    "duration_ms": item.get("duration_ms"),
                    "metrics": item.get("metrics", {}),
                }
            )
    return cases, group_summaries


def build_evidence_index(root: Path, browser_results: dict[str, Any]) -> dict[str, Any]:
    raw_entries = browser_results.get("evidence", [])
    entries: list[dict[str, Any]] = []
    for item in raw_entries:
        relative = item.get("path")
        if not isinstance(relative, str):
            raise ValueError("Evidence entry has no relative path")
        capture_path = validate_capture_file(root, relative, item.get("screenshot_bytes"))
        metadata = {
            "capture_method": item.get("method"),
            "captured_at_utc": item.get("captured_at_utc"),
            "screenshot_bytes": capture_path.stat().st_size,
        }
        for key in (
            "process_command",
            "process_exit_status",
            "process_duration_ms",
            "raw_log_path",
            "source_origin",
        ):
            if key in item:
                metadata[key] = item[key]
        case_ids = item.get("case_ids", [])
        entries.append(
            {
                "id": item.get("evidence_id"),
                "path": f"evidencias/laboratorio/{relative}",
                "case_id": case_ids[0] if len(case_ids) == 1 else None,
                "case_ids": case_ids,
                "case": case_ids[0] if len(case_ids) == 1 else case_ids,
                "caption": item.get("caption"),
                "method": item.get("method"),
                "metadata": metadata,
            }
        )
    evidence_ids = [entry["id"] for entry in entries]
    if len(evidence_ids) != len(set(evidence_ids)):
        raise ValueError("Evidence IDs must be unique")
    return {
        "generated_at_utc": utc_now(),
        "root": "evidencias/laboratorio",
        "capture_count": len(entries),
        "terminal_capture_count": sum(1 for entry in entries if entry["id"].startswith("TERM-")),
        "browser_capture_count": sum(1 for entry in entries if entry["id"].startswith("BROWSER-")),
        "captures": entries,
    }


def check_evidence_for_secrets(root: Path) -> list[str]:
    prohibited_text = (
        "U7-lab-Reader!2026",
        "U7-lab-Editor!2026",
        "U7-lab-Admin!2026",
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        "12345678901234567890",
        "287082",
        "lab_session=",
    )
    allowed_suffixes = {".json", ".jsonl", ".log", ".txt", ".md", ".csv", ".sha256"}
    violations: list[str] = []
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in allowed_suffixes:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for fragment in prohibited_text:
            if fragment in text:
                violations.append(f"{path.relative_to(root)} contains a prohibited fixture credential/token fragment")
                break
    return violations


def write_manifest(root: Path) -> list[dict[str, Any]]:
    files: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if path.name == "manifest.sha256" or path.name == ".keep" or path.is_dir():
            continue
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"Manifest refuses non-regular evidence path: {path.relative_to(root)}")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        files.append(
            {
                "path": path.relative_to(root).as_posix(),
                "sha256": digest,
                "bytes": path.stat().st_size,
            }
        )
    generated = utc_now()
    lines = [
        f"# SHA-256 manifest generated {generated}; this file and pre-existing .keep markers are excluded."
    ]
    lines.extend(f"{item['sha256']}  {item['path']}" for item in files)
    (root / "manifest.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return files


def write_source_manifest(root: Path, startup_metadata: dict[str, Any]) -> dict[str, Any]:
    project_root = Path(__file__).resolve().parents[1]
    laboratory_root = project_root / "laboratorio"
    capture_hash = startup_metadata.get("lab_capture_source_sha256", "")
    if not re.fullmatch(r"[0-9a-f]{64}", capture_hash):
        raise ValueError("LAB_CAPTURE_SOURCE_SHA256 is required to fingerprint herramientas/lab_capture.py")
    entries: list[tuple[str, str]] = []
    for path in sorted(laboratory_root.rglob("*")):
        relative = path.relative_to(project_root)
        if path.name in {".keep", ".DS_Store"} or "node_modules" in relative.parts or "__pycache__" in relative.parts:
            continue
        if path.is_symlink():
            raise ValueError(f"Source manifest refuses a symlink: {relative.as_posix()}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError(f"Source manifest refuses non-regular path: {relative.as_posix()}")
        entries.append((relative.as_posix(), hashlib.sha256(path.read_bytes()).hexdigest()))
    entries.append(("herramientas/lab_capture.py", capture_hash))
    entries.sort(key=lambda item: item[0])
    content = [
        "# SHA-256 source/fixture fingerprint; paths are relative to the project root.",
        "# Includes laboratorio/ except node_modules, __pycache__, .keep and .DS_Store, plus herramientas/lab_capture.py.",
    ]
    content.extend(f"{digest}  {path}" for path, digest in entries)
    manifest_path = root / "source_manifest.sha256"
    manifest_path.write_text("\n".join(content) + "\n", encoding="utf-8")
    return {
        "path": "evidencias/laboratorio/source_manifest.sha256",
        "file_count": len(entries),
        "manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "capture_helper_sha256": capture_hash,
        "scope": "laboratorio source, fixtures, UI, test/capture scripts, package lock, and herramientas/lab_capture.py; excludes node_modules",
    }


def finalize(root: Path) -> dict[str, Any]:
    startup_path = root / "runtime" / "startup.json"
    startup_metadata = read_json(startup_path) if startup_path.is_file() else {}
    source_manifest = write_source_manifest(root, startup_metadata)
    capture_source_consistent = (
        startup_metadata.get("lab_capture_source_sha256")
        == source_manifest.get("capture_helper_sha256")
        and bool(startup_metadata.get("lab_capture_source_sha256"))
    )
    browser_path = root / "browser-results.json"
    browser_results = read_json(browser_path) if browser_path.is_file() else {}
    functional_cases, group_summaries = collect_functional_cases(root)
    browser_cases = []
    for item in browser_results.get("browser", {}).get("cases", []):
        browser_cases.append(
            {
                "case_id": item.get("case_id"),
                "group": "browser",
                "related_case_ids": next(
                    (
                        entry.get("case_ids", [])
                        for entry in browser_results.get("evidence", [])
                        if entry.get("evidence_id") == item.get("case_id")
                    ),
                    [],
                ),
                "case": item.get("expected"),
                "expected": item.get("expected"),
                "observed": item.get("observed"),
                "pass": bool(item.get("passed")),
                "passed": bool(item.get("passed")),
                "command": item.get("command", browser_results.get("command")),
                "started_utc": item.get("started_utc"),
                "duration_ms": item.get("duration_ms"),
                "metrics": {},
            }
        )
    cases = functional_cases + browser_cases
    evidence_index = build_evidence_index(root, browser_results)
    functional_ids = [case["case_id"] for case in functional_cases]
    expected_functional_ids = [case_id for group in GROUPS.values() for case_id in group]
    functional_complete = functional_ids == expected_functional_ids
    browser_complete = {case["case_id"] for case in browser_cases} == {
        "BROWSER-01",
        "BROWSER-02",
        "BROWSER-03",
        "BROWSER-04",
    }
    evidence_complete = set(entry["id"] for entry in evidence_index["captures"]) == EXPECTED_EVIDENCE_IDS
    all_cases_passed = bool(cases) and all(case["pass"] for case in cases)
    network_is_internal = startup_metadata.get("docker_network_internal") is True
    startup_identity_complete = bool(
        startup_metadata.get("container_id")
        and startup_metadata.get("runtime_image_reference")
        and startup_metadata.get("runtime_image_id")
        and startup_metadata.get("docker_run_argv")
    )
    external_requests_blocked = (
        browser_results.get("browser", {}).get("metrics", {}).get("blocked_external_requests") == 0
        and browser_results.get("terminal", {}).get("metrics", {}).get("blocked_external_requests") == 0
    )
    status = "PASS" if functional_complete and browser_complete and evidence_complete and all_cases_passed and network_is_internal and external_requests_blocked and startup_identity_complete and capture_source_consistent else "INCOMPLETE_OR_FAILED"

    functional_group_data = [
        read_json(root / "groups" / f"{group}.json")
        for group in GROUPS
        if (root / "groups" / f"{group}.json").is_file()
    ]
    functional_http_requests = sum(item.get("http_requests", 0) for item in functional_group_data)
    request_payload_bytes = sum(item.get("request_payload_bytes_sent", 0) for item in functional_group_data)
    response_body_bytes = sum(item.get("response_body_bytes_received", 0) for item in functional_group_data)
    request_duration_ms = sum(item.get("request_duration_ms_total", 0) for item in functional_group_data)
    input_case = next((case for case in functional_cases if case["case_id"] == "INPUT-01"), None)
    attack_case = next((case for case in functional_cases if case["case_id"] == "ATTACK-01"), None)
    backup_case = next((case for case in functional_cases if case["case_id"] == "RECOVERY-01"), None)
    audit_case = next((case for case in functional_cases if case["case_id"] == "AUDIT-01"), None)
    revoke_case = next((case for case in functional_cases if case["case_id"] == "SESSION-01"), None)
    browser_metrics = browser_results.get("browser", {}).get("metrics", {})

    stack = {
        "python": functional_group_data[0].get("runtime", {}).get("python") if functional_group_data else None,
        "sqlite": sqlite3.sqlite_version,
        "python_platform": functional_group_data[0].get("runtime", {}).get("platform") if functional_group_data else None,
        "docker_server": startup_metadata.get("docker_server_version", os.environ.get("LAB_DOCKER_SERVER_VERSION")),
        "docker_network": startup_metadata.get("docker_network", os.environ.get("LAB_DOCKER_NETWORK")),
        "docker_network_internal": network_is_internal,
        "container_image": startup_metadata.get("runtime_image_reference", os.environ.get("LAB_RUNTIME_IMAGE")),
        "container_image_id": startup_metadata.get("runtime_image_id", os.environ.get("LAB_RUNTIME_IMAGE_ID")),
        "container_image_source": startup_metadata.get("runtime_image_source", os.environ.get("LAB_RUNTIME_IMAGE_SOURCE")),
        "container_manifest_digest": startup_metadata.get("runtime_manifest_digest", os.environ.get("LAB_RUNTIME_MANIFEST_DIGEST")),
        "node": browser_results.get("stack", {}).get("node"),
        "playwright_core": browser_results.get("stack", {}).get("playwright_core"),
        "browser": browser_results.get("stack", {}).get("browser"),
        "browser_version": browser_results.get("stack", {}).get("browser_version"),
        "browser_headless": browser_results.get("stack", {}).get("headless"),
        "host_platform": browser_results.get("stack", {}).get("host_platform"),
    }
    commands = {
        "network_create": NETWORK_COMMAND if startup_metadata.get("docker_network_created_by_this_start") else None,
        "server_start": startup_metadata.get("start_command", os.environ.get("LAB_START_COMMAND", "python3 herramientas/lab_capture.py --start-container")),
        "docker_run_command_argv": startup_metadata.get("docker_run_argv"),
        "docker_run_command_shell": startup_metadata.get("docker_run_command"),
        "runtime_image_id_check": "docker image inspect --format '{{.Id}}' \"$LAB_RUNTIME_IMAGE\"",
        "terminal_groups": {
            item["group"]: item.get("execution_command")
            for item in functional_group_data
            if item.get("group") != "all"
        },
        "browser_and_terminal_capture": browser_results.get("command", BROWSER_CAPTURE_COMMAND),
        "browser_capture_reproducible_form": BROWSER_CAPTURE_COMMAND,
        "server_log_capture": "python3 herramientas/lab_capture.py --collect-server-log",
        "server_stop_and_network_remove": "docker stop proyectouniti-lab-demo && docker network rm proyectouniti-lab-isolated",
    }

    violations = check_evidence_for_secrets(root)
    result = {
        "generated_at_utc": utc_now(),
        "scope": "local_synthetic_fixture_laboratory",
        "institutional_data_used": False,
        "institutional_findings_claimed": False,
        "run_status": status,
        "completeness": {
            "functional_cases_expected": len(expected_functional_ids),
            "functional_cases_observed": len(functional_cases),
            "functional_case_ids_complete": functional_complete,
            "browser_cases_expected": 4,
            "browser_cases_observed": len(browser_cases),
            "browser_cases_complete": browser_complete,
            "screenshots_expected": len(EXPECTED_EVIDENCE_IDS),
            "screenshots_observed": evidence_index["capture_count"],
            "screenshot_ids_complete": evidence_complete,
            "all_cases_passed": all_cases_passed,
            "docker_internal_network_verified": network_is_internal,
            "runtime_startup_identity_recorded": startup_identity_complete,
            "capture_helper_source_hash_matches_startup": capture_source_consistent,
            "source_manifest_created": bool(source_manifest.get("manifest_sha256")),
            "blocked_external_browser_requests": external_requests_blocked,
            "evidence_secret_scan_violations": violations,
        },
        "stack": stack,
        "source_manifest": source_manifest,
        "official_python_alternative": OFFICIAL_PYTHON_RUNTIME,
        "resource_limits": {
            "container_cpu": "1 CPU",
            "container_memory_bytes": 268_435_456,
            "container_pids_limit": 32,
            "cpu_seconds_ulimit": 90,
            "file_size_ulimit_bytes": 1_048_576,
            "open_files_ulimit": 64,
            "tmpfs_bytes": 33_554_432,
            "container_root_filesystem_read_only": True,
            "laboratorio_mount_read_only": True,
            "evidence_mount_write_scope": "/outputs -> evidencias/laboratorio only",
        },
        "network_scope": {
            "docker_network_internal": network_is_internal,
            "service_bind_inside_container": "127.0.0.1:8765",
            "host_loopback_proxy": "127.0.0.1:18765",
            "pty_capture_server": "127.0.0.1:18766",
            "docker_published_ports": [],
            "external_test_targets": 0,
            "blocked_external_browser_requests": {
                "app_browser_context": browser_results.get("browser", {}).get("metrics", {}).get("blocked_external_requests"),
                "terminal_browser_context": browser_results.get("terminal", {}).get("metrics", {}).get("blocked_external_requests"),
            },
        },
        "commands": commands,
        "cases": cases,
        "groups": group_summaries,
        "terminal_capture_runs": browser_results.get("terminal", {}).get("cases", []),
        "metrics": {
            "functional_cases_passed": sum(1 for case in functional_cases if case["pass"]),
            "functional_cases_total": len(functional_cases),
            "browser_cases_passed": sum(1 for case in browser_cases if case["pass"]),
            "browser_cases_total": len(browser_cases),
            "terminal_screenshots": evidence_index["terminal_capture_count"],
            "browser_screenshots": evidence_index["browser_capture_count"],
            "functional_http_requests": functional_http_requests,
            "functional_request_payload_bytes": request_payload_bytes,
            "functional_response_body_bytes": response_body_bytes,
            "functional_average_http_response_ms": round(request_duration_ms / functional_http_requests, 3)
            if functional_http_requests
            else None,
            "browser_app_http_requests": browser_metrics.get("app_requests"),
            "browser_api_http_requests": browser_metrics.get("api_requests"),
            "browser_request_payload_bytes": browser_metrics.get("request_payload_bytes"),
            "browser_http_status_counts": browser_metrics.get("status_codes"),
            "measured_functional_plus_browser_http_requests": functional_http_requests
            + int(browser_metrics.get("app_requests", 0)),
            "input_limit_bytes": input_case["observed"].get("limit_bytes") if input_case and input_case["pass"] else None,
            "oversized_request_bytes": input_case["observed"].get("oversized_bytes") if input_case and input_case["pass"] else None,
            "oversized_request_status": input_case["observed"].get("oversized_status") if input_case and input_case["pass"] else None,
            "normal_request_after_oversized_status": input_case["observed"].get("normal_status") if input_case and input_case["pass"] else None,
            "audit_required_fields_verified": audit_case["pass"] if audit_case else False,
            "session_reuse_after_revocation_status": revoke_case["observed"].get("reused_session_status") if revoke_case and revoke_case["pass"] else None,
            "attack_fixture_files_staged": attack_case["observed"].get("staged_fixture_files") if attack_case and attack_case["pass"] else None,
            "staging_alerts_generated": attack_case["observed"].get("alerts_generated") if attack_case and attack_case["pass"] else None,
            "backup_files_hash_verified": backup_case["observed"].get("files_verified") if backup_case and backup_case["pass"] else None,
            "backup_restore_hashes_match": backup_case["observed"].get("all_hashes_match") if backup_case and backup_case["pass"] else None,
            "recovery_damage_detected_in_working_copy": backup_case["observed"].get("damage_detected") if backup_case and backup_case["pass"] else None,
            "recovery_source_unchanged": backup_case["observed"].get("source_unchanged_during_damage") if backup_case and backup_case["pass"] else None,
            "recovery_backup_unchanged": backup_case["observed"].get("backup_unchanged_during_damage") if backup_case and backup_case["pass"] else None,
            "recovery_restoration_completed": backup_case["observed"].get("restoration_completed") if backup_case and backup_case["pass"] else None,
            "recovery_timings_ms": backup_case["observed"].get("timings_ms") if backup_case and backup_case["pass"] else None,
        },
        "limitations": [
            "All accounts and records are synthetic fixtures; no Universidad Nacional del Altiplano systems, users, or findings were accessed or represented.",
            "The 64 KiB scenario is one bounded oversized request followed by one valid request; it is not a flood, load, or DDoS-resistance test.",
            "MITRE ATT&CK T1083, T1005, and T1074.001 are represented only by enumeration, copying, and staging of the two bundled synthetic files.",
            "The alert is a simple local rule over a staging directory, not a SIEM/EDR deployment or institutional monitoring result.",
            "The SQLite audit record is structured test evidence; it is mutable and does not establish legal non-repudiation.",
            "Captured execution used the already-present marfil-pdf-test image and its recorded local image ID; that image is not distributed. The pinned official Python slim option is documented but was not pulled or executed, so it does not recreate the captured runtime or promise pixel-identical screenshots.",
            "RECOVERY-01 is a synthetic file-restoration test: it mutates one disposable working copy, then restores it from backup. It does not test service continuity, high availability, or ransomware behavior.",
            "The source manifest fingerprints laboratory code and fixtures (plus the PTY helper) to reproduce conditions; it does not guarantee pixel-identical output across runtime or browser images.",
            "The headed browser used Playwright screenshots of a live local app and PTY-backed terminal page; no screenshot contains a password, TOTP seed/code, session token, or cookie.",
            "Terminal.app AppleScript window enumeration did not return within the 5-second bound, so no window ID was obtained and screencapture -l was not used; the dedicated PTY-backed terminal fallback was captured instead.",
        ],
    }
    if violations:
        result["run_status"] = "INCOMPLETE_OR_FAILED"

    (root / "resultados.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (root / "evidence_index.json").write_text(
        json.dumps(evidence_index, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    final_violations = check_evidence_for_secrets(root)
    if final_violations:
        result["run_status"] = "INCOMPLETE_OR_FAILED"
        result["completeness"]["evidence_secret_scan_violations"] = final_violations
        (root / "resultados.json").write_text(
            json.dumps(result, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    manifest_files = write_manifest(root)
    return {
        "run_status": result["run_status"],
        "functional_cases": f"{result['metrics']['functional_cases_passed']}/{result['metrics']['functional_cases_total']}",
        "browser_cases": f"{result['metrics']['browser_cases_passed']}/{result['metrics']['browser_cases_total']}",
        "screenshots": evidence_index["capture_count"],
        "manifest_files": len(manifest_files),
        "manifest_sha256": hashlib.sha256((root / "manifest.sha256").read_bytes()).hexdigest(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Aggregate the laboratory's measured outputs and evidence hashes.")
    parser.add_argument("--evidence-dir", type=Path, default=DEFAULT_OUTPUT_ROOT)
    args = parser.parse_args()
    summary = finalize(evidence_root(args.evidence_dir))
    print(
        f"FINALIZATION status={summary['run_status']} functional={summary['functional_cases']} "
        f"browser={summary['browser_cases']} screenshots={summary['screenshots']} "
        f"manifest_files={summary['manifest_files']} manifest_sha256={summary['manifest_sha256']}",
        flush=True,
    )
    return 0 if summary["run_status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
