"""Run bounded local HTTP/fixture cases and persist measured, redacted results."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import platform
import sys
import time
import sqlite3
from pathlib import Path
from typing import Any

from .test_suite import CASE_DEFINITIONS, CASE_EXPECTATIONS, GROUPS, LabHarness, utc_now


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_ROOT = PROJECT_ROOT / "evidencias" / "laboratorio"


def _output_root() -> Path:
    configured = os.environ.get("LAB_OUTPUT_ROOT")
    return Path(configured).resolve() if configured else DEFAULT_OUTPUT_ROOT.resolve()


def _within_output_root(path: Path | str, label: str) -> Path:
    resolved = Path(path).resolve()
    root = _output_root()
    if resolved != root and not resolved.is_relative_to(root):
        raise ValueError(f"{label} must be below the laboratory evidence directory")
    return resolved


def _case_metrics(harness: LabHarness) -> dict[str, Any]:
    clients = harness.clients
    durations = [duration for client in clients for duration in client.request_durations_ms]
    return {
        "http_requests": sum(client.request_count for client in clients),
        "request_payload_bytes_sent": sum(client.payload_bytes_sent for client in clients),
        "response_body_bytes_received": sum(client.payload_bytes_received for client in clients),
        "request_duration_ms_total": round(sum(durations), 3),
        "max_request_duration_ms": round(max(durations, default=0.0), 3),
    }


def _run_case(case_id: str, runtime_root: Path, command: str) -> dict[str, Any]:
    title, callback = CASE_DEFINITIONS[case_id]
    started_at = utc_now()
    start = time.perf_counter()
    harness = LabHarness()
    try:
        observed = callback(harness, runtime_root)
        passed = True
        error = None
    except Exception as exception:  # A failed assertion must be recorded as a failed case.
        observed = None
        passed = False
        error = {"type": type(exception).__name__, "message": str(exception)[:300]}
    finally:
        metrics = _case_metrics(harness)
        harness.close()
    duration_ms = round((time.perf_counter() - start) * 1000, 3)
    result: dict[str, Any] = {
        "case_id": case_id,
        "case": title,
        "expected": CASE_EXPECTATIONS[case_id],
        "observed": observed if passed else error,
        "passed": passed,
        "command": command,
        "started_utc": started_at,
        "finished_utc": utc_now(),
        "duration_ms": duration_ms,
        "metrics": metrics,
    }
    return result


def run_group(group: str, artifact_dir: Path, runtime_dir: Path, command: str) -> dict[str, Any]:
    case_ids = tuple(CASE_DEFINITIONS) if group == "all" else GROUPS[group]
    results: list[dict[str, Any]] = []
    started_at = utc_now()
    for case_id in case_ids:
        result = _run_case(case_id, runtime_dir, command)
        results.append(result)
        status = "PASS" if result["passed"] else "FAIL"
        print(
            f"[{status}] {case_id} | {result['duration_ms']:.3f} ms | "
            f"{json.dumps(result['observed'], ensure_ascii=False, separators=(',', ':'))}",
            flush=True,
        )
    summary = {
        "group": group,
        "started_utc": started_at,
        "finished_utc": utc_now(),
        "command": command,
        "cases_total": len(results),
        "cases_passed": sum(1 for result in results if result["passed"]),
        "cases_failed": sum(1 for result in results if not result["passed"]),
        "http_requests": sum(result["metrics"]["http_requests"] for result in results),
        "request_payload_bytes_sent": sum(
            result["metrics"]["request_payload_bytes_sent"] for result in results
        ),
        "response_body_bytes_received": sum(
            result["metrics"]["response_body_bytes_received"] for result in results
        ),
        "request_duration_ms_total": round(
            sum(result["metrics"]["request_duration_ms_total"] for result in results), 3
        ),
        "duration_ms": round(sum(result["duration_ms"] for result in results), 3),
        "runtime": {
            "python": platform.python_version(),
            "sqlite": sqlite3.sqlite_version,
            "platform": platform.system(),
        },
        "cases": results,
    }
    group_dir = artifact_dir / "groups"
    group_dir.mkdir(parents=True, exist_ok=True)
    path = group_dir / f"{group}.json"
    path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(
        f"GROUP_RESULT group={group} passed={summary['cases_passed']}/{summary['cases_total']} "
        f"failed={summary['cases_failed']} http_requests={summary['http_requests']} "
        f"duration_ms={summary['duration_ms']:.3f} result={path}",
        flush=True,
    )
    return summary


class Tee:
    def __init__(self, *streams: Any):
        self.streams = streams

    def write(self, text: str) -> int:
        for stream in self.streams:
            stream.write(text)
            stream.flush()
        return len(text)

    def flush(self) -> None:
        for stream in self.streams:
            stream.flush()


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the synthetic local laboratory test cases.")
    parser.add_argument("--group", choices=(*GROUPS.keys(), "all"), required=True)
    parser.add_argument("--artifact-dir", type=Path, default=DEFAULT_OUTPUT_ROOT / "work")
    parser.add_argument("--runtime-dir", type=Path, default=DEFAULT_OUTPUT_ROOT / "runtime")
    parser.add_argument("--command-label", default="python3 -m laboratorio.run_tests")
    args = parser.parse_args()
    artifact_dir = _within_output_root(args.artifact_dir, "--artifact-dir")
    runtime_dir = _within_output_root(args.runtime_dir, "--runtime-dir")
    artifact_dir.mkdir(parents=True, exist_ok=True)
    runtime_dir.mkdir(parents=True, exist_ok=True)
    log_dir = artifact_dir / "logs" / "groups"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f"{args.group}.log"
    with log_path.open("w", encoding="utf-8") as log_file:
        output = Tee(sys.stdout, log_file)
        with contextlib.redirect_stdout(output):
            print(f"COMMAND {args.command_label}", flush=True)
            print(
                f"GROUP {args.group} cases={len(CASE_DEFINITIONS) if args.group == 'all' else len(GROUPS[args.group])}",
                flush=True,
            )
            summary = run_group(args.group, artifact_dir, runtime_dir, args.command_label)
    return 0 if summary["cases_failed"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
