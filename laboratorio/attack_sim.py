"""Safe file-activity demonstration restricted to bundled synthetic fixtures."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
import time
from typing import Any


FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures" / "attack" / "data"
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_ROOT = PROJECT_ROOT / "evidencias" / "laboratorio"


def _output_root() -> Path:
    configured = os.environ.get("LAB_OUTPUT_ROOT")
    return Path(configured).resolve() if configured else DEFAULT_OUTPUT_ROOT.resolve()


def _validated_output(path: Path | str) -> Path:
    output = Path(path).resolve()
    root = _output_root()
    if output == root or not output.is_relative_to(root):
        raise ValueError("Fixture output must remain below the laboratory evidence directory")
    return output


def _fixture_files() -> list[Path]:
    root = FIXTURE_ROOT.resolve(strict=True)
    files: list[Path] = []
    for entry in sorted(os.scandir(root), key=lambda item: item.name):
        candidate = Path(entry.path)
        if entry.is_file(follow_symlinks=False) and candidate.resolve(strict=True).parent == root:
            files.append(candidate)
    if not files:
        raise RuntimeError("The synthetic fixture set is empty")
    return files


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(16_384), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _output_directory(parent: Path, name: str) -> Path:
    directory = parent / name
    if directory.is_symlink():
        raise ValueError("Fixture operation refuses a symlinked output directory")
    directory.mkdir(parents=True, exist_ok=True)
    if directory.resolve(strict=True).parent != parent.resolve(strict=True):
        raise ValueError("Fixture output directory escaped its assigned parent")
    return directory


def _output_file(parent: Path, name: str) -> Path:
    path = parent / name
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError("Fixture operation refuses a symlink or non-file output target")
    return path


def monitor_fixture_staging(staging_dir: Path | str, output_dir: Path | str) -> dict[str, Any]:
    """Apply a self-contained local rule to one fixture-only staging directory."""
    output = _validated_output(output_dir)
    staging = Path(staging_dir).resolve(strict=True)
    if staging.parent != output or staging.name != "staging":
        raise ValueError("The local staging rule accepts only this run's direct staging directory")
    observed_files = sorted(
        entry.name
        for entry in os.scandir(staging)
        if entry.is_file(follow_symlinks=False)
    )
    alert = None
    if observed_files:
        alert = {
            "alert_id": "LAB-ALERT-001",
            "rule_id": "LAB-DET-001",
            "created_at_utc": _utc_now(),
            "classification": "synthetic_fixture_staging_observed",
            "observed_file_count": len(observed_files),
            "scope": "bundled_fixtures_only",
        }
    alerts_path = _output_file(output, "alerts.jsonl")
    alerts_path.write_text(
        (json.dumps(alert, ensure_ascii=False, separators=(",", ":")) + "\n") if alert else "",
        encoding="utf-8",
    )
    return {
        "observed_staged_files": observed_files,
        "alerts_generated": int(alert is not None),
        "alert_rule_id": alert["rule_id"] if alert else None,
        "alert_file": alerts_path.name,
        "rule_scope": "self_contained_local_fixture_directory",
    }


def simulate_fixture_activity(output_dir: Path | str) -> dict[str, Any]:
    """Enumerate, copy, and stage only the fixed synthetic fixture set, then alert."""
    output = _validated_output(output_dir)
    source_root = FIXTURE_ROOT.resolve(strict=True)
    files = _fixture_files()
    staging_dir = _output_directory(output, "staging")

    enumerated_names = [path.name for path in files]
    staged_names: list[str] = []
    for source in files:
        if source.parent != source_root:
            raise RuntimeError("Refusing to copy a path outside the fixed fixture directory")
        target = _output_file(staging_dir, source.name)
        shutil.copyfile(source, target, follow_symlinks=False)
        staged_names.append(target.name)

    monitoring = monitor_fixture_staging(staging_dir, output)
    observed_files = monitoring["observed_staged_files"]
    if monitoring["alerts_generated"] != 1:
        raise RuntimeError("The monitoring rule did not observe any staged fixture files")

    return {
        "techniques": ["T1083", "T1005", "T1074.001"],
        "enumerated_fixture_files": len(enumerated_names),
        "enumerated_names": enumerated_names,
        "copied_fixture_files": len(files),
        "staged_fixture_files": len(observed_files),
        "alerts_generated": monitoring["alerts_generated"],
        "alert_rule_id": monitoring["alert_rule_id"],
        "alert_file": monitoring["alert_file"],
        "monitoring_rule": monitoring["rule_scope"],
        "fixture_only": True,
    }


def verify_fixture_backup_restore(output_dir: Path | str) -> dict[str, Any]:
    """Damage one disposable working copy, restore from backup, and verify SHA-256."""
    output = _validated_output(output_dir)
    source_root = FIXTURE_ROOT.resolve(strict=True)
    files = _fixture_files()
    working_dir = _output_directory(output, "working")
    backup_dir = _output_directory(output, "backup")
    restored_dir = _output_directory(output, "restored")
    started = time.perf_counter()
    phase_timings: dict[str, float] = {}
    comparisons: list[dict[str, Any]] = []
    source_hashes_before: dict[str, str] = {}
    working_hashes_before: dict[str, str] = {}

    phase_start = time.perf_counter()
    for source in files:
        if source.parent != source_root:
            raise RuntimeError("Refusing to copy a path outside the fixed fixture directory")
        working = _output_file(working_dir, source.name)
        shutil.copyfile(source, working, follow_symlinks=False)
        source_hashes_before[source.name] = _sha256(source)
        working_hashes_before[source.name] = _sha256(working)
        if source_hashes_before[source.name] != working_hashes_before[source.name]:
            raise RuntimeError("Initial working copy differs from its source fixture")
    phase_timings["copy_to_working"] = round((time.perf_counter() - phase_start) * 1000, 3)

    phase_start = time.perf_counter()
    for source in files:
        backup = _output_file(backup_dir, source.name)
        shutil.copyfile(_output_file(working_dir, source.name), backup, follow_symlinks=False)
    phase_timings["create_backup"] = round((time.perf_counter() - phase_start) * 1000, 3)

    damage_target = files[0]
    damage_working_path = _output_file(working_dir, damage_target.name)
    backup_hashes_before_damage = {
        path.name: _sha256(_output_file(backup_dir, path.name)) for path in files
    }
    phase_start = time.perf_counter()
    original_working_bytes = damage_working_path.read_bytes()
    if not original_working_bytes:
        raise RuntimeError("Refusing to mutate an empty fixture working copy")
    damaged_bytes = bytes((original_working_bytes[0] ^ 0x01,)) + original_working_bytes[1:]
    damage_working_path.write_bytes(damaged_bytes)
    damaged_hash = _sha256(damage_working_path)
    damage_detected = damaged_hash != working_hashes_before[damage_target.name]
    source_hashes_after_damage = {path.name: _sha256(path) for path in files}
    working_hashes_after_damage = {
        path.name: _sha256(_output_file(working_dir, path.name)) for path in files
    }
    backup_hashes_after_damage = {
        path.name: _sha256(_output_file(backup_dir, path.name)) for path in files
    }
    source_unchanged_during_damage = source_hashes_after_damage == source_hashes_before
    backup_unchanged_during_damage = backup_hashes_after_damage == backup_hashes_before_damage
    phase_timings["controlled_working_copy_damage"] = round((time.perf_counter() - phase_start) * 1000, 3)
    if not damage_detected or not source_unchanged_during_damage or not backup_unchanged_during_damage:
        raise RuntimeError("Controlled alteration was not isolated to the disposable working copy")

    phase_start = time.perf_counter()
    for source in files:
        working = _output_file(working_dir, source.name)
        backup = _output_file(backup_dir, source.name)
        restored = _output_file(restored_dir, source.name)
        shutil.copyfile(backup, working, follow_symlinks=False)
        shutil.copyfile(working, restored, follow_symlinks=False)
    phase_timings["restore_from_backup"] = round((time.perf_counter() - phase_start) * 1000, 3)

    phase_start = time.perf_counter()
    for source in files:
        working = _output_file(working_dir, source.name)
        backup = _output_file(backup_dir, source.name)
        restored = _output_file(restored_dir, source.name)
        source_hash_after = _sha256(source)
        backup_hash_after = _sha256(backup)
        working_hash_after_restore = _sha256(working)
        restored_hash = _sha256(restored)
        comparisons.append(
            {
                "file": source.name,
                "source_sha256_before": source_hashes_before[source.name],
                "working_before_sha256": working_hashes_before[source.name],
                "backup_sha256": backup_hashes_before_damage[source.name],
                "controlled_damage_applied": source.name == damage_target.name,
                "working_after_damage_sha256": working_hashes_after_damage[source.name],
                "source_sha256_after": source_hash_after,
                "backup_sha256_after_damage": backup_hash_after,
                "working_restored_sha256": working_hash_after_restore,
                "restored_snapshot_sha256": restored_hash,
                "source_unchanged": source_hash_after == source_hashes_before[source.name],
                "backup_unchanged": backup_hash_after == backup_hashes_before_damage[source.name],
                "restoration_matches_source": source_hash_after
                == backup_hash_after
                == working_hash_after_restore
                == restored_hash,
            }
        )
    phase_timings["verify_final_hashes"] = round((time.perf_counter() - phase_start) * 1000, 3)

    all_match = bool(comparisons) and all(
        item["source_unchanged"]
        and item["backup_unchanged"]
        and item["restoration_matches_source"]
        for item in comparisons
    )
    phase_timings["total"] = round((time.perf_counter() - started) * 1000, 3)
    report = {
        "algorithm": "SHA-256",
        "files_verified": len(comparisons),
        "all_hashes_match": all_match,
        "fixture_only": True,
        "operation_label": "prueba_de_restauracion_de_archivos",
        "service_continuity_tested": False,
        "damage_method": "flip_first_byte_xor_0x01_in_disposable_working_copy_only",
        "damage_target": damage_target.name,
        "damage_detected": damage_detected,
        "damage_before_sha256": working_hashes_before[damage_target.name],
        "damage_after_sha256": damaged_hash,
        "source_unchanged_during_damage": source_unchanged_during_damage,
        "backup_unchanged_during_damage": backup_unchanged_during_damage,
        "restoration_completed": all_match,
        "timings_ms": phase_timings,
        "comparisons": comparisons,
        "verified_at_utc": _utc_now(),
    }
    if not all_match:
        raise RuntimeError("Restored working copies do not match source and backup hashes")
    _output_file(output, "verification.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return report
