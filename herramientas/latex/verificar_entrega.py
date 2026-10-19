"""Verify the compiled academic deliverable and its recorded evidence."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PDF = ROOT / "entrega/Informe_Plan_Ciberseguridad_UNA_Puno.pdf"
TEX = PDF.with_suffix(".tex")


def command(*args: str) -> str:
    return subprocess.check_output(args, cwd=ROOT, text=True)


def verify_manifest(manifest: Path, base: Path) -> int:
    count = 0
    for line in manifest.read_text().splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        digest, filename = line.split(maxsplit=1)
        target = base / filename.lstrip("*")
        assert hashlib.sha256(target.read_bytes()).hexdigest() == digest, target
        count += 1
    return count


def main() -> None:
    cover = command("pdftotext", "-f", "1", "-l", "1", str(PDF), "-")
    text = command("pdftotext", str(PDF), "-")
    fonts = command("pdffonts", str(PDF))
    info = command("pdfinfo", str(PDF))
    source = TEX.read_text()
    log = PDF.with_suffix(".log").read_text()
    required_cover = [
        "Ing. Fidel Ernesto Ticona Yanqui",
        "Alfonte Tarqui Rendo",
        "Tópicos de Ciberseguridad",
        "https://github.com/ForLess01/ProyectoUnitI",
    ]
    assert all(value in cover for value in required_cover), cover
    assert not re.search(r"undefined|Fatal error|Overfull", log), "Unresolved LaTeX issue"
    assert "Resumen ejecutivo" not in text
    assert "Resumen" in text
    assert re.search(r"Author:\s+Alfonte Tarqui Rendo", info)
    assert source.count("\\anexo{") == 10
    assert source.count("\\captura{") == 14
    assert source.count("\\bibitem{") == 25
    montserrat = [line for line in fonts.splitlines() if "Montserrat" in line]
    assert len(montserrat) >= 4 and all("yes" in line for line in montserrat)
    results = json.loads((ROOT / "evidencias/laboratorio/resultados.json").read_text())
    assert len(results["cases"]) == 17 and all(case["pass"] for case in results["cases"])
    evidence_count = verify_manifest(
        ROOT / "evidencias/laboratorio/manifest.sha256", ROOT / "evidencias/laboratorio"
    )
    code_count = verify_manifest(ROOT / "evidencias/laboratorio/source_manifest.sha256", ROOT)
    assert evidence_count == 41 and code_count == 16
    print(json.dumps({
        "status": "PASS",
        "pages": int(re.search(r"Pages:\s+(\d+)", info).group(1)),
        "cover_fields_verified": required_cover,
        "annexes": 10,
        "screenshots_in_report": 14,
        "bibliographic_references": 25,
        "cases_passed": 17,
        "evidence_hashes_verified": evidence_count,
        "source_hashes_verified": code_count,
        "montserrat_embedded": True,
        "overfull_boxes": 0,
        "pdf_sha256": hashlib.sha256(PDF.read_bytes()).hexdigest(),
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
