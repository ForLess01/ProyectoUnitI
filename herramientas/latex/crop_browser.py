#!/usr/bin/env python3
"""Create lossless, geometry-only detail crops from the four browser screenshots."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from PIL import Image


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SOURCE_DIR = PROJECT_ROOT / "evidencias" / "laboratorio" / "capturas"
DESTINATION_DIR = PROJECT_ROOT / "recursos" / "figuras" / "navegador"
MANIFEST_PATH = DESTINATION_DIR / "browser-crops.json"
DESCRIPTION = "recorte geométrico de la tarjeta de navegador original para legibilidad; sin edición del contenido"
EXPECTED_SOURCE_SIZE = (1440, 980)

# Coordinates are [left, top, right, bottom); right and bottom are exclusive.
# BROWSER-01 has a taller MFA form and response; the other cards share a shorter height.
CROPS = (
    ("browser-01-mfa-required.png", "browser-01-detalle.png", (743, 87, 1287, 709)),
    ("browser-02-access-allowed.png", "browser-02-detalle.png", (743, 96, 1287, 683)),
    ("browser-03-rbac-403.png", "browser-03-detalle.png", (743, 96, 1287, 683)),
    ("browser-04-session-revoked.png", "browser-04-detalle.png", (743, 96, 1287, 683)),
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def prepare_crop(
    original_name: str, destination_name: str, rectangle: tuple[int, int, int, int]
) -> dict:
    original_path = SOURCE_DIR / original_name
    destination_path = DESTINATION_DIR / destination_name
    if not original_path.is_file():
        raise FileNotFoundError(f"Missing original screenshot: {original_path}")

    original_sha256 = sha256_file(original_path)
    with Image.open(original_path) as original:
        if original.format != "PNG":
            raise ValueError(f"Expected PNG input: {original_path}")
        if original.size != EXPECTED_SOURCE_SIZE:
            raise ValueError(
                f"Unexpected dimensions for {original_path}: {original.size}; "
                f"expected {EXPECTED_SOURCE_SIZE}"
            )

        left, top, right, bottom = rectangle
        if not (0 <= left < right <= original.width and 0 <= top < bottom <= original.height):
            raise ValueError(f"Crop rectangle is outside the original: {original_path}")

        crop = original.crop(rectangle)
        crop.load()
        original_mode = original.mode

    if sha256_file(original_path) != original_sha256:
        raise RuntimeError(f"Original changed while it was being read: {original_path}")

    width, height = crop.size
    return {
        "original_path": original_path,
        "destination_path": destination_path,
        "crop": crop,
        "original_sha256": original_sha256,
        "original_dimensions": {
            "width": EXPECTED_SOURCE_SIZE[0],
            "height": EXPECTED_SOURCE_SIZE[1],
        },
        "original_rect": {"x": left, "y": top, "width": width, "height": height},
        "destination_rect": {"x": 0, "y": 0, "width": width, "height": height},
        "destination_dimensions": {"width": width, "height": height},
        "mode": original_mode,
    }


def main() -> None:
    records = [prepare_crop(*spec) for spec in CROPS]

    # Recheck every original before writing any derived image.
    for record in records:
        if sha256_file(record["original_path"]) != record["original_sha256"]:
            raise RuntimeError(f"Original changed before crop output: {record['original_path']}")

    DESTINATION_DIR.mkdir(parents=True, exist_ok=True)
    manifest_items = []
    for record in records:
        crop = record["crop"]
        destination_path = record["destination_path"]
        crop.save(destination_path, format="PNG", compress_level=9)

        with Image.open(destination_path) as saved:
            if saved.size != crop.size or saved.mode != crop.mode or saved.tobytes() != crop.tobytes():
                raise RuntimeError(f"Saved crop differs at the pixel level: {destination_path}")

        if sha256_file(record["original_path"]) != record["original_sha256"]:
            raise RuntimeError(f"Original changed during crop output: {record['original_path']}")

        destination_sha256 = sha256_file(destination_path)
        manifest_items.append(
            {
                "description": DESCRIPTION,
                "original": record["original_path"].relative_to(PROJECT_ROOT).as_posix(),
                "destination": destination_path.relative_to(PROJECT_ROOT).as_posix(),
                "original_dimensions": record["original_dimensions"],
                "destination_dimensions": record["destination_dimensions"],
                "original_rect": record["original_rect"],
                "destination_rect": record["destination_rect"],
                "original_sha256": record["original_sha256"],
                "destination_sha256": destination_sha256,
            }
        )
        print(
            f"{destination_path.name}: "
            f"{record['original_dimensions']['width']}x{record['original_dimensions']['height']} "
            f"-> {crop.width}x{crop.height}; pixel content preserved"
        )

    manifest = {
        "description": DESCRIPTION,
        "coordinate_system": "pixels; origin at top-left; rectangle right/bottom edges are exclusive",
        "operation": "Pillow crop only; no scaling, redraw, retouching, or text reconstruction",
        "items": manifest_items,
    }
    MANIFEST_PATH.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"Manifest: {MANIFEST_PATH.relative_to(PROJECT_ROOT).as_posix()}")


if __name__ == "__main__":
    main()
