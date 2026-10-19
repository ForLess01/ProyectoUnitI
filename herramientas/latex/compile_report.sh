#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(CDPATH= cd -- "${SCRIPT_DIR}/../.." && pwd)"
REPORT_SOURCE="${PROJECT_ROOT}/entrega/Informe_Plan_Ciberseguridad_UNA_Puno.tex"
FONT_DIR="${PROJECT_ROOT}/recursos/fuentes/Montserrat"

if [[ ! -f "${REPORT_SOURCE}" ]]; then
  printf 'No se encuentra el fuente del informe: %s\n' "${REPORT_SOURCE}" >&2
  exit 2
fi

for tool in latexmk xelatex shasum; do
  if ! command -v "${tool}" >/dev/null 2>&1; then
    printf 'Falta el comando requerido: %s\n' "${tool}" >&2
    exit 2
  fi
done

if ! (cd "${FONT_DIR}" && shasum -a 256 --check SHA256SUMS); then
  printf 'La verificación SHA-256 de Montserrat falló.\n' >&2
  exit 2
fi

# Mantiene como directorio de trabajo la raíz: el estilo usa rutas de fuentes relativas.
# SOURCE_DATE_EPOCH se hereda si el llamador lo define; el script no fija fechas.
cd "${PROJECT_ROOT}"
exec latexmk \
  -xelatex \
  -interaction=nonstopmode \
  -halt-on-error \
  -file-line-error \
  -outdir="${PROJECT_ROOT}/entrega" \
  "${REPORT_SOURCE}"
