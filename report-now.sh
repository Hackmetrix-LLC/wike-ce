#!/usr/bin/env bash
# report-now.sh — genera el reporte de wik3 on-demand con lo que haya en
# el workspace. No re-corre recon/passive/active/validate, solo lanza el
# stage de reporte contra los artifacts existentes.
#
# Uso:
#   ./report-now.sh                        # slug por default: local
#   ./report-now.sh <slug>                 # p.ej. my-app
#   ./report-now.sh <slug> --auto-approve  # passthrough de flags a fabro
#
# Si tienes un run largo corriendo y quieres cortarlo y reportar con lo
# que ya encontró: matalo (Ctrl+C en la terminal de fabro) y luego corre
# este script — el workspace queda intacto.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$REPO_ROOT"

SLUG="${1:-local}"; shift || true
ENGAGEMENT="./engagements/engagement.${SLUG}.yaml"

if [ ! -f "$ENGAGEMENT" ]; then
  echo "ERROR: no existe $ENGAGEMENT" >&2
  echo "engagements disponibles:" >&2
  ls engagements/engagement.*.yaml 2>/dev/null | sed 's|engagements/engagement\.||; s|\.yaml$||; s|^|  |' >&2
  exit 1
fi

if [ ! -d "wik3/${SLUG}" ]; then
  echo "ERROR: no existe workspace wik3/${SLUG} — corre wik3 al menos una vez antes." >&2
  exit 1
fi

# Resumen de inputs disponibles (para que sepas qué va a usar el agente)
echo "=== inputs disponibles en wik3/${SLUG}/ ==="
for f in passive/findings.json active/findings.json validated/findings.json validated/chains.json evidence/screenshots/index.json recon/summary.md recon/assets.json; do
  path="wik3/${SLUG}/${f}"
  if [ -f "$path" ]; then
    size=$(wc -c < "$path" | tr -d ' ')
    printf "  ✓ %-45s %s bytes\n" "$f" "$size"
  else
    printf "  ✗ %-45s (ausente)\n" "$f"
  fi
done
echo

REPORT_FILE="wik3/${SLUG}/report.md"
if [ -f "$REPORT_FILE" ]; then
  TS=$(date +%Y%m%dT%H%M%S)
  BACKUP="wik3/${SLUG}/report.${TS}.bak.md"
  cp "$REPORT_FILE" "$BACKUP"
  echo "[backup] $REPORT_FILE → $BACKUP"
  echo
fi

exec fabro run wik3-report --goal "$ENGAGEMENT" "$@"
