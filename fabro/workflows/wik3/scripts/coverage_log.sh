#!/usr/bin/env bash
# coverage_log.sh — registra técnicas y endpoints probados durante el run
# para alimentar las listas "Cobertura del análisis" del reporte final.
#
# Dos modos:
#
#   coverage_log.sh attack <technique> [--target <url>] [--outcome <verdict>] [--note "..."]
#     Registra una técnica intentada (SQLi, XSS, IDOR, JWT-alg-none, etc.).
#     Se agrega a /workspace/wik3/<slug>/coverage/attempts.jsonl.
#
#   coverage_log.sh endpoint <url> [--method GET|POST|...] [--note "..."]
#     Registra un endpoint analizado. Se agrega a coverage/endpoints.jsonl.
#     IMPORTANTE: scope_guard.sh ya hace esto automáticamente para CUALQUIER
#     URL que pase su check, así que en general NO necesitas llamar a este
#     modo manualmente. Úsalo solo si quieres agregar metadata extra (método,
#     nota) que el hook automático no captura.
#
# Ambos archivos son JSONL: una línea por entrada, dedup en read time.
set -euo pipefail

source "$(dirname "$0")/_common.sh"

WROOT="${WIK3_DIR:-$(wik3_dir)}"
COV_DIR="$WROOT/coverage"
mkdir -p "$COV_DIR"

usage() {
    cat >&2 <<'EOF'
coverage_log.sh — registra cobertura del análisis para el reporte final.

USO
  coverage_log.sh attack <technique> [--target <url>] [--outcome <verdict>] [--note "..."]
  coverage_log.sh endpoint <url> [--method GET|POST|...] [--note "..."]

EJEMPLO
  coverage_log.sh attack "SQLi-error-based" --target https://api.example.com/v1/users --outcome probable
  coverage_log.sh attack "JWT-alg-none" --target https://api.example.com/auth/refresh --outcome confirmed
  coverage_log.sh attack "IDOR" --target https://app.example.com/orders/{id} --outcome false_positive

CUANDO USAR (modo attack)
- Lo escribe el nodo coverage_scan (deriva del exec.log cada iteración). Registra
  CADA técnica × target intentada, incluidas las que fallan/bloquean — lo que NO
  funcionó es la mayor parte de la cobertura. Dedup en write por
  (technique+target+outcome): repetir es inofensivo.
- Outcome valores típicos: "confirmed", "probable", "false_positive",
  "not_vulnerable", "blocked_by_roe", "blocked_by_waf".

CUANDO NO USAR
- Modo "endpoint": casi nunca, scope_guard.sh ya loggea automáticamente.
EOF
    exit 1
}

[ $# -lt 2 ] && usage

MODE="$1"; shift

case "$MODE" in
    attack)
        TECHNIQUE="$1"; shift
        TARGET=""; OUTCOME=""; NOTE=""
        while [ $# -gt 0 ]; do
            case "$1" in
                --target)   TARGET="$2"; shift 2 ;;
                --outcome)  OUTCOME="$2"; shift 2 ;;
                --note)     NOTE="$2"; shift 2 ;;
                *) echo "unknown arg: $1" >&2; usage ;;
            esac
        done
        TS=$(date -u +%FT%TZ)
        ENTRY=$(jq -cn \
            --arg ts "$TS" \
            --arg technique "$TECHNIQUE" \
            --arg target "$TARGET" \
            --arg outcome "$OUTCOME" \
            --arg note "$NOTE" \
            '{ts:$ts, technique:$technique}
             + (if $target  != "" then {target:$target}   else {} end)
             + (if $outcome != "" then {outcome:$outcome} else {} end)
             + (if $note    != "" then {note:$note}       else {} end)')
        # Dedup en write: no re-appendear un intento idéntico (técnica+target+
        # outcome). coverage_scan re-procesa el exec.log con overlap cada
        # iteración, así que sin esto se duplicarían las filas del CSV.
        if [ -f "$COV_DIR/attempts.jsonl" ] && \
           jq -e --arg t "$TECHNIQUE" --arg tg "$TARGET" --arg o "$OUTCOME" \
              'select(.technique==$t and (.target//"")==$tg and (.outcome//"")==$o)' \
              "$COV_DIR/attempts.jsonl" >/dev/null 2>&1; then
            echo "dup (skip): $TECHNIQUE${TARGET:+ → $TARGET}${OUTCOME:+ ($OUTCOME)}"
        else
            echo "$ENTRY" >> "$COV_DIR/attempts.jsonl"
            echo "logged: $TECHNIQUE${TARGET:+ → $TARGET}${OUTCOME:+ ($OUTCOME)}"
        fi
        ;;
    endpoint)
        URL="$1"; shift
        METHOD=""; NOTE=""; SOURCE="manual"
        while [ $# -gt 0 ]; do
            case "$1" in
                --method)   METHOD="$2"; shift 2 ;;
                --note)     NOTE="$2"; shift 2 ;;
                --source)   SOURCE="$2"; shift 2 ;;  # uso interno (scope_guard)
                *) echo "unknown arg: $1" >&2; usage ;;
            esac
        done
        TS=$(date -u +%FT%TZ)
        ENTRY=$(jq -cn \
            --arg ts "$TS" \
            --arg url "$URL" \
            --arg method "$METHOD" \
            --arg note "$NOTE" \
            --arg source "$SOURCE" \
            '{ts:$ts, url:$url, source:$source}
             + (if $method != "" then {method:$method} else {} end)
             + (if $note   != "" then {note:$note}     else {} end)')
        echo "$ENTRY" >> "$COV_DIR/endpoints.jsonl"
        ;;
    -h|--help)
        usage
        ;;
    *)
        echo "unknown mode: $MODE" >&2
        usage
        ;;
esac
