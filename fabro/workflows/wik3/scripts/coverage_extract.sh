#!/usr/bin/env bash
# coverage_extract.sh — ventana incremental del exec.log para el nodo
# coverage_scan, que deriva las técnicas intentadas de los comandos REALES
# que ejecutó el agente (en vez de depender de que loguee a mano).
#
#   window  → imprime el delta del exec.log desde el offset guardado MENOS un
#             overlap (para no cortar intentos a mitad del borde). No avanza el
#             offset (recién en commit), así que si el nodo falla, no se pierde.
#   commit  → avanza el offset al fin actual del exec.log.
#
# El offset (bytes ya procesados) vive en coverage/.exec-offset.
set -euo pipefail

source "$(dirname "$0")/_common.sh"
WROOT="${WIK3_DIR:-$(wik3_dir)}"
LOG="$WROOT/exec.log"
COV="$WROOT/coverage"; mkdir -p "$COV"
OFF="$COV/.exec-offset"
OVERLAP="${WIK3_COV_OVERLAP:-4000}"      # bytes de solape
MAXWIN="${WIK3_COV_MAXWIN:-400000}"      # cap de la ventana (evita context blow-up)

cmd="${1:-}"
[ -f "$LOG" ] || { [ "$cmd" = window ] && echo "(exec.log no existe aún)"; exit 0; }
size=$(wc -c < "$LOG")
start=$(cat "$OFF" 2>/dev/null || echo 0)

case "$cmd" in
    window)
        s=$((start - OVERLAP)); [ "$s" -lt 0 ] && s=0
        # Cap: si el delta es enorme, quedarse con los últimos MAXWIN bytes.
        if [ $((size - s)) -gt "$MAXWIN" ]; then
            s=$((size - MAXWIN))
            echo "[coverage_extract] ventana capada a últimos ${MAXWIN}B (delta grande)" >&2
        fi
        tail -c +$((s + 1)) "$LOG"
        ;;
    commit)
        printf '%s' "$size" > "$OFF"
        echo "offset → $size"
        ;;
    *)
        echo "uso: $0 {window|commit}" >&2; exit 2 ;;
esac
