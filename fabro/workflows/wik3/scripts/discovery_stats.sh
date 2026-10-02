#!/usr/bin/env bash
# discovery_stats.sh — imprime stats del queue de iteracion actual Y
# auto-incrementa el contador para la proxima iteracion.
#
# Esta disenado para ser llamado UNA SOLA VEZ al cierre de cada iteracion
# (desde check_discoveries). Llamadas duplicadas bumpearian iteration de mas.
set -euo pipefail

source "$(dirname "$0")/_common.sh"
WROOT=$(wik3_dir)
DIR="$WROOT/discovery"
QUEUE="$DIR/queue.jsonl"
ITER_FILE="$DIR/iteration"

mkdir -p "$DIR"
touch "$QUEUE"
ITER=$(cat "$ITER_FILE" 2>/dev/null || echo 1)

NEW_THIS_ITER=0
TOTAL=0
if [ -s "$QUEUE" ]; then
    NEW_THIS_ITER=$(jq --argjson iter "$ITER" -c 'select(.iteration == $iter)' "$QUEUE" 2>/dev/null | wc -l | tr -d ' ')
    TOTAL=$(wc -l < "$QUEUE" | tr -d ' ')
fi
REJECTED=0
if [ -s "$DIR/rejected.jsonl" ]; then
    REJECTED=$(wc -l < "$DIR/rejected.jsonl" | tr -d ' ')
fi

NEXT_ITER=$((ITER + 1))
echo "$NEXT_ITER" > "$ITER_FILE"

# Cap de iteraciones: configurable via engagement.yaml (max_iterations), default 5.
# Es POR RUN, no acumulado entre runs: cada run hace max_iterations iteraciones
# EXTRA. iteration_base lo fija el prepare step al arrancar el run (la iteración
# con la que arrancó). Sin base file → fallback a 1 (comportamiento viejo) para
# no romper engagements previos.
MAX=$(yq -r '.max_iterations // 5' "$WROOT/engagement.yaml" 2>/dev/null || echo 5)
case "$MAX" in ''|*[!0-9]*) MAX=5 ;; esac
[ "$MAX" -lt 1 ] && MAX=1
[ "$MAX" -gt 20 ] && MAX=20
BASE=$(cat "$DIR/iteration_base" 2>/dev/null || echo 1)
case "$BASE" in ''|*[!0-9]*) BASE=1 ;; esac
# Iteraciones hechas en ESTE run (1-based): la que recién terminó cuenta.
ITER_THIS_RUN=$((ITER - BASE + 1))
[ "$ITER_THIS_RUN" -lt 1 ] && ITER_THIS_RUN=1
if [ "$ITER_THIS_RUN" -lt "$MAX" ]; then UNDER_CAP=true; else UNDER_CAP=false; fi

cat <<EOF
{
  "iteration": $ITER,
  "iteration_this_run": $ITER_THIS_RUN,
  "new_this_iteration": $NEW_THIS_ITER,
  "next_iteration": $NEXT_ITER,
  "total_queue": $TOTAL,
  "total_rejected": $REJECTED,
  "max_iterations": $MAX,
  "under_cap": $UNDER_CAP
}
EOF
