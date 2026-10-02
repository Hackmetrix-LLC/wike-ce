#!/usr/bin/env bash
# cmd_cap.sh — pre_tool_use hook: limita la cantidad de comandos shell por
# VISITA DE NODO (runaway guard). Sin esto, un nodo atascado en loop puede
# ejecutar miles de comandos (caso real: 9339 comandos en una iteración →
# exec.log de 23GB → disco lleno → run muerto). Al pasar el cap, bloquea el
# comando y empuja al agente a cerrar la etapa.
#
# El cap es POR VISITA DE NODO (alineado con el cap de 25 min por nodo): cada
# entrada a un nodo arranca con presupuesto fresco. El contador se llavea por
# (iteración + node_id); se resetea al cambiar cualquiera de los dos.
#
# Cap configurable via WIK3_CMD_CAP (default 250).
set -uo pipefail

# Drena el input del tool (fabro lo pipea por stdin); no lo necesitamos.
cat >/dev/null 2>&1 || true

source "$(dirname "$0")/_common.sh" 2>/dev/null || true

MAX="${WIK3_CMD_CAP:-250}"
WK="${WIK3_DIR:-$(wik3_dir 2>/dev/null)}"
[ -n "$WK" ] && [ -d "$WK" ] || exit 0

ITER=$(cat "$WK/discovery/iteration" 2>/dev/null || echo 1)
NODE="${FABRO_NODE_ID:-$(cat "$WK/.current-node" 2>/dev/null || echo '?')}"
KEY="${ITER}:${NODE}"
CF="$WK/.cmd-count"

prev_key=""; count=0
if [ -f "$CF" ]; then
    read -r prev_key count < "$CF" 2>/dev/null || { prev_key=""; count=0; }
fi
[ "$prev_key" = "$KEY" ] || count=0
count=$((count + 1))
printf '%s %s\n' "$KEY" "$count" > "$CF" 2>/dev/null || true

if [ "$count" -gt "$MAX" ]; then
    echo "BLOCK[cmd-cap]: alcanzaste $MAX comandos en este nodo ($NODE, iter $ITER). NO ejecutes más comandos. Emite AHORA tu JSON de cierre: si te quedó trabajo pendiente pon active_incomplete:true (el discovery loop te devuelve en la próxima iteración) y describe en el summary qué estabas haciendo." >&2
    exit 1
fi
exit 0
