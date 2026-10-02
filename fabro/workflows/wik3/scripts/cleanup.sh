#!/usr/bin/env bash
# cleanup.sh — housekeeping al cierre del engagement (corre tras el loop de
# discovery, antes de farewell). Best-effort: NUNCA rompe el cierre del run.
#
# Hace:
#   1. Borra scratch efímero del run (estados de browser, temporales en /tmp).
#   2. Borra el symlink legacy 'current' si quedó de runs viejos (ya no se usa).
#   3. Marca finished_at en el workspace del engagement.
#   4. Aviso de fin al panel (say.sh) con un resumen breve de hallazgos.
set +e

WROOT="${WIK3_DIR:-/workspace/wik3/$(cat /workspace/wik3/.active-slug 2>/dev/null)}"

# 1) Scratch efímero (no toca el workspace del engagement).
rm -f /tmp/*.tmp /tmp/state*.json /tmp/wik3-*.tmp /tmp/ol.tmp /tmp/sm.tmp 2>/dev/null

# 2) Symlink legacy 'current' (reemplazado por el marker .active-slug).
[ -L /workspace/wik3/current ] && rm -f /workspace/wik3/current 2>/dev/null

# 2b) Manifiesto de retest: respaldo por si el nodo retest no llegó a borrarlo.
#     Si no se borra, el PRÓXIMO run se trataría como retest. El dashboard
#     también lo borra al iniciar un run normal.
[ -d "$WROOT" ] && rm -f "$WROOT/retest-targets.json" 2>/dev/null

# 3) Marca de fin.
[ -d "$WROOT" ] && date +%s > "$WROOT/finished_at" 2>/dev/null

# 4) Aviso de fin al panel del dashboard.
VULNS=$(ls -1d "$WROOT"/vulns/V-* 2>/dev/null | wc -l | tr -d ' ')
bash "$(dirname "$0")/say.sh" "Engagement finalizado · ${VULNS} hallazgo(s) registrado(s). Revisa el panel." 2>/dev/null

echo "cleanup ok · finished_at=$(cat "$WROOT/finished_at" 2>/dev/null) · vulns=${VULNS}"
exit 0
