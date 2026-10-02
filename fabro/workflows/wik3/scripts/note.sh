#!/usr/bin/env bash
# note.sh — registra una observacion informativa (no-vuln) en notes.jsonl.
#
# Uso:
#   note.sh <stage> <title> [detail] [--tags tag1,tag2]
#
# Ejemplos:
#   note.sh recon "Spring Boot detectado (via /actuator/health)" "version 2.5.4, endpoints actuator expuestos pero requieren auth" --tags framework,fingerprint
#   note.sh passive "JWT usa HS256" "kid field vacio, alg no es none, firma correcta contra secret conocido" --tags auth,jwt
#   note.sh active "Login respondio 401 con mensaje verboso" "el body del 401 expone 'user not found' vs 'bad password' (enum de usuarios)" --tags auth,info-leak
#
# Propositos:
# - El dashboard lee notes.jsonl y lo muestra en el panel "Observaciones".
# - No es una vulnerability — para eso, usa scripts/vuln.sh add --phase ... (layout vulns/<id>/).
# - Es signal que vale la pena tener a la vista (context, fingerprints, partial-issues).
#
# IMPORTANTE — resolución del engagement:
# El destino del notes.jsonl SIEMPRE es el engagement activo. NO se honra cwd.
# La resolución es: WIK3_ENGAGEMENT env var (path al yaml) → si no, readlink
# de $WIK3_DIR. Si haces `cd /workspace/wik3/<otro> && note.sh`,
# note.sh escribe al engagement actual del agente, NO al directorio donde
# cd-easte. Esto es by-design: el agente no debe poder "saltar" de engagement
# (lo bloquea scope_guard.sh) y note.sh refuerza el contrato.
set -euo pipefail

source "$(dirname "$0")/_common.sh"
WROOT=$(wik3_dir)
NOTES="$WROOT/notes.jsonl"
mkdir -p "$WROOT"

STAGE="${1:-}"
TITLE="${2:-}"
DETAIL="${3:-}"
shift 3 2>/dev/null || true

TAGS=""
while [ $# -gt 0 ]; do
    case "$1" in
        --tags) TAGS="${2:-}"; shift 2 ;;
        *) shift ;;
    esac
done

if [ -z "$STAGE" ] || [ -z "$TITLE" ]; then
    echo "ERROR: uso: note.sh <stage> <title> [detail] [--tags a,b]" >&2
    exit 1
fi

TS=$(date -u +%FT%TZ)
TAGS_JSON=$(echo "$TAGS" | tr ',' '\n' | jq -R . | jq -sc 'map(select(length>0))')

jq -cn \
    --arg ts "$TS" \
    --arg stage "$STAGE" \
    --arg title "$TITLE" \
    --arg detail "$DETAIL" \
    --argjson tags "$TAGS_JSON" \
    '{ts:$ts, stage:$stage, title:$title, detail:$detail, tags:$tags}' \
    >> "$NOTES"

echo "noted [$STAGE] $TITLE"
