#!/usr/bin/env bash
# cred_verify.sh — verifica si una cred funciona contra un endpoint y actualiza el vault.
#
# Uso: cred_verify.sh <cred-id> <endpoint-url> [method]
#   method default: GET
#
# Logica:
#   - Request con auth_template formatted con {value}
#   - 2xx/3xx: marca verified, agrega endpoint a endpoints_allow, setea status=valid
#   - 401/403: agrega a endpoints_deny, NO cambia status (el cred puede ser valido en otros endpoints)
#   - 5xx / timeout: no cambia nada (transiente)
#   - 404: no cambia nada (no informa sobre cred, solo sobre endpoint)
#
# Output (stdout): JSON con resultado de verificacion (sin exponer value).

set -euo pipefail

CID="${1:-}"
ENDPOINT="${2:-}"
METHOD="${3:-GET}"

if [ -z "$CID" ] || [ -z "$ENDPOINT" ]; then
    echo "usage: cred_verify.sh <cred-id> <endpoint-url> [method]" >&2
    exit 2
fi

source "$(dirname "$0")/_common.sh"
VAULT="$(wik3_dir)/creds/vault.jsonl"
if [ ! -s "$VAULT" ]; then
    echo "{\"error\":\"vault empty\"}" >&2; exit 1
fi

ENTRY=$(jq -c --arg id "$CID" 'select(.id == $id)' "$VAULT" | head -1)
if [ -z "$ENTRY" ]; then
    echo "{\"error\":\"cred not found: $CID\"}" >&2; exit 1
fi

VALUE=$(echo "$ENTRY" | jq -r '.value')
TEMPLATE=$(echo "$ENTRY" | jq -r '.usable_on.auth_template // ""')
if [ -z "$TEMPLATE" ]; then
    echo "{\"error\":\"no auth_template set for $CID\"}" >&2; exit 1
fi

# Render header: replace {value} con el valor real.
# Usamos python para evitar romper con caracteres especiales de sed (|, &, /, \).
HEADER=$(python3 -c 'import sys; print(sys.argv[1].replace("{value}", sys.argv[2]))' "$TEMPLATE" "$VALUE")

# Request; capture HTTP code + time
CODE=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 15 \
    -X "$METHOD" -H "$HEADER" "$ENDPOINT" 2>/dev/null || echo "000")

TS=$(date -u +%FT%TZ)
ACTION=""  # "allow", "deny", or "" (nothing)
STATUS_CHANGE=""

case "$CODE" in
    2*|3*) ACTION="allow"; STATUS_CHANGE="verified" ;;
    401|403) ACTION="deny"; STATUS_CHANGE="rejected_on_endpoint" ;;
    000) STATUS_CHANGE="transient_error" ;;
    *) STATUS_CHANGE="indeterminate_http_$CODE" ;;
esac

if [ -n "$ACTION" ]; then
    TMP=$(mktemp)
    # Pasamos valores como --arg/--argjson para evitar inyeccion en jq
    jq -c --arg id "$CID" --arg ep "$ENDPOINT" --arg ts "$TS" --arg action "$ACTION" \
        'if .id == $id then
            if $action == "allow" then
                .usable_on.endpoints_allow |= (. + [$ep] | unique)
                | .lifecycle.status = "valid"
                | .lifecycle.last_verified_at = $ts
                | .lifecycle.last_verified_endpoint = $ep
            elif $action == "deny" then
                .usable_on.endpoints_deny |= (. + [$ep] | unique)
            else . end
         else . end' "$VAULT" > "$TMP"
    mv "$TMP" "$VAULT"
    chmod 600 "$VAULT"
fi

jq -cn \
    --arg id "$CID" --arg ep "$ENDPOINT" --arg code "$CODE" --arg st "$STATUS_CHANGE" \
    '{cred: $id, endpoint: $ep, http_code: $code, change: $st}'
