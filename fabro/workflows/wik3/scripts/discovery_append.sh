#!/usr/bin/env bash
# discovery_append.sh — agrega un item al queue de descubrimiento, validando scope.
# Uso: discovery_append.sh <kind> <value> <source>
#   kind   = endpoint | file | host | subdomain | param
#   value  = la URL / path / hostname
#   source = etiqueta tipo "recon:linkfinder", "active:A-007", "validate_chain:C-002"
#
# Outputs JSON en stdout con accion tomada (added / duplicate / rejected_scope / rejected_oos).
set -euo pipefail

KIND="${1:-}"
VALUE="${2:-}"
SOURCE="${3:-unknown}"

if [ -z "$KIND" ] || [ -z "$VALUE" ]; then
    echo '{"error":"usage: discovery_append.sh <kind> <value> <source>"}' >&2
    exit 2
fi

source "$(dirname "$0")/_common.sh"
WROOT=$(wik3_dir)
DIR="$WROOT/discovery"
QUEUE="$DIR/queue.jsonl"
REJECTED="$DIR/rejected.jsonl"
ITER_FILE="$DIR/iteration"
SCOPE="$WROOT/scope.txt"
OOS="$WROOT/out_of_scope.txt"

mkdir -p "$DIR"
touch "$QUEUE" "$REJECTED"
ITER=$(cat "$ITER_FILE" 2>/dev/null || echo 1)
TS=$(date -u +%FT%TZ)

host_of() {
    # Devuelve host[:port] — NO strippea el port.
    # Ej: http://target:3000/x -> target:3000 ; 10.0.0.1:8080 -> 10.0.0.1:8080
    case "$1" in
        http://*|https://*) echo "$1" | sed -E 's|^https?://||; s|[/?#].*||' ;;
        /*) echo "" ;;  # path-only: sin host explicito
        *) echo "$1" | sed -E 's|[/?#].*||' ;;
    esac
}

# Si el value es path-only ("/xxx"), lo consideramos in-scope si hay al menos
# un scope entry (se asume relativo al scope primario). Evita rechazar
# `/ftp/backup.zip`, `/api/orders/5`, etc. que el agente genera durante probing.
is_path_only() {
    case "$1" in /*) return 0 ;; *) return 1 ;; esac
}

emit_reject() {
    local reason="$1"
    local e="{\"value\":$(jq -Rn --arg v "$VALUE" '$v'),\"kind\":$(jq -Rn --arg k "$KIND" '$k'),\"source\":$(jq -Rn --arg s "$SOURCE" '$s'),\"reason\":$(jq -Rn --arg r "$reason" '$r'),\"iteration\":$ITER,\"rejected_at\":\"$TS\"}"
    echo "$e" >> "$REJECTED"
    echo "$e"
}

# Out-of-scope check
if [ -s "$OOS" ]; then
    while IFS= read -r oos; do
        [ -z "$oos" ] && continue
        if echo "$VALUE" | grep -qF "$oos"; then
            emit_reject "out-of-scope match: $oos"
            exit 0
        fi
    done < "$OOS"
fi

# In-scope check — delegado a scope_matches (ver _common.sh).
# Path-only ("/xxx") se acepta si hay scope (asumimos relativo al scope primario).
MATCH=0
if is_path_only "$VALUE" && [ -s "$SCOPE" ]; then
    # Para path-only, si el scope tiene alguna entrada con path, chequear prefix
    while IFS= read -r s; do
        [ -z "$s" ] && continue
        if scope_matches "$VALUE" "$s"; then
            MATCH=1; break
        fi
    done < "$SCOPE"
    # Si ninguno tenia path, aceptar (bare host scope, path-only asumido in-scope)
    if [ "$MATCH" = "0" ]; then
        HAS_PATH_SCOPE=0
        while IFS= read -r s; do
            [ -z "$s" ] && continue
            [ -n "$(scope_norm_path "$(scope_path_of "$s")")" ] && { HAS_PATH_SCOPE=1; break; }
        done < "$SCOPE"
        [ "$HAS_PATH_SCOPE" = "0" ] && MATCH=1
    fi
elif [ -s "$SCOPE" ]; then
    while IFS= read -r s; do
        [ -z "$s" ] && continue
        if scope_matches "$VALUE" "$s"; then
            MATCH=1; break
        fi
    done < "$SCOPE"
fi

if [ "$MATCH" = "0" ]; then
    emit_reject "not in scope (value='$VALUE')"
    exit 0
fi

# Dedupe (exact match on value, any iteration) — usar jq porque el queue puede tener
# entries pretty-printed o compactos indistintamente.
if [ -s "$QUEUE" ] && jq -e --arg v "$VALUE" 'select(.value == $v)' "$QUEUE" >/dev/null 2>&1; then
    jq -cn --arg v "$VALUE" '{action:"duplicate", value:$v}'
    exit 0
fi

# Assign next ID
NEXT=$(($(wc -l < "$QUEUE" 2>/dev/null | tr -d ' ') + 1))
ID=$(printf 'D-%04d' "$NEXT")

ENTRY=$(jq -cn \
    --arg id "$ID" \
    --arg kind "$KIND" \
    --arg value "$VALUE" \
    --arg source "$SOURCE" \
    --argjson iter "$ITER" \
    --arg ts "$TS" \
    '{id:$id, kind:$kind, value:$value, source:$source, iteration:$iter, discovered_at:$ts, consumed_by:[]}')

echo "$ENTRY" >> "$QUEUE"
echo "$ENTRY"
