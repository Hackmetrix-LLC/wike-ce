#!/usr/bin/env bash
# cred_append.sh — agrega una credencial al vault.
#
# Uso: cred_append.sh --kind <kind> --value <value> --source <source> [options]
#   --kind          jwt | session_cookie | api_key | bearer | basic | password_hash | plaintext_creds | oauth_token
#   --value         el material criptografico (no se registra en stdout)
#   --source        etiqueta del descubrimiento: "recon:secretfinder", "active:A-002", "engagement"
#   --via           descripcion corta: "SQLi login bypass"
#   --host          host donde es usable (se puede repetir). Default: todos los de scope.txt
#   --role          admin | customer | service | unknown (default: unknown)
#   --user-id       ID del usuario dueño (si aplica)
#   --user-email    email del usuario dueño
#   --auth-template template para usar, con {value} como placeholder.
#                   Defaults por kind:
#                     jwt/bearer     → "Authorization: Bearer {value}"
#                     session_cookie → "Cookie: {value}"
#                     api_key        → "X-API-Key: {value}"
#                     basic          → "Authorization: Basic {value}"
#
# Output (stdout): JSON con el entry creado SIN el campo value (por seguridad).
# El value se guarda en vault.jsonl (chmod 600).

set -euo pipefail

source "$(dirname "$0")/_common.sh"
WROOT=$(wik3_dir)
DIR="$WROOT/creds"
VAULT="$DIR/vault.jsonl"
SCOPE="$WROOT/scope.txt"
mkdir -p "$DIR"
touch "$VAULT" && chmod 600 "$VAULT"

KIND=""; VALUE=""; SOURCE=""; VIA=""; ROLE="unknown"
USER_ID=""; USER_EMAIL=""; AUTH_TEMPLATE=""
HOSTS_JSON="[]"; HOSTS_ARR=()

while [ $# -gt 0 ]; do
    case "$1" in
        --kind) KIND="$2"; shift 2 ;;
        --value) VALUE="$2"; shift 2 ;;
        --source) SOURCE="$2"; shift 2 ;;
        --via) VIA="$2"; shift 2 ;;
        --role) ROLE="$2"; shift 2 ;;
        --user-id) USER_ID="$2"; shift 2 ;;
        --user-email) USER_EMAIL="$2"; shift 2 ;;
        --auth-template) AUTH_TEMPLATE="$2"; shift 2 ;;
        --host) HOSTS_ARR+=("$2"); shift 2 ;;
        *) echo "unknown flag: $1" >&2; exit 2 ;;
    esac
done

if [ -z "$KIND" ] || [ -z "$VALUE" ] || [ -z "$SOURCE" ]; then
    echo "usage: cred_append.sh --kind <k> --value <v> --source <s> [options]" >&2
    exit 2
fi

# Default auth_template por kind si no se paso
if [ -z "$AUTH_TEMPLATE" ]; then
    case "$KIND" in
        jwt|bearer) AUTH_TEMPLATE="Authorization: Bearer {value}" ;;
        session_cookie) AUTH_TEMPLATE="Cookie: {value}" ;;
        api_key) AUTH_TEMPLATE="X-API-Key: {value}" ;;
        basic) AUTH_TEMPLATE="Authorization: Basic {value}" ;;
        *) AUTH_TEMPLATE="" ;;
    esac
fi

# Default hosts: todos los de scope.txt (hosts extraidos)
if [ "${#HOSTS_ARR[@]}" -eq 0 ] && [ -s "$SCOPE" ]; then
    while IFS= read -r s; do
        [ -z "$s" ] && continue
        # Preservar port (s|:.*|| removido intencionalmente)
        h=$(echo "$s" | sed -E 's|^https?://||; s|[/?#].*||')
        [ -n "$h" ] && HOSTS_ARR+=("$h")
    done < "$SCOPE"
fi
# Build HOSTS_JSON safely (empty array if no hosts)
if [ "${#HOSTS_ARR[@]}" -eq 0 ]; then
    HOSTS_JSON="[]"
else
    HOSTS_JSON=$(printf '%s\n' "${HOSTS_ARR[@]}" | jq -R . | jq -cs '.')
fi

# Dedup by value hash (usa sha256sum si esta, sino shasum -a 256).
# Verificacion con jq para ser robusto ante JSON pretty-printed.
if command -v sha256sum >/dev/null; then
    VHASH=$(echo -n "$VALUE" | sha256sum | cut -c1-16)
else
    VHASH=$(echo -n "$VALUE" | shasum -a 256 | cut -c1-16)
fi
if [ -s "$VAULT" ] && jq -e --arg h "$VHASH" 'select(.value_hash == $h)' "$VAULT" >/dev/null 2>&1; then
    jq -cn --arg h "$VHASH" '{action:"duplicate", value_hash:$h}'
    exit 0
fi

NEXT=$(($(wc -l < "$VAULT" | tr -d ' ') + 1))
ID=$(printf 'C-%03d' "$NEXT")
TS=$(date -u +%FT%TZ)

ENTRY=$(jq -cn \
    --arg id "$ID" \
    --arg kind "$KIND" \
    --arg value "$VALUE" \
    --arg value_hash "$VHASH" \
    --arg source "$SOURCE" \
    --arg via "$VIA" \
    --arg role "$ROLE" \
    --arg user_id "$USER_ID" \
    --arg user_email "$USER_EMAIL" \
    --arg auth_template "$AUTH_TEMPLATE" \
    --argjson hosts "$HOSTS_JSON" \
    --arg ts "$TS" \
    '{
        id: $id,
        kind: $kind,
        value: $value,
        value_hash: $value_hash,
        source: $source,
        via: (if $via == "" then null else $via end),
        role: $role,
        user_id: (if $user_id == "" then null else $user_id end),
        user_email: (if $user_email == "" then null else $user_email end),
        usable_on: {
            hosts: $hosts,
            endpoints_allow: [],
            endpoints_deny: [],
            auth_template: $auth_template
        },
        lifecycle: {
            expires_at: null,
            last_verified_at: null,
            last_verified_endpoint: null,
            status: "unverified"
        },
        discovered_at: $ts
    }')

echo "$ENTRY" >> "$VAULT"

# Stdout: version SIN value, con hash truncado como preview
echo "$ENTRY" | jq -c '{action:"added", id:.id, kind:.kind, role:.role, source:.source, value_hash:.value_hash, hosts:.usable_on.hosts}'
