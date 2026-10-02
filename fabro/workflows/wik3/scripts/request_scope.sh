#!/usr/bin/env bash
# request_scope.sh <host-o-pattern> <razón>
#
# Pide al humano permiso para extender el scope. Wrappea ask_user.sh con
# un formato estructurado que el dashboard detecta y renderiza con
# botones aprobar/rechazar inline.
#
# Si el admin aprueba: el host queda agregado a scope.txt y este script
# imprime "APPROVED" a stdout (más cualquier nota que el admin haya
# dejado). El scope_guard.sh re-lee scope.txt en cada invocación, así
# que la siguiente tool call del agente ya tiene el host habilitado.
#
# Si rechaza o timeout: imprime "REJECTED" + razón (si la dio) y exit 0
# — el agente sigue con el scope actual.
#
# Uso:
#   bash scripts/request_scope.sh "admin.example.com" "encontré subdomain takeover hint en el HTML"
set -euo pipefail

HOST="${1:-}"
REASON="${2:-}"

if [ -z "$HOST" ] || [ -z "$REASON" ]; then
    echo "usage: request_scope.sh <host-o-pattern> <razón corta>" >&2
    exit 2
fi

# Si el host YA está cubierto por scope.txt (una entrada de dominio cubre sus
# subdominios) y NO está más-específicamente en out_of_scope, no molestamos al
# operador: ya está en scope. Ej: scope tiene example.com → app.example.com
# ya está dentro; no hace falta pedir expansión.
source "$(dirname "$0")/_common.sh"
_WROOT=$(wik3_dir)
_host=$(scope_hostname_only "$HOST")
if [ -n "$_host" ]; then
    _in=$(scope_host_match_len "$_host" "$_WROOT/scope.txt")
    _out=$(scope_host_match_len "$_host" "$_WROOT/out_of_scope.txt")
    if [ "$_in" -gt 0 ] && { [ "$_out" -eq 0 ] || [ "$_in" -gt "$_out" ]; }; then
        echo "APPROVED (ya cubierto): '$_host' ya está dentro del scope actual (una entrada de dominio cubre sus subdominios). No hace falta expansión — sigue."
        exit 0
    fi
fi

# El formato lo detecta server.py (regex sobre pending_agent.txt). NO
# cambiar la cabecera sin actualizar el parser.
REPLY=$("$(dirname "$0")/ask_user.sh" "SCOPE_REQUEST: $HOST
RAZÓN: $REASON")

# server.py escribe "APPROVED" o "REJECTED" como prefijo cuando responde
# desde el endpoint /api/scope/(approve|reject). Si el operador respondió
# con /api/whisper (mensaje libre), no hay prefijo y lo dejamos pasar
# como respuesta normal.
echo "$REPLY"
