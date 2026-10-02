#!/usr/bin/env bash
# say.sh — el agente manda un mensaje al usuario (no bloquea, fire-and-forget).
#
# Uso: say.sh "Encontre un JWT admin, sigo con validacion de chains."
#      say.sh "Hola! Estoy en active_analyze, iter 2."
#
# El mensaje aparece en el dashboard de conversacion. No espera respuesta
# (para eso usar ask_user.sh que sí bloquea).
set -euo pipefail

source "$(dirname "$0")/_common.sh"

MSG="${1:-}"
if [ -z "$MSG" ]; then
    echo "usage: say.sh <message>" >&2
    exit 2
fi

WROOT=$(wik3_dir)
CONVO="$WROOT/convo"
mkdir -p "$CONVO"

jq -cn --arg ts "$(date -u +%FT%TZ)" --arg t "$MSG" \
    '{ts:$ts, from:"agent", kind:"message", text:$t}' >> "$CONVO/log.jsonl"

echo "said: $MSG"
