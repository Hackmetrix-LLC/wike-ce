#!/usr/bin/env bash
# ask_user.sh — el agente le pregunta algo al humano y espera respuesta.
#
# Uso: ask_user.sh "¿Puedo probar /admin aunque no esté en scope explícito?"
#
# Mecanismo:
# 1. Escribe la pregunta a convo/pending_agent.txt (para que el dashboard la destaque)
# 2. Agrega al convo/log.jsonl
# 3. Polla convo/inbox.md cada 3s hasta max_wait_seconds
# 4. Si hay respuesta: la imprime a stdout, clea pending + inbox, agrega al log
# 5. Si timeout: imprime "[TIMEOUT]", clea pending, sale 0 (no rompe al agente)
#
# El agente debe parsear el stdout: si empieza con "[TIMEOUT]", usar mejor interpretacion.
set -euo pipefail

source "$(dirname "$0")/_common.sh"

QUESTION="${1:-}"
MAX_WAIT="${2:-7200}"  # segundos — default 120 min para que el operador
                       # tenga tiempo de responder (antes era 60s, demasiado
                       # corto para preguntas que requerian buscar info).
POLL_INTERVAL=3        # 3s — costo trivial (2400 polls en 2h) y baja latencia
                       # cuando llega la respuesta.

if [ -z "$QUESTION" ]; then
    echo "usage: ask_user.sh <question> [max_wait_seconds]" >&2
    exit 2
fi

WROOT=$(wik3_dir)
CONVO="$WROOT/convo"
mkdir -p "$CONVO"

LOG="$CONVO/log.jsonl"
PENDING="$CONVO/pending_agent.txt"
INBOX="$CONVO/inbox.md"

TS=$(date -u +%FT%TZ)
echo "$QUESTION" > "$PENDING"
jq -cn --arg ts "$TS" --arg t "$QUESTION" \
    '{ts:$ts, from:"agent", kind:"question", text:$t}' >> "$LOG"

# Polling loop
elapsed=0
while [ "$elapsed" -lt "$MAX_WAIT" ]; do
    if [ -s "$INBOX" ]; then
        reply=$(cat "$INBOX")
        : > "$INBOX"
        : > "$PENDING"
        RTS=$(date -u +%FT%TZ)
        jq -cn --arg ts "$RTS" --arg t "$reply" \
            '{ts:$ts, from:"user", kind:"reply", text:$t}' >> "$LOG"
        echo "$reply"
        exit 0
    fi
    sleep "$POLL_INTERVAL"
    elapsed=$((elapsed + POLL_INTERVAL))
done

: > "$PENDING"
jq -cn --arg ts "$(date -u +%FT%TZ)" \
    '{ts:$ts, from:"system", kind:"timeout", text:"no user reply"}' >> "$LOG"
echo "[TIMEOUT: no user reply in ${MAX_WAIT}s, continua con tu mejor interpretacion]"
exit 0
