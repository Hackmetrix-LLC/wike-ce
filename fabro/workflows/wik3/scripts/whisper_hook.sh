#!/usr/bin/env bash
# whisper_hook.sh — pre_tool_use hook.
#
# Si el usuario metio un "whisper" via dashboard (no una respuesta a pregunta),
# bloquea el tool call e inyecta el mensaje como error → el agente lo ve en
# su proximo turno y puede ajustar comportamiento.
#
# No interfiere con ask_user.sh: si hay pending_agent.txt seteado, el inbox
# pertenece a esa pregunta y lo dejamos pasar para que ask_user.sh lo consuma.
set -euo pipefail

source "$(dirname "$0")/_common.sh"
WROOT=$(wik3_dir)
CONVO="$WROOT/convo"
INBOX="$CONVO/inbox.md"
PENDING="$CONVO/pending_agent.txt"

# Si el agente esta esperando respuesta (ask_user.sh corriendo), no intercepto.
[ -s "$PENDING" ] && exit 0

# Sin whisper pendiente, dejar pasar el tool call.
[ -s "$INBOX" ] || exit 0

MSG=$(cat "$INBOX")
: > "$INBOX"

# Log en convo
mkdir -p "$CONVO"
jq -cn --arg ts "$(date -u +%FT%TZ)" --arg t "$MSG" \
    '{ts:$ts, from:"user", kind:"whisper", text:$t}' >> "$CONVO/log.jsonl"

# Bloquea con el mensaje en stderr — el agente lo interpreta como "la tool fallo
# y vino con este feedback del usuario".
cat >&2 <<EOF
BLOCK[whisper]: el usuario te esta hablando. Mensaje:

  "$MSG"

Que hacer:
1. Si es una PREGUNTA DIRECTA o SALUDO (ej: "hola", "¿como va?", "¿que encontraste?"),
   respondele con:
     bash /workspace/fabro/workflows/wik3/scripts/say.sh "tu respuesta breve"
   y despues retry tu tool call original.
2. Si es GUIDANCE/CONTEXT para tu tarea (ej: "proba tambien /admin", "el target cambio,
   es 192.168.X"), integralo al flujo, opcionalmente respondele con say.sh "entendido, procedo",
   y retry con el nuevo contexto.
3. Si no entendes el mensaje, usa ask_user.sh para pedir aclaracion.

NO ignores el mensaje. Al menos acknowledge con say.sh.
EOF
exit 1
