#!/usr/bin/env bash
# share.sh — el agente comparte un archivo con el usuario (via dashboard).
#
# Uso: share.sh <path-al-archivo> ["descripcion opcional"]
#
# Copia el archivo a convo/shared/from_agent/<filename> y agrega entry al
# convo log para que aparezca en el dashboard con link de descarga.
set -euo pipefail

source "$(dirname "$0")/_common.sh"

SRC="${1:-}"
DESC="${2:-}"

if [ -z "$SRC" ] || [ ! -f "$SRC" ]; then
    echo "usage: share.sh <file> [description]" >&2
    echo "archivo no existe: '$SRC'" >&2
    exit 2
fi

WROOT=$(wik3_dir)
CONVO="$WROOT/convo"
SHARED="$CONVO/shared/from_agent"
mkdir -p "$SHARED"

FILENAME=$(basename "$SRC")
# Sanitizar: solo [a-zA-Z0-9._-]
SAFE=$(echo "$FILENAME" | tr -cd 'a-zA-Z0-9._-')
[ -z "$SAFE" ] && SAFE="file"
# Evitar colisiones: si ya existe, agregar timestamp
DEST="$SHARED/$SAFE"
if [ -e "$DEST" ]; then
    TS_SUFFIX=$(date -u +%s)
    SAFE="${TS_SUFFIX}_${SAFE}"
    DEST="$SHARED/$SAFE"
fi

cp "$SRC" "$DEST"
SIZE=$(wc -c < "$DEST" | tr -d ' ')

jq -cn \
    --arg ts "$(date -u +%FT%TZ)" \
    --arg fn "$SAFE" \
    --argjson sz "$SIZE" \
    --arg desc "$DESC" \
    --arg dir "from_agent" \
    '{ts:$ts, from:"agent", kind:"file", filename:$fn, size:$sz, direction:$dir, description:(if $desc == "" then null else $desc end)}' \
    >> "$CONVO/log.jsonl"

echo "shared: $SAFE ($SIZE bytes) -> $DEST"
