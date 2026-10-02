#!/usr/bin/env bash
# see.sh — wrapper bash a see.py (analizar una imagen con un vision LLM).
#
# see.py es un script Python. Este wrapper existe porque el agente (y los prompts)
# invocan las tools como `bash <name>.sh`; sin el wrapper, `bash see.sh` intentaría
# ejecutar el fuente Python con bash y fallaría ("import: command not found").
exec python3 "$(dirname "$0")/see.py" "$@"
