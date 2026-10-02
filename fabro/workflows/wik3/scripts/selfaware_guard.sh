#!/usr/bin/env bash
# selfaware_guard.sh — pre_tool_use (shell): AUTOCONCIENCIA del agente.
#
# Detecta comportamiento DERROCHADOR (fuerza bruta / martilleo HTTP / repetición
# del mismo enfoque) y le inyecta al agente un aviso para que CAMBIE de estrategia,
# en vez de quemar el presupuesto de tiempo del nodo (25-30 min) sin converger.
# Caso real: retos donde el agente cae en loops de `for ... curl` contra un target
# con rate-limit (2.5s/req) → la fuerza bruta se arrastra → el nodo timeoutea.
#
# NO es un muro: deja pasar la mayoría de los comandos; cada N comandos
# derrochadores en un mismo nodo bloquea UNO con feedback (el agente lo lee y
# pivota). El contador se llavea por (iteración + node_id) y se resetea al cambiar
# cualquiera de los dos — mismo patrón que cmd_cap.sh.
#
# Umbral del primer aviso configurable via WIK3_SELFAWARE_WARN_AT (default 4).
set -uo pipefail

INPUT=$(cat 2>/dev/null || echo '')
source "$(dirname "$0")/_common.sh" 2>/dev/null || true
WK="${WIK3_DIR:-$(wik3_dir 2>/dev/null)}"
[ -n "$WK" ] && [ -d "$WK" ] || exit 0
[ -z "$INPUT" ] && exit 0

# Aplanar a una línea: los loops vienen multilinea y grep mira línea por línea.
FLAT=$(printf '%s' "$INPUT" | tr '\n' ' ')

# ¿Comando derrochador? (a) loops HTTP, (b) brute-forcers, (c) fuzzers con wordlist,
# (d) martilleo: muchos curl/wget en un solo comando.
BRUTE_RE='(for|while)[[:space:]].*(curl|wget|nc )|seq[[:space:]].*(curl|wget)|xargs[[:space:]].*(curl|wget)|\b(hydra|medusa|patator|ncrack|crackmapexec|sqlmap|wfuzz)\b|(ffuf|gobuster|feroxbuster|dirsearch|wfuzz)[[:space:]].*-w'
HITS=$(printf '%s' "$FLAT" | grep -oiE 'curl|wget' | wc -l | tr -d ' ')

is_waste=0
printf '%s' "$FLAT" | grep -iqE "$BRUTE_RE" && is_waste=1
[ "${HITS:-0}" -ge 5 ] && is_waste=1
[ "$is_waste" = 1 ] || exit 0

ITER=$(cat "$WK/discovery/iteration" 2>/dev/null || echo 1)
NODE="${FABRO_NODE_ID:-$(cat "$WK/.current-node" 2>/dev/null || echo '?')}"
KEY="${ITER}:${NODE}"
CF="$WK/.selfaware-count"

prev=""; n=0
if [ -f "$CF" ]; then read -r prev n < "$CF" 2>/dev/null || { prev=""; n=0; }; fi
[ "$prev" = "$KEY" ] || n=0
n=$((n + 1))
printf '%s %s\n' "$KEY" "$n" > "$CF" 2>/dev/null || true

WARN_AT="${WIK3_SELFAWARE_WARN_AT:-4}"
# Avisar en n = WARN_AT, 2*WARN_AT, 3*WARN_AT, ... (golpecitos periódicos).
[ "$((n % WARN_AT))" -eq 0 ] || exit 0

# Escalada: más firme cuanto más se insiste.
if [ "$n" -ge "$((WARN_AT * 3))" ]; then
    extra="Ya van DEMASIADOS. Si el próximo comando no es de una hipótesis claramente distinta, CIERRA el nodo ahora con tu resumen (no sigas martillando)."
else
    extra="Emite el próximo comando solo si es de una estrategia DISTINTA."
fi

cat >&2 <<EOF
AUTOCONCIENCIA[selfaware]: llevas $n comandos de fuerza bruta/martilleo en este nodo ($NODE).
Este patrón rara vez converge y se come el presupuesto de tiempo del nodo (25-30 min); además muchos
targets tienen rate-limit y la fuerza bruta se arrastra sin avanzar. PARA y reflexiona:
  1) ¿Qué evidencia YA tienes? Re-léela antes de tirar más requests.
  2) Busca el bug por LÓGICA, no por espray: source/config expuesto, IDOR, injection puntual, auth flaw, headers.
  3) Si necesitas fuzzing, acótalo (wordlist chica, 1 hipótesis concreta), no barridos masivos.
  4) Si ya probaste un enfoque >2 veces sin resultado, descártalo y cambia de hipótesis.
$extra
EOF
exit 1
