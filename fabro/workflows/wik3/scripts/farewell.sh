#!/usr/bin/env bash
# farewell.sh — easter egg de cierre del workflow.
#
# Imprime un ASCII art aleatorio a stdout (queda en exec.log) y lo
# appendea como mensaje del sistema en convo/log.jsonl para que aparezca
# en el chat del dashboard del wik3.
#
# Nunca rompe el workflow: cualquier error -> exit 0 silencioso.
set +e

WROOT="${WIK3_DIR:-/workspace/wik3/$(cat /workspace/wik3/.active-slug 2>/dev/null)}"
LOG="$WROOT/convo/log.jsonl"

# ─── Set de ASCII arts ──────────────────────────────────────────────────
# Cada función imprime su arte. Agregar nuevos como `art_NN()`.
# Heredoc con 'EOF' cuotado: los \ y / se preservan literales, sin escape.

art_01() {
cat <<'EOF'
       _    _
      / \  / \          .--.
     ( o )( o )       ( -- )
      \_^__^_/       _( '' )_
       \___/         (_  ''  _)
      ╔══════════════════════╗
      ║  wik3 OUT — pwn well ║
      ╚══════════════════════╝
EOF
}

art_02() {
cat <<'EOF'
        ____
       /\  /\
      /  \/  \
     /___/\___\        engagement done.
        |  |          findings cocinados,
       /    \         informe horneado.
      /______\
EOF
}

art_03() {
cat <<'EOF'
     ╔═════════════════════════╗
     ║                         ║
     ║      ░░ wik3 ░░         ║
     ║   ░░ has shipped ░░     ║
     ║                         ║
     ║   no shells were        ║
     ║   harmed in production  ║
     ║                         ║
     ╚═════════════════════════╝
EOF
}

art_04() {
cat <<'EOF'
        .--.
       |o_o |     thanks for hacking.
       |:_/ |     run terminado.
      //   \ \
     (|     | )
    /'\_   _/`\
    \___)=(___/
EOF
}

art_05() {
cat <<'EOF'
       ___________________
      |                   |
      |   [ done ]        |
      |                   |
      |   $ wik3 --help   |
      |   > work hard,    |
      |     find harder.  |
      |___________________|
        ||              ||
        ||______________||
EOF
}

art_06() {
cat <<'EOF'
            __
       _   |  |
      | |  |  |     a wik3 was here.
      | |__|  |     vulns mapeadas,
      |_______|     scope respetado,
        ||  ||      coffee consumed.
        ||  ||
       (    )
EOF
}

art_07() {
cat <<'EOF'
        ___,@
       /  <
      |__/  |        // engagement complete //
      |  | |         // payload delivered  //
      |  | |         // exit clean         //
      ====='
EOF
}

art_08() {
cat <<'EOF'
       ┌─────────────────────────┐
       │  > wik3 run finished    │
       │  > status: SHIPPED      │
       │  > artifacts: ready     │
       │  > coffee level: 0%     │
       └─────────────────────────┘
EOF
}

art_09() {
cat <<'EOF'
              ___
            //   \\        ☠ wik3 ☠
           //     \\       findings landed
          //_______\\      shells unbroken
          \\       //
           \\_____//
              | |
            __/ \__
EOF
}

art_10() {
cat <<'EOF'
       ╭───────────────────────╮
       │  ▄▄▄▄    wik3   ▄▄▄▄  │
       │ █    █  done.  █    █ │
       │ █    █  rest   █    █ │
       │  ▀▀▀▀          ▀▀▀▀   │
       ╰───────────────────────╯
            "stay curious."
EOF
}

# ─── Selección aleatoria ────────────────────────────────────────────────
N_ARTS=10
PICK=$(( RANDOM % N_ARTS + 1 ))
FN=$(printf "art_%02d" "$PICK")

ART=$("$FN" 2>/dev/null)

# Si por algún motivo el pick falló, usar art_01 como fallback.
[ -z "$ART" ] && ART=$(art_01)

# ─── stdout ─────────────────────────────────────────────────────────────
printf '\n%s\n\n' "$ART"

# ─── chat del dashboard ─────────────────────────────────────────────────
# Append a convo/log.jsonl como mensaje del sistema. El dashboard lo
# pinta como un turno mas en la "Conversación con el agente".
if [ -d "$WROOT/convo" ] && command -v jq >/dev/null 2>&1; then
    TS=$(date -u +%FT%TZ)
    jq -cn --arg ts "$TS" --arg t "$ART" \
        '{ts:$ts, from:"system", kind:"farewell", text:$t}' >> "$LOG" 2>/dev/null
fi

exit 0
