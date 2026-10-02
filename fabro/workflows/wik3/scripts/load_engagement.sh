#!/usr/bin/env bash
# load_engagement.sh — parsea el engagement YAML y prepara el workspace.
#
# Aislamiento por engagement: cada engagement se guarda en
# /workspace/wik3/<slug>/ donde <slug> se deriva del nombre del archivo
# (ej: engagement.juice-shop.yaml -> juice-shop). Se escribe el marker
# /workspace/wik3/.active-slug con el slug activo; los scripts/prompts/hooks
# resuelven el engagement por slug (expuesto como $WIK3_DIR en el sandbox),
# sin depender de un symlink mutable.
#
# Si un engagement ya existe, se preserva su state (queue, vault, findings)
# y se re-seedea solo si aun no tiene datos — ningun run destruye el
# progreso de otro engagement.
#
# Uso: load_engagement.sh <path-al-yaml>
set -euo pipefail

ENG_PATH="${1:-}"
if [ -z "$ENG_PATH" ] || [ ! -f "$ENG_PATH" ]; then
    echo "ERROR: engagement file not found: '$ENG_PATH'" >&2
    exit 1
fi

command -v yq >/dev/null 2>&1 || {
    echo "ERROR: yq no esta instalado. En kali: apt-get install -y yq" >&2
    exit 1
}

source "$(dirname "$0")/_common.sh"

# Derivar slug DESDE el goal yaml que nos pasaron — load_engagement es la
# autoridad que establece el engagement activo en esta VM. Hay que IGNORAR
# cualquier WIK3_SLUG/WIK3_DIR heredado: el exec-logger (BASH_ENV) los exporta
# desde el marker .active-slug, que puede estar STALE de un engagement anterior
# corrido en esta misma VM. Si no los limpiamos, wik3_slug() toma el slug viejo
# (paso 1) e ignora este goal yaml → el run se carga en el directorio equivocado
# y contamina los findings del engagement anterior (bug cross-engagement).
export WIK3_ENGAGEMENT="$ENG_PATH"
unset WIK3_SLUG WIK3_DIR
SLUG=$(wik3_slug)
[ -z "$SLUG" ] && SLUG="default"

BASE=/workspace/wik3
OUT_DIR="$BASE/$SLUG"
mkdir -p "$OUT_DIR"

# Marker con el slug activo: fuente de verdad para resolver el engagement sin el
# symlink mutable 'current'. Lo leen el exec-logger (BASH_ENV), _common.sh y los
# hooks; se expone como $WIK3_DIR en el shell del agente.
printf '%s' "$SLUG" > "$BASE/.active-slug"

# Copiar el yaml siempre (es source of truth de la config para este run)
cp "$ENG_PATH" "$OUT_DIR/engagement.yaml"

MODE=$(yq -r '.mode' "$ENG_PATH")
case "$MODE" in
    pasivo|activo) ;;
    *) echo "ERROR: mode invalido '$MODE' (debe ser pasivo|activo)" >&2; exit 1;;
esac
echo -n "$MODE" > "$OUT_DIR/mode.txt"

# Flags de modo. Se leen primero y el preset CTF los coordina antes de escribir.
#   quick_test: 1 sola pasada, sin validate/senior ni loop. Atajo de smoke-test.
#   exploit_to_completion: lleva cada vuln al OBJETIVO concreto (leer archivo,
#     RCE, extraer dato) en vez de quedarse en "probable". Para labs desechables.
#   ctf: PRESET de benchmark. Mide al wik3 REAL contra un CTF: enciende
#     exploit_to_completion (rematar hasta el flag + anti-señuelo) y APAGA
#     quick_test (corre el flujo COMPLETO recon→passive→active→validate→senior,
#     sin atajos, igual que producción). Coordina los otros para que no se
#     contradigan. Default OFF; NO afecta engagements reales salvo opt-in.
QUICK=$(yq -r '(.operational_guidance.quick_test // .quick_test) // false' "$ENG_PATH" 2>/dev/null)
ETC=$(yq -r '(.operational_guidance.exploit_to_completion // .exploit_to_completion) // false' "$ENG_PATH" 2>/dev/null)
CTF=$(yq -r '(.operational_guidance.ctf // .ctf) // false' "$ENG_PATH" 2>/dev/null)
if [ "$CTF" = "true" ]; then
    # El preset CTF manda: flujo real completo (quick OFF) + remate (ETC ON).
    QUICK=false
    ETC=true
fi
[ "$QUICK" = "true" ] && echo -n "true" > "$OUT_DIR/quick_test.txt" || echo -n "false" > "$OUT_DIR/quick_test.txt"
[ "$ETC" = "true" ] && echo -n "true" > "$OUT_DIR/exploit_to_completion.txt" || echo -n "false" > "$OUT_DIR/exploit_to_completion.txt"
[ "$CTF" = "true" ] && echo -n "true" > "$OUT_DIR/ctf.txt" || echo -n "false" > "$OUT_DIR/ctf.txt"

yq -r '.scope.domains[]?, .scope.ips[]?, .scope.urls[]?' "$ENG_PATH" > "$OUT_DIR/scope.txt"
yq -r '.scope.out_of_scope[]?' "$ENG_PATH" > "$OUT_DIR/out_of_scope.txt"

if [ ! -s "$OUT_DIR/scope.txt" ]; then
    echo "ERROR: scope vacio. Define scope.domains / .ips / .urls." >&2
    exit 1
fi

# Consistency check — si yq parseó silencionsamente menos entries que las
# declaradas en el yaml, el agente podría operar con un scope/oos truncado.
# Esto pasó al menos una vez (yq cortó out_of_scope a 2/8 entries en un yaml
# con comments inline mid-list). Comparar count de líneas `- ` bajo cada key
# en el yaml crudo contra count en el archivo cargado.
yaml_count() {
    # Cuenta items de la lista yaml `<key>` bajo `<parent>`. Robusto a
    # comments y whitespace.
    local parent="$1" key="$2" yamlfile="$3"
    awk -v parent="$parent" -v key="$key" '
        $0 ~ "^[[:space:]]*" parent ":" { in_parent=1; in_key=0; next }
        in_parent && $0 ~ "^[[:space:]]*" key ":" {
            in_key=1
            # Detectar indentation del primer item con "  - "
            next
        }
        in_key {
            # Salimos del bloque al ver una línea no-comentada con menos
            # indentación (otra key del mismo nivel) o sin "  - ".
            if ($0 ~ /^[[:space:]]*-[[:space:]]+/) { count++; next }
            if ($0 ~ /^[[:space:]]*#/ || $0 ~ /^[[:space:]]*$/) next
            in_key=0
        }
        END { print count+0 }
    ' "$yamlfile"
}
declared_oos=$(yaml_count "scope" "out_of_scope" "$ENG_PATH")
loaded_oos=$(grep -c -v -E '^\s*$' "$OUT_DIR/out_of_scope.txt" 2>/dev/null || echo 0)
declared_urls=$(yaml_count "scope" "urls" "$ENG_PATH")
declared_domains=$(yaml_count "scope" "domains" "$ENG_PATH")
declared_ips=$(yaml_count "scope" "ips" "$ENG_PATH")
declared_scope=$((declared_urls + declared_domains + declared_ips))
loaded_scope=$(grep -c -v -E '^\s*$' "$OUT_DIR/scope.txt" 2>/dev/null || echo 0)

if [ "$declared_oos" -gt "$loaded_oos" ]; then
    echo "ERROR: yq cargó $loaded_oos entries de out_of_scope pero el yaml declara $declared_oos." >&2
    echo "       Probablemente yq cortó la lista por un comment inline u otro caso edge." >&2
    echo "       Revisa $ENG_PATH y $OUT_DIR/out_of_scope.txt — abortando antes de exponer al agente a un scope mal cargado." >&2
    exit 1
fi
if [ "$declared_scope" -gt 0 ] && [ "$declared_scope" -gt "$loaded_scope" ]; then
    echo "ERROR: yq cargó $loaded_scope entries de scope (urls+domains+ips) pero el yaml declara $declared_scope." >&2
    echo "       Mismo patrón de truncamiento. Abortando." >&2
    exit 1
fi

yq -r '
  (.credentials // {}) | to_entries[] |
  "CRED_" + (.key | upcase) + "=" + (.value | tojson)
' "$ENG_PATH" > "$OUT_DIR/creds.env"
chmod 600 "$OUT_DIR/creds.env"

yq -r '.rules_of_engagement // {}' "$ENG_PATH" > "$OUT_DIR/roe.yaml"

# safety.read_only_mode → safety_read_only.txt ("true" o "false"). El hook
# scope_guard.sh lo lee para bloquear payloads destructivos.
yq -r '.safety.read_only_mode // false' "$ENG_PATH" > "$OUT_DIR/safety_read_only.txt"

# operational_guidance.forbidden_endpoints_patterns → forbidden_endpoints.txt
# (regex por línea). scope_guard.sh las usa como defense-in-depth aunque los
# prompts también dicen al agente que las respete. Si el campo no existe, el
# archivo queda vacío y el guard pasa.
yq -r '.operational_guidance.forbidden_endpoints_patterns[]?' "$ENG_PATH" \
    2>/dev/null | grep -v '^\s*$' > "$OUT_DIR/forbidden_endpoints.txt" || true

# operational_guidance.user_agent → user_agent.txt. Si el operador NO lo
# seteó, escribimos un UA realista por default — nunca un identificador
# tipo "wik3-agent" que delate el scanner.
# (Chrome 130 / macOS — versión razonablemente actual sin ser bleeding-edge.)
DEFAULT_UA='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36'
UA=$(yq -r '.operational_guidance.user_agent // ""' "$ENG_PATH" 2>/dev/null)
if [ -z "$UA" ] || [ "$UA" = "null" ]; then
    UA="$DEFAULT_UA"
fi
printf '%s' "$UA" > "$OUT_DIR/user_agent.txt"

# Timestamp de inicio del engagement — idempotente: solo si no existe.
# Se preserva en re-runs (incluido report-now.sh) para que el reporte
# muestre el tiempo TOTAL desde el primer disparo, no desde el ultimo.
[ -f "$OUT_DIR/started_at" ] || date +%s > "$OUT_DIR/started_at"

# Init discovery loop state — idempotente: solo si no existe
mkdir -p "$OUT_DIR/discovery"
[ -f "$OUT_DIR/discovery/iteration" ] || echo "1" > "$OUT_DIR/discovery/iteration"
[ -f "$OUT_DIR/discovery/queue.jsonl" ] || : > "$OUT_DIR/discovery/queue.jsonl"
[ -f "$OUT_DIR/discovery/rejected.jsonl" ] || : > "$OUT_DIR/discovery/rejected.jsonl"

# Init creds vault — idempotente. Solo seedea con creds del engagement
# si el vault esta vacio (primera vez que corremos este engagement).
mkdir -p "$OUT_DIR/creds"
if [ ! -f "$OUT_DIR/creds/vault.jsonl" ]; then
    : > "$OUT_DIR/creds/vault.jsonl"
    chmod 600 "$OUT_DIR/creds/vault.jsonl"
fi

CRED_APPEND="fabro/workflows/wik3/scripts/cred_append.sh"

if [ ! -s "$OUT_DIR/creds/vault.jsonl" ]; then
    # webapp: user/pass plaintext
    WU=$(yq -r '.credentials.webapp.user // ""' "$ENG_PATH")
    WP=$(yq -r '.credentials.webapp.pass // ""' "$ENG_PATH")
    if [ -n "$WU" ] && [ -n "$WP" ]; then
        COMBO="$WU:$WP"
        bash "$CRED_APPEND" --kind plaintext_creds --value "$COMBO" \
            --source engagement --via "engagement.yaml webapp" \
            --role customer --user-email "$WU" \
            --auth-template "user=$WU pass={value}" >/dev/null || true
    fi

    # api: bearer
    AB=$(yq -r '.credentials.api.bearer // ""' "$ENG_PATH")
    if [ -n "$AB" ] && [ "$AB" != "null" ]; then
        bash "$CRED_APPEND" --kind bearer --value "$AB" \
            --source engagement --via "engagement.yaml api" \
            --role customer >/dev/null || true
    fi
fi

echo "engagement: $SLUG"
echo "mode: $MODE"
echo "scope:"; sed 's/^/  /' "$OUT_DIR/scope.txt"
if [ -s "$OUT_DIR/out_of_scope.txt" ]; then
    echo "out_of_scope:"; sed 's/^/  /' "$OUT_DIR/out_of_scope.txt"
fi
echo "loaded -> $OUT_DIR/"
echo "active-slug -> $SLUG"
