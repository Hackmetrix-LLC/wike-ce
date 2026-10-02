#!/usr/bin/env bash
# scope_guard.sh — hook pre_tool_use combinado.
#
# Dos responsabilidades en orden:
#   1. WHISPER CHECK: si el usuario mando un whisper (convo/inbox.md tiene
#      contenido y no hay pending_agent.txt), bloquear el tool call e inyectar
#      el mensaje como error. El agente lo lee, responde con say.sh, y retry.
#   2. SCOPE CHECK: lista blanca estricta. URLs que no matcheen scope.txt o
#      que matcheen out_of_scope.txt → block.
#
# Exit 0 = allow, 1 = block (Fabro aborta el tool call y pasa stderr al agente).
set -euo pipefail

source "$(dirname "$0")/_common.sh"
SLUG=$(wik3_slug)
WROOT=$(wik3_dir)
SCOPE="$WROOT/scope.txt"
OOS="$WROOT/out_of_scope.txt"
CONVO="$WROOT/convo"
INBOX="$CONVO/inbox.md"
PENDING="$CONVO/pending_agent.txt"

INPUT_RAW=$(cat 2>/dev/null || echo '')
# URL-decode una vez para que payloads tipo `https%3A%2F%2Fevil.com` no
# escapen al regex de extracción de URLs.
INPUT_DECODED=$(printf '%b' "$(printf '%s' "$INPUT_RAW" | sed -E 's/%([0-9a-fA-F]{2})/\\x\1/g')" 2>/dev/null || true)
# Si decode falló (input no era URL-encoded), usar raw.
[ -z "$INPUT_DECODED" ] && INPUT_DECODED="$INPUT_RAW"
# Para todo el resto del script, "INPUT" es la versión decodeada.
INPUT="$INPUT_DECODED"

# (Activity log se hace ahora vía docker logs del fabro-agent container,
# no via trap aquí. Ver dashboard server.py /api/agent-log.)

# ─── 1) WHISPER CHECK ────────────────────────────────────────────────────────
# Si hay whisper pendiente Y el agente no está en modo "esperando respuesta"
# (ask_user.sh), bloquear e inyectar.
if [ -s "$INBOX" ] && [ ! -s "$PENDING" ]; then
    # Race: dos tool calls concurrentes pueden entrar aqui. Usamos 'mv'
    # como grab atomico: solo uno gana el rename, el otro ve "no existe" y sale.
    TMPGRAB="$CONVO/inbox.$$.grab"
    if mv "$INBOX" "$TMPGRAB" 2>/dev/null; then
        MSG=$(cat "$TMPGRAB")
        rm -f "$TMPGRAB"
        # Recrear inbox vacio para que el proximo POST /api/whisper funcione
        : > "$INBOX"
        if [ -n "$MSG" ]; then
            mkdir -p "$CONVO"
            jq -cn --arg ts "$(date -u +%FT%TZ)" --arg t "$MSG" \
                '{ts:$ts, from:"user", kind:"whisper", text:$t}' >> "$CONVO/log.jsonl"
            # APPEND (no overwrite) para que multiples whispers/uploads
            # se acumulen hasta que el agente procese y limpie.
            {
                echo ""
                echo "=== WHISPER del usuario ($(date -u +%FT%TZ)) ==="
                echo ""
                echo "$MSG"
                echo ""
                echo "Accion: responder con 'say.sh' antes de retry tu tool call."
            } >> "$CONVO/attention.md"
            exit 1
        fi
    fi
    # Perdiste el race o MSG quedo vacio — dejar pasar
fi

# ─── 1b) ENGAGEMENT ISOLATION (filesystem) ───────────────────────────────────
# Defensa determinística contra "el agente se cambia de cliente". Bloquea:
#   (a) Cualquier path absoluto /workspace/wik3/<sub>/... donde <sub> no sea
#       el slug actual ni un alias permitido (.exec-logger, .burp).
#       Cubre lectura, escritura, cd y todo lo que cite paths absolutos.
#   (b) Acceso relativo wik3/<otro> a otro engagement real (WorkingDir=/workspace).
#   (c) cd al directorio padre /workspace/wik3.
#   (d) Mutación del marker .active-slug (controla $WIK3_DIR; solo lo escribe
#       load_engagement.sh — cambiar de engagement se hace desde el dashboard).
#
# El slug se resuelve via wik3_slug() (env WIK3_SLUG/WIK3_ENGAGEMENT o el marker
# .active-slug). Ya no hay symlink 'current'.
#
# Por qué aquí y no en AppArmor/seccomp: el agente corre en un container con
# permisos amplios sobre /workspace/wik3/ porque los scripts del workflow
# necesitan touch a ese tree. Un guard a nivel de comando es el lugar correcto
# (defense-in-depth sobre la isolación por filesystem del parking).
ISOLATION_ALIASES_PAT="\.exec-logger|\.burp"

# Canonicalización léxica (colapsa . y ..) SIN tocar el FS: no usamos realpath
# para no seguir symlinks que el agente podría plantar dentro de su engagement.
# Cierra el bypass de traversal (ej. /workspace/wik3/<slug>/../<otro>).
__canon_abs() {
    local p="$1" part
    local -a parts=() out=()
    IFS='/' read -ra parts <<< "$p" || true
    for part in "${parts[@]}"; do
        case "$part" in
            ''|.) : ;;
            ..) [ "${#out[@]}" -gt 0 ] && unset 'out[$((${#out[@]}-1))]' ;;
            *) out+=("$part") ;;
        esac
    done
    if [ "${#out[@]}" -gt 0 ]; then
        local IFS='/'; echo "/${out[*]}"
    else
        echo "/"
    fi
}

# ¿El primer componente bajo /workspace/wik3/ pertenece a otro engagement?
# Permitidos: el slug activo + aliases (.exec-logger, .burp).
__iso_forbidden() {
    local sub="$1"
    [ "$sub" = "$SLUG" ] && return 1
    printf '%s' "$sub" | grep -qxE "$ISOLATION_ALIASES_PAT" && return 1
    return 0
}

# (a) Referencias ABSOLUTAS a /workspace/wik3[/...]. Se canonicalizan primero
#     para que el traversal no escape el check.
ABS_REFS=$(echo "$INPUT" | grep -oE '/workspace/wik3[^[:space:]"'"'"'`<>;|&)]*' | sort -u || true)
for ref in $ABS_REFS; do
    cref=$(__canon_abs "$ref")
    sub="${cref#/workspace/wik3}"; sub="${sub#/}"; sub="${sub%%/*}"
    if __iso_forbidden "$sub"; then
        echo "BLOCK[isolation]: prohibido tocar otro engagement: $ref → $cref (slug actual: $SLUG). El cambio de engagement se hace desde el dashboard." >&2
        exit 1
    fi
done

# (b) Referencias RELATIVAS "wik3/<algo>": el WorkingDir del sandbox es
#     /workspace, así que `cat wik3/<otro>/...` resuelve a otro engagement sin
#     citar la ruta absoluta. Se bloquea SOLO si <algo> es un directorio real
#     bajo /workspace/wik3 y no es el activo/alias — así "fabro/workflows/wik3/
#     scripts/..." o un echo casual no dan falso positivo.
REL_REFS=$(echo "$INPUT" | grep -oE 'wik3/[^[:space:]"'"'"'`<>;|&)]*' | sort -u || true)
for ref in $REL_REFS; do
    cref=$(__canon_abs "/workspace/$ref")
    sub="${cref#/workspace/wik3}"; sub="${sub#/}"; sub="${sub%%/*}"
    [ -n "$sub" ] || continue
    if [ -d "/workspace/wik3/$sub" ] && __iso_forbidden "$sub"; then
        echo "BLOCK[isolation]: prohibido acceder a otro engagement por ruta relativa: $ref (slug actual: $SLUG)." >&2
        exit 1
    fi
done

# (c) cd/pushd al DIRECTORIO PADRE (/workspace/wik3 o wik3): desde ahí los
#     siblings quedan accesibles por nombre relativo. cd a tu slug ($WIK3_DIR)
#     NO matchea (tiene un componente después de wik3/).
if echo "$INPUT" | grep -qE '(^|[[:space:]&;|`(])(cd|pushd)[[:space:]]+(/workspace/)?wik3/?([[:space:]&;|)]|$)'; then
    echo "BLOCK[isolation]: prohibido cd al directorio padre de engagements (/workspace/wik3). Usa \$WIK3_DIR o tu slug." >&2
    exit 1
fi
# (d) Mutación del marker .active-slug (controla qué engagement es $WIK3_DIR).
#     Solo load_engagement.sh lo escribe; el agente no debe tocarlo. Cubrir
#     redirecciones y verbos de escritura en cualquier forma de path. La lectura
#     (cat) queda permitida.
if echo "$INPUT" | grep -qE '(>>?|tee|rm|unlink|mv|cp|ln|truncate|dd|sed[[:space:]]+-i)[^|;&`]*\.active-slug'; then
    echo "BLOCK[isolation]: prohibido modificar el marker .active-slug (lo gestiona el sistema, no el agente)." >&2
    exit 1
fi

# ─── 2) SCOPE CHECK ──────────────────────────────────────────────────────────
[ -z "$INPUT" ] && exit 0
[ -s "$SCOPE" ] || exit 0  # sin scope configurado, no enforzamos

# Extraer URLs http(s) del input
URLS=$(echo "$INPUT" | grep -oE 'https?://[^ "'"'"'<>()]+' | sort -u || true)

# Hosts "externos" cuyo acceso dejamos pasar (OSINT + infra estandar).
is_external_osint() {
    case "$1" in
        *crt.sh*|*nvd.nist.gov*|*cve.mitre.org*|*exploit-db.com*) return 0 ;;
        *github.com*|*githubusercontent.com*|*gitlab.com*) return 0 ;;
        *shodan.io*|*censys.io*|*archive.org*|*web.archive.org*) return 0 ;;
        *alienvault.com*|*otx.alienvault.com*|*commoncrawl*) return 0 ;;
        *oast.live*|*oast.pro*|*oast.site*|*oast.online*|*oast.me*|*oast.fun*) return 0 ;;
        *projectdiscovery.io*|*go.dev*|*pkg.go.dev*) return 0 ;;
        *127.0.0.1*|*localhost*|*169.254.169.254*) return 0 ;;
        *) return 1 ;;
    esac
}

# ─── Scope check unificado (hostname-aware, most-specific-wins) ──────────────
# Para cada URL del input:
#   1. Si es OSINT externo (crt.sh, NVD, github, etc.) → permitir.
#   2. Calcular match más específico contra scope.txt y out_of_scope.txt
#      (longitud del hostname coincidente).
#   3. Si OOS gana sobre scope → block.
#   4. Si scope no matchea (o matchea menos que OOS) → block.
#   5. Si scope tiene path no trivial, además exigir prefix match del path.
#
# Esto resuelve el bug de substring match donde `example.com` en OOS
# bloqueaba accidentalmente `staging.imd.example.com` (in-scope).
if [ -n "$URLS" ]; then
    for url in $URLS; do
        if is_external_osint "$url"; then
            continue
        fi
        host=$(scope_hostname_only "$url")
        scope_len=$(scope_host_match_len "$host" "$SCOPE")
        oos_len=$(scope_host_match_len "$host" "$OOS")

        # OOS gana si su match es más específico (o iguales — preferir denegar)
        if [ "$oos_len" -gt 0 ] && [ "$oos_len" -ge "$scope_len" ]; then
            echo "BLOCK[scope]: out_of_scope match más específico que scope: $url" >&2
            exit 1
        fi
        if [ "$scope_len" -eq 0 ]; then
            echo "BLOCK[scope]: URL fuera de scope: $url" >&2
            exit 1
        fi

        # Path check: si alguna entry de scope con este host tiene path no
        # trivial, validar prefix. Esto preserva el comportamiento previo
        # de scope_matches.
        url_path=$(scope_norm_path "$(scope_path_of "$url")")
        path_required=0
        path_matched=0
        while IFS= read -r s; do
            case "$s" in ''|\#*) continue ;; esac
            shost=$(scope_hostname_only "$s")
            # Solo validar paths de entries cuyo hostname coincide con el del URL
            if [ "$host" = "$shost" ] || [[ "$host" == *."$shost" ]]; then
                spath=$(scope_norm_path "$(scope_path_of "$s")")
                if [ -n "$spath" ] && [ "$spath" != "/" ]; then
                    path_required=1
                    case "$url_path" in
                        "$spath"|"$spath"/*) path_matched=1; break ;;
                    esac
                fi
            fi
        done < "$SCOPE"
        if [ "$path_required" = "1" ] && [ "$path_matched" = "0" ]; then
            echo "BLOCK[scope]: path fuera de scope para $host: $url_path" >&2
            exit 1
        fi

        # forbidden_endpoints_patterns: regex contra el path (no contra la
        # URL completa). El operador escribe patterns en
        # operational_guidance.forbidden_endpoints_patterns; load_engagement.sh
        # las volcó a forbidden_endpoints.txt. Defense-in-depth: aunque el
        # prompt dice al agente que las respete, aquí bloqueamos de hard.
        if [ -s "$WROOT/forbidden_endpoints.txt" ]; then
            while IFS= read -r pat; do
                case "$pat" in ''|\#*) continue ;; esac
                if echo "$url_path" | grep -qE "$pat"; then
                    echo "BLOCK[forbidden-endpoint]: $url_path matchea pattern '$pat'" >&2
                    exit 1
                fi
            done < "$WROOT/forbidden_endpoints.txt"
        fi
    done
fi

# ─── 2b) SCANNER TARGETS (host/IP bare) ──────────────────────────────────────
# Tools como nmap/masscan/rustscan/nikto aceptan host/IP crudos que el regex
# http(s) de arriba no captura. Validar el target contra scope_host y exigir
# -p <puerto> cuando el scope especifica puerto.
if echo "$INPUT" | grep -qE '(^|[[:space:]])(nmap|masscan|rustscan|nikto|dig|nslookup|host|whois|ping|traceroute|tracert|mtr|fping|hping3|tcpdump|tshark|getent)([[:space:]]|$)'; then
    SCOPE_PORTS=$(grep -oE ':[0-9]+' "$SCOPE" | tr -d ':' | sort -u || true)

    # Bloqueo explicito de scans wildcard cuando el scope tiene puertos.
    if [ -n "$SCOPE_PORTS" ] && echo "$INPUT" | grep -qE '(^|[[:space:]])(-p-|--top-ports)([[:space:]]|=|$)'; then
        echo "BLOCK[scope]: scan de todos los puertos no permitido (scope ports: $(echo $SCOPE_PORTS | tr '\n' ' '))" >&2
        exit 1
    fi

    # Tokens que parezcan target: IPv4 (con CIDR opcional) o hostname con TLD.
    TARGETS=$(echo "$INPUT" | tr ' \t' '\n\n' | \
        grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]+)?$|^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$' | \
        sort -u || true)

    for t in $TARGETS; do
        is_external_osint "$t" && continue
        host_ok=0
        while IFS= read -r s; do
            [ -z "$s" ] && continue
            sh=$(scope_host_of "$s")
            sh_host="${sh%%:*}"
            if [ "$t" = "$sh_host" ] || [ "$t" = "$sh" ]; then
                host_ok=1; break
            fi
        done < "$SCOPE"
        if [ "$host_ok" = "0" ]; then
            echo "BLOCK[scope]: target de scanner fuera de scope: $t" >&2
            exit 1
        fi
    done

    # Port enforcement: solo aplica a tools que escanean puertos (nmap/masscan/
    # rustscan/nikto). DNS/whois/ping no piden puerto, así que el check los
    # exoneraría incorrectamente.
    IS_PORTSCAN=0
    if echo "$INPUT" | grep -qE '(^|[[:space:]])(nmap|masscan|rustscan|nikto)([[:space:]]|$)'; then
        IS_PORTSCAN=1
    fi
    if [ -n "$SCOPE_PORTS" ] && [ "$IS_PORTSCAN" = "1" ]; then
        CMD_PORTS=$(echo "$INPUT" | \
            grep -oE '(^|[[:space:]])(-p|--ports)[ \t=]*[0-9][0-9,.-]*' | \
            sed -E 's/.*(-p|--ports)[[:space:]=]*//' | tr ',' '\n' | sort -u || true)
        if [ -z "$CMD_PORTS" ]; then
            echo "BLOCK[scope]: scope define puerto especifico — scanner requiere -p <puerto> (ports: $(echo $SCOPE_PORTS | tr '\n' ' '))" >&2
            exit 1
        fi
        for p in $CMD_PORTS; do
            case "$p" in
                *-*)
                    echo "BLOCK[scope]: rango de puertos '$p' excede scope (ports: $(echo $SCOPE_PORTS | tr '\n' ' '))" >&2
                    exit 1 ;;
                ''|*[!0-9]*)
                    echo "BLOCK[scope]: puerto invalido '$p'" >&2
                    exit 1 ;;
                *)
                    if ! echo "$SCOPE_PORTS" | grep -qxF "$p"; then
                        echo "BLOCK[scope]: puerto $p fuera de scope (ports: $(echo $SCOPE_PORTS | tr '\n' ' '))" >&2
                        exit 1
                    fi ;;
            esac
        done
    fi
fi

# Modo pasivo: bloquear tools activos
MODE=$(cat "$WROOT/mode.txt" 2>/dev/null || echo '')
if [ "$MODE" = "pasivo" ]; then
    if echo "$INPUT" | grep -qiE 'nmap |nikto |ffuf |gobuster |feroxbuster |sqlmap |nuclei |hydra |retire '; then
        echo "BLOCK[scope]: mode=pasivo no permite tools de probing activo" >&2
        exit 1
    fi
fi

# safety.read_only_mode: bloquear payloads que modifiquen o destruyan datos.
# La lista cubre los casos obvios sin tocar HTTP POST/PUT (que son legítimos
# para login y APIs de read). El hacker que necesite ejecutar algo borderline
# puede desactivar el flag en la config y re-correr.
RO=$(cat "$WROOT/safety_read_only.txt" 2>/dev/null || echo "")
if [ "$RO" = "true" ]; then
    if echo "$INPUT" | grep -qiE '\b(DROP[[:space:]]+(TABLE|DATABASE|SCHEMA|INDEX|VIEW)|TRUNCATE[[:space:]]+TABLE|DELETE[[:space:]]+FROM|UPDATE[[:space:]]+[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]+SET|INSERT[[:space:]]+INTO|ALTER[[:space:]]+(TABLE|DATABASE)|CREATE[[:space:]]+(TABLE|DATABASE|USER|ROLE)|GRANT[[:space:]]+|REVOKE[[:space:]]+|RENAME[[:space:]]+TABLE)\b'; then
        echo "BLOCK[safety]: read_only_mode activo — payload con SQL destructivo (INSERT/UPDATE/DELETE/DROP/TRUNCATE/...)" >&2
        exit 1
    fi
    if echo "$INPUT" | grep -qE '(^|[[:space:]])(rm[[:space:]]+-[rf]+|rm[[:space:]]+-[rf]*[[:space:]]+/|mv[[:space:]]+|dd[[:space:]]+if=|mkfs|shred|chmod[[:space:]]+[0-7]+[[:space:]]+/|chown[[:space:]]+)'; then
        echo "BLOCK[safety]: read_only_mode activo — comando shell destructivo (rm/mv/dd/mkfs/shred/chmod/chown)" >&2
        exit 1
    fi
    # HTTP destructivo: PUT/PATCH/DELETE en curl/hurl/python-requests/fetch.
    # POST queda permitido (login, search, GraphQL queries — necesarios para
    # reads). Si el agente necesita POST destructivo (mutations), tiene que
    # parar el run y pedir desactivar el flag.
    if echo "$INPUT" | grep -qiE '(-X|--request)[[:space:]=]+(PUT|DELETE|PATCH)\b|\b(requests|httpx|aiohttp|urllib3)\.(put|delete|patch)\b|(^|[[:space:]\\n])(PUT|DELETE|PATCH)[[:space:]]+https?://|"method"[[:space:]]*:[[:space:]]*"(PUT|DELETE|PATCH)"|--upload-file\b|-T[[:space:]]'; then
        echo "BLOCK[safety]: read_only_mode activo — request HTTP destructivo (PUT/DELETE/PATCH/upload). POST sigue permitido para login/search." >&2
        exit 1
    fi
fi

# ─── 3) COVERAGE LOG (passive) ───────────────────────────────────────────────
# endpoints.jsonl alimenta la sección "Cobertura del análisis" del reporte
# final con cada URL que pasó scope. El log de comandos del agente vive
# ahora en docker logs del container, no aquí.
COV_DIR="$WROOT/coverage"
mkdir -p "$COV_DIR" 2>/dev/null || true
if [ -n "${URLS:-}" ]; then
    {
        for url in $URLS; do
            is_external_osint "$url" && continue
            jq -cn \
                --arg ts "$(date -u +%FT%TZ)" \
                --arg url "$url" \
                --arg source "scope_guard" \
                '{ts:$ts, url:$url, source:$source}'
        done
    } >> "$COV_DIR/endpoints.jsonl" 2>/dev/null || true
fi

exit 0
