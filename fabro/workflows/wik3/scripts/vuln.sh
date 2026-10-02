#!/usr/bin/env bash
# vuln.sh — CRUD de vulnerabilidades en el layout vulns/<id>-<slug>/.
#
# Layout por vuln:
#   vulns/V-NNN-<slug>/
#     meta.json   — {id, title, severity, confidence, affected, phase, cvss?,
#                    references?, exploit_public?, source, created_at,
#                    review:{status,by,at,note}}
#     info.md     — texto libre (descripción + evidencia narrativa)
#     retest.py   — script determinístico (opcional, lo escribe el import o el operador)
#
# Source of truth: el filesystem. No hay agregados a JSON.
#
# Uso:
#   vuln.sh add --severity X --title "..." --phase passive [--affected host] [--cvss N] [--source agent|imported] [--info "texto"|@file]
#       → imprime el id (V-NNN-slug) a stdout
#   vuln.sh add-case <id> --location "..." [--params "k=v,k2=v2"] [--method GET] [--evidence "..."|@file] [--status confirmed|probable|inconclusive]
#       → appendea un caso de explotación a meta.json.cases[]. Útil cuando una
#         vuln raíz (mismo bug, mismo root cause) se manifiesta en N endpoints.
#         En lugar de crear N vulns separadas → 1 vuln + N casos.
#   vuln.sh list [--severity X] [--phase Y] [--status pending|validated|false_positive|wont_fix]
#       → JSONL: un meta por línea
#   vuln.sh show <id>
#       → JSON con {meta, info, retest_present:bool}
#   vuln.sh update <id> --key=value [--key=value...]
#       → edición atómica de meta.json (claves de primer nivel). El valor se
#         guarda como string, salvo cvss numérico o un valor que sea objeto/array
#         JSON ({...}/[...]), que se almacena como JSON anidado (ej. senior_review).
#   vuln.sh validate <id> --status validated|false_positive|wont_fix [--note "..."]
#       → setea meta.json.review
set -euo pipefail

# Resolver el wik3_dir activo: env WIK3_DIR (exportada por el exec-logger) o el
# marker /workspace/wik3/.active-slug (escrito por load_engagement.sh).
if [ -n "${WIK3_DIR:-}" ]; then
    WROOT="$WIK3_DIR"
elif [ -s /workspace/wik3/.active-slug ]; then
    WROOT="/workspace/wik3/$(cat /workspace/wik3/.active-slug)"
else
    echo "ERROR: vuln.sh requiere \$WIK3_DIR env var o el marker /workspace/wik3/.active-slug" >&2
    exit 2
fi

VULNS_DIR="$WROOT/vulns"
mkdir -p "$VULNS_DIR"

cmd="${1:-}"; shift || true

now_iso() { date -u +%FT%TZ; }

slugify() {
    echo "$1" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9]+/-/g; s/^-+//; s/-+$//' | cut -c1-40
}

next_id() {
    local counter="$VULNS_DIR/.counter"
    # flock evita race conditions cuando varios bash -c del agente corren
    # en paralelo. macOS no tiene flock — sin lock funciona igual para tests
    # locales y para el caso single-threaded del agente típico.
    if command -v flock >/dev/null 2>&1; then
        (
            exec 9>"$VULNS_DIR/.lock"
            flock 9
            local n
            n=$(cat "$counter" 2>/dev/null || echo 0)
            n=$((n + 1))
            echo "$n" > "$counter"
            printf "V-%03d" "$n"
        )
    else
        local n
        n=$(cat "$counter" 2>/dev/null || echo 0)
        n=$((n + 1))
        echo "$n" > "$counter"
        printf "V-%03d" "$n"
    fi
}

find_dir() {
    # $1: id (V-NNN o V-NNN-slug). Devuelve el path completo del dir o vacío.
    local id="$1"
    local prefix="$id"
    # Si vino "V-NNN-slug", el prefijo ya es completo.
    if [ -d "$VULNS_DIR/$id" ]; then
        echo "$VULNS_DIR/$id"
        return 0
    fi
    # Si vino solo "V-NNN", buscar el dir que empiece con eso.
    local match
    match=$(find "$VULNS_DIR" -maxdepth 1 -type d -name "${id}-*" -print -quit 2>/dev/null)
    [ -n "$match" ] && echo "$match" || true
}

read_meta() {
    # $1: dir. Imprime meta.json a stdout, o {} si no existe.
    local d="$1"
    if [ -f "$d/meta.json" ]; then
        cat "$d/meta.json"
    else
        echo "{}"
    fi
}

write_meta() {
    # $1: dir. stdin: nuevo meta JSON. Escribe atómico.
    local d="$1"
    local tmp="$d/meta.json.tmp"
    cat > "$tmp"
    mv "$tmp" "$d/meta.json"
}

cmd_add() {
    local title="" severity="" confidence="" affected="" phase="" cvss="" source="agent" ref=""
    local info=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --title)      title="$2"; shift 2 ;;
            --severity)   severity="$2"; shift 2 ;;
            --confidence) confidence="$2"; shift 2 ;;
            --affected)   affected="$2"; shift 2 ;;
            --phase)      phase="$2"; shift 2 ;;
            --cvss)       cvss="$2"; shift 2 ;;
            --source)     source="$2"; shift 2 ;;
            --ref)        ref="$2"; shift 2 ;;
            --info)
                if [[ "$2" == @* ]]; then
                    info=$(cat "${2:1}")
                else
                    info="$2"
                fi
                shift 2
                ;;
            *) echo "unknown flag: $1" >&2; exit 2 ;;
        esac
    done
    [ -n "$title" ] || { echo "ERROR: --title requerido" >&2; exit 2; }
    [ -n "$severity" ] || { echo "ERROR: --severity requerido" >&2; exit 2; }
    [ -n "$phase" ] || { echo "ERROR: --phase requerido (passive|active|validated)" >&2; exit 2; }
    case "$severity" in
        critical|high|medium|low|info) ;;
        *) echo "ERROR: severity inválido: $severity" >&2; exit 2 ;;
    esac
    case "$phase" in
        passive|active|validated|imported) ;;
        *) echo "ERROR: phase inválido: $phase" >&2; exit 2 ;;
    esac

    local id slug dir affected_arr cvss_val
    id=$(next_id)
    slug=$(slugify "$title")
    dir="$VULNS_DIR/${id}-${slug}"
    mkdir -p "$dir"

    # affected: comma-separated → array JSON
    if [ -n "$affected" ]; then
        affected_arr=$(echo "$affected" | jq -R 'split(",") | map(gsub("^\\s+|\\s+$"; ""))')
    else
        affected_arr="[]"
    fi
    cvss_val="null"
    if [ -n "$cvss" ]; then
        cvss_val="$cvss"
    fi

    jq -n \
        --arg id "${id}-${slug}" \
        --arg title "$title" \
        --arg severity "$severity" \
        --arg confidence "${confidence:-likely}" \
        --argjson affected "$affected_arr" \
        --arg phase "$phase" \
        --argjson cvss "$cvss_val" \
        --arg source "$source" \
        --arg report_id "$ref" \
        --arg created_at "$(now_iso)" \
        '{id:$id, title:$title, severity:$severity, confidence:$confidence,
          affected:$affected, phase:$phase, cvss:$cvss, source:$source,
          report_id:$report_id,
          created_at:$created_at,
          cases:[],
          review:{status:"pending", by:"", at:"", note:""}}' > "$dir/meta.json"

    if [ -n "$info" ]; then
        printf '%s\n' "$info" > "$dir/info.md"
    else
        : > "$dir/info.md"
    fi

    echo "${id}-${slug}"
}

cmd_add_case() {
    # Appendea un caso de explotación a meta.json.cases[] de una vuln existente.
    # Útil para consolidar bugs con mismo root cause: en lugar de N vulns
    # separadas (V-001, V-002, ...) cuando son el mismo IDOR/SQLi/etc. en
    # distintos endpoints, se reporta 1 vuln raíz + N casos.
    local id="${1:-}"; shift || true
    [ -n "$id" ] || { echo "ERROR: add-case requiere <id>" >&2; exit 2; }
    local dir
    dir=$(find_dir "$id")
    [ -n "$dir" ] && [ -d "$dir" ] || { echo "ERROR: vuln no encontrada: $id" >&2; exit 2; }

    local location="" params="" method="" evidence="" status="confirmed"
    while [ $# -gt 0 ]; do
        case "$1" in
            --location) location="$2"; shift 2 ;;
            --params)   params="$2"; shift 2 ;;
            --method)   method="$2"; shift 2 ;;
            --evidence)
                if [[ "$2" == @* ]]; then
                    evidence=$(cat "${2:1}")
                else
                    evidence="$2"
                fi
                shift 2 ;;
            --status)   status="$2"; shift 2 ;;
            *) echo "unknown flag: $1" >&2; exit 2 ;;
        esac
    done
    [ -n "$location" ] || { echo "ERROR: --location requerido (URL, path, host, etc.)" >&2; exit 2; }
    case "$status" in
        confirmed|probable|inconclusive) ;;
        *) echo "ERROR: --status inválido: $status (confirmed|probable|inconclusive)" >&2; exit 2 ;;
    esac

    local cur new
    cur=$(read_meta "$dir")
    new=$(echo "$cur" | jq \
        --arg location "$location" \
        --arg params "$params" \
        --arg method "$method" \
        --arg evidence "$evidence" \
        --arg status "$status" \
        --arg added_at "$(now_iso)" \
        '
        (.cases // []) as $existing
        | .cases = ($existing + [{
            location: $location,
            params: $params,
            method: $method,
            evidence: $evidence,
            status: $status,
            added_at: $added_at
          }])
        ')
    echo "$new" | write_meta "$dir"
    # Imprime cuántos casos quedan totales.
    echo "$new" | jq -r '"✓ caso agregado · total casos: \(.cases | length)"'
}

cmd_list() {
    local f_severity="" f_phase="" f_status=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --severity) f_severity="$2"; shift 2 ;;
            --phase)    f_phase="$2"; shift 2 ;;
            --status)   f_status="$2"; shift 2 ;;
            *) echo "unknown flag: $1" >&2; exit 2 ;;
        esac
    done
    local count=0
    for d in "$VULNS_DIR"/V-*/; do
        [ -d "$d" ] || continue
        [ -f "$d/meta.json" ] || continue
        local meta; meta=$(cat "$d/meta.json")
        if [ -n "$f_severity" ]; then
            local s; s=$(echo "$meta" | jq -r '.severity // ""')
            [ "$s" = "$f_severity" ] || continue
        fi
        if [ -n "$f_phase" ]; then
            local p; p=$(echo "$meta" | jq -r '.phase // ""')
            [ "$p" = "$f_phase" ] || continue
        fi
        if [ -n "$f_status" ]; then
            local rs; rs=$(echo "$meta" | jq -r '.review.status // "pending"')
            [ "$rs" = "$f_status" ] || continue
        fi
        echo "$meta" | jq -c .
        count=$((count + 1))
    done
    # Emit señal explícita en stderr cuando el filtrado da 0 hits — sin
    # esto, el agente puede intentar parsear stdin vacío con jq/python y
    # romper con un stack trace ruidoso.
    if [ "$count" -eq 0 ]; then
        local filters=""
        [ -n "$f_severity" ] && filters="$filters severity=$f_severity"
        [ -n "$f_phase" ]    && filters="$filters phase=$f_phase"
        [ -n "$f_status" ]   && filters="$filters status=$f_status"
        [ -n "$filters" ] && filters=" (filtros:$filters)" || filters=""
        echo "# 0 vulns en este engagement${filters}" >&2
    fi
}

cmd_show() {
    local id="${1:-}"
    [ -n "$id" ] || { echo "usage: vuln.sh show <id>" >&2; exit 2; }
    local d; d=$(find_dir "$id")
    [ -n "$d" ] || { echo "ERROR: vuln $id no existe" >&2; exit 1; }
    local meta info retest_present
    meta=$(cat "$d/meta.json")
    info=$(cat "$d/info.md" 2>/dev/null || echo "")
    retest_present="false"; [ -f "$d/retest.py" ] && retest_present="true"
    jq -n --argjson meta "$meta" --arg info "$info" --argjson rp "$retest_present" \
       '{meta:$meta, info:$info, retest_present:$rp}'
}

cmd_update() {
    local id="${1:-}"; shift || true
    [ -n "$id" ] || { echo "usage: vuln.sh update <id> --k=v ..." >&2; exit 2; }
    local d; d=$(find_dir "$id")
    [ -n "$d" ] || { echo "ERROR: vuln $id no existe" >&2; exit 1; }
    local meta; meta=$(read_meta "$d")
    while [ $# -gt 0 ]; do
        local arg="$1"
        case "$arg" in
            --*=*)
                local k="${arg#--}"; k="${k%%=*}"
                local v="${arg#*=}"
                # Tipado del valor:
                #   - cvss numérico               → número JSON
                #   - valor que empieza con { o [ y parsea como JSON → objeto/array JSON
                #     (necesario para campos anidados como senior_review; con --arg se
                #      guardaban como string escapado "{\"verdict\":...}" en vez de objeto)
                #   - todo lo demás               → string (preserva escalares como "high")
                if [ "$k" = "cvss" ] && [[ "$v" =~ ^[0-9.]+$ ]]; then
                    meta=$(echo "$meta" | jq --argjson v "$v" ".${k} = \$v")
                elif { [[ "$v" == "{"* ]] || [[ "$v" == "["* ]]; } && printf '%s' "$v" | jq -e . >/dev/null 2>&1; then
                    meta=$(echo "$meta" | jq --argjson v "$v" ".${k} = \$v")
                else
                    meta=$(echo "$meta" | jq --arg v "$v" ".${k} = \$v")
                fi
                shift
                ;;
            *) echo "unknown arg: $arg" >&2; exit 2 ;;
        esac
    done
    echo "$meta" | write_meta "$d"
}

cmd_validate() {
    local id="${1:-}"; shift || true
    [ -n "$id" ] || { echo "usage: vuln.sh validate <id> --status X [--note ...]" >&2; exit 2; }
    local d; d=$(find_dir "$id")
    [ -n "$d" ] || { echo "ERROR: vuln $id no existe" >&2; exit 1; }
    local status="" note="" by="${WIK3_REVIEW_ACTOR:-agent}"
    while [ $# -gt 0 ]; do
        case "$1" in
            --status) status="$2"; shift 2 ;;
            --note)   note="$2"; shift 2 ;;
            --by)     by="$2"; shift 2 ;;
            *) echo "unknown flag: $1" >&2; exit 2 ;;
        esac
    done
    case "$status" in
        pending|validated|false_positive|wont_fix) ;;
        *) echo "ERROR: status inválido: $status" >&2; exit 2 ;;
    esac
    # Solo el HACKER (humano) puede VALIDAR una vuln. El agente puede descartarla
    # (false_positive / wont_fix) o dejarla pending, pero NO marcarla 'validated'
    # — eso simularía una validación humana. Las acciones autorizadas por el hacker
    # (validación desde el dashboard, import de un reporte) setean
    # WIK3_HUMAN_VALIDATE=1; el entorno del agente no lo tiene.
    if [ "$status" = "validated" ] && [ "${WIK3_HUMAN_VALIDATE:-}" != "1" ]; then
        echo "ERROR: solo el hacker puede validar una vuln. Tú (agente) puedes marcar false_positive o wont_fix, pero no 'validated'." >&2
        exit 3
    fi
    local meta; meta=$(read_meta "$d")
    meta=$(echo "$meta" | jq --arg s "$status" --arg b "$by" --arg t "$(now_iso)" --arg n "$note" \
        '.review = {status:$s, by:$b, at:$t, note:$n}')
    echo "$meta" | write_meta "$d"
}

cmd_retest() {
    # Marca el RESULTADO del retest agéntico de una vuln (no es la review humana).
    local id="${1:-}"; shift || true
    [ -n "$id" ] || { echo "usage: vuln.sh retest <id> --state vulnerable|fixed|mitigated|missing_creds|inconclusive [--evidence ...]" >&2; exit 2; }
    local d; d=$(find_dir "$id")
    [ -n "$d" ] || { echo "ERROR: vuln $id no existe" >&2; exit 1; }
    local state="" evidence="" by="${WIK3_REVIEW_ACTOR:-agent}"
    while [ $# -gt 0 ]; do
        case "$1" in
            --state)    state="$2"; shift 2 ;;
            --evidence) if [[ "$2" == @* ]]; then evidence=$(cat "${2:1}"); else evidence="$2"; fi; shift 2 ;;
            --by)       by="$2"; shift 2 ;;
            *) echo "unknown flag: $1" >&2; exit 2 ;;
        esac
    done
    case "$state" in
        vulnerable|fixed|mitigated|missing_creds|inconclusive|running) ;;
        *) echo "ERROR: state inválido: $state (vulnerable|fixed|mitigated|missing_creds|inconclusive)" >&2; exit 2 ;;
    esac
    local meta; meta=$(read_meta "$d")
    meta=$(echo "$meta" | jq --arg s "$state" --arg b "$by" --arg t "$(now_iso)" --arg e "$evidence" \
        '.retest = {state:$s, by:$b, at:$t, evidence:$e}')
    echo "$meta" | write_meta "$d"
    echo "✓ retest $id → $state"
}

print_usage() {
cat <<'EOF'
usage: vuln.sh <cmd> [args]
  add       Crear vuln. Imprime el id.
            --title T --severity critical|high|medium|low|info --phase passive|active|validated
            [--affected h1,h2] [--confidence ...] [--cvss N] [--source agent|imported] [--ref report-id] [--info "txt"|@file]
  add-case  Appendear caso de explotación a meta.json.cases[] (mismo root cause, distintos endpoints).
            <id> --location "..." [--params k=v,..] [--method GET] [--evidence "txt"|@file]
            [--status confirmed|probable|inconclusive]
  list      Listar vulns como JSONL. [--severity X] [--phase Y] [--status pending|validated|false_positive|wont_fix]
  show      Mostrar JSON con {meta, info, retest_present}. <id>
  update    Editar meta.json (--key=value). Valor objeto/array JSON ({...}/[...]) se guarda
            anidado (ej. --senior_review='{"verdict":"report"}'); el resto como string.
  validate  Marcar review status. <id> --status false_positive|wont_fix|pending [--note "..."]
            ('validated' es exclusivo del hacker — requiere WIK3_HUMAN_VALIDATE=1)
  retest    Marcar RESULTADO del retest. <id> --state vulnerable|fixed|mitigated|missing_creds|inconclusive [--evidence "..."|@file]

Ayuda: vuln.sh --help   |   vuln.sh <cmd> --help
EOF
}

# Ayuda por subcomando: `vuln.sh <cmd> --help` (antes --help se tomaba como id o
# como flag desconocido → "ERROR: vuln --help no existe" / "unknown flag: --help").
case "${1:-}" in -h|--help) print_usage; exit 0 ;; esac

case "$cmd" in
    add)      cmd_add "$@" ;;
    add-case) cmd_add_case "$@" ;;
    list)     cmd_list "$@" ;;
    show)     cmd_show "$@" ;;
    update)   cmd_update "$@" ;;
    validate) cmd_validate "$@" ;;
    retest)   cmd_retest "$@" ;;
    -h|--help|help) print_usage ;;
    "")       print_usage >&2; exit 2 ;;
    *) echo "comando desconocido: $cmd" >&2; print_usage >&2; exit 2 ;;
esac
