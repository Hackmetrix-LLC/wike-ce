#!/usr/bin/env bash
# _common.sh — helpers compartidos entre scripts de wik3.
# Source desde cada helper para derivar el slug del engagement en curso.
#
# Orden de resolucion:
#   1. Env var WIK3_SLUG (exportada por el exec-logger BASH_ENV desde el marker)
#   2. Env var WIK3_ENGAGEMENT (path del yaml, propagado via workflow.toml)
#   3. Marker /workspace/wik3/.active-slug (escrito por load_engagement.sh)
#   4. "default" si nada de lo anterior existe
#
# Sin symlink mutable 'current': cada run resuelve su slug de forma estable.

wik3_slug() {
    # 1. Slug ya resuelto y exportado al shell (exec-logger).
    if [ -n "${WIK3_SLUG:-}" ]; then
        echo "$WIK3_SLUG"
        return 0
    fi
    local eng="${WIK3_ENGAGEMENT:-}"
    # 2. Path del yaml: valido solo si parece real (no el template {{ goal }}).
    if [ -n "$eng" ] \
        && [ "$eng" != '{{ goal }}' ] \
        && { [[ "$eng" == *.yaml ]] || [[ "$eng" == *.yml ]]; }; then
        basename "$eng" \
            | sed -E 's/^engagement[.-]?//; s/\.ya?ml$//' \
            | tr '[:upper:] ' '[:lower:]-' \
            | tr -cd 'a-z0-9_-'
        return 0
    fi
    # 3. Marker con el slug activo (fuente de verdad sin symlink).
    if [ -s /workspace/wik3/.active-slug ]; then
        cat /workspace/wik3/.active-slug
        return 0
    fi
    echo "default"
}

wik3_dir() { echo "/workspace/wik3/$(wik3_slug)"; }

# ─── Scope matching helpers ──────────────────────────────────────────────────
#
# Comportamiento:
#   scope entry          | valor                            | match?
#   ---------------------|----------------------------------|--------
#   http://h:3000        | http://h:3000/any                | yes (host+port equal)
#   http://h:3000        | http://h:8081                    | no (different port)
#   http://h:3000/app    | http://h:3000/app                | yes (exact)
#   http://h:3000/app    | http://h:3000/app/x              | yes (prefix)
#   http://h:3000/app    | http://h:3000/other              | no (path not prefix)
#   10.0.0.1 (bare IP)   | http://10.0.0.1:any              | yes (no port = wildcard)
#   /api                 | http://h:3000/api/v1             | yes (path match)
#
# Diseño: si scope tiene path NO trivial, se requiere prefix match del path.

# Devuelve "host[:port]" — preserva port. Strip de "*." inicial: una entrada
# "*.foo.com" se trata igual que "foo.com" (apex + subdominios), así el
# operador puede escribir el wildcard explícito sin cambiar la cobertura.
scope_host_of() {
    case "$1" in
        http://*|https://*) echo "$1" | sed -E 's|^https?://||; s|[/?#].*||' ;;
        /*) echo "" ;;
        *) echo "$1" | sed -E 's|[/?#].*||; s|^\*\.||' ;;
    esac
}

# Devuelve solo hostname (sin port, sin auth) — para hostname-aware matching.
scope_hostname_only() {
    scope_host_of "$1" | sed -E 's|^[^@]+@||; s|:.*||'
}

# Devuelve la longitud de match más larga del hostname `$1` contra cualquier
# entry del archivo `$2`. Match modes:
#   - exact: hostname == entry
#   - parent: hostname endswith ".${entry}"
# Si no hay match, devuelve 0. Las entries del archivo pueden ser URLs (en
# cuyo caso se les extrae el hostname) o hostnames pelados.
scope_host_match_len() {
    local host="$1" listfile="$2"
    [ -z "$host" ] && { echo 0; return; }
    [ ! -s "$listfile" ] && { echo 0; return; }
    local best=0
    local entry entry_host entry_len
    while IFS= read -r entry; do
        # Skip blank y comments
        case "$entry" in ''|\#*) continue ;; esac
        # Limpiar inline trailing whitespace/comments
        entry=$(echo "$entry" | sed -E 's/[[:space:]]+#.*$//; s/[[:space:]]+$//')
        [ -z "$entry" ] && continue
        # Extraer hostname (la entry puede ser URL o host)
        entry_host=$(scope_hostname_only "$entry")
        [ -z "$entry_host" ] && continue
        entry_len=${#entry_host}
        if [ "$host" = "$entry_host" ]; then
            [ $entry_len -gt $best ] && best=$entry_len
        else
            case "$host" in
                *."$entry_host") [ $entry_len -gt $best ] && best=$entry_len ;;
            esac
        fi
    done < "$listfile"
    echo "$best"
}

# Devuelve path del URL o path-only; "" si no hay path.
scope_path_of() {
    case "$1" in
        http://*|https://*)
            local rest="${1#http*://}"
            case "$rest" in
                */*) echo "/${rest#*/}" | sed -E 's|[?#].*||' ;;
                *)   echo "" ;;
            esac
            ;;
        /*) echo "$1" | sed -E 's|[?#].*||' ;;
        *)  echo "" ;;
    esac
}

# Normalizar path: "/" vacio, strip trailing "/".
scope_norm_path() {
    local p="$1"
    [ -z "$p" ] || [ "$p" = "/" ] && { echo ""; return; }
    echo "${p%/}"
}

# Retorna 0 (match) o 1 (no match).
scope_matches() {
    local value="$1" scope_entry="$2"
    local vh=$(scope_host_of "$value")
    local sh=$(scope_host_of "$scope_entry")
    local sp=$(scope_norm_path "$(scope_path_of "$scope_entry")")
    local vp=$(scope_norm_path "$(scope_path_of "$value")")

    # Host check — si el value tiene host, comparar con el scope;
    # si el value es path-only (sin host), asumimos que se refiere al scope primario.
    if [ -n "$sh" ] && [ -n "$vh" ]; then
        if [ "$vh" = "$sh" ]; then
            :  # exacto
        elif echo "$value" | grep -qF "$sh" 2>/dev/null; then
            :  # substring (ej: bare IP sin port matches URLs con port)
        else
            return 1
        fi
    fi

    # Path check — solo si scope tiene path no trivial
    if [ -n "$sp" ]; then
        case "$vp" in
            "$sp"|"$sp"/*) return 0 ;;
            *) return 1 ;;
        esac
    fi
    return 0
}
