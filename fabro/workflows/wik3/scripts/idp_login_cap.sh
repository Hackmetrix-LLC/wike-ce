#!/usr/bin/env bash
# idp_login_cap.sh — pre_tool_use hook: limita los intentos de LOGIN contra un
# IdP (Auth0/Okta/Azure AD/Google). Los IdP bloquean la cuenta por brute-force
# tras ~10 logins fallidos. Caso real: el agente martilló /oauth/token +
# /u/login/password contra Auth0 y bloqueó la cuenta de prueba.
#
# Cuenta SOLO los endpoints de submit de credenciales / token exchange (no el
# /authorize ni la carga de la página de login). El contador es por engagement
# y se resetea al inicio de cada run (prepare step). Cap via WIK3_IDP_LOGIN_CAP
# (default 8). Al pasar el cap, bloquea y empuja a reusar la sesión o ask_user.
set -uo pipefail

INPUT=$(cat 2>/dev/null || echo '')
source "$(dirname "$0")/_common.sh" 2>/dev/null || true
WK="${WIK3_DIR:-$(wik3_dir 2>/dev/null)}"
[ -n "$WK" ] && [ -d "$WK" ] || exit 0

# ¿Es un intento de login/auth contra un IdP conocido? Submit de credenciales o
# token exchange (lo que cuenta para el brute-force), o browse.py login.
_is_login=0
if echo "$INPUT" | grep -iqE '(auth0\.com|okta\.com|login\.microsoftonline\.com|accounts\.google\.com)' \
   && echo "$INPUT" | grep -iqE '(oauth/token|/u/login/password|usernamepassword/login|/co/authenticate|dbconnections/[a-z_]*(login|signup|change_password))'; then
    _is_login=1
elif echo "$INPUT" | grep -iqE 'browse\.py[[:space:]]+(login|form-login)'; then
    _is_login=1
fi
[ "$_is_login" = 1 ] || exit 0

MAX="${WIK3_IDP_LOGIN_CAP:-8}"
case "$MAX" in ''|*[!0-9]*) MAX=8 ;; esac
CF="$WK/.idp-login-count"
count=$(cat "$CF" 2>/dev/null || echo 0)
case "$count" in ''|*[!0-9]*) count=0 ;; esac
count=$((count + 1))
printf '%s\n' "$count" > "$CF" 2>/dev/null || true

if [ "$count" -gt "$MAX" ]; then
    echo "BLOCK[idp-login-cap]: ya hiciste $MAX intentos de login contra el IdP (Auth0/Okta/etc.). Los IdP BLOQUEAN la cuenta por brute-force tras ~10 fallos — DETENTE. Si ya lograste loguearte, reusa el storageState guardado (browse.py fetch/eval --state-in / cred_verify). Si el login sigue fallando, NO reintentes: usa ask_user.sh para avisar al operador. Y NO toques endpoints de admin del IdP (/oidc/register, /api/v2, change_password) salvo autorización explícita." >&2
    exit 1
fi
exit 0
