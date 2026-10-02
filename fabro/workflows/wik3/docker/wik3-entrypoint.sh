#!/usr/bin/env bash
# wik3-entrypoint.sh — corre primero cuando el container fabro-agent arranca.
#
# Si /etc/wik3-burp/ca.crt está montado y no está vacío (vía bind mount
# definido en workflow.toml [run.sandbox] extra_mounts), lo agrega al trust
# store del container y exporta env vars para tools que no usan el trust
# store del OS (Node, etc.).
#
# Sin cert montado, el container arranca normal sin trustear nada extra.
set -e

EXTRA_CA="/etc/wik3-burp/ca.crt"
if [ -s "$EXTRA_CA" ]; then
  install -m 0644 "$EXTRA_CA" /usr/local/share/ca-certificates/wik3-burp.crt
  update-ca-certificates --fresh >/dev/null 2>&1 || true
  export REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
  export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
  export NODE_EXTRA_CA_CERTS="$EXTRA_CA"
  echo "[wik3-entrypoint] burp CA installed ($(wc -c < "$EXTRA_CA") bytes)"
fi

exec "$@"
