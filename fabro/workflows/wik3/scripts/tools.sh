#!/usr/bin/env bash
# tools.sh — indice de los helpers disponibles en el sandbox de wik3.
#
# Uso:
#   tools.sh                   # lista todas con one-liner
#   tools.sh <name>            # usage + ejemplos completos de una tool
#   tools.sh --search <query>  # busca por keyword (name/summary/tags)
#
# Es el source-of-truth para los helpers custom de wik3. Los prompts pueden
# referirse a este comando en vez de duplicar docs. Tools externas (nmap,
# ffuf, curl, jq, yq, etc.) tienen su propio `--help`; consulta el
# Dockerfile (fabro/workflows/wik3/docker/Dockerfile) para el inventario.
set -euo pipefail

usage_list() {
cat <<'EOF'
wik3 · indice de helpers

CONVO (canal con el usuario humano)
  say.sh                Enviar mensaje al usuario (fire-and-forget, no bloquea)
  ask_user.sh           Hacer pregunta bloqueante al usuario (120min timeout)
  share.sh              Compartir un archivo con el usuario (aparece en dashboard)
  see.sh                Analizar una imagen con vision LLM (default haiku)

DISCOVERY & STATE
  discovery_append.sh   Agregar endpoint/file/host/subdomain/param al queue
  discovery_stats.sh    Stats de iteracion (LLAMAR 1 VEZ por gate — auto-incrementa)
  cred_append.sh        Guardar credential en el vault (dedupe, scope-check, nunca imprime value)
  cred_verify.sh        Validar una credential con 1 probe (marca endpoints_allow/deny)
  note.sh               Registrar observacion no-vuln (sale en el panel del dashboard)
  coverage_log.sh       Loggear tecnica intentada (SQLi, XSS, IDOR, etc.) para "Cobertura del analisis"

FINDINGS (vulnerabilidades)
  vuln.sh               CRUD de vulns: add / add-case / list / show / update / validate

ACTIVE PROBING (Playwright-based)
  browse.py             login / form-login / fetch / eval / crawl contra SPAs y webapps con CSRF
  screenshot.py         Screenshots batch (request/login/js-exec/sequence)

META
  tools.sh              Esta misma tool: indice + detalles por nombre
  tools.sh <name>       Ver usage completo de una tool

Tools externas (nmap, ffuf, gobuster, curl, jq, yq, python3, etc.) estan
pre-instaladas en la imagen fabro-agent. Consulta su propio `-h` o mira
`fabro/workflows/wik3/docker/Dockerfile` para el inventario actual.
EOF
}

usage_say() {
cat <<'EOF'
say.sh — enviar un mensaje al usuario humano (fire-and-forget).

USO
  say.sh "<texto>"

CUANDO USAR
- Progress updates ("Encontre JWT admin, sigo con chains.").
- Acknowledge de un whisper del usuario antes de retry.
- Saludo / confirmacion.
- Heads-up de un finding critico en vivo.

CUANDO NO USAR
- Si necesitas respuesta: usa ask_user.sh (bloqueante).
- Cada 2 minutos sin novedades: no spamees.

EJEMPLO
  say.sh "Iteracion 2 arrancando. Passive encontro 3 high. Active ahora."
EOF
}

usage_ask_user() {
cat <<'EOF'
ask_user.sh — hacer una pregunta bloqueante al usuario (timeout 120 min).

USO
  ask_user.sh "<pregunta>"
  ask_user.sh "<pregunta>" <segundos>     # override del timeout

COMPORTAMIENTO
- Bloquea hasta 120 minutos esperando respuesta via dashboard.
- Si llega respuesta: se imprime a stdout.
- Si timeout: imprime "[TIMEOUT: ...]" y seguis con tu mejor interpretacion.

CUANDO USAR
- Expansion de scope ("el hint sugiere /api/v2, ¿autorizado?").
- Decisiones eticas ("¿subir cookie contra user real?").
- Priorizacion entre 3+ chains plausibles.
- Aclaraciones sobre el target (prod vs lab, max_rps).

CUANDO NO USAR
- Trivialidades ("¿curl o python?"). Decidi solo.
- Si scope dice claramente no → respetalo, no preguntes.
- Consultas de conocimiento general → usa tu razonamiento.

EJEMPLO
  ask_user.sh "Encontre hint de /admin pero no esta en scope explicito. ¿Autorizado probarlo?"
EOF
}

usage_share() {
cat <<'EOF'
share.sh — compartir un archivo con el usuario (link de descarga en dashboard).

USO
  share.sh <path> [descripcion]

CUANDO USAR
- Dump de DB via SQLi UNION.
- PCAP / HAR capturado.
- Script PoC generado.
- JSON de evidencia que el operador va a revisar.

EJEMPLO
  share.sh $WIK3_DIR/active/evidence/users-dump.json \
    "Dump Users via SQLi UNION en /rest/products/search"
EOF
}

usage_see() {
cat <<'EOF'
see.sh — analizar una imagen con vision LLM (OpenAI-compatible).

USO
  see.sh <path-a-imagen> "<prompt>" [--model gpt-5.4-mini] [--detail low|high|auto]

CUANDO USAR
- Usuario sube screenshot via dashboard → describir lo que se ve.
- Captura tomada por screenshot.py → extraer texto/elementos.
- Diagrama / grafico en evidencia.

CUANDO NO USAR
- Texto/JSON → `cat` es suficiente.
- Binarios → `file`, `xxd`.
- NO uses PIL/xxd/struct para "leer" una imagen — usa see.sh.

MODELS
- Default: gpt-5.4-mini (barato).
- Para mas detalle: --model gpt-5.4 o gpt-5.4-pro.

DETAIL
- 'low' ahorra tokens (thumbnail analysis).
- 'high' para lectura precisa (OCR, textos pequeños).
- 'auto' (default) deja que el modelo decida.

ENDPOINT
- Lee OPENAI_BASE_URL del env (si esta seteado apunta al LiteLLM proxy).
- Si no, cae a https://api.openai.com.

EJEMPLO
  see.sh $WIK3_DIR/convo/shared/from_user/screenshot.png \
    "¿qué endpoints admin se ven? lista botones/links visibles"
EOF
}

usage_vuln() {
cat <<'EOF'
vuln.sh — CRUD de vulnerabilidades (findings) en vulns/<id>-<slug>/.

SUBCOMANDOS
  add        Crear vuln (imprime el id).
             --title T --severity critical|high|medium|low|info --phase passive|active|validated
             [--affected h1,h2] [--confidence ...] [--cvss N] [--source agent|imported] [--info "txt"|@file]
  add-case   Appendear caso a una vuln existente (mismo root cause, distintos endpoints).
             <id> --location "..." [--params k=v,..] [--method GET] [--evidence "txt"|@file]
             [--status confirmed|probable|inconclusive]
  list       Listar como JSONL. [--severity X] [--phase Y] [--status pending|validated|false_positive|wont_fix]
  show       Mostrar JSON {meta, info, retest_present}. <id>
  update     Editar meta.json (--key=value). Objeto/array JSON ({...}/[...]) → anidado
             (ej. --senior_review='{"verdict":"report"}'); el resto como string.
  validate   Descartar un finding. <id> --status false_positive|wont_fix [--note "..."]
             OJO: NO puedes marcar 'validated' — validar una vuln es exclusivo del hacker (humano).

AYUDA
  bash scripts/vuln.sh --help          # esta ayuda
  bash scripts/vuln.sh <cmd> --help    # ayuda de un subcomando

EJEMPLO
  bash scripts/vuln.sh add --title "IDOR en /api/orders" --severity high --phase active \
    --affected api.target.com --info "GET /api/orders/{id} sin check de tenant → datos cross-tenant"
  bash scripts/vuln.sh list --phase active
  bash scripts/vuln.sh add-case V-003-idor --location "/api/invoices/{id}" --status confirmed
EOF
}

usage_note() {
cat <<'EOF'
note.sh — registrar una observacion informativa (no-vuln).

USO
  note.sh <stage> "<title>" ["<detail>"] [--tags a,b,c]

ARGS
  stage    recon | passive | active | validate
  title    texto corto (< 100 chars)
  detail   opcional, una linea con contexto adicional
  tags     opcional, lista separada por comas

CUANDO USAR
- Framework/tech detectado + su version (fingerprint informativo).
- Config expuesta pero mitigada (ej: /actuator require auth).
- Senales de defensa (WAF, CSP, cookies bien puestas, rate limit).
- Comportamiento raro que vale la pena tener a la vista sin elevarlo a finding.
- Razones de descarte de false positives (en validate).
- Flujos de negocio / estructura / modelo de la app (--tags business) — alimentan el
  modelo del objetivo ($WIK3_DIR/memory.md + threat_model.md) que la explotacion lee
  para apuntar a alto impacto.
- Correcciones de observaciones previas (--tags correccion) — actualiza memory.md /
  threat_model.md a la version correcta.

CUANDO NO USAR
- Para findings reales → bash scripts/vuln.sh add --phase passive|active.
- Para items accionables (endpoints, files, subdomains) → discovery_append.sh.

DONDE SALE
- /workspace/wik3/<slug>/notes.jsonl
- Panel "Observaciones" del dashboard.

EJEMPLO
  note.sh recon "Spring Boot 2.5 detectado" \
    "via /actuator/info; endpoints require auth" \
    --tags framework,fingerprint
EOF
}

usage_discovery_append() {
cat <<'EOF'
discovery_append.sh — agregar un item al discovery queue.

USO
  discovery_append.sh <kind> <value> <source>

ARGS
  kind     endpoint | file | subdomain | host | param
  value    la URL/path/hostname/ip/nombre-param
  source   de donde salio ("recon:linkfinder", "passive:js-map", "active:A-007")

COMPORTAMIENTO
- Valida scope (rechaza out-of-scope → discovery/rejected.jsonl).
- Dedupea por hash del value.
- Items nuevos disparan el loop: passive/active/validate vuelven a correr en la siguiente iteracion con ese input.

EJEMPLOS
  discovery_append.sh endpoint "http://target:3000/rest/admin" "recon:linkfinder"
  discovery_append.sh subdomain "staging.target.com" "recon:crtsh"
  discovery_append.sh file "/ftp/backup.zip" "recon:directory-listing"
  discovery_append.sh param "redirectUrl" "active:A-012"
EOF
}

usage_discovery_stats() {
cat <<'EOF'
discovery_stats.sh — stats de iteracion para el check_discoveries gate.

USO
  discovery_stats.sh

COMPORTAMIENTO
- Emite JSON a stdout:
  {iteration, new_this_iteration, next_iteration, total_queue, total_rejected}
- AUTO-INCREMENTA el contador de iteracion.

IMPORTANTE
- Llamar **UNA SOLA VEZ** por pasada del gate. Llamadas duplicadas bumpearian
  iteration incorrectamente.
- Uso exclusivo del nodo check_discoveries.

EJEMPLO
  discovery_stats.sh
  # {"iteration":2,"new_this_iteration":5,"next_iteration":3,"total_queue":18,"total_rejected":3}
EOF
}

usage_cred_append() {
cat <<'EOF'
cred_append.sh — guardar una credencial en el vault.

USO
  cred_append.sh --kind <type> --value "<secret>" \
      --source "<origen>" [--via "<descripcion>"] \
      [--role admin|customer|...] [--user-email "<email>"] \
      [--auth-template "<template-con-{value}>"]

ARGS CLAVE
  --kind              jwt | bearer | plaintext_creds | cookie | api_key | hash
  --value             el secreto (NO se imprime a stdout, solo el id asignado)
  --source            de donde salio ("engagement", "active:A-002", "passive:leak")
  --role              rol en la app (admin, customer, staff, ...)
  --auth-template     como se usa (ej: "Authorization: Bearer {value}")

COMPORTAMIENTO
- Valida scope (el value no puede ser de un host fuera de scope).
- Dedupea por hash — llamadas duplicadas retornan el mismo id.
- Perms 600 en el vault file.
- Output a stdout: solo el id asignado (ej: "C-003").

CUANDO USAR
- JWT obtenido via SQLi login bypass.
- Hash extraido de un dump.
- Session cookie tras login valido.
- API key hardcoded en un JS bundle.
- OAuth secret en una config leak.

EJEMPLO
  cred_append.sh --kind jwt --value "eyJhbGci..." \
    --source "active:A-002" --via "SQLi login bypass" \
    --role admin --user-email "admin@juice-sh.op" \
    --auth-template "Authorization: Bearer {value}"
EOF
}

usage_cred_verify() {
cat <<'EOF'
cred_verify.sh — validar una credencial con 1 probe contra un endpoint.

USO
  cred_verify.sh <cred-id> <endpoint-url>

COMPORTAMIENTO
- Hace 1 request al endpoint usando auth_template del cred.
- 2xx/3xx → marca status=valid, agrega a endpoints_allow.
- 401/403 → agrega a endpoints_deny (el cred existe pero no autoriza aqui).
- Otro → status=unknown.

CUANDO USAR
- Tras guardar un cred nuevo, antes de usarlo como base para chains.
- Para confirmar end-to-end que una chain teorica produce un cred usable.

EJEMPLO
  cred_verify.sh C-001 "http://192.168.100.5:3000/api/Users"
EOF
}

usage_browse() {
cat <<'EOF'
browse.py — Playwright para SPAs, formularios con CSRF, y crawling autenticado.

SUBCOMANDOS
  login <url> <email> <pass> [--state-out <file>]
      Login SPA (Angular/React/Vue con JWT en localStorage).

  form-login <url> --fields '<json>' [--state-out <file>]
      Login form tradicional (DVWA, WordPress, Rails — scrapea hidden tokens).

  fetch <url> [--state-in <file>] [--method GET|POST] [--body <json>]
      Request autenticado usando session guardado.

  eval <url> --script "<js>" [--state-in <file>]
      Ejecutar JS en el contexto de la pagina (DOM-XSS, localStorage, etc.).

  crawl <url> [--state-in <file>] [--max-pages N]
      Crawl autenticado siguiendo links internos; alimenta discovery queue.

AUTO-FEED AL QUEUE
Todos los subcomandos interceptan xhr/fetch/docs/scripts del browser y los
agregan al discovery queue automaticamente. El output incluye stats:
  {"discovery": {"seen": 42, "added": 28, "rejected_out_of_scope": 14}}

EJEMPLO (login SPA)
  browse.py login http://target:3000/#/login admin@site.com password \
      --state-out /tmp/session.json

EJEMPLO (form login DVWA)
  browse.py form-login http://target/login.php \
      --fields '{"username":"admin","password":"password","Login":"Login"}' \
      --state-out /tmp/session.json
EOF
}

usage_screenshot() {
cat <<'EOF'
screenshot.py — screenshots via Playwright. USA SIEMPRE EL MODO BATCH.

USO BATCH
  screenshot.py batch $WIK3_DIR/evidence/screenshots/jobs.json

jobs.json es un array de jobs; cada uno con `fid` + `kind` + campos:

KINDS
  request       Mostrar la respuesta cruda del server (JSON de SQLi, archivo expuesto).
                {"fid":"A-001","kind":"request","url":"...","headers":{...}}
  login         Login + screenshot post-login.
                {"fid":"A-003","kind":"login","login_url":"...","email":"...","password":"..."}
  js-exec       Inyectar JS y screenshot del resultado (JWT forjado, DOM-XSS demo).
                {"fid":"A-004","kind":"js-exec","url":"...","script":"localStorage.setItem(...)..."}
  sequence      Serie de steps (goto/fill/click/wait/set_storage) — ideal para chains.
                {"fid":"C-001-final","kind":"sequence","steps":[...]}

OUTPUT
- <FID>.png + <FID>.caption.txt en $WIK3_DIR/evidence/screenshots/
- Errores → errors.log (no abortan el batch).
- Un log por job: "[i/N] FID OK Xs -> file.png".

PRIORIDADES DE CAPTURA
1. Cada chain critical (FID = <CHAIN_ID>-final).
2. Cada finding critical/high (FID = id del finding).
3. Medium solo si tiene componente visual.
4. Info/low sin valor visual → omitir.
EOF
}

usage_coverage_log() {
cat <<'EOF'
coverage_log.sh — registra tecnicas/endpoints probados para la "Cobertura
                   del analisis" del reporte final.

USO
  coverage_log.sh attack <technique> [--target <url>] [--outcome <verdict>] [--note "..."]
  coverage_log.sh endpoint <url> [--method GET|POST|...] [--note "..."]

NOTA: el modo attack lo escribe el nodo `coverage_scan` (deriva las técnicas del
exec.log cada iteración). El agente de active NO necesita llamarlo a mano.

CUANDO USAR (modo attack — uso de coverage_scan / writer interno)
- Por CADA técnica × target intentada, incluidas las que fallan/bloquean. Ej:
    coverage_log.sh attack "SQLi-error-based" --target https://api/x/users --outcome not_vulnerable
    coverage_log.sh attack "JWT-alg-none"     --target https://api/auth     --outcome confirmed
    coverage_log.sh attack "IDOR"             --target https://app/orders/{id} --outcome false_positive
- Outcome: confirmed | probable | false_positive | not_vulnerable | blocked_by_roe | blocked_by_waf
- Sé exhaustivo: lo que NO funcionó es la mayor parte de la cobertura. Dedup en write
  por (technique+target+outcome), así que repetir es inofensivo.

CUANDO NO USAR
- Modo endpoint: scope_guard.sh ya loggea automaticamente cada URL que
  pasa el scope check. Solo úsalo manual si queres agregar metadata
  extra (metodo, nota) que el hook automatico no captura.

EJEMPLO
  coverage_log.sh attack "SSRF-marker" --target https://api.example.com/import-url --outcome probable --note "Timing confirma el callback pero el endpoint interno objetivo no respondio"
EOF
}

case "${1:-}" in
    "") usage_list ;;
    say|say.sh) usage_say ;;
    ask_user|ask_user.sh) usage_ask_user ;;
    share|share.sh) usage_share ;;
    see|see.sh) usage_see ;;
    vuln|vuln.sh) usage_vuln ;;
    note|note.sh) usage_note ;;
    discovery_append|discovery_append.sh) usage_discovery_append ;;
    discovery_stats|discovery_stats.sh) usage_discovery_stats ;;
    cred_append|cred_append.sh) usage_cred_append ;;
    cred_verify|cred_verify.sh) usage_cred_verify ;;
    coverage_log|coverage_log.sh) usage_coverage_log ;;
    browse|browse.py) usage_browse ;;
    screenshot|screenshot.py) usage_screenshot ;;
    tools|tools.sh)
        echo "tools.sh — esta tool. 'tools.sh' lista todo, 'tools.sh <name>' detalla."
        ;;
    --search)
        q="${2:-}"
        if [ -z "$q" ]; then
            echo "ERROR: --search requires <query>" >&2
            exit 1
        fi
        # Simple grep sobre el output de list + todas las tools
        {
            usage_list
            for t in say ask_user share see vuln note discovery_append discovery_stats cred_append cred_verify browse screenshot; do
                echo "--- $t ---"
                "usage_$t"
            done
        } | grep -iE "$q" -B1 -A2 | head -40
        ;;
    -h|--help)
        head -n 9 "$0" | sed 's/^# \{0,1\}//'
        ;;
    *)
        echo "ERROR: tool desconocida '$1'. Ejecuta 'tools.sh' para ver el indice." >&2
        exit 1
        ;;
esac
