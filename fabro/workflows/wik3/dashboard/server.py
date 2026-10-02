#!/usr/bin/env python3
"""
wik3 dashboard — sirve un HTML con widgets live del run en curso y CRUD de
engagements.

Modos:
  - local-dev: sin auth, sin gestión de engagements (solo viewer del workspace local).
  - VM (box): con basic auth (WIK3_DASHBOARD_PASSWORD) + CRUD completo
    (crear engagement vía LLM, editar, correr, parar, borrar).

Uso:
    python3 server.py [--port 8888] [--wik3-root /path/to/wik3]

Endpoints (subset):
    GET  /                               → dashboard.html
    GET  /api/state?engagement=<slug>    → estado agregado del run
    GET  /api/agent-log → cola del exec.log del agente (últimos 4 MB, liviano para el browser)
    GET  /api/engagements                → lista con metadata
    POST /api/engagements/draft          → texto → LLM → {slug, yaml, parsed, summary}
    POST /api/engagements                → persistir engagement
    GET  /api/engagements/<slug>         → yaml + meta + parsed
    PUT  /api/engagements/<slug>         → actualizar (re-serializa YAML)
    DELETE /api/engagements/<slug>       → borrar YAML + workspace + meta + parked + reset-failed unit + symlink/marker (409 si corre)
    POST /api/engagements/<slug>/run     → systemctl start wik3-engagement@<slug>
    POST /api/engagements/<slug>/stop    → systemctl stop  wik3-engagement@<slug>
    GET  /screenshots/<file>             → sirve PNGs de evidence/
    GET  /api/results-bundle?engagement=<slug> → zip con findings + chains + notes + engagement.yaml + exec.log
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hmac
import json
import mimetypes
import os
import re
import secrets
import shutil
import subprocess
import tempfile
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

try:
    import yaml  # PyYAML, requerido para serializar/parsear engagements
except ImportError:
    yaml = None  # type: ignore[assignment]

SCRIPT_DIR = Path(__file__).resolve().parent
# Plantillas de reporte (estilo Hackmetrix por tipo de vuln) + su índice para el
# clasificador del botón "¿Cómo reportarla?". Viajan en el bundle (sync).
TEMPLATES_DIR = SCRIPT_DIR.parent / "templates"
# Reporte completo estilo Hackmetrix/OffSec: plantilla del informe end-to-end +
# plantillas por tipo de vuln + assets de marca (portada, logo, CSS). Tab "Reporte".
REPORT_TEMPLATES_DIR = SCRIPT_DIR.parent / "report_templates"
REPORT_ASSETS_DIR = SCRIPT_DIR.parent / "report_assets"
WIK3_ROOT = Path(os.environ.get("WIK3_ROOT", "wik3"))
# Staging de engagements parkeados por el aislamiento (engagement-isolation.sh):
# mientras un engagement corre, los demás se mueven aquí, FUERA de WIK3_ROOT, para
# que no entren en el bind-mount /workspace del container. El dashboard corre en el
# host, así que para mostrarlos hay que leerlos también desde acá.
PARK_DIR = Path(os.environ.get("WIK3_PARK_DIR", "/var/lib/wik3-parked"))
ENGAGEMENTS_DIR = Path(
    os.environ.get(
        "WIK3_ENGAGEMENTS_DIR",
        str(WIK3_ROOT.parent / "engagements"),
    )
)
EXAMPLE_YAML_PATH = Path(
    os.environ.get(
        "WIK3_EXAMPLE_YAML",
        str(SCRIPT_DIR.parent / "engagement.example.yaml"),
    )
)
FABRO_SERVER = os.environ.get("FABRO_SERVER", "http://127.0.0.1:8787")
TOKEN_PATH = Path.home() / ".fabro" / "dev-token"

# ─── Modo VM ────────────────────────────────────────────────────────────────
# Si WIK3_DASHBOARD_PASSWORD está seteada, todo request requiere basic auth y
# se exponen los endpoints de CRUD/run/stop.
BOX_PASSWORD = os.environ.get("WIK3_DASHBOARD_PASSWORD", "").strip() or None
BOX_HACKER_EMAIL = os.environ.get("WIK3_HACKER_EMAIL", "").strip() or None
BOX_INSTANCE_NAME = os.environ.get("WIK3_INSTANCE_NAME", "").strip() or None

# Tab "Reporte": detrás de flag. Habilitado por WIK3_REPORT_TAB=1.
# REPORT_TAB_EMAILS queda vacío; no hay allowlist de cuentas por defecto.
REPORT_TAB_EMAILS: set[str] = set()


def _report_tab_enabled() -> bool:
    if os.environ.get("WIK3_REPORT_TAB", "").strip().lower() in ("1", "true", "yes", "on"):
        return True
    return (BOX_HACKER_EMAIL or "").strip().lower() in REPORT_TAB_EMAILS
BOX_INSTANCE_ZONE = os.environ.get("WIK3_INSTANCE_ZONE", "").strip() or None
BOX_PROJECT_ID = os.environ.get("WIK3_PROJECT_ID", "").strip() or None

# ─── Admin API (PR B) ───────────────────────────────────────────────────────
# Token bearer para /admin/*. La instancia admin (admin, PR C) lo genera y lo
# inyecta como metadata GCP `admin-token` al crear cada wik3. startup.sh lo
# graba en /etc/wik3/admin-token y este módulo lo carga al import.
# Override por env var solo para dev-local.
_ADMIN_TOKEN_PATH = Path(os.environ.get("WIK3_ADMIN_TOKEN_PATH") or "/etc/wik3/admin-token")
ADMIN_TOKEN = (os.environ.get("WIK3_ADMIN_TOKEN") or "").strip()
if not ADMIN_TOKEN and _ADMIN_TOKEN_PATH.is_file():
    try:
        ADMIN_TOKEN = _ADMIN_TOKEN_PATH.read_text().strip()
    except Exception:
        ADMIN_TOKEN = ""

# ─── LLM (engagement gen) ──────────────────────────────────────────────────
LLM_MODEL = os.environ.get("WIK3_DASHBOARD_LLM_MODEL", "claude-sonnet-4-6")
LLM_MAX_TOKENS = int(os.environ.get("WIK3_DASHBOARD_LLM_MAX_TOKENS", "8000"))
FEW_SHOT_COUNT = 3
TTL_DAYS = int(os.environ.get("WIK3_ENGAGEMENT_TTL_DAYS", "60"))

# El sidecar de metadata vive en `<engagements>/.meta/<slug>.json`.
META_DIR_NAME = ".meta"

SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,40}$")


# ════════════════════════════════════════════════════════════════════════════
# Persistencia de engagements
# ════════════════════════════════════════════════════════════════════════════

def _meta_dir() -> Path:
    return ENGAGEMENTS_DIR / META_DIR_NAME


def _engagement_path(slug: str) -> Path:
    return ENGAGEMENTS_DIR / f"engagement.{slug}.yaml"


def _meta_path(slug: str) -> Path:
    return _meta_dir() / f"{slug}.json"


def _read_meta(slug: str) -> dict:
    p = _meta_path(slug)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except Exception:
        return {}


def _write_meta(slug: str, meta: dict) -> None:
    _meta_dir().mkdir(parents=True, exist_ok=True)
    _meta_path(slug).write_text(json.dumps(meta, indent=2, sort_keys=True))


def _list_slugs() -> list[str]:
    if not ENGAGEMENTS_DIR.is_dir():
        return []
    out = []
    for p in sorted(ENGAGEMENTS_DIR.glob("engagement.*.yaml")):
        slug = p.stem.removeprefix("engagement.")
        if SLUG_RE.match(slug):
            out.append(slug)
    return out


def _now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_yaml_safe(text: str) -> dict | None:
    if yaml is None:
        return None
    try:
        data = yaml.safe_load(text)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _dump_yaml(data: dict) -> str:
    if yaml is None:
        raise RuntimeError("PyYAML no está instalado")
    return yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=100)


def _validate_engagement(parsed: dict) -> list[str]:
    """Valida campos mínimos requeridos. Devuelve lista de errores
    (vacía si todo OK).

    Reglas:
    - mode ∈ {pasivo, activo}
    - scope es dict
    - al menos uno de scope.{domains,ips,urls} es lista no vacía
    - scope.{domains,ips,urls,out_of_scope} (si están) son listas de strings
    - rules_of_engagement (si está) es dict; max_rps si está es int 1-100;
      forbidden_techniques si está es lista de strings
    - credentials no se valida (es muy variable según schema)
    """
    errs: list[str] = []
    if not isinstance(parsed, dict):
        return ["la config raíz no es un dict YAML válido"]

    mode = parsed.get("mode")
    if mode not in ("pasivo", "activo"):
        errs.append(f"`mode` debe ser 'pasivo' o 'activo' (es {mode!r})")

    types = parsed.get("types")
    if types is not None:
        if not isinstance(types, list) or not types:
            errs.append("`types` debe ser una lista no vacía")
        else:
            valid_types = ("blackbox", "webapp", "mobile", "internal", "cloud")
            for t in types:
                if not isinstance(t, str):
                    errs.append("`types` debe contener solo strings")
                    break
                if t not in valid_types:
                    errs.append(f"`types` contiene valor inválido {t!r}; permitidos: {list(valid_types)}")

    scope = parsed.get("scope")
    if not isinstance(scope, dict):
        errs.append("`scope` debe existir y ser un objeto")
    else:
        # Engagement vacio (sin targets) es VALIDO al crear — se usa cuando se
        # importa un reporte que va a llenar el scope despues. El boton "Run"
        # del dashboard sigue bloqueando arranque sin scope (ver _handle_run).
        for key in ("domains", "ips", "urls"):
            v = scope.get(key)
            if v is None:
                continue
            if not isinstance(v, list):
                errs.append(f"`scope.{key}` debe ser una lista")
                continue
            if any(not isinstance(x, str) for x in v):
                errs.append(f"`scope.{key}` debe contener solo strings")
        oos = scope.get("out_of_scope")
        if oos is not None:
            if not isinstance(oos, list):
                errs.append("`scope.out_of_scope` debe ser una lista")
            elif any(not isinstance(x, str) for x in oos):
                errs.append("`scope.out_of_scope` debe contener solo strings")

    roe = parsed.get("rules_of_engagement")
    if roe is not None:
        if not isinstance(roe, dict):
            errs.append("`rules_of_engagement` debe ser un objeto")
        else:
            if "max_rps" in roe:
                rps = roe["max_rps"]
                if not isinstance(rps, int) or isinstance(rps, bool) or rps < 1 or rps > 100:
                    errs.append("`rules_of_engagement.max_rps` debe ser un entero entre 1 y 100")
            if "forbidden_techniques" in roe:
                ft = roe["forbidden_techniques"]
                if not isinstance(ft, list) or any(not isinstance(x, str) for x in ft):
                    errs.append("`rules_of_engagement.forbidden_techniques` debe ser una lista de strings")
            if "notify_on_critical" in roe and not isinstance(roe["notify_on_critical"], bool):
                errs.append("`rules_of_engagement.notify_on_critical` debe ser true o false")

    safety = parsed.get("safety")
    if safety is not None:
        if not isinstance(safety, dict):
            errs.append("`safety` debe ser un objeto")
        else:
            ro = safety.get("read_only_mode")
            if ro is not None and not isinstance(ro, bool):
                errs.append("`safety.read_only_mode` debe ser true o false")
    return errs


def _is_read_only(parsed: dict) -> bool:
    s = parsed.get("safety") if isinstance(parsed, dict) else None
    return bool(isinstance(s, dict) and s.get("read_only_mode") is True)


# ════════════════════════════════════════════════════════════════════════════
# LLM: texto → engagement YAML
# ════════════════════════════════════════════════════════════════════════════

LLM_SYSTEM_PROMPT = """Eres un generador de engagement YAMLs para wik3 (agente autónomo de pentesting).

Recibes una descripción del cliente/sistema a pentestar y produces un YAML estructurado.

Convenciones:
- mode=activo salvo que el cliente pida solo recon/OSINT.
- max_rps: 5 si producción/sin autoscaling/con WAF; 10-15 si staging.
- Si hay datos financieros, fiscales, médicos o pagos: agrega notify_on_critical=true y
  considera forbidden_techniques con destructive_payloads.
- Si hay APIs de terceros declaradas: agrégalas a out_of_scope.
- safety.read_only_mode=true ES EL DEFAULT (siempre incluye esta línea en el
  YAML). Solo seteá false si el operador autoriza explícitamente pruebas
  destructivas (frases inequívocas como "puede romper datos", "test env,
  destructivo OK", "borra lo que necesites", "autorizado a destruir
  registros"). Bajo read_only=true, el agente y el scope_guard bloquean
  payloads SQL DML/DDL (INSERT/UPDATE/DELETE/DROP/TRUNCATE/...), HTTP
  destructivo (PUT/PATCH/DELETE/upload) y comandos shell destructivos
  (rm/mv/dd/etc). Para probar flujos CRUD bajo read_only=true, el agente
  crea registros NUEVOS (POST) y los documenta en notes.jsonl para limpieza
  posterior — nunca toca registros pre-existentes.
- operational_guidance.forbidden_endpoints_patterns: lista de regex
  contra el path de la URL. SIEMPRE incluir patterns para endpoints
  inferidos como peligrosos según el contexto:
    · si hay pagos/checkout/billing → ^/(payment|checkout|invoice|billing)
    · si hay autorización OAuth/SSO → ^/oauth/(authorize|token|callback)
    · si hay APIs de terceros → patterns de sus callbacks
    · cuentas reales o producción → ^/(admin|account)/(delete|destroy|deactivate)
    · cualquier endpoint que mencione el operador como "no romper"
  El scope_guard.sh enforza estas patterns como hard block (defense-in-depth).
- operational_guidance.user_agent: SIEMPRE setearlo a un UA realista de
  browser actual (ej. "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)
  AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36").
  El default de curl/python/etc delata scraper y muchos WAFs lo bloquean.
- Comentarios en español neutro (tú/tienes, NO voseo) explicando: solicitante,
  ambiente, peculiaridades del target, decisiones tomadas.
- El slug es kebab-case derivado del nombre del cliente o producto.
- `types`: lista de tipos de engagement. Detecta del contexto:
  * `blackbox`: pentest de superficie AMPLIA sobre un dominio — el alcance
    incluye descubrir subdominios, hosts, servicios y toda la superficie
    expuesta (no está encajonado a una sola app). Marcar si menciona
    "blackbox", "caja negra", "subdominios", "superficie externa", "recon del
    dominio", o dan solo el dominio raíz para que se enumere todo.
  * `webapp`: encajonado a UNA aplicación web específica — APIs HTTP/REST,
    GraphQL, SPAs DENTRO de esa app. NO se sale a enumerar subdominios/otros
    hosts. Default cuando dan una app/URL concreta y acotada.
  * `mobile`: apps Android (APK) o iOS (IPA). Marcar si menciona "app móvil",
    "APK", "IPA", "Play Store", "App Store", o nombres de apps mobile.
  * `internal`: red interna corporativa, Active Directory, SMB/Kerberos,
    lateral movement, escalada en LAN. Marcar si menciona VPN, RDP interno,
    .local, "red interna", "dominio AD", "BloodHound".
  * `cloud`: AWS/GCP/Azure infrastructure, IAM, S3 buckets, K8s. Marcar si
    menciona "cuenta AWS/GCP/Azure", "IAM", "S3", "Lambda", "Cloud Functions",
    keys provistas (AKIA*, GOOG*).
  Lista de strings. Si es mezcla (común: webapp + cloud cuando hay app +
  cuenta AWS), incluye todos los que apliquen. Si el operador pasó un hint
  con tipos preseleccionados, respétalo — combínalo si detectas más.
- scope: usa EXACTAMENTE los dominios/IPs/URLs que dio el operador. NUNCA
  inventes placeholders (`example.com`, `target.com`, `admin-target.*`, etc.):
  un YAML con dominios inventados se ve válido pero corre contra hosts
  inexistentes y el engagement "no funciona". Si el operador NO dio targets
  concretos, deja `scope.domains` VACÍO y agrega un comentario `# FALTA:
  dominios/URLs reales del target` para que se note (el botón Run igual bloquea
  scope vacío). Nunca inventes valores de relleno.
- credentials: si el operador dio credenciales, encódalas SIEMPRE como YAML
  estructurado, NUNCA en comentarios ni con placeholders (REDACTED/CHANGEME):
    · cuenta principal webapp → `credentials.webapp: {login_url, user, pass}`.
    · cuentas adicionales (multi-rol/multi-tenant, necesarias para tests de
      autorización horizontal/vertical) → `additional_credentials: [{id, type:
      webapp, login_url, user, pass, role}]`, UNA entrada por cuenta (el agente
      las carga al vault). Si hay 2+ cuentas y solo encodeas una, el agente no
      puede probar authz cross-cuenta. No uses `extra_accounts` ni un
      `api.bearer: ""` vacío como relleno.

Responde SIEMPRE con JSON estricto, sin code fences ni texto fuera del JSON,
con esta forma exacta:
{
  "slug": "kebab-case",
  "yaml": "contenido completo del yaml como string",
  "summary": "1-2 frases sobre qué generaste y decisiones clave (en español)"
}
"""


def _few_shot_paths() -> list[Path]:
    """Hasta FEW_SHOT_COUNT engagements existentes (los más recientes), como
    contexto few-shot para el LLM. Si no hay, devuelve []."""
    if not ENGAGEMENTS_DIR.is_dir():
        return []
    candidates = sorted(
        ENGAGEMENTS_DIR.glob("engagement.*.yaml"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return candidates[:FEW_SHOT_COUNT]


def _build_llm_user_message(prompt: str, prior_yaml: str | None, types_hint: list[str] | None = None) -> str:
    parts: list[str] = []
    if EXAMPLE_YAML_PATH.is_file():
        parts += [
            "ESQUEMA DE REFERENCIA (engagement.example.yaml):",
            "```yaml",
            EXAMPLE_YAML_PATH.read_text(),
            "```",
            "",
        ]
    if types_hint:
        parts += [
            f"HINT DEL OPERADOR — tipos preseleccionados: {types_hint}. "
            "Inclúyelos en `types` del YAML. Puedes agregar más si el texto "
            "los justifica, pero no quites los que el operador eligió.",
            "",
        ]
    for path in _few_shot_paths():
        slug = path.stem.removeprefix("engagement.")
        parts += [
            f"EJEMPLO REAL ({slug}):",
            "```yaml",
            path.read_text(),
            "```",
            "",
        ]
    if prior_yaml:
        parts += [
            "YAML ACTUAL (refinarlo según el feedback):",
            "```yaml",
            prior_yaml,
            "```",
            "",
            "FEEDBACK DEL OPERADOR:",
            prompt,
        ]
    else:
        parts += [
            "DESCRIPCIÓN DEL ENGAGEMENT (del operador):",
            prompt,
        ]
    return "\n".join(parts)


LLM_IMPORT_SYSTEM = """\
Eres un parser de reportes de pentest. Tus tareas:

1. Extraer el SCOPE del proyecto (hosts/IPs/URLs en alcance) — los targets
   que el pentest cubrió.
2. Extraer cada vulnerabilidad del reporte.

IDIOMA: el texto en español que generes (info, etc) debe estar en español
neutro (tú/usas/configuras, imperativos "revisa"/"ejecuta"/"copia"). NO uses
voseo argentino ("vos/tenés/querés", "abrí/mandá/copiá") ni modismos
rioplatenses ("che", "dale", "acá"). EXCEPCIÓN: `title` y `report_id` se copian
VERBATIM del reporte (no los traduzcas ni reescribas). El reporte original
puede estar en cualquier idioma.

OUTPUT — JSONL estricto. Una línea = un objeto JSON válido. NO uses code
fences, NO emitas prose.

PRIMERA LÍNEA (opcional): un objeto `_meta` con el scope extraído.
Si el reporte enumera targets en la sección de scope/alcance, emite:

  {"_meta": {"scope": {"domains": ["foo.com"], "ips": ["1.2.3.4"], "urls": ["https://x.com/path"]}}}

Reglas para el scope:
- Solo hosts/IPs explícitamente declarados como scope/alcance del pentest.
- Sub-dominios anidados: usa solo el dominio raíz (el matcher cubre
  sub-dominios automáticamente). Ej: si el reporte lista "app.foo.com" y
  "api.foo.com" y "foo.com", emite solo `["foo.com"]`.
- Si no puedes determinar scope con confianza, OMITE la línea `_meta`.

LÍNEAS SIGUIENTES: una por vulnerabilidad.

Reglas para vulns:
- Si una vuln aparece como "mitigada", "ya resuelta", "won't fix" o "false positive"
  en el reporte original → IGNORALA (no la incluyas en el output).
- El campo `retest` es código Python que va a ejecutarse para verificar si la vuln
  sigue presente. DEBE:
    * Usar SOLO la stdlib (urllib, json, ssl, http.client, socket, re).
    * Imprimir como ÚLTIMA línea exactamente:
        print(json.dumps({"status": "<estado>", "evidence": "<texto corto>"}))
      donde <estado> ∈ {"vulnerable", "mitigated", "inconclusive"}.
    * NO depender de tiempos (race, sleep > 5s), side channels, ni interacción humana.
      Si no se puede automatizar, emite igualmente un script de 3 líneas que printee
      status="inconclusive" con razón en evidence.
    * NO leer archivos del filesystem ni ejecutar comandos del sistema.

Campos por vuln (todos en una línea JSON):
  title         string — el NOMBRE EXACTO de la vuln tal como aparece en el
                reporte (VERBATIM, no lo reescribas, acortes ni traduzcas).
  report_id     string opcional — el identificador de la vuln en el reporte tal
                cual (ej. "HM-001", "VULN-3", "Finding 4", "5.2"). Cópialo
                verbatim. Si el reporte no le asigna id, déjalo "".
  severity      uno de: critical | high | medium | low | info.
  affected      array de strings (hosts o URLs).
  info          string en markdown: descripción + impacto + referencias.
  reproduction  string en markdown: el PASO A PASO para reproducir la vuln tal
                como lo describe el reporte (endpoints, método, requests, payloads,
                IDs/UUIDs concretos, credenciales/cuenta necesarias, qué se espera
                ver). Cópialo lo más fiel posible del reporte — esto es lo que el
                agente sigue al re-testear. Si el reporte no trae pasos, déjalo "".
  retest        string con el script Python completo (incluye los imports).
  cvss          number opcional (0-10).
  references    array opcional de URLs.
"""


_LLM_CHAT_SYSTEM = """\
Eres el asistente del operador de wik3 — un pentester humano revisando
o trabajando un engagement. Estás disponible SIEMPRE, sin importar si
el agente fabro que corre el workflow está activo o no.

IDIOMA (OBLIGATORIO): responde SIEMPRE en español neutro latinoamericano,
tratando de "tú" (tú tienes, ¿quieres que…?, imperativos "revisa"/"ejecuta"/
"dime"/"cuéntame"). NUNCA uses voseo argentino/rioplatense: prohibido "vos",
"tenés", "querés", "preferís", "referís", "decime", "fijate", "mirá", "dale",
"che", "acá". Aunque el operador te escriba en voseo, tú respondes en tú neutro.

# Tus herramientas

Eres el «agente del proyecto»: tienes acceso de **lectura COMPLETA** a los
archivos del engagement — puedes leer cualquiera, listar carpetas y buscar
(grep) en todo el workspace. Tu valor es **extraer inteligencia** de lo que el
agente produjo (recon, findings, notas, evidencia, exec.log).

Tienes 3 tools (úsalas activamente — no respondas de memoria si la
respuesta depende de archivos del workspace):

## `read_engagement_file(path)`

Lee un archivo del workspace del engagement. `path` es relativo a la
raíz del workspace (ej. `"vulns/V-007-idor-abc/info.md"`,
`"engagement.yaml"`, `"passive/summary.md"`).

- Cap por archivo: 100 KB. Si el archivo es más grande, recibes
  metadata (size + primeras ~2k chars) + un warning, y decides si
  quieres leerlo igual con `force=true`.
- Si el path no existe o está fuera del workspace, recibes un error.
- Para listar contenido de una carpeta, usa path terminado en `/`
  (ej. `"vulns/"` lista los directorios de vulns).

## `grep_engagement(query)`

Busca un texto (substring, case-insensitive) en TODOS los archivos del
workspace y devuelve `archivo:línea` de cada coincidencia. Úsalo cuando
no sabes en qué archivo está algo (un endpoint, host, token, nombre de
vuln) — primero ubicas con grep, luego lees el archivo con
`read_engagement_file`.

## `message_running_agent(message)`

Envía un mensaje al agente fabro que está corriendo el workflow. El
mensaje se entrega vía `convo/inbox.md`; el agente lo lee en su
próximo tool call y responde con `say.sh`.

- Si NO hay agente corriendo, recibes un error claro. En ese caso,
  informas al operador y le sugieres alternativas (arrancar un Run
  con hint, esperar al próximo run, etc).
- Útil cuando el operador escribe algo dirigido al agente activo
  (ej. *"dile al agente que pruebe el endpoint /admin"*).

# Layout del workspace típico

Conócelo y elige qué leer según la pregunta. Tamaños orientativos:

| Path | Contenido | Tamaño |
|------|-----------|--------|
| `engagement.yaml` | Config del run (scope, mode, types, ROE, creds hint) | ~2KB |
| `passive/summary.md` | Narrativa del análisis pasivo | 5-20KB |
| `active/summary.md` | Narrativa del análisis activo (probing real) | 5-20KB |
| `validated/summary.md` | Chains validadas con PoC | 2-10KB |
| `validated/chains.json` | Attack chains compuestas en JSON | 1-5KB |
| `senior_review/log.md` | Decisiones del senior review (verdict por iter) | 5-50KB |
| `vulns/V-NNN-slug/meta.json` | Severity, phase, status, affected | ~1KB |
| `vulns/V-NNN-slug/info.md` | Descripción completa | 3-8KB |
| `vulns/V-NNN-slug/exploit.md` | Playbook de explotación (opcional) | 5-10KB |
| `vulns/V-NNN-slug/retest.py` | Retest determinístico (opcional) | 1-5KB |
| `vulns/V-NNN-slug/reproduction.md` | Paso a paso manual (opcional) | 3-8KB |
| `notes.jsonl` | Observaciones no-vuln (jsonl, 1/línea) | 1-50KB |
| `recon/assets.json` | Hosts, subdomains, endpoints | 5-30KB |
| `discovery/queue.jsonl` | Items descubiertos pendientes/consumidos | 1-50KB |
| `creds/vault.jsonl` | Credentials acumuladas (los `value` están redactados) | 1-10KB |
| **`exec.log`** | Shell del agente | **PUEDE SER >50MB** |

# Heurísticas de uso

- Pregunta tipo *"qué hace V-007"* → primero lista `vulns/` con
  `read_engagement_file("vulns/")` para encontrar el slug, después lee
  `vulns/V-007-<slug>/info.md`.
- Pregunta tipo *"resumime los findings"* o *"qué se hizo en activo"* →
  lee los `summary.md` de las fases relevantes. NO leas cada `info.md`
  individual (saturaría el contexto sin necesidad).
- Pregunta tipo *"qué endpoints exploró el agente"* → `recon/assets.json`
  + `discovery/queue.jsonl`.
- Pregunta tipo *"qué creds se encontraron"* → `creds/vault.jsonl`
  (los `value` están redactados por seguridad).
- Pregunta tipo *"por qué V-NNN quedó probable"* → `vulns/V-NNN.../info.md`
  + `senior_review/log.md` para ver el verdict.
- **NO leas `exec.log`** salvo que la pregunta requiera ver acciones
  concretas del shell que no están en `summary.md`. Si lo lees, avisa
  al operador y pide acotación temporal (ej. "los últimos 50KB").
- NO leas archivos especulativamente. Si la pregunta es vaga, pídele al
  operador que acote antes.

# Cuándo usar message_running_agent

- Cuando el operador escribe algo dirigido al agente activo. Le pasas
  el texto literal o levemente reformulado.
- Tras enviar exitosamente, confirma al operador con "✓ entregado al
  inbox del agente" (o el msg que devuelva la tool).
- Si la tool retorna error (no hay agente corriendo), explícaselo al
  operador y sugiere: arrancar un Run con hint si quiere que el
  mensaje se procese al inicio del próximo run.

# Estilo

- Respuestas concisas. Bullets cuando son varias cosas. Bloques de
  código con backticks si citas paths o comandos.
- NO saludos largos ni cierres formales. Va al grano.
- Cita IDs concretos (V-007, C-001, ...) cuando hablas de findings.
- Si no encuentras algo en los archivos leídos, dilo explícito en
  lugar de inventar. No alucines vulns que no existen en el workspace.
"""


_LLM_VULN_FROM_DESC_SYSTEM = """\
Eres un asistente de un pentester. Recibes una descripción libre escrita por
el operador sobre UNA vulnerabilidad que encontró manualmente. Tu trabajo es
estructurarla en JSON con los campos que el sistema espera.

IDIOMA: cualquier texto en español que generes (title, info, etc) debe estar
en español neutro (tú/usas/configuras, imperativos "revisa"/"ejecuta"/
"copia"). NO uses voseo argentino ("vos/tenés/querés", "abrí/mandá/copiá")
ni modismos rioplatenses ("che", "dale", "acá").

OUTPUT — un único objeto JSON estricto, sin code fences ni texto fuera, con
estos campos:

  title         string corto (≤80 chars), descriptivo.
  severity      uno de: critical | high | medium | low | info.
  phase         uno de: passive | active | validated. Default "active" si
                el operador describe un exploit ejecutado; "passive" si solo
                observó algo sospechoso sin probar; "validated" si menciona
                que ya validó/confirmó.
  confidence    uno de: confirmed | probable | likely | unlikely.
                "confirmed" si describe PoC end-to-end; "probable" si parcial
                (señal sólida sin impacto demostrado); "likely" si solo
                hipótesis sin probar; "unlikely" si dudas.
  affected      array de strings (hosts, URLs, endpoints, paths). Si el
                operador no especifica, deja [] y el operador completa.
  info          string markdown con TODAS estas secciones (omitir solo si
                genuinamente no aplica):
                ## Descripción
                ## Impacto
                ## Precondiciones
                ## Reproducción
                ## Evidencia
                ## Referencias
                Si el operador no menciona algo (ej: referencias), genera
                la sección con un placeholder corto tipo "—" en lugar de
                inventar.
  cvss          number opcional (0-10) si puede estimarse del contexto.
  references    array opcional de URLs.

REGLAS:
- NO inventes datos del target (hostnames, IPs, paths) que el operador no
  haya mencionado.
- NO generes PoCs ni código ejecutable en `info` — la sección Reproducción
  describe pasos en texto, no es retest.py.
- Si la descripción es muy vaga (1-2 frases sin detalle), devuelve igual el
  JSON con campos placeholder y `confidence="unlikely"` para que el
  operador edite antes de guardar.
- El operador puede editar todo después, tu output es un BORRADOR, no la
  versión final.
"""


_LLM_RETEST_SYSTEM = """Eres un experto en pentesting. Te paso los metadatos y descripción de una vulnerabilidad ya descubierta. Genera un script `retest.py` determinístico que verifique si la vuln SIGUE presente.

IDIOMA: los comentarios del código y cualquier `evidence` string deben estar en español neutro (tú/usas/configuras, imperativos "revisa"/"ejecuta"/"verifica"). NO uses voseo argentino ("vos/tenés/querés", "verificá"/"comprobá") ni modismos rioplatenses ("che", "dale", "acá").

CÓMO USAR EL CONTEXTO:
El `info.md` debería tener secciones estándar (## Descripción, ## Impacto, ## Precondiciones, ## Reproducción, ## Evidencia, ## Referencias, ## Links internos). Usalas:
- `## Reproducción` te da los pasos exactos — el retest tiene que ejecutar esos mismos pasos.
- `## Precondiciones` te dice qué creds/contexto necesita.
- `## Evidencia` te dice qué buscar en el response para confirmar (string específico, status code, header, etc.).
Si alguna sección falta, haz el mejor esfuerzo con lo que hay, pero NO inventes pasos que no están sustentados.

VALIDACIÓN PRECISA (lo más importante):
El retest tiene que validar LA MISMA vulnerabilidad, no algo parecido. Reproduce el exploit EXACTO de `## Reproducción` con los MISMOS identificadores y payloads reales que la demostraron (mismo endpoint, método, params, IDs concretos, header/token). NUNCA uses valores sintéticos / aleatorios / inexistentes (un uuid4 al azar, un ID adivinado, un recurso que no existe) como prueba — un 404 sobre un recurso inexistente NO prueba nada.

Semántica ESTRICTA del status (no la relajes):
- "vulnerable": el exploit exacto SIGUE funcionando — está presente la señal de éxito de `## Evidencia` (p. ej. lees el dato de la víctima, 200 con el recurso cross-tenant, el string/condición que confirmó el bug originalmente).
- "mitigated": SOLO si el servidor ahora BLOQUEA activamente el MISMO request que antes tuvo éxito POR LA LÓGICA DE AUTORIZACIÓN (p. ej. el request que devolvía 200 con datos ahora responde 401/403 con un mensaje de ownership/tenant, o el control de acceso lo rechaza explícitamente). Un 404 genérico, una respuesta vacía, un "not found", "sin datos", o que el recurso ya no exista NO es "mitigated". CUIDADO con los 403 de WAF: un 403 puede venir del WAF/anti-bot (por User-Agent de Python, headers faltantes, o rate-limit) y NO de la autorización — eso NO es "mitigated", es "inconclusive". Antes de concluir "mitigated" por un 403/401, asegúrate de mandar User-Agent de navegador y los mismos headers del exploit original; si el bloqueo podría ser del WAF, devuelve "inconclusive".
- "inconclusive": si no puedes correr una prueba fiel — falta un ID de víctima real, faltan creds o contexto, la respuesta es ambigua, o el recurso de la reproducción ya no existe. Ante la duda, "inconclusive". La AUSENCIA de la señal de la vuln NO es evidencia de mitigación.

IDOR / BOLA / cross-tenant / authz: debes apuntar a un recurso REAL de OTRO tenant o usuario (un ID concreto que esté en `## Reproducción` / `## Evidencia`) y comprobar si la cuenta actual lo puede leer/operar (acceso = vulnerable; rechazo POR AUTORIZACIÓN con 401/403 = mitigated). OJO: un 401/403 solo cuenta como "mitigated" si viene de la lógica de authz (mensaje de ownership/tenant), NO si podría ser del WAF (User-Agent de Python, headers faltantes, rate-limit) — manda User-Agent de navegador y mismos headers del exploit; si el 403 podría ser del WAF, devuelve "inconclusive". Si no hay un ID de víctima real en el contexto, léelo de una env var (p. ej. `WIK3_VICTIM_ID`) y, si no está seteada, devuelve "inconclusive" con una evidencia que diga exactamente qué ID real hace falta — NO inventes uno ni uses uno aleatorio.

`evidence` debe citar el request exacto y la señal concreta (status + qué se vio) que sustenta el veredicto.

PROHIBIDO ABSOLUTAMENTE EN EL RETEST:
El retest puede correrse automáticamente N veces contra producción. Nunca debe causar daño ni levantar alarmas. Si la única manera de verificar la vuln es haciendo algo de esta lista, NO LO HAGAS — emitas un retest "safe-stub" (ver sección "AUTORUN" abajo).
- SQL DML/DDL: INSERT, UPDATE, DELETE, DROP, TRUNCATE, ALTER, CREATE, GRANT, REVOKE.
- HTTP destructivo: PUT, PATCH, DELETE; uploads (multipart con file que el servidor procesa).
- POST con efectos: pagos, emisión de facturas, envío de emails/SMS, registro masivo, mutations GraphQL que escriben.
- Brute force / credential stuffing: nunca enviar > 5 requests al mismo endpoint con creds distintas.
- Fuzzing / escaneo agresivo: nada que parezca scanner (ej. > 20 paths probados en 10s).
- Exfiltración: si la vuln expone datos sensibles (PII, dumps de DB), NO descargues el contenido completo — leé solo lo mínimo para confirmar el bug (count, primer registro, header de schema).
- DoS / rate-limit drain: no inundes el endpoint, no busques timeouts del server.

REQUISITOS DEL SCRIPT (cuando ES seguro):
- Python 3, SOLO stdlib (urllib, json, ssl, http.client, socket, re, os, sys, base64). NO usar requests ni libs externas.
- HEADERS REALISTAS (crítico): manda SIEMPRE un User-Agent de navegador real en CADA request HTTP. Por defecto urllib manda "Python-urllib/3.x", que MUCHOS WAF bloquean con 403 — y entonces el retest cree falsamente que la vuln está "mitigated". Usa el MISMO User-Agent y los mismos headers (Accept, Content-Type, Origin/Referer si aplica) que usó el exploit/navegador original. Un User-Agent seguro por defecto: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36". El request del retest debe ser INDISTINGUIBLE del que funcionó en la reproducción.
- Timeouts cortos (≤ 10s por request). Máximo 5 requests totales por script.
- Imprimir como ÚLTIMA línea exactamente:
    print(json.dumps({"status": "<estado>", "evidence": "<texto corto>"}))
  donde <estado> ∈ {"vulnerable", "mitigated", "inconclusive"}.
- Si la vuln requiere creds o un ID de recurso víctima: leer de env vars (WIK3_USER, WIK3_PASS, WIK3_TOKEN, WIK3_VICTIM_ID y similares WIK3_VICTIM_*) — NO hardcodear. Si una env var necesaria no está, devuelve "inconclusive" diciendo cuál falta.
- NO leer archivos del filesystem ni correr comandos del sistema.
- Comentar cada bloque indicando qué del `info.md` lo justifica.

AUTORUN — flag obligatorio en la PRIMERA LÍNEA:
La PRIMERA LÍNEA del script (antes del shebang/imports) DEBE ser uno de estos dos marcadores literales:

  # WIK3_AUTORUN: true

cuando el script es seguro (cumple todos los requisitos arriba y no toca nada de la lista prohibida). El runner lo ejecuta automáticamente.

  # WIK3_AUTORUN: false

cuando NO se puede verificar la vuln sin alguna acción prohibida o ruidosa. En ese caso emitas un "safe-stub": script de 3-5 líneas que printea status="inconclusive" con razón clara, ej:
  # WIK3_AUTORUN: false
  import json
  print(json.dumps({"status": "inconclusive", "evidence": "Requiere POST destructivo a /api/payments para verificar — no automatizable"}))

Mejor un retest manual obvio que uno automático que rompe producción.

OUTPUT: SOLO el código Python, sin ```python fences, sin texto previo ni posterior. La primera línea SIEMPRE es el marcador WIK3_AUTORUN."""

_LLM_EXPLOIT_SYSTEM = """Eres un experto en pentesting documentando exploits. Te paso los metadatos y descripción de una vulnerabilidad. Genera `exploit.md` — un playbook de cómo se explota end-to-end.

IDIOMA: todo el markdown que generes debe estar en español neutro (tú/usas/configuras, imperativos "revisa"/"ejecuta"/"verifica"). NO uses voseo argentino ("vos/tenés/querés", "ejecutá"/"corré"/"verificá"/"comprobá") ni modismos rioplatenses ("che", "dale", "acá").

CÓMO USAR EL CONTEXTO:
El `info.md` debería tener secciones (## Descripción, ## Impacto, ## Precondiciones, ## Reproducción, ## Evidencia, ## Referencias). Tu trabajo NO es duplicar info.md — es ESCALAR la información a un playbook accionable que un pentester pueda seguir paso a paso. Toma la reproducción de info.md y conviértela en exploit secuencial con comandos exactos. Si info.md está incompleto, haz el mejor esfuerzo con lo que hay y marca explícitamente qué tendría que verificar el operador antes de correr.

ESTRUCTURA (markdown):
## Resumen
1-2 líneas describiendo el vector (qué tipo de bug, dónde, qué consigue).

## Precondiciones
Qué necesita el atacante: creds (ID del vault si está en info.md), posición de red, knowledge previo. Si info.md dice "unauth", marcarlo claramente.

## Paso a paso
Comandos/requests EXACTOS, numerados. Que un pentester pueda copy-paste sin pensar.
1. `comando concreto con placeholders claros`
2. `comando concreto`
...

## Payload
Bloques de código con los payloads concretos (curls, SQL injections, JS, headers raw). Si hay variantes (GET vs POST, JSON vs form), incluye las relevantes.

## Impacto
Lo que consigue el atacante al final del flow. Sé específico con datos: "lee N rows de tabla X", "ejecuta comando arbitrario como usuario Y".

## Mitigación sugerida
Cómo se arregla del lado del cliente (no del lado del pentester). Cita controles concretos (parámetro X, header Y, parche Z).

OUTPUT: SOLO el markdown, sin ```markdown fences, sin texto previo ni posterior. Sé conciso y concreto — comandos curl/HTTP reales, no descripciones vagas. Si info.md no soporta un paso (ej: pide creds pero no menciona cuáles), marcalo con `[VERIFICAR: ...]` en el playbook."""


_LLM_REPRODUCTION_SYSTEM = """Eres un pentester senior ayudando a un hacker a armar el PASO A PASO de una vulnerabilidad para incluirlo en el reporte al cliente. El hacker te pide literalmente: "necesito que me ayudes con el paso a paso. Dame los comandos exactos para agregar al reporte, qué capturas sacar y qué poner antes de cada captura para que sea claro."

IDIOMA: español neutro (tú/usas/configuras, imperativos "abre"/"ejecuta"/"copia"/"verifica"). NUNCA uses voseo argentino ("abrí/ejecutá/sacá/verificá") ni modismos rioplatenses ("che", "dale", "acá").

Tu salida es un documento en markdown, listo para pegar en el reporte. Cada paso DEBE tener tres cosas:
1. **Texto antes de la captura**: 1-2 frases en tono de reporte que el hacker pone JUSTO ANTES de la captura, para que quede claro qué se hace y qué demuestra.
2. **El comando o request EXACTO** en bloque de código (curl / HTTP / acción de UI), con los valores CONCRETOS del hallazgo (endpoint, método, headers, IDs/UUIDs/tokens reales tomados de la evidencia). Copy-paste, completos, con User-Agent de navegador si aplica. Nada de placeholders si la evidencia tiene el valor real.
3. **Qué captura sacar**: indica exactamente la captura de pantalla a tomar en ese paso (qué ventana / respuesta / campo debe verse para que sea evidencia clara).

ESTRUCTURA (markdown):
## Requisitos
Lo necesario antes de empezar (cuenta/credenciales por rol —no pegues secretos—, herramienta, acceso de red).

## Pasos
Para cada paso usa EXACTAMENTE este formato:
### Paso N — <acción corta>
<1-2 frases para el reporte que van antes de la captura>
```
<comando o request exacto, o la acción de UI a realizar>
```
📸 **Captura:** <qué debe verse en la captura>

## Resultado esperado
1-3 líneas: qué demuestra en conjunto el paso a paso (el impacto real del hallazgo).

REGLAS:
- Usa los datos REALES de la evidencia / info.md / reproducción previa / casos (endpoints, IDs, tokens, status codes, response). Si falta un dato, márcalo como `[VERIFICAR: ...]` — NO lo inventes.
- Los comandos deben ser copy-paste y reproducir el hallazgo tal cual.
- NO incluyas remediación ni teoría del root cause (eso va en otra sección del reporte).
- Sé conciso y accionable; cada paso aporta a demostrar el hallazgo.

OUTPUT: SOLO el markdown, sin ```markdown fences alrededor, sin texto previo ni posterior."""


# ── "¿Cómo reportarla?" — clasificador de template + generador de reporte ─────
def _load_templates_index() -> list:
    """Lee templates/index.json (archivo + tipo de vuln + descripción + keywords)."""
    try:
        data = json.loads((TEMPLATES_DIR / "index.json").read_text())
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _load_report_type_index() -> list:
    """Construye el índice de las plantillas por-tipo de reportes_offsec
    (report_templates/<categoria>/*.md), reemplazando a las 51 viejas de
    templates/. Cada entrada: file (relativo a report_templates/), vuln_type
    (1er heading del .md), description (categoría) y keywords (del nombre)."""
    out: list = []
    try:
        paths = sorted(REPORT_TEMPLATES_DIR.glob("*/*.md"))
    except Exception:
        return out
    for p in paths:
        try:
            txt = p.read_text()
        except Exception:
            continue
        title = ""
        for line in txt.splitlines():
            s = line.strip()
            if s.startswith("#"):
                title = s.lstrip("#").strip()
                break
        stem = p.stem.lower()
        kws = [k for k in re.split(r"[-_]", stem) if len(k) >= 3]
        cat = re.sub(r"^\d+-", "", p.parent.name).replace("-", " ")
        out.append({
            "file": f"{p.parent.name}/{p.name}",
            "vuln_type": title or p.stem,
            "description": cat,
            "keywords": kws,
        })
    return out


_LLM_REPORT_CLASSIFY_SYSTEM = """Eres un clasificador. Te doy una vulnerabilidad detectada (título, severidad, afectados, descripción, info) y una LISTA de plantillas de reporte disponibles (cada una con su `file`, tipo de vuln, descripción y keywords). Elige la plantilla cuyo TIPO de vulnerabilidad MÁS se parece a la vuln detectada, para usarla como ejemplo de cómo reportarla.

Devuelve SOLO un objeto JSON (sin ```fences):
{"file": "<archivo.md elegido>", "match": true, "reason": "<1 línea>"}

Reglas:
- "file" debe ser EXACTAMENTE uno de los `file` de la lista, o "" si NINGUNA plantilla corresponde razonablemente.
- Compara por TIPO de debilidad (IDOR, XSS, SSRF, misconfig de cloud, CSRF, etc.), NO por el target ni el cliente.
- match=true SOLO si hay correspondencia real de tipo. Si dudas o no calza ninguna, devuelve file="" y match=false (se usará una plantilla general)."""


_LLM_REPORT_HOWTO_SYSTEM = """Eres un pentester senior de Hackmetrix. Te doy (1) el contexto REAL de una vulnerabilidad detectada y (2) una PLANTILLA de ejemplo del estilo Hackmetrix para este tipo de vuln. Tu ÚNICA tarea es redactar la PoC (prueba de concepto) de ESTA vuln: el paso a paso EXACTO y reproducible que demuestra que es real.

IDIOMA: español neutro (tú/usas, imperativos "revisa"/"ejecuta"/"verifica"). NUNCA voseo ("revisá/ejecutá/verificá") ni modismos rioplatenses ("che", "dale", "acá").

Genera SOLO la PoC en markdown, empezando por el encabezado `## PoC`, con una lista numerada de pasos. Cada paso DEBE incluir:
  1. una frase de qué se hace y qué demuestra,
  2. el **comando o request EXACTO para reproducirla** en bloque de código (curl / HTTP / acción de UI), copy-paste, con los valores CONCRETOS de la evidencia (endpoint, método, headers, IDs/UUIDs/tokens reales, User-Agent de navegador si aplica) y la **salida verbatim COMPLETA** que confirma el bug (header/body/status tal cual salió, en una sola línea si hace falta) — NUNCA la abrevies con `...` ni la parafrasees,
  3. qué captura sacar: `!§ INSERTAR IMAGEN (qué debe verse) §!`.

Reglas:
- Usa la PLANTILLA SOLO como guía del estilo/tono de la reproducción. NO copies sus secciones de reporte (Descripción, Componentes Afectados, Impacto, Remediación, Referencias) ni las agregues. NADA de "cómo reportarla", NADA de "¿qué es?". SOLO la PoC.
- Si la PoC es destructiva, NO la ejecutes: márcala como teórica e indícalo claramente.
- Donde falte un dato real, deja `[REDACTAR: ...]` — NO inventes IDs/tokens/respuestas.

OUTPUT: SOLO el markdown de la PoC (empezando por `## PoC`), sin ```fences alrededor, sin texto previo ni posterior."""


_LLM_REPORT_FULL_SYSTEM = """Eres un pentester senior de Hackmetrix redactando el INFORME FINAL de un pentest para entregar al cliente. Te doy: (1) datos del engagement, (2) la PLANTILLA del reporte completo (estructura end-to-end), (3) las PLANTILLAS por tipo de vuln (formato de cada hallazgo) y (4) las vulnerabilidades VALIDADAS con su evidencia/PoC real.

Genera el informe COMPLETO en markdown siguiendo EXACTAMENTE la estructura de la plantilla del reporte completo (Resumen Ejecutivo, Objetivos, Convenciones, Metodología, Alcance, Tabla de Vulnerabilidades, Resumen de Hallazgos, Detalles Técnicos, Conclusiones, Apéndices).

IDIOMA: español neutro (tú/usas, imperativos "revisa"/"ejecuta"/"verifica"). NUNCA voseo ("revisá/ejecutá") ni modismos rioplatenses.

Reglas:
- Rellena las secciones ejecutivas (1-7, 9, apéndices) con la info REAL del engagement: el resumen ejecutivo orientado a gerencia, la distribución de hallazgos por severidad (cuéntalos de las vulns dadas), el alcance (los hosts/URLs dados), la metodología estándar, las conclusiones (causas raíz comunes que veas en los hallazgos).
- Sección 8 (Detalles Técnicos): documenta CADA vulnerabilidad validada como un hallazgo, usando el FORMATO de la plantilla por tipo más parecida (encabezado con CWE + severidad, tabla CVSS/CWE/OWASP, Descripción, Componentes Afectados, Detalles/PoC con los requests/respuestas reales, Impacto, Remediación, Referencias). Usa los datos REALES de cada vuln (su PoC, endpoints, IDs/tokens). NO inventes; donde falte un dato deja `[REDACTAR: ...]`. Donde haga falta una captura, deja `!§ INSERTAR IMAGEN (qué debe verse) §!`.
- La Tabla de Vulnerabilidades (sección 6): una fila por vuln validada (ID, título, severidad, estado).
- CVSS 4.0: el vector y score BASE miden la técnica; la **criticidad final** debe reflejar el impacto de NEGOCIO. Si el hallazgo toca PII/PHI, datos financieros, credenciales/secretos o acceso masivo, eleva los requisitos de seguridad en el vector environmental (`CR:H`/`IR:H`/`AR:H`) y reporta la criticidad final acorde — un IDOR/exposición "high" por score base es **critical** si expone datos sensibles. Respeta la `severidad` que ya trae cada vuln (el Hacker Senior la calibró por negocio); si la subes, justifícalo en el texto del hallazgo.
- SOLO incluye las vulnerabilidades validadas que te di. No agregues hallazgos inventados.
- Borra los comentarios `<!-- -->` y los `{{placeholders}}` que no apliquen (rellénalos o quítalos).

OUTPUT: SOLO el markdown del informe, sin ```fences alrededor, sin texto previo ni posterior."""


def _classify_report_template(vuln_summary: str, index: list, general: str = "_general.md") -> tuple[str, bool, str]:
    """Elige el template más parecido a la vuln. Devuelve (file, matched, reason).
    Si ninguno calza (o falla), devuelve (`general`, False, ...)."""
    if not index:
        return general, False, "sin índice de plantillas"
    lines = []
    for e in index:
        kw = ", ".join(e.get("keywords") or [])
        lines.append(f"- file: {e.get('file','')} | tipo: {e.get('vuln_type','')} | {e.get('description','')} | keywords: {kw}")
    user = vuln_summary + "\n\n# Plantillas disponibles\n" + "\n".join(lines)
    try:
        raw = _llm_complete(_LLM_REPORT_CLASSIFY_SYSTEM, user, max_tokens=300)
    except Exception as e:
        return general, False, f"clasificador falló: {e}"
    obj = _parse_json_object(raw) or {}
    f = str(obj.get("file") or "").strip()
    reason = str(obj.get("reason") or "")
    valid = {e.get("file") for e in index}
    if f and f in valid:
        return f, True, reason
    return general, False, reason


def _llm_generate_vuln_artifact(meta: dict, info_md: str, kind: str, available_env_keys: list[str] | None = None) -> str:
    """Llama a Claude para generar retest.py, exploit.md o reproduction.md a
    partir del meta + info de una vuln. `kind` ∈ {"retest.py", "exploit.md",
    "reproduction.md"}. `available_env_keys` son los nombres de env vars que
    el operador configuró (sin values) — el LLM los usa en retest.py."""
    api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY no está disponible en el entorno del dashboard")
    base_url = os.environ.get("ANTHROPIC_BASE_URL", "https://api.anthropic.com").rstrip("/")
    if kind == "retest.py":
        system = _LLM_RETEST_SYSTEM
    elif kind == "exploit.md":
        system = _LLM_EXPLOIT_SYSTEM
    elif kind == "reproduction.md":
        system = _LLM_REPRODUCTION_SYSTEM
    else:
        raise ValueError(f"kind inválido: {kind!r}")

    creds_section = ""
    if kind == "retest.py" and available_env_keys:
        creds_section = (
            "\n## Credenciales disponibles (env vars)\n"
            "El operador configuró estas env vars que el retest puede leer via os.environ. "
            "Usá EXACTAMENTE estos nombres si el retest necesita autenticarse. NO inventes "
            "otras keys (no van a estar disponibles al correr).\n"
            + "\n".join(f"- {k}" for k in available_env_keys)
            + "\n"
        )

    user_text = (
        f"Vulnerabilidad:\n"
        f"- id: {meta.get('id', '')}\n"
        f"- título: {meta.get('title', '')}\n"
        f"- severidad: {meta.get('severity', '')}\n"
        f"- fase: {meta.get('phase', '')}\n"
        f"- afectado: {', '.join(meta.get('affected') or []) or '—'}\n"
        f"- confidence: {meta.get('confidence', '')}\n\n"
        f"## info.md\n{info_md or '(vacío)'}\n"
        f"{creds_section}"
    )
    payload = {
        "model": LLM_MODEL,
        "max_tokens": 4000,
        "system": system,
        "messages": [{"role": "user", "content": user_text}],
    }
    url = base_url + ("/messages" if base_url.endswith("/v1") else "/v1/messages")
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        method="POST",
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=180) as r:
        resp = json.loads(r.read().decode("utf-8"))
    out = (resp.get("content") or [{}])[0].get("text", "").strip()
    # Strip ``` fences si Claude los puso por error.
    if out.startswith("```"):
        out = re.sub(r"^```[a-z]*\s*\n?", "", out)
        out = re.sub(r"\n?```\s*$", "", out)
    return out


def _llm_complete(system: str, user_text: str, max_tokens: int = 4000) -> str:
    """Llamada genérica a Claude (mensaje único de usuario). Devuelve el texto,
    sin ```fences. Reutilizada por la generación de threat model + chains desde
    las vulns validadas por el hacker."""
    api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY no está disponible en el entorno del dashboard")
    base_url = os.environ.get("ANTHROPIC_BASE_URL", "https://api.anthropic.com").rstrip("/")
    payload = {
        "model": LLM_MODEL,
        "max_tokens": max_tokens,
        "system": system,
        "messages": [{"role": "user", "content": user_text}],
    }
    url = base_url + ("/messages" if base_url.endswith("/v1") else "/v1/messages")
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        method="POST",
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=240) as r:
        resp = json.loads(r.read().decode("utf-8"))
    out = (resp.get("content") or [{}])[0].get("text", "").strip()
    if out.startswith("```"):
        out = re.sub(r"^```[a-z]*\s*\n?", "", out)
        out = re.sub(r"\n?```\s*$", "", out)
    return out


def _llm_chat_plain(system: str, messages: list[dict], max_tokens: int = 1400) -> str:
    """Chat multi-turn SIN tools: system + historial de mensajes (role/content).
    Devuelve el texto de la respuesta. Usado por el chat por-vuln del modal."""
    api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY no está disponible en el entorno del dashboard")
    base_url = os.environ.get("ANTHROPIC_BASE_URL", "https://api.anthropic.com").rstrip("/")
    model = os.environ.get("WIK3_DASHBOARD_VULN_CHAT_MODEL", LLM_MODEL)
    payload = {"model": model, "max_tokens": max_tokens, "system": system, "messages": messages}
    url = base_url + ("/messages" if base_url.endswith("/v1") else "/v1/messages")
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"),
        headers={"x-api-key": api_key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
        method="POST",
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=180) as r:
        resp = json.loads(r.read().decode("utf-8"))
    parts = [b.get("text", "") for b in (resp.get("content") or []) if b.get("type") == "text"]
    return "".join(parts).strip()


_LLM_CREDS_SYSTEM = """Eres un normalizador de credenciales para retests. Te paso texto libre que un hacker pegó con las credenciales/variables que un retest necesita (usuario, contraseña, token, API key, IDs, base URL, headers, cookies, etc.) en CUALQUIER formato (YAML, "user: x / pass: y", prosa, "el usuario es X y la clave Y", etc.).

Tu salida: SOLO líneas `KEY=value`, una por línea, sin markdown ni prose, sin comillas innecesarias.

Reglas:
- KEY en MAYÚSCULAS con guion bajo, con prefijo WIK3_ cuando sea genérico: WIK3_USER, WIK3_PASS, WIK3_TOKEN, WIK3_API_KEY, WIK3_BASE_URL, WIK3_VICTIM_ID, WIK3_COOKIE, etc. Si el texto sugiere un nombre claro, respétalo en MAYÚSCULAS.
- El value es TODO lo que sigue al `=` (puede tener @, &, *, espacios, símbolos). NO lo recortes ni lo alteres.
- NO inventes credenciales que no estén. Omite comentarios/instrucciones que no sean credenciales.
- Una credencial por línea."""


def _looks_like_env(text: str) -> bool:
    """True si el texto ya viene como KEY=value limpio (no hace falta el LLM)."""
    lines = [l for l in text.splitlines() if l.strip() and not l.lstrip().startswith("#")]
    return bool(lines) and all(re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", l) for l in lines)


def _llm_parse_creds(text: str) -> str:
    """Texto libre de credenciales → líneas KEY=value (env vars), vía LLM."""
    return _llm_complete(_LLM_CREDS_SYSTEM, text, max_tokens=1000).strip()


_LLM_AUTH_SYSTEM = """Eres un asistente que prepara la AUTENTICACIÓN para un retest automatizado. Un hacker pega texto libre con TODO lo necesario para que un agente se loguee y vuelva a probar vulnerabilidades: credenciales (usuario, contraseña, token, API key, cookies, headers, segundo factor), la(s) URL(s) de la página de login, y opcionalmente cómo loguearse (pasos, tipo de auth: formulario / SSO / OAuth / Basic, etc.). El formato de entrada es CUALQUIERA (prosa, YAML, "user: x / pass: y", etc.).

Tu trabajo: extraer y estructurar esa info, y VALIDAR si alcanza para loguearse.

Devuelve SOLO un objeto JSON válido (sin ```fences ni texto alrededor), con esta forma EXACTA:
{
  "env": ["WIK3_USER=...", "WIK3_PASS=...", ...],
  "login_urls": ["https://.../login", ...],
  "how_to_login": "1-3 frases de cómo autenticarse (tipo de auth y pasos), o ''",
  "complete": true,
  "missing": ""
}

Reglas:
- env: KEY en MAYÚSCULAS con guion bajo, prefijo WIK3_ cuando sea genérico (WIK3_USER, WIK3_PASS, WIK3_TOKEN, WIK3_API_KEY, WIK3_COOKIE, WIK3_OTP...). El value es TODO lo que sigue al '='; NO lo recortes ni alteres. NO inventes credenciales.
- login_urls: SOLO URLs absolutas (http/https) que sean realmente la página/endpoint de login. Si el hacker da un dominio sin ruta y no se conoce la ruta exacta de login, NO la inventes: déjala fuera y marca complete=false pidiéndola.
- complete=true SOLO si: (a) hay al menos una login_url usable, (b) hay credenciales suficientes para autenticarse (usuario+contraseña, o un token/cookie de sesión válido), y (c) queda claro cómo loguearse. Si falta CUALQUIERA, complete=false.
- missing: cuando complete=false, di concreto y accionable QUÉ falta, dirigido al hacker ("Falta la URL exacta de la página de login", "Faltan las credenciales (usuario y contraseña, o un token)", "No queda claro si el login es por formulario o SSO; indícalo"). Si complete=true, "".
- Español neutro, tratando de tú. NUNCA voseo. NO inventes nada que no esté en el texto."""


def _llm_parse_auth(text: str) -> dict:
    """Texto libre de auth → {env[], login_urls[], how_to_login, complete, missing}.
    Extrae creds + página(s) de login y VALIDA si alcanza para loguearse."""
    raw = _llm_complete(_LLM_AUTH_SYSTEM, text, max_tokens=1200)
    obj = _parse_json_object(raw) or {}
    def _strlist(v):
        return [str(x).strip() for x in v if isinstance(x, str) and x.strip()] if isinstance(v, list) else []
    return {
        "env": _strlist(obj.get("env")),
        "login_urls": _strlist(obj.get("login_urls")),
        "how_to_login": str(obj.get("how_to_login") or "").strip(),
        "complete": bool(obj.get("complete")),
        "missing": str(obj.get("missing") or "").strip(),
    }


_LLM_VULN_CHAT_SYSTEM = """Eres un pentester senior de wik3 ayudando a un hacker a entender y validar UNA vulnerabilidad específica. Más abajo tienes TODO el contexto de esa vuln (metadatos, descripción, info, pasos de reproducción, exploit y casos). Respondes preguntas sobre ESA vuln: qué es, cómo reproducirla/explotarla, si podría ser un falso positivo, si la severidad está bien, qué evidencia falta, cómo remediarla, etc.

REGLAS:
- Español neutro, tratando de "tú" (NUNCA voseo: nada de "vos", "tenés", "podés", "fijate", "dale", "acá").
- Cíñete a la evidencia del contexto. Si algo no está, dilo ("no hay evidencia de X en este hallazgo") en vez de inventar. No inventes IDs, endpoints, tokens ni datos que no estén en el contexto.
- Conciso y accionable. Si te piden un PoC/comando, básate en la reproducción/exploit existentes.
- Eres un asistente de análisis: NO ejecutas nada ni cambias el estado de la vuln; el hacker valida/descarta aparte.
- Cuando sea ÚTIL entregar un archivo (script de PoC/exploit, payload, wordlist, CSV, request crudo, etc.), créalo en su propio bloque con este formato EXACTO:
  [[FILE: nombre.ext]]
  ...contenido EXACTO del archivo...
  [[/FILE]]
  El sistema lo guarda y le da al hacker un link de descarga. Usa nombres claros con extensión (ej. poc_idor.sh, payload.json). Pon SOLO el contenido del archivo dentro del bloque (sin ```fences). No abuses: crea un archivo solo cuando aporte; para snippets cortos basta con un bloque de código normal en el texto."""


_LLM_DESCRIBE_SYSTEM = """Eres un pentester senior explicándole una vulnerabilidad a otro hacker para que la valide. Te paso los metadatos y la evidencia que haya disponible de un hallazgo. Tu trabajo es escribir una explicación clara y concreta de QUÉ ES la vulnerabilidad y CUÁL ES SU IMPACTO.

REGLAS:
- Escribe en español neutro, tratando de "tú" (NUNCA voseo: nada de "vos", "tenés", "podés", "fijate", "dale", "acá").
- "description": 2 a 5 frases. Qué es el bug, en qué consiste, dónde aparece. Concreto y técnico pero legible. Si la evidencia es escasa, deduce con cuidado a partir del título y lo afectado, sin inventar detalles que no se sostengan (no afirmes datos específicos que no estén en la evidencia).
- "impact": 1 a 3 frases. Qué puede hacer un atacante y por qué importa (datos expuestos, acciones no autorizadas, etc.).
- NO inventes IDs, payloads, ni endpoints que no aparezcan en el contexto. Si algo no se sabe, descríbelo en términos generales.
- NO escribas pasos de reproducción ni remediación: solo qué es y su impacto.

OUTPUT: SOLO un objeto JSON válido, sin ```fences ni texto antes/después. Forma exacta:
{"description": "...", "impact": "..."}"""


def _parse_json_object(s: str):
    """Parsea un objeto JSON tolerando prosa alrededor. Devuelve dict | None."""
    s = (s or "").strip()
    try:
        v = json.loads(s)
        return v if isinstance(v, dict) else None
    except Exception:
        pass
    m = re.search(r"\{.*\}", s, re.S)
    if m:
        try:
            v = json.loads(m.group(0))
            return v if isinstance(v, dict) else None
        except Exception:
            return None
    return None


def _parse_json_array(s: str):
    """Parsea un array JSON tolerando prosa alrededor. Devuelve list | None."""
    s = (s or "").strip()
    try:
        v = json.loads(s)
        return v if isinstance(v, list) else None
    except Exception:
        pass
    m = re.search(r"\[.*\]", s, re.S)
    if m:
        try:
            v = json.loads(m.group(0))
            return v if isinstance(v, list) else None
        except Exception:
            return None
    return None


_LLM_CHAINS_SYSTEM = """Eres un pentester senior construyendo CADENAS DE ATAQUE (attack chains) a partir de las vulnerabilidades que el hacker humano ya VALIDÓ. Busca combinaciones que multipliquen el impacto (ej: SSRF + metadata → creds; IDOR + endpoint admin → privesc; subdomain takeover + cookie scope → hijack global). Usa SOLO las vulns validadas que te paso, referenciándolas por su id en cada paso.

Devuelve SOLO un array JSON (sin prosa, sin ```fences) con este shape exacto:
[
  {
    "id": "C-001",
    "title": "...",
    "severity": "critical|high|medium|low|info",
    "steps": [
      {"finding": "<id de una vuln validada>", "action": "qué se hace en este paso"}
    ],
    "business_impact": "impacto de negocio concreto de la cadena"
  }
]

Reglas:
- Cada step.finding DEBE ser el id EXACTO de una de las vulns validadas que te paso. No inventes ids.
- Si NO hay combinaciones encadenables, devuelve []  (array vacío).
- IDs de cadena correlativos: C-001, C-002, …
- Español neutro (tú/tienes), NUNCA voseo. Devuelve SOLO el JSON."""


def _llm_extract_vulns(text: str | None, pdf_b64: str | None, available_env_keys: list[str] | None = None) -> tuple[list[dict], dict]:
    """Llama a Claude con el reporte (texto y/o PDF) y devuelve
    (vulns, extra_meta). vulns es la lista de dicts con title, severity, etc.
    extra_meta puede contener {"scope": {...}} si el LLM lo extrajo.
    `available_env_keys`: nombres (sin values) de env vars que el retest puede
    leer al correr — el LLM los usa para que el `retest` inline use los
    nombres correctos."""
    api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY no está disponible en el entorno del dashboard")
    base_url = os.environ.get("ANTHROPIC_BASE_URL", "https://api.anthropic.com").rstrip("/")

    content: list[dict] = []
    if pdf_b64:
        # El archivo se manda como document/application/pdf. Si NO es un PDF de
        # verdad (p. ej. un .doc/.docx), la API responde 400 opaco. Validamos los
        # magic bytes (%PDF) y damos un error accionable.
        try:
            head = base64.b64decode(pdf_b64[:8])
        except Exception:
            head = b""
        if not head.startswith(b"%PDF"):
            raise ValueError(
                "El archivo subido no es un PDF válido (¿es un .doc/.docx u otro "
                "formato?). Expórtalo a PDF y vuelve a subirlo, o pega el texto del "
                "reporte en el campo de texto.")
        content.append({
            "type": "document",
            "source": {"type": "base64", "media_type": "application/pdf", "data": pdf_b64},
        })
    if text:
        content.append({"type": "text", "text": text})
    if available_env_keys:
        content.append({
            "type": "text",
            "text": (
                "## Credenciales disponibles (env vars)\n"
                "El operador configuró estas env vars que cada retest puede leer via "
                "os.environ. Si necesitas autenticación en el script `retest`, usa "
                "EXACTAMENTE estos nombres (no inventes otros):\n"
                + "\n".join(f"- {k}" for k in available_env_keys)
            ),
        })
    if not content:
        raise ValueError("ni text ni pdf_b64 provistos")

    payload = {
        "model": LLM_MODEL,
        "max_tokens": 16000,
        "system": LLM_IMPORT_SYSTEM,
        "messages": [{"role": "user", "content": content}],
    }
    url = base_url + ("/messages" if base_url.endswith("/v1") else "/v1/messages")
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        method="POST",
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=300) as r:
        resp = json.loads(r.read().decode("utf-8"))
    raw = (resp.get("content") or [{}])[0].get("text", "").strip()
    # Strip code fences si Claude los puso por error.
    if raw.startswith("```"):
        raw = re.sub(r"^```(?:json|jsonl)?\s*\n?", "", raw)
        raw = re.sub(r"\n?```\s*$", "", raw)
    vulns = []
    extra_meta: dict = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue
        # La primera linea (o cualquier linea) puede ser _meta con scope, etc.
        meta = obj.get("_meta")
        if isinstance(meta, dict):
            if isinstance(meta.get("scope"), dict):
                extra_meta["scope"] = meta["scope"]
            continue
        vulns.append(obj)
    return vulns, extra_meta


def _llm_draft_vuln(description: str) -> dict:
    """Toma la descripción libre del operador y devuelve un dict con los
    campos estructurados de la vuln (title, severity, phase, confidence,
    affected, info markdown, cvss, references). El operador edita y luego
    /vulns/manual lo persiste.

    Usa Opus 4.7 (no el default sonnet del dashboard) porque la calidad
    del structuring importa: es 1 request por nueva vuln manual y queda
    grabado como artefacto del engagement. Override via env si el
    operador quiere cambiar."""
    api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    base_url = os.environ.get("ANTHROPIC_BASE_URL", "https://api.anthropic.com").rstrip("/")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY no está disponible en el entorno del dashboard")
    model = os.environ.get("WIK3_DASHBOARD_VULN_DRAFT_MODEL", "claude-opus-4-7")
    payload = {
        "model": model,
        "max_tokens": 4096,
        "system": _LLM_VULN_FROM_DESC_SYSTEM,
        "messages": [{"role": "user", "content": f"Descripción del operador:\n\n{description}"}],
    }
    body = json.dumps(payload).encode("utf-8")
    url = base_url + ("/messages" if base_url.endswith("/v1") else "/v1/messages")
    req = urllib.request.Request(
        url, data=body,
        headers={"x-api-key": api_key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
        method="POST",
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=180) as r:
        resp = json.loads(r.read().decode("utf-8"))
    text = resp["content"][0]["text"].strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*\n", "", text)
        text = re.sub(r"\n```\s*$", "", text)
    data = json.loads(text)
    if not isinstance(data, dict):
        raise RuntimeError("respuesta LLM no es un objeto JSON")
    # Sanitización mínima — defaults sensatos si el LLM omitió algo.
    data.setdefault("title", "Vulnerabilidad manual (sin título)")
    data.setdefault("severity", "medium")
    data.setdefault("phase", "active")
    data.setdefault("confidence", "likely")
    data.setdefault("affected", [])
    data.setdefault("info", "## Descripción\n\n—\n")
    if not isinstance(data["affected"], list):
        data["affected"] = [str(data["affected"])]
    return data


_CHAT_TOOLS = [
    {
        "name": "read_engagement_file",
        "description": (
            "Lee un archivo del workspace del engagement. `path` es relativo "
            "a la raíz del workspace (ej. 'vulns/V-007-foo/info.md', "
            "'engagement.yaml', 'passive/summary.md'). Para listar el "
            "contenido de una carpeta, usa un path terminado en '/' "
            "(ej. 'vulns/' lista los directorios de vulns). Cap por archivo: "
            "100KB; si el archivo es más grande devuelve metadata + preview "
            "salvo que pases `force=true`."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path relativo al workspace del engagement"},
                "force": {"type": "boolean", "description": "Si true, devuelve el archivo entero aunque exceda el cap. Default false."},
            },
            "required": ["path"],
        },
    },
    {
        "name": "grep_engagement",
        "description": (
            "Busca un texto (substring, case-insensitive) en TODOS los archivos "
            "del workspace del engagement (grep recursivo). Devuelve archivo:línea "
            "de cada coincidencia (cap 200). Úsalo para ubicar dónde se menciona "
            "algo (un endpoint, host, token, vuln) sin saber el archivo; luego lee "
            "el archivo entero con read_engagement_file."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Texto a buscar (substring, case-insensitive)"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "message_running_agent",
        "description": (
            "Envía un mensaje al agente fabro que está corriendo el workflow. "
            "Se entrega vía convo/inbox.md y el agente lo lee en su próximo "
            "tool call. Si NO hay agente corriendo, devuelve error y debes "
            "informar al operador. Útil cuando el operador escribe algo "
            "dirigido al agente activo."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "message": {"type": "string", "description": "Texto a entregar al agente"},
            },
            "required": ["message"],
        },
    },
]


def _llm_chat_call(messages: list[dict]) -> dict:
    """Wrapper sobre la API de Anthropic con tool use habilitado.
    Devuelve el dict completo del response (incluye content blocks).
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    base_url = os.environ.get("ANTHROPIC_BASE_URL", "https://api.anthropic.com").rstrip("/")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY no está disponible en el entorno del dashboard")
    model = os.environ.get("WIK3_DASHBOARD_CHAT_MODEL", "claude-opus-4-7")
    payload = {
        "model": model,
        "max_tokens": 8192,
        "system": _LLM_CHAT_SYSTEM,
        "tools": _CHAT_TOOLS,
        "messages": messages,
    }
    body = json.dumps(payload).encode("utf-8")
    url = base_url + ("/messages" if base_url.endswith("/v1") else "/v1/messages")
    req = urllib.request.Request(
        url, data=body,
        headers={"x-api-key": api_key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
        method="POST",
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=180) as r:
        return json.loads(r.read().decode("utf-8"))


def _llm_generate(prompt: str, prior_yaml: str | None, types_hint: list[str] | None = None) -> dict:
    api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    base_url = os.environ.get("ANTHROPIC_BASE_URL", "https://api.anthropic.com").rstrip("/")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY no está disponible en el entorno del dashboard")

    user_msg = _build_llm_user_message(prompt, prior_yaml, types_hint=types_hint)
    payload = {
        "model": LLM_MODEL,
        "max_tokens": LLM_MAX_TOKENS,
        "system": LLM_SYSTEM_PROMPT,
        "messages": [{"role": "user", "content": user_msg}],
    }
    body = json.dumps(payload).encode("utf-8")
    # Si la base url ya incluye /v1, no la dupliques.
    url = base_url + ("/messages" if base_url.endswith("/v1") else "/v1/messages")
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        method="POST",
    )
    # Bypass HTTP(S)_PROXY del entorno: el dashboard NUNCA debería hablar
    # al LLM via squid/Burp. Squid chainea a Burp cuando el reverse tunnel
    # está vivo, y Burp re-firma TLS con su CA self-signed → urllib falla
    # con SSL_VERIFY_FAILED. Burp es para tráfico del agente contra el
    # target; el dashboard sale directo via Cloud NAT.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=180) as r:
        resp_body = r.read().decode("utf-8")
    resp = json.loads(resp_body)
    blocks = resp.get("content") or []
    text = (blocks[0].get("text", "") if blocks else "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*\n", "", text)
        text = re.sub(r"\n```\s*$", "", text)
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # El modelo respondió en prosa (aclaración/negativa) en vez del JSON
        # pedido. Rescatamos el primer objeto JSON embebido; si no hay, damos un
        # error accionable que muestra lo que dijo el modelo (en vez del críptico
        # "Expecting value: line 1 column 1").
        data = None
        m = re.search(r"\{.*\}", text, re.S)
        if m:
            try:
                data = json.loads(m.group(0))
            except json.JSONDecodeError:
                data = None
        if data is None:
            snippet = text[:400] if text else "(respuesta vacía)"
            raise RuntimeError(
                "el modelo respondió en texto, no en el JSON esperado (suele pasar "
                "si el prompt es ambiguo o pide una aclaración). Reformula el prompt "
                "con el objetivo y el scope claros y reintenta. El modelo dijo: "
                + snippet
            )
    for k in ("slug", "yaml", "summary"):
        if k not in data:
            raise RuntimeError(f"respuesta LLM sin clave {k!r}: keys={list(data)}")
    data["slug"] = re.sub(r"[^a-z0-9-]", "-", data["slug"].lower()).strip("-")[:40]
    if not SLUG_RE.match(data["slug"]):
        raise RuntimeError(f"slug LLM inválido: {data['slug']!r}")
    return data


# ════════════════════════════════════════════════════════════════════════════
# Run management (systemd template wik3-engagement@<slug>.service)
# ════════════════════════════════════════════════════════════════════════════

UNIT_PREFIX = "wik3-engagement@"
UNIT_SUFFIX = ".service"


def _systemctl(*args: str, timeout: int = 10) -> tuple[int, str, str]:
    try:
        r = subprocess.run(
            ["systemctl", *args],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except FileNotFoundError:
        return 127, "", "systemctl no disponible"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


def _active_run_slug() -> str | None:
    """Devuelve el slug del engagement actualmente corriendo, o None."""
    rc, out, _ = _systemctl(
        "list-units", "--type=service", "--state=active", "--no-legend",
        f"{UNIT_PREFIX}*{UNIT_SUFFIX}",
        timeout=5,
    )
    if rc != 0:
        return None
    for line in out.splitlines():
        # Formato: wik3-engagement@<slug>.service  loaded active running ...
        first = line.strip().split()
        if not first:
            continue
        unit = first[0]
        if unit.startswith(UNIT_PREFIX) and unit.endswith(UNIT_SUFFIX):
            slug = unit[len(UNIT_PREFIX):-len(UNIT_SUFFIX)]
            if SLUG_RE.match(slug):
                return slug
    return None


def _is_unit_active(slug: str) -> bool:
    rc, out, _ = _systemctl("is-active", f"{UNIT_PREFIX}{slug}{UNIT_SUFFIX}", timeout=5)
    return out == "active"


# ════════════════════════════════════════════════════════════════════════════
# State aggregation (igual que antes: per-slug)
# ════════════════════════════════════════════════════════════════════════════

def _active_slug() -> str:
    """Slug del engagement activo desde el marker /workspace/wik3/.active-slug
    (reemplaza al symlink 'current'). Fallback: primer engagement dir real."""
    try:
        s = (WIK3_ROOT / ".active-slug").read_text().strip()
        if s:
            return s
    except OSError:
        pass
    try:
        for entry in sorted(WIK3_ROOT.iterdir()):
            if entry.is_dir() and not entry.is_symlink() and not entry.name.startswith("."):
                return entry.name
    except OSError:
        pass
    return ""


def _pick_engagement_dir(slug: str) -> Path:
    """Devuelve el dir con la DATA real del engagement, prefiriendo el montado.

    El parking a veces deja un directorio VACÍO en WIK3_ROOT mientras la data
    real vive en PARK_DIR. `p.exists()` es true para un dir vacío, así que el
    chequeo viejo devolvía el stub vacío → la UI mostraba el engagement vacío.
    Usamos la presencia de `engagement.yaml` como marca de "data real".
    """
    mounted = WIK3_ROOT / slug
    parked = PARK_DIR / slug
    if (mounted / "engagement.yaml").is_file():
        return mounted
    if (parked / "engagement.yaml").is_file():
        return parked
    return mounted


def resolve_engagement_dir(engagement: str | None) -> Path:
    slug = engagement or "current"
    if "/" in slug or ".." in slug:
        slug = "current"
    # "current" es un sentinel ("el engagement activo"), resuelto via el marker
    # .active-slug — ya no via un symlink en el filesystem.
    if slug == "current":
        slug = _active_slug() or slug
    return _pick_engagement_dir(slug)


def list_engagements_with_meta() -> list[dict]:
    """Combina YAMLs, sidecars de meta y workspace para devolver una lista
    consolidada para la UI."""
    out: list[dict] = []
    active_slug = _active_run_slug()
    # Engagement activo desde el marker .active-slug (sin symlink 'current').
    current_target = _active_slug() or None

    for slug in _list_slugs():
        meta = _read_meta(slug)
        ws = _pick_engagement_dir(slug)  # montado o parkeado (el que tiene data real)
        findings_total = 0
        chains_total = 0
        last_modified = 0.0
        if ws.is_dir():
            try:
                last_modified = ws.stat().st_mtime
            except Exception:
                pass
            ff = ws / "validated" / "findings.json"
            cf = ws / "validated" / "chains.json"
            try:
                if ff.exists():
                    findings_total = len(json.loads(ff.read_text()))
            except Exception:
                pass
            try:
                if cf.exists():
                    chains_total = len(json.loads(cf.read_text()))
            except Exception:
                pass
        created_at = meta.get("created_at")
        ttl_days = int(meta.get("ttl_days", TTL_DAYS))
        expires_at = None
        if created_at:
            try:
                ts = dt.datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                expires_at = (ts + dt.timedelta(days=ttl_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
            except Exception:
                pass
        # types: source of truth es el YAML, no la meta. Fallback ["webapp"].
        types: list[str] = ["webapp"]
        yaml_path = _engagement_path(slug)
        if yaml_path.exists():
            try:
                parsed_yaml = _parse_yaml_safe(yaml_path.read_text())
                if isinstance(parsed_yaml, dict):
                    yt = parsed_yaml.get("types")
                    if isinstance(yt, list):
                        cleaned = [t for t in yt if isinstance(t, str) and t in ("blackbox", "webapp", "mobile", "internal", "cloud")]
                        if cleaned:
                            types = cleaned
            except Exception:
                pass
        out.append({
            "slug": slug,
            "display_name": meta.get("display_name") or slug,
            "created_at": created_at,
            "started_at": meta.get("started_at"),
            "expires_at": expires_at,
            "ttl_days": ttl_days,
            "read_only_mode": bool(meta.get("read_only_mode")),
            "types": types,
            "is_running": slug == active_slug,
            "is_current": slug == current_target,
            "findings_total": findings_total,
            "chains_total": chains_total,
            "last_modified": last_modified,
        })
    out.sort(key=lambda e: (e["created_at"] or "", e["slug"]), reverse=True)
    return out


def read_token() -> str:
    try:
        return TOKEN_PATH.read_text().strip()
    except Exception:
        return ""


def fabro_get(path: str) -> dict | list | None:
    token = read_token()
    if not token:
        return None
    try:
        req = urllib.request.Request(
            f"{FABRO_SERVER}{path}",
            headers={"Authorization": f"Bearer {token}"},
        )
        with urllib.request.urlopen(req, timeout=3) as r:
            return json.loads(r.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)}


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        # Solo objetos: una línea que parsea a string/número/array (queue.jsonl
        # corrupto) rompía a los consumidores que hacen e.get(...) → 'str' object
        # has no attribute 'get', y crasheaba todo /api/state.
        if isinstance(obj, dict):
            out.append(obj)
    return out


def read_json(path: Path) -> list | dict | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


def severity_count(items: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in items or []:
        sev = (f.get("severity") or "unknown").lower()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


# ─── Revisión humana de findings ──────────────────────────────────────────────
# Cada finding lleva un campo `review` con la decisión del hacker:
#   status ∈ {pending, validated, false_positive, wont_fix}
# El default es `pending` cuando el campo no existe en disco.
REVIEW_STATUSES = {"pending", "validated", "false_positive", "wont_fix", "mitigated"}
# Severidades validas para overrides del hacker al revisar (el agente las
# propone pero el humano puede ajustarlas).
SEVERITIES = {"critical", "high", "medium", "low", "info"}
_REVIEW_LOCK = threading.Lock()

# Coalescing del rebuild de threat_model + chains desde vulns validadas: al
# validar varias vulns seguidas, no spawneamos N rebuilds; corre uno y si
# llegan más validaciones mientras corre, queda "dirty" y vuelve a correr una
# vez al terminar.
_REPORT_BUILD_GUARD = threading.Lock()
_REPORT_BUILD_STATE: dict[str, dict] = {}   # slug -> {"running": bool, "dirty": bool}


# ─── Mensajes del admin (avisos al hacker) ──────────────────────────────────
# El admin puede empujar mensajes via POST /admin/messages (bearer token).
# El hacker los ve como modal automatico hasta marcarlos como leidos.
# Storage append-only en /var/lib/wik3/messages.jsonl.
MESSAGES_PATH = Path(os.environ.get("WIK3_MESSAGES_PATH") or "/var/lib/wik3/messages.jsonl")
_MESSAGES_LOCK = threading.Lock()
# Datos del equipo que el admin empuja a este box (solo si el hacker es TL).
# La pestaña "Equipo" solo se muestra si llegó un push reciente (frescura).
TEAM_PATH = Path(os.environ.get("WIK3_TEAM_PATH") or "/var/lib/wik3/team.json")
TEAM_FRESH_SECS = int(os.environ.get("WIK3_TEAM_FRESH_SECS", "360"))  # push 5 min + 1 min de gracia


def _read_messages() -> list[dict]:
    if not MESSAGES_PATH.is_file():
        return []
    out: list[dict] = []
    try:
        for line in MESSAGES_PATH.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except Exception:
                continue
    except Exception:
        pass
    return out


def _write_messages(msgs: list[dict]) -> None:
    MESSAGES_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = MESSAGES_PATH.with_suffix(".jsonl.tmp")
    with tmp.open("w") as f:
        for m in msgs:
            f.write(json.dumps(m, ensure_ascii=False) + "\n")
    os.replace(tmp, MESSAGES_PATH)


# ─── Branding (configurable en primer acceso) ───────────────────────────────
# Storage en /var/lib/wik3/brand/. La primera vez que el hacker entra al
# dashboard, ve un wizard pidiendo nombre + logo + bg + paleta. Después
# se persiste a disco y nunca se vuelve a mostrar (salvo que el operador
# borre brand.json).
BRAND_DIR = Path(os.environ.get("WIK3_BRAND_DIR") or "/var/lib/wik3/brand")
BRAND_JSON_PATH = BRAND_DIR / "brand.json"
_BRAND_LOGO_EXT = {
    "image/png": "png", "image/jpeg": "jpg", "image/jpg": "jpg",
    "image/svg+xml": "svg", "image/webp": "webp",
}
_BRAND_BG_EXT = {
    "image/png": "png", "image/jpeg": "jpg", "image/jpg": "jpg", "image/webp": "webp",
}
BRAND_LOGO_MAX = 1024 * 1024       # 1 MB
BRAND_BG_MAX = 3 * 1024 * 1024     # 3 MB
DEFAULT_PALETTE = {
    "bg": "#0a0e1a", "panel": "#10151f", "accent": "#22d3ee", "fg": "#e2e8f0",
}
_HEX_RE = re.compile(r"^#[0-9a-fA-F]{3,8}$")


def _sanitize_palette(raw) -> dict:
    out = dict(DEFAULT_PALETTE)
    if isinstance(raw, dict):
        for k in DEFAULT_PALETTE:
            v = raw.get(k)
            if isinstance(v, str) and _HEX_RE.match(v.strip()):
                out[k] = v.strip()
    return out


def read_brand() -> dict:
    if not BRAND_JSON_PATH.is_file():
        return {"configured": False, "name": "", "has_logo": False, "has_bg": False, "palette": dict(DEFAULT_PALETTE)}
    try:
        data = json.loads(BRAND_JSON_PATH.read_text())
    except Exception:
        return {"configured": False, "name": "", "has_logo": False, "has_bg": False, "palette": dict(DEFAULT_PALETTE)}
    logo_fn = data.get("logo_filename") or ""
    bg_fn = data.get("bg_filename") or ""
    return {
        "configured": True,
        "name": data.get("name") or "",
        "has_logo": bool(logo_fn) and (BRAND_DIR / logo_fn).is_file(),
        "has_bg": bool(bg_fn) and (BRAND_DIR / bg_fn).is_file(),
        "palette": _sanitize_palette(data.get("palette")),
        "configured_at": data.get("configured_at"),
        "configured_by": data.get("configured_by"),
    }


def _persist_brand_image(prefix: str, content_b64: str, content_type: str, ext_map: dict, max_bytes: int) -> tuple[str, str]:
    ext = ext_map.get(content_type or "", "png")
    raw = base64.b64decode(content_b64)
    if len(raw) > max_bytes:
        raise ValueError(f"{prefix} demasiado grande ({len(raw)} bytes, max {max_bytes})")
    for old in BRAND_DIR.glob(f"{prefix}.*"):
        try:
            old.unlink()
        except Exception:
            pass
    filename = f"{prefix}.{ext}"
    (BRAND_DIR / filename).write_bytes(raw)
    return filename, content_type or "image/png"


def write_brand(name: str, logo_b64: str, logo_ct: str, bg_b64: str, bg_ct: str, palette: dict, actor: str) -> None:
    BRAND_DIR.mkdir(parents=True, exist_ok=True)
    try:
        BRAND_DIR.chmod(0o755)
    except Exception:
        pass
    prev = {}
    if BRAND_JSON_PATH.is_file():
        try:
            prev = json.loads(BRAND_JSON_PATH.read_text()) or {}
        except Exception:
            prev = {}
    info = {
        "name": name,
        "palette": _sanitize_palette(palette),
        "configured_at": _now_iso(),
        "configured_by": actor or "",
    }
    if logo_b64:
        fn, ct = _persist_brand_image("logo", logo_b64, logo_ct, _BRAND_LOGO_EXT, BRAND_LOGO_MAX)
        info["logo_filename"] = fn; info["logo_content_type"] = ct
    elif prev.get("logo_filename"):
        info["logo_filename"] = prev["logo_filename"]
        info["logo_content_type"] = prev.get("logo_content_type") or "image/png"
    if bg_b64:
        fn, ct = _persist_brand_image("bg", bg_b64, bg_ct, _BRAND_BG_EXT, BRAND_BG_MAX)
        info["bg_filename"] = fn; info["bg_content_type"] = ct
    elif prev.get("bg_filename"):
        info["bg_filename"] = prev["bg_filename"]
        info["bg_content_type"] = prev.get("bg_content_type") or "image/png"
    tmp = BRAND_JSON_PATH.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(info, indent=2, ensure_ascii=False))
    os.replace(tmp, BRAND_JSON_PATH)


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    os.replace(tmp, path)


def normalize_review(f: dict) -> dict:
    r = f.get("review") if isinstance(f, dict) else None
    if not isinstance(r, dict):
        r = {}
    status = r.get("status")
    if status not in REVIEW_STATUSES:
        status = "pending"
    return {
        "status": status,
        "by": r.get("by") or "",
        "at": r.get("at") or "",
        "note": r.get("note") or "",
    }


def count_review_status(items: list[dict]) -> dict[str, int]:
    counts = {s: 0 for s in REVIEW_STATUSES}
    for f in items or []:
        s = (f.get("review") or {}).get("status") or "pending"
        if s in counts:
            counts[s] += 1
    return counts


# ─── Version info ───────────────────────────────────────────────────────────
# startup.sh escribe estos archivos al boot. /etc/wik3/.image-name viene del
# metadata server; .wik3-commit y .bundle-sha vienen de quien armó el bundle
# (deploy-box.sh o el provisioner de admin). Override por env para dev.
_IMAGE_NAME_PATH = Path(os.environ.get("WIK3_IMAGE_NAME_PATH") or "/etc/wik3/.image-name")
_BUNDLE_SHA_PATH = Path(os.environ.get("WIK3_BUNDLE_SHA_PATH") or "/etc/wik3/.bundle-sha")
_WIK3_COMMIT_PATH = Path(os.environ.get("WIK3_COMMIT_PATH") or "/etc/wik3/.wik3-commit")


def _read_short(path: Path) -> str:
    try:
        return path.read_text().strip()
    except Exception:
        return ""


def version_info() -> dict:
    return {
        "image": _read_short(_IMAGE_NAME_PATH),
        "bundle_sha": _read_short(_BUNDLE_SHA_PATH),
        "code_commit": _read_short(_WIK3_COMMIT_PATH),
    }


def current_iteration(wik3_dir: Path) -> int:
    f = wik3_dir / "discovery" / "iteration"
    try:
        return int(f.read_text().strip())
    except Exception:
        return 1


def current_node(wik3_dir: Path) -> str | None:
    # Lo escribe el hook stage_start de workflow.toml (FABRO_NODE_ID) en cada
    # entrada de nodo. None si todavía no arrancó ningún nodo.
    f = wik3_dir / ".current-node"
    try:
        v = f.read_text().strip()
        return v or None
    except Exception:
        return None


def latest_wik3_run(engagement: str | None = None) -> dict | None:
    runs = fabro_get("/api/v1/runs")
    if not isinstance(runs, list):
        return None
    for r in runs:
        if r.get("workflow_slug") not in {"wik3", "wik3-finalize", "wik3-report"}:
            continue
        if engagement and engagement != "current":
            goal = r.get("goal", "")
            if engagement not in goal:
                continue
        return r
    return None


def _count_status(results: list[dict]) -> dict[str, int]:
    out: dict[str, int] = {}
    for r in results:
        s = r.get("status") or "unknown"
        out[s] = out.get(s, 0) + 1
    return out


def _find_vuln_dir(wik3_dir: Path, vid: str) -> Path | None:
    """Devuelve el path de la carpeta de la vuln cuyo id matchea `vid`.
    Acepta el id completo (V-001-slug, A-002-slug, P-005-slug) o el prefijo
    (V-001, A-002, P-005). Soporta los prefijos del layout nuevo (V-) y los
    del workflow legacy que escribe findings.json (A-/P-/F-...)."""
    vulns_dir = wik3_dir / "vulns"
    if not vulns_dir.is_dir():
        return None
    # Match exacto del id completo.
    direct = vulns_dir / vid
    if direct.is_dir():
        return direct
    # Match por prefijo (X-NNN → X-NNN-*). Acepta cualquier prefijo de una
    # letra que use el workflow (V, A, P, F, ...).
    if re.match(r"^[A-Z]-\d+$", vid):
        for sub in vulns_dir.iterdir():
            if sub.is_dir() and sub.name.startswith(vid + "-"):
                return sub
    return None


def _vid_prefix(s) -> str:
    m = re.match(r"^[A-Z]-\d+", str(s or ""))
    return m.group(0) if m else str(s or "")


def _delete_vuln(wik3_dir: Path, vid: str) -> bool:
    """Borra una vuln: su carpeta vulns/<vid>/ (layout nuevo) + sus entradas en
    los arrays legacy findings.json (passive/active/validated). Idempotente."""
    removed = False
    vd = _find_vuln_dir(wik3_dir, vid)
    if vd is not None and vd.is_dir():
        try:
            shutil.rmtree(vd, ignore_errors=True)
            removed = True
        except Exception:
            pass
    target = _vid_prefix(vid)
    for sub in ("passive", "active", "validated"):
        p = wik3_dir / sub / "findings.json"
        data = read_json(p)
        if not isinstance(data, list):
            continue
        kept = [e for e in data if not (isinstance(e, dict) and _vid_prefix(e.get("id", "")) == target)]
        if len(kept) != len(data):
            write_json(p, kept)
            removed = True
    return removed


def list_vulns(wik3_dir: Path) -> list[dict]:
    """Lee todas las vulns desde vulns/<id>-<slug>/meta.json. Fallback a las
    legacy JSON arrays (passive/active/validated) si vulns/ está vacío —
    así engagements viejos siguen visibles aunque no estén migrados al
    layout nuevo.

    Devuelve una lista plana de dicts (compatible con el shape histórico
    que usaba la UI: id, severity, title, affected, phase, review, ...).
    """
    vulns_dir = wik3_dir / "vulns"
    if vulns_dir.is_dir():
        out = []
        for sub in sorted(vulns_dir.iterdir()):
            if not sub.is_dir() or not sub.name.startswith("V-"):
                continue
            meta_path = sub / "meta.json"
            if not meta_path.is_file():
                continue
            try:
                meta = json.loads(meta_path.read_text())
            except Exception:
                continue
            meta.setdefault("review", {"status": "pending", "by": "", "at": "", "note": ""})
            cases = meta.get("cases") if isinstance(meta.get("cases"), list) else []
            meta["cases"] = cases
            meta["cases_count"] = len(cases)
            meta["has_retest"] = (sub / "retest.py").is_file()
            out.append(meta)
        if out:
            sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            out.sort(key=lambda f: (sev_order.get((f.get("severity") or "").lower(), 9), f.get("id", "")))
            return out

    # Fallback: legacy JSON arrays.
    passive = read_json(wik3_dir / "passive" / "findings.json") or []
    active = read_json(wik3_dir / "active" / "findings.json") or []
    validated = read_json(wik3_dir / "validated" / "findings.json") or []
    return _merge_findings(passive, active, validated)


# ── Mapa de superficie de ataque (radial: ejercicio en el centro) ───────────
def _as_hostname(s: str) -> str:
    """Extrae hostname (lowercase, sin esquema/puerto/path/auth) de una entry
    que puede ser URL, host:port, host/path o host pelado. '' si no aplica."""
    if not s:
        return ""
    v = s.strip()
    if "://" in v:
        v = v.split("://", 1)[1]
    head = v.split("/", 1)[0]
    if "@" in head:
        v = v.split("@", 1)[1]
    for sep in ("/", "?", "#"):
        i = v.find(sep)
        if i != -1:
            v = v[:i]
    v = v.split(":", 1)[0]
    return v.lower().strip()


def _scope_state(host: str, scope_hosts: list[str], oos_hosts: list[str]) -> str:
    """'in' | 'out' | 'unknown' para un hostname vs scope/out_of_scope.
    Match exacto o subdominio (host endswith '.'+entry). Gana el match MÁS
    ESPECÍFICO: una entrada exacta / de sufijo más largo pesa más que un padre
    más corto, así un subdominio in-scope (os.example.com) no queda tapado
    por su padre out-of-scope (example.com). Empate → out (la exclusión
    explícita es la opción conservadora)."""
    def best_match_len(h: str, entries: list[str]) -> int:
        best = -1
        for e in entries:
            eh = _as_hostname(e)
            if eh and (h == eh or h.endswith("." + eh)):
                best = max(best, len(eh))
        return best
    in_len = best_match_len(host, scope_hosts)
    out_len = best_match_len(host, oos_hosts)
    if in_len < 0 and out_len < 0:
        return "unknown"
    return "in" if in_len > out_len else "out"


def build_attack_surface(wik3_dir: Path, label: str) -> dict:
    """Arma el grafo radial: centro = ejercicio; hosts/subdominios como radios;
    endpoints colgando de su host; vulns mapeadas al host por `affected` +
    `cases[].location`. Lee recon/assets.json, discovery/queue.jsonl y vulns/."""
    scope_hosts = _read_scope_list(wik3_dir / "scope.txt")
    oos_hosts = _read_scope_list(wik3_dir / "out_of_scope.txt")

    hosts: dict[str, dict] = {}

    def ensure_host(raw: str):
        h = _as_hostname(raw)
        if not h:
            return None
        node = hosts.get(h)
        if node is None:
            node = {
                "host": h,
                "scope": _scope_state(h, scope_hosts, oos_hosts),
                "ips": [], "tech": [], "ports": [],
                "endpoints": [], "vulns": [], "_ep_seen": set(),
            }
            hosts[h] = node
        return node

    # Sembrar con el scope para que el centro tenga radios aunque no haya recon.
    for s in scope_hosts:
        ensure_host(s)

    # recon/assets.json
    try:
        assets = json.loads((wik3_dir / "recon" / "assets.json").read_text())
    except Exception:
        assets = {}
    if isinstance(assets, dict):
        for hrec in (assets.get("hosts") or []):
            if not isinstance(hrec, dict):
                continue
            node = ensure_host(hrec.get("host") or "")
            if not node:
                continue
            for src, dst in (("ips", "ips"), ("tech", "tech"), ("ports", "ports")):
                for v in (hrec.get(src) or []):
                    if v not in node[dst]:
                        node[dst].append(v)
        for sd in (assets.get("subdomains") or []):
            ensure_host(sd if isinstance(sd, str) else (sd.get("host", "") if isinstance(sd, dict) else ""))
        for ep in (assets.get("endpoints") or []):
            url = ep.get("url", "") if isinstance(ep, dict) else (ep if isinstance(ep, str) else "")
            node = ensure_host(url)
            if node and url and url not in node["_ep_seen"]:
                node["_ep_seen"].add(url)
                node["endpoints"].append(url)

    # discovery/queue.jsonl
    qpath = wik3_dir / "discovery" / "queue.jsonl"
    if qpath.is_file():
        try:
            for line in qpath.read_text().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except Exception:
                    continue
                kind = item.get("kind") or ""
                val = item.get("value") or ""
                if kind in ("host", "subdomain"):
                    ensure_host(val)
                elif kind in ("endpoint", "file"):
                    node = ensure_host(val)
                    if node and val and val not in node["_ep_seen"]:
                        node["_ep_seen"].add(val)
                        node["endpoints"].append(val)
        except Exception:
            pass

    # vulns → host por affected[] + cases[].location
    unmapped: list[dict] = []
    for v in list_vulns(wik3_dir):
        vsum = {
            "id": v.get("id") or "",
            "title": v.get("title") or "",
            "severity": (v.get("severity") or "info").lower(),
            "phase": v.get("phase") or "",
            "review": (v.get("review") or {}).get("status") or "pending",
            "cases_count": v.get("cases_count") or (len(v["cases"]) if isinstance(v.get("cases"), list) else 0),
        }
        locs: list[str] = []
        aff = v.get("affected")
        if isinstance(aff, list):
            locs += [a for a in aff if isinstance(a, str)]
        elif isinstance(aff, str):
            locs.append(aff)
        for c in (v.get("cases") or []):
            if isinstance(c, dict) and c.get("location"):
                locs.append(c["location"])
        matched = False
        seen_h: set[str] = set()
        for loc in locs:
            h = _as_hostname(loc)
            if not h or h in seen_h:
                continue
            seen_h.add(h)
            node = ensure_host(h)
            if node:
                node["vulns"].append(vsum)
                matched = True
        if not matched:
            unmapped.append(vsum)

    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
    host_list = []
    for node in hosts.values():
        node.pop("_ep_seen", None)
        node["endpoints_total"] = len(node["endpoints"])
        node["endpoints"] = node["endpoints"][:40]
        node["vulns"].sort(key=lambda x: sev_rank.get(x["severity"], 9))
        node["worst_severity"] = node["vulns"][0]["severity"] if node["vulns"] else None
        host_list.append(node)
    scope_ord = {"in": 0, "unknown": 1, "out": 2}
    host_list.sort(key=lambda n: (scope_ord.get(n["scope"], 3), -len(n["vulns"]), n["host"]))

    return {
        "center": {"label": label, "scope": scope_hosts, "out_of_scope": oos_hosts},
        "hosts": host_list,
        "unmapped_vulns": unmapped,
        "totals": {
            "hosts": len(host_list),
            "in_scope": sum(1 for n in host_list if n["scope"] == "in"),
            "vulns": sum(len(n["vulns"]) for n in host_list) + len(unmapped),
        },
    }


def aggregate_state(engagement: str | None = None) -> dict:
    # Source of truth para "el engagement existe" = el YAML, NO la carpeta
    # del workspace. El workspace dir wik3/<slug>/ puede no existir (engagement
    # nuevo nunca corrido) y el dashboard tiene que mostrar el detail igual.
    # El symlink `current` solo lo usa fabro al correr — el dashboard nunca
    # debe depender de él para resolver qué engagement mostrar.
    if engagement and engagement != "current":
        if not _engagement_path(engagement).is_file():
            available = []
            try:
                for y in ENGAGEMENTS_DIR.glob("engagement.*.yaml"):
                    if y.stem.startswith("engagement."):
                        available.append(y.stem[len("engagement."):])
            except Exception:
                pass
            return {
                "engagement": engagement,
                "engagement_not_found": True,
                "available_engagements": sorted(available),
            }
        # YAML existe → garantizar workspace dir (idempotente). Sin esto los
        # endpoints downstream (import, scope, file write) que validan
        # `wik3_dir.is_dir()` rompen aunque el YAML esté OK.
        try:
            (WIK3_ROOT / engagement).mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
    wik3_dir = resolve_engagement_dir(engagement)
    run = latest_wik3_run(engagement) or {}
    all_findings = list_vulns(wik3_dir)
    # Para los contadores legacy (passive_total / active_total / etc.)
    # rompemos los findings por fase desde el campo `phase` del meta.
    passive_findings = [f for f in all_findings if f.get("phase") == "passive"]
    active_findings = [f for f in all_findings if f.get("phase") == "active"]
    validated_findings = [f for f in all_findings if f.get("phase") == "validated"]
    chains = read_json(wik3_dir / "validated" / "chains.json") or []
    queue = read_jsonl(wik3_dir / "discovery" / "queue.jsonl")
    rejected = read_jsonl(wik3_dir / "discovery" / "rejected.jsonl")
    vault = read_jsonl(wik3_dir / "creds" / "vault.jsonl")
    notes = read_jsonl(wik3_dir / "notes.jsonl")

    ss_dir = wik3_dir / "evidence" / "screenshots"
    screenshots = []
    if ss_dir.exists():
        for png in sorted(ss_dir.glob("*.png")):
            fid = png.stem
            cap_path = ss_dir / f"{fid}.caption.txt"
            caption = cap_path.read_text().strip().splitlines()[0] if cap_path.exists() else ""
            screenshots.append({"fid": fid, "file": png.name, "caption": caption})

    by_iter: dict[str, int] = {}
    by_source: dict[str, int] = {}
    by_kind: dict[str, int] = {}
    for e in queue:
        it = str(e.get("iteration", "?"))
        by_iter[it] = by_iter.get(it, 0) + 1
        src = e.get("source", "?").split(":")[0]
        by_source[src] = by_source.get(src, 0) + 1
        by_kind[e.get("kind", "?")] = by_kind.get(e.get("kind", "?"), 0) + 1

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    chains_sorted = sorted(
        chains,
        key=lambda c: (sev_order.get((c.get("severity") or "").lower(), 9), c.get("id", "")),
    )

    vault_safe = []
    for v in vault:
        vault_safe.append({
            "id": v.get("id"),
            "kind": v.get("kind"),
            "role": v.get("role"),
            "source": v.get("source"),
            "via": v.get("via"),
            "status": (v.get("lifecycle") or {}).get("status"),
            "allow": len((v.get("usable_on") or {}).get("endpoints_allow") or []),
            "deny": len((v.get("usable_on") or {}).get("endpoints_deny") or []),
            "hosts": (v.get("usable_on") or {}).get("hosts") or [],
        })

    reviewed_validated = [f for f in all_findings if (f.get("review") or {}).get("status") == "validated"]
    return {
        "run": run,
        "report_tab_enabled": _report_tab_enabled(),
        "engagement": engagement or "current",
        "iteration": current_iteration(wik3_dir),
        "current_node": current_node(wik3_dir),
        # `running` confiable vía systemd: el objeto run de fabro a veces trae
        # status=None, así que el dashboard NO debe gatear en run.status para
        # badges/indicadores (thinking, nodo+iteración).
        "running": _is_unit_active(engagement) if (engagement and engagement != "current") else bool(_active_run_slug()),
        "findings": {
            "passive_total": len(passive_findings),
            "active_total": len(active_findings),
            "validated_total": len(validated_findings),
            "validated_by_severity": severity_count(validated_findings),
            "passive_by_severity": severity_count(passive_findings),
            "active_by_severity": severity_count(active_findings),
            "review_by_status": count_review_status(all_findings),
            "human_validated_by_severity": severity_count(reviewed_validated),
            "human_validated_total": len(reviewed_validated),
        },
        "chains": chains_sorted,
        "chains_by_severity": severity_count(chains),
        "discovery": {
            "total": len(queue),
            "rejected": len(rejected),
            "by_iter": by_iter,
            "by_source": by_source,
            "by_kind": by_kind,
            "recent": queue[-10:][::-1],
        },
        "vault": vault_safe,
        "screenshots": screenshots,
        "convo": read_convo(wik3_dir),
        "notes": notes[-100:],
        "all_findings": all_findings,
        "has_memory": (wik3_dir / "memory.md").is_file(),
        "has_threat_model": (wik3_dir / "threat_model.md").is_file(),
    }


def _merge_findings(passive: list, active: list, validated: list) -> list:
    merged: dict[str, dict] = {}
    for f in passive:
        fid = f.get("id") or ""
        merged[fid] = dict(f, phase="passive")
    for f in active:
        fid = f.get("id") or ""
        merged[fid] = dict(f, phase="active")
    for f in validated:
        fid = f.get("id") or ""
        existing = merged.get(fid, {})
        merged[fid] = dict(existing, **f, phase="validated")
    for fid, f in merged.items():
        f["review"] = normalize_review(f)
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
    return sorted(
        merged.values(),
        key=lambda f: (sev_order.get((f.get("severity") or "unknown").lower(), 9), f.get("id", "")),
    )


_SCOPE_REQUEST_RE = re.compile(
    r"^SCOPE_REQUEST:\s*(?P<add>[^\n]+)(?:\s*\n\s*RAZ[ÓO]N:\s*(?P<reason>.+))?$",
    re.DOTALL,
)


def parse_scope_request(text: str) -> dict | None:
    """Si el texto pendiente del agente es un SCOPE_REQUEST estructurado,
    devuelve {add, reason}. Sino None."""
    if not text or not text.lstrip().startswith("SCOPE_REQUEST:"):
        return None
    m = _SCOPE_REQUEST_RE.match(text.strip())
    if not m:
        # Igual lo marcamos como scope_request aunque la razón falte —
        # mejor mostrarlo destacado que perder la señal.
        first_line = text.strip().splitlines()[0]
        return {"add": first_line[len("SCOPE_REQUEST:"):].strip(), "reason": ""}
    return {"add": m.group("add").strip(), "reason": (m.group("reason") or "").strip()}


def _update_engagement_scope_yaml(slug: str, host: str) -> str:
    """Appendea `host` a .scope.domains del YAML del engagement (idempotente).
    Sin esto, squid-allowlist.sh regenera el allowlist desde el YAML y
    pierde el host agregado en runtime. Devuelve string de warning si
    algo falló (vacío si todo OK)."""
    yaml_path = _engagement_path(slug)
    if not yaml_path.is_file():
        return f"(WARN: no encontré {yaml_path})"
    try:
        parsed = _parse_yaml_safe(yaml_path.read_text())
        if parsed is None:
            return "(WARN: YAML del engagement no parsea)"
        parsed.setdefault("scope", {}).setdefault("domains", [])
        domains = parsed["scope"]["domains"]
        changed = False
        if host not in domains:
            domains.append(host)
            changed = True
        # Si el host estaba en out_of_scope, sacarlo: si no, OOS gana sobre el
        # scope y el host seguiría bloqueado pese a la aprobación.
        oos = parsed["scope"].get("out_of_scope")
        if isinstance(oos, list) and host in oos:
            parsed["scope"]["out_of_scope"] = [h for h in oos if h != host]
            changed = True
        if changed:
            yaml_path.write_text(_dump_yaml(parsed))
        return ""
    except Exception as e:
        return f"(WARN: no pude actualizar el YAML: {e})"


# ─── Edición manual del scope desde la UI ───────────────────────────────────
# El hacker puede modificar scope.txt y out_of_scope.txt desde el dashboard
# (GET/POST /api/scope). Wildcards "*.X" se aceptan en input por costumbre
# pero se normalizan a "X" — el scope_guard ya hace match parent por design.
def _normalize_scope_entry(entry: str) -> str:
    s = (entry or "").strip()
    # strip trailing inline comment
    if "#" in s:
        s = s.split("#", 1)[0].rstrip()
    # Preservamos el prefijo "*." tal cual lo escribe el operador: es más claro
    # para el hacker ("*.example.com" comunica que cubre subdominios). El
    # matching (scope_host_of en _common.sh) trata "*.foo" igual que "foo"
    # (apex + subdominios), así que la cobertura no cambia.
    return s.lower()


def _bare_host(entry: str) -> str:
    """Reduce una URL/host (ej 'https://app3.foo.com:443/path?x') a su host
    pelado ('app3.foo.com'). Quita esquema, userinfo, puerto, path/query/fragment
    y el prefijo wildcard '*.'. Devuelve '' si no parece un host válido. Se usa
    para meter al scope los hosts EXACTOS de los `affected` de las vulns y de las
    páginas de login — así squid (dstdomain exact-match) los deja pasar."""
    s = (entry or "").strip().lower()
    if not s:
        return ""
    s = re.sub(r"^\*\.", "", s)          # *.foo.com -> foo.com
    s = re.sub(r"^[a-z][a-z0-9+.-]*://", "", s)  # esquema
    s = s.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    s = s.split("@")[-1]                 # userinfo
    s = s.split(":", 1)[0]               # puerto
    return s if re.match(r"^[a-z0-9.-]+\.[a-z0-9.-]+$", s) else ""


def _read_scope_list(path: Path) -> list[str]:
    """Lee un archivo tipo scope.txt y devuelve entries únicos preservando
    orden de aparición. Ignora líneas vacías y comentarios."""
    if not path.is_file():
        return []
    out: list[str] = []
    seen: set[str] = set()
    for line in path.read_text().splitlines():
        e = _normalize_scope_entry(line)
        if not e or e in seen:
            continue
        seen.add(e)
        out.append(e)
    return out


def _write_scope_list(path: Path, entries: list[str]) -> None:
    """Reescribe el archivo entero con las entries normalizadas + dedupe."""
    cleaned: list[str] = []
    seen: set[str] = set()
    for e in entries:
        n = _normalize_scope_entry(e)
        if not n or n in seen:
            continue
        seen.add(n)
        cleaned.append(n)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(cleaned) + ("\n" if cleaned else ""))


def _replace_engagement_scope_yaml(slug: str, domains: list[str], out_of_scope: list[str]) -> str:
    """Reemplaza completo scope.domains y out_of_scope del YAML del engagement.
    Como _update_engagement_scope_yaml pero para bulk edit desde la UI."""
    yaml_path = _engagement_path(slug)
    if not yaml_path.is_file():
        return f"(WARN: no encontré {yaml_path})"
    try:
        parsed = _parse_yaml_safe(yaml_path.read_text())
        if parsed is None:
            return "(WARN: YAML del engagement no parsea)"
        parsed.setdefault("scope", {})["domains"] = list(domains)
        if out_of_scope:
            parsed["scope"]["out_of_scope"] = list(out_of_scope)
        else:
            parsed["scope"].pop("out_of_scope", None)
        yaml_path.write_text(_dump_yaml(parsed))
        return ""
    except Exception as e:
        return f"(WARN: no pude actualizar el YAML: {e})"


def _refresh_squid_allowlist(slug: str) -> str:
    """Corre squid-allowlist.sh <slug> que regenera /etc/squid/allowed_hosts.txt
    desde el YAML del engagement y hace reload de squid. Sin esto, los hosts
    recién aprobados pasan el scope_guard del agente pero squid los bloquea
    con 403. Devuelve warning si algo falló."""
    script = Path("/opt/wik3/bin/squid-allowlist.sh")
    if not script.is_file():
        # local-dev (sin /opt/wik3/bin/...): no-op silencioso, no es error.
        return ""
    try:
        result = subprocess.run(
            [str(script), slug], capture_output=True, text=True, timeout=15,
        )
        if result.returncode != 0:
            return f"(WARN: squid-allowlist exit {result.returncode}: {result.stderr.strip()[:200]})"
        return ""
    except subprocess.TimeoutExpired:
        return "(WARN: squid-allowlist timeout)"
    except Exception as e:
        return f"(WARN: squid-allowlist falló: {e})"


def read_convo(wik3_dir: Path) -> dict:
    convo_dir = wik3_dir / "convo"
    log = read_jsonl(convo_dir / "log.jsonl")
    pending_path = convo_dir / "pending_agent.txt"
    pending = ""
    if pending_path.exists():
        try:
            pending = pending_path.read_text().strip()
        except Exception:
            pending = ""
    scope_request = parse_scope_request(pending) if pending else None
    return {
        "log": log[-30:],
        "pending_question": pending if pending else None,
        "scope_request": scope_request,
    }


# ════════════════════════════════════════════════════════════════════════════
# HTTP Handler
# ════════════════════════════════════════════════════════════════════════════

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    # ── auth ──────────────────────────────────────────────────────────────
    def _check_auth(self) -> bool:
        if not BOX_PASSWORD:
            return True
        hdr = self.headers.get("Authorization", "")
        if hdr.startswith("Basic "):
            try:
                decoded = base64.b64decode(hdr[6:]).decode("utf-8", errors="replace")
                _, _, sent = decoded.partition(":")
                if hmac.compare_digest(sent, BOX_PASSWORD):
                    return True
            except Exception:
                pass
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="wik3-box"')
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"Authentication required\n")
        return False

    def _auth_actor(self) -> str:
        hdr = self.headers.get("Authorization", "")
        if hdr.startswith("Basic "):
            try:
                decoded = base64.b64decode(hdr[6:]).decode("utf-8", errors="replace")
                user, _, _ = decoded.partition(":")
                return user
            except Exception:
                return ""
        return BOX_HACKER_EMAIL or ""

    def _check_admin_auth(self) -> bool:
        # En dev-local (sin BOX_PASSWORD) no hay auth — admin abierto.
        if not BOX_PASSWORD:
            return True
        if not ADMIN_TOKEN:
            self._json(
                {"error": "admin deshabilitado en esta wik3 (sin metadata 'admin-token')"},
                code=503,
            )
            return False
        hdr = self.headers.get("Authorization", "")
        if hdr.startswith("Bearer "):
            sent = hdr[7:].strip()
            try:
                if hmac.compare_digest(sent, ADMIN_TOKEN):
                    return True
            except Exception:
                pass
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Bearer realm="wik3-admin"')
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"error":"admin bearer token required"}\n')
        return False

    # ── helpers ───────────────────────────────────────────────────────────
    def _json(self, obj, code: int = 200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0") or "0")
        return self.rfile.read(length) if length else b""

    def _read_json_body(self) -> dict:
        try:
            return json.loads(self._read_body().decode("utf-8") or "{}")
        except Exception:
            return {}

    # ── slug routing ──────────────────────────────────────────────────────
    @staticmethod
    def _match_engagement_path(path: str) -> tuple[str, str | None]:
        """Devuelve (action, slug). action ∈ {list, item, run, stop, draft, '' (no match)}.
        Acepta tanto /api/engagements/* (hacker, basic-auth) como
        /admin/engagements/* (admin, bearer token)."""
        for prefix in ("/api/engagements", "/admin/engagements"):
            if path == prefix:
                return ("list", None)
            if path == f"{prefix}/draft":
                return ("draft", None)
            m = re.match(rf"^{re.escape(prefix)}/([a-z0-9][a-z0-9-]{{0,40}})(?:/(run|stop))?$", path)
            if m:
                slug = m.group(1)
                sub = m.group(2)
                if sub == "run":
                    return ("run", slug)
                if sub == "stop":
                    return ("stop", slug)
                return ("item", slug)
        return ("", None)

    # ── POST ──────────────────────────────────────────────────────────────
    def do_POST(self):
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(self.path)
        if parsed.path.startswith("/admin"):
            if not self._check_admin_auth():
                return
        elif not self._check_auth():
            return
        qs = parse_qs(parsed.query)
        engagement = (qs.get("engagement") or ["current"])[0]

        action, slug = self._match_engagement_path(parsed.path)

        if action == "draft":
            self._handle_draft()
            return
        if action == "list":
            self._handle_create_engagement()
            return
        if action == "run" and slug:
            self._handle_run(slug)
            return
        if action == "stop" and slug:
            self._handle_stop(slug)
            return

        # Revisión humana de finding: POST /api/findings/<fid>/review
        m = re.match(r"^/api/findings/([A-Za-z0-9_.\-]+)/review$", parsed.path)
        if m:
            self._handle_review_finding(engagement, m.group(1))
            return

        # Mensajes del admin (bearer): POST /admin/messages
        if parsed.path == "/admin/messages":
            self._handle_admin_message_post()
            return
        # Tabla del equipo (bearer): POST /admin/team
        if parsed.path == "/admin/team":
            self._handle_admin_team_post()
            return
        # Recibir un engagement movido desde otra wik3 (bearer): POST /admin/engagement-import
        if parsed.path == "/admin/engagement-import":
            if not self._check_admin_auth():
                return
            self._handle_admin_engagement_import()
            return
        # Marcar mensaje como leido (basic auth)
        m = re.match(r"^/api/messages/([a-f0-9]{16})/read$", parsed.path)
        if m:
            self._handle_message_mark_read(m.group(1))
            return

        # Scope expansion (aprobación / rechazo del operador a SCOPE_REQUEST)
        if parsed.path == "/api/scope/approve":
            self._handle_scope_decision(engagement, approve=True)
            return
        if parsed.path == "/api/scope/reject":
            self._handle_scope_decision(engagement, approve=False)
            return
        # Edición manual del scope desde la UI (bulk replace).
        if parsed.path == "/api/scope/update":
            self._handle_scope_update(engagement)
            return

        if parsed.path == "/api/branding/setup":
            body = self._read_json_body()
            name = (body.get("name") or "").strip()
            logo_b64 = (body.get("logo_b64") or "").strip()
            logo_ct = (body.get("logo_content_type") or "").strip()
            bg_b64 = (body.get("bg_b64") or "").strip()
            bg_ct = (body.get("bg_content_type") or "").strip()
            palette = body.get("palette") or {}
            if not name:
                self._json({"error": "name es obligatorio"}, code=400); return
            if len(name) > 80:
                self._json({"error": "name max 80 chars"}, code=400); return
            try:
                write_brand(name, logo_b64, logo_ct, bg_b64, bg_ct, palette, self._auth_actor())
            except ValueError as e:
                self._json({"error": str(e)}, code=400); return
            except Exception as e:
                self._json({"error": f"no pude guardar el branding: {e}"}, code=500); return
            self._json({"ok": True, **read_brand()})
            return

        # Import reporte + retest run.
        m = re.match(r"^/api/engagements/([a-z0-9][a-z0-9-]{0,40})/import$", parsed.path)
        if m:
            self._handle_import_report(m.group(1))
            return
        m = re.match(r"^/api/engagements/([a-z0-9][a-z0-9-]{0,40})/retest/run$", parsed.path)
        if m:
            self._handle_retest_run(m.group(1))
            return
        m = re.match(r"^/api/engagements/([a-z0-9][a-z0-9-]{0,40})/retest/regenerate-all$", parsed.path)
        if m:
            self._handle_retest_regenerate_all(m.group(1))
            return
        # Generar retest.py o exploit.md con LLM
        # POST /api/engagements/<slug>/vulns/<vid>/generate?name=retest.py
        m = re.match(r"^/api/engagements/([a-z0-9][a-z0-9-]{0,40})/vulns/([A-Z]-[A-Za-z0-9_.\-]+)/generate$", parsed.path)
        if m:
            name = (qs.get("name") or [""])[0]
            self._handle_vuln_file_generate(m.group(1), m.group(2), name)
            return
        # Correr el retest.py de UNA vuln (desde el modal de la vuln).
        m = re.match(r"^/api/engagements/([a-z0-9][a-z0-9-]{0,40})/vulns/([A-Z]-[A-Za-z0-9_.\-]+)/retest/run$", parsed.path)
        if m:
            self._handle_vuln_retest_run(m.group(1), m.group(2))
            return
        # Auto-generar la descripción ("¿Qué es?") de UNA vuln cuando falta.
        # POST /api/engagements/<slug>/vulns/<vid>/describe
        m = re.match(r"^/api/engagements/([a-z0-9][a-z0-9-]{0,40})/vulns/([A-Z]-[A-Za-z0-9_.\-]+)/describe$", parsed.path)
        if m:
            self._handle_vuln_describe(m.group(1), m.group(2))
            return
        # Chat por-vuln (modal "hablar con la vuln"): POST .../vulns/<vid>/chat
        m = re.match(r"^/api/engagements/([a-z0-9][a-z0-9-]{0,40})/vulns/([A-Z]-[A-Za-z0-9_.\-]+)/chat$", parsed.path)
        if m:
            self._handle_vuln_chat_post(m.group(1), m.group(2))
            return
        # "¿Cómo reportarla?": POST .../vulns/<vid>/report-howto — clasifica el
        # template más parecido y genera el markdown de reporte de la vuln.
        m = re.match(r"^/api/engagements/([a-z0-9][a-z0-9-]{0,40})/vulns/([A-Z]-[A-Za-z0-9_.\-]+)/report-howto$", parsed.path)
        if m:
            self._handle_vuln_report_howto(m.group(1), m.group(2))
            return
        # Reporte completo (tab Reporte): POST genera el markdown on-demand.
        m = re.match(r"^/api/engagements/([a-z0-9][a-z0-9-]{0,40})/report/markdown$", parsed.path)
        if m:
            self._handle_report_markdown(m.group(1))
            return
        # Borrado en bloque de vulns (checkbox + Borrar): POST .../vulns/delete
        m = re.match(r"^/api/engagements/([a-z0-9][a-z0-9-]{0,40})/vulns/delete$", parsed.path)
        if m:
            self._handle_vuln_bulk_delete(m.group(1))
            return
        # Retest agéntico (checkbox + Retest): POST .../retest-run {ids}
        m = re.match(r"^/api/engagements/([a-z0-9][a-z0-9-]{0,40})/retest-run$", parsed.path)
        if m:
            self._handle_agentic_retest(m.group(1))
            return

        # Borrador de una vuln manual: texto libre → LLM → JSON estructurado
        # POST /api/engagements/<slug>/vulns/draft
        m = re.match(r"^/api/engagements/([a-z0-9][a-z0-9-]{0,40})/vulns/draft$", parsed.path)
        if m:
            self._handle_vuln_manual_draft(m.group(1))
            return

        # Persistir una vuln manual con los campos editados por el operador.
        # POST /api/engagements/<slug>/vulns/manual
        m = re.match(r"^/api/engagements/([a-z0-9][a-z0-9-]{0,40})/vulns/manual$", parsed.path)
        if m:
            self._handle_vuln_manual_create(m.group(1))
            return

        # Chat con Opus 4.7 (tool use: read_engagement_file +
        # message_running_agent). Funciona running o stopped.
        # POST /api/engagements/<slug>/chat
        m = re.match(r"^/api/engagements/([a-z0-9][a-z0-9-]{0,40})/chat$", parsed.path)
        if m:
            self._handle_chat_message(m.group(1))
            return

        # whisper / upload (sin cambios)
        if parsed.path == "/api/whisper":
            self._handle_whisper(engagement)
            return
        if parsed.path == "/api/upload":
            self._handle_upload(engagement)
            return
        self.send_error(404)

    # ── PUT / DELETE ──────────────────────────────────────────────────────
    def do_PUT(self):
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(self.path)
        if parsed.path.startswith("/admin"):
            if not self._check_admin_auth():
                return
        elif not self._check_auth():
            return
        action, slug = self._match_engagement_path(parsed.path)
        if action == "item" and slug:
            self._handle_update_engagement(slug)
            return
        # PUT /api/engagements/<slug>/vulns/<vid>/file?name=retest.py
        m = re.match(r"^/api/engagements/([a-z0-9][a-z0-9-]{0,40})/vulns/(V-[A-Za-z0-9_.\-]+)/file$", parsed.path)
        if m:
            qs = parse_qs(parsed.query)
            name = (qs.get("name") or [""])[0]
            self._handle_vuln_file_put(m.group(1), m.group(2), name)
            return
        # PUT /api/engagements/<slug>/retest/creds — guarda env vars para retest.
        m = re.match(r"^/api/engagements/([a-z0-9][a-z0-9-]{0,40})/retest/creds$", parsed.path)
        if m:
            self._handle_retest_creds_put(m.group(1))
            return
        self.send_error(404)

    def do_DELETE(self):
        from urllib.parse import urlparse
        parsed = urlparse(self.path)
        if parsed.path.startswith("/admin"):
            if not self._check_admin_auth():
                return
        elif not self._check_auth():
            return
        action, slug = self._match_engagement_path(parsed.path)
        if action == "item" and slug:
            self._handle_delete_engagement(slug)
            return
        self.send_error(404)

    # ── GET ───────────────────────────────────────────────────────────────
    def do_GET(self):
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(self.path)
        is_admin = parsed.path.startswith("/admin")
        if is_admin:
            if not self._check_admin_auth():
                return
        elif not self._check_auth():
            return
        qs = parse_qs(parsed.query)
        engagement = (qs.get("engagement") or ["current"])[0]

        # Pestaña Equipo del TL (auth hacker): GET /api/team
        if parsed.path == "/api/team":
            self._handle_team_get()
            return

        action, slug = self._match_engagement_path(parsed.path)
        if action == "list":
            self._json({
                "engagements": list_engagements_with_meta(),
                "active_run": _active_run_slug(),
            })
            return
        if action == "item" and slug:
            self._handle_get_engagement(slug)
            return

        # Endpoints solo bajo /admin/* — admin los consume para métricas.
        if is_admin and parsed.path == "/admin/state":
            self._json(aggregate_state(engagement))
            return
        if is_admin and parsed.path == "/admin/summary":
            self._handle_admin_summary()
            return
        if is_admin and parsed.path == "/admin/findings-export":
            self._handle_admin_findings_export()
            return
        if is_admin and parsed.path == "/admin/costs":
            self._handle_admin_costs()
            return
        # Exportar un engagement para moverlo a otra wik3: GET /admin/engagement-export?slug=
        if is_admin and parsed.path == "/admin/engagement-export":
            self._handle_admin_engagement_export(qs.get("slug", [""])[0])
            return

        if parsed.path == "/api/state":
            self._json(aggregate_state(engagement))
            return
        if parsed.path == "/api/branding":
            self._json(read_brand())
            return
        if parsed.path in ("/branding/logo", "/branding/bg"):
            kind = parsed.path.rsplit("/", 1)[-1]
            info = read_brand()
            if not info.get("has_" + kind):
                self.send_error(404); return
            try:
                bd = json.loads(BRAND_JSON_PATH.read_text())
                fn = bd.get(f"{kind}_filename") or ""
                fp = BRAND_DIR / fn
                if not fp.is_file():
                    self.send_error(404); return
                data = fp.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", bd.get(f"{kind}_content_type") or "image/png")
                self.send_header("Cache-Control", "public, max-age=300")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except Exception:
                self.send_error(500)
            return

        if parsed.path == "/api/box":
            burp_active = False
            try:
                burp_state_path = Path("/var/lib/wik3/burp-proxy-state")
                if burp_state_path.is_file():
                    burp_active = burp_state_path.read_text().strip() == "on"
            except Exception:
                pass
            self._json({
                "mode": "box" if BOX_PASSWORD else "local",
                "hacker_email": BOX_HACKER_EMAIL,
                "instance_name": BOX_INSTANCE_NAME,
                "instance_zone": BOX_INSTANCE_ZONE,
                "project_id": BOX_PROJECT_ID,
                "active_run": _active_run_slug(),
                "ttl_days": TTL_DAYS,
                "llm_available": bool(os.environ.get("ANTHROPIC_API_KEY", "").strip()),
                "burp_proxy_active": burp_active,
                "version": version_info(),
            })
            return
        if parsed.path == "/api/conversation":
            self._json(read_convo(resolve_engagement_dir(engagement)))
            return
        if parsed.path == "/api/scope":
            wik3_dir = resolve_engagement_dir(engagement)
            self._json({
                "scope": _read_scope_list(wik3_dir / "scope.txt"),
                "out_of_scope": _read_scope_list(wik3_dir / "out_of_scope.txt"),
            })
            return
        if parsed.path == "/api/attack-surface":
            wik3_dir = resolve_engagement_dir(engagement)
            label = engagement if engagement and engagement != "current" else wik3_dir.name
            self._json(build_attack_surface(wik3_dir, label))
            return
        if parsed.path == "/api/messages":
            unread_only = (qs.get("unread_only") or ["0"])[0] in ("1", "true")
            msgs = _read_messages()
            if unread_only:
                msgs = [m for m in msgs if not m.get("read_at")]
            self._json({"messages": msgs})
            return
        # GET /api/engagements/<slug>/vulns/<vid>/file?name=retest.py
        m = re.match(r"^/api/engagements/([a-z0-9][a-z0-9-]{0,40})/vulns/(V-[A-Za-z0-9_.\-]+)/file$", parsed.path)
        if m:
            name = (qs.get("name") or [""])[0]
            self._handle_vuln_file_get(m.group(1), m.group(2), name)
            return
        # Reporte completo: GET markdown existente / GET pdf generado.
        m = re.match(r"^/api/engagements/([a-z0-9][a-z0-9-]{0,40})/report/markdown$", parsed.path)
        if m:
            self._handle_report_markdown(m.group(1))
            return
        m = re.match(r"^/api/engagements/([a-z0-9][a-z0-9-]{0,40})/report/html$", parsed.path)
        if m:
            self._handle_report_html(m.group(1))
            return
        m = re.match(r"^/api/engagements/([a-z0-9][a-z0-9-]{0,40})/report/pdf$", parsed.path)
        if m:
            self._handle_report_pdf(m.group(1))
            return
        # Chat por-vuln (historial): GET /api/engagements/<slug>/vulns/<vid>/chat
        m = re.match(r"^/api/engagements/([a-z0-9][a-z0-9-]{0,40})/vulns/([A-Z]-[A-Za-z0-9_.\-]+)/chat$", parsed.path)
        if m:
            self._handle_vuln_chat_get(m.group(1), m.group(2))
            return
        # GET /api/engagements/<slug>/retest — history de runs.
        # También /admin/engagements/<slug>/retest (bearer) para el admin.
        m = re.match(r"^/(?:api|admin)/engagements/([a-z0-9][a-z0-9-]{0,40})/retest$", parsed.path)
        if m:
            self._handle_retest_history(m.group(1))
            return
        # GET /api/engagements/<slug>/retest/creds — devuelve KEYS (sin values).
        m = re.match(r"^/api/engagements/([a-z0-9][a-z0-9-]{0,40})/retest/creds$", parsed.path)
        if m:
            self._handle_retest_creds_get(m.group(1))
            return
        if parsed.path == "/api/doc":
            # Visor de docs markdown del engagement (memory.md / threat_model.md).
            # Whitelist estricta del nombre — sin path traversal.
            name = (qs.get("name") or [""])[0]
            if name not in ("memory.md", "threat_model.md"):
                self._json({"error": "doc no permitido"}, code=400)
                return
            doc_path = resolve_engagement_dir(engagement) / name
            exists = doc_path.is_file()
            content = ""
            if exists:
                try:
                    content = doc_path.read_text(encoding="utf-8", errors="replace")[:1_000_000]
                except Exception as e:
                    content = f"[error leyendo {name}: {e}]"
            self._json({"name": name, "exists": exists, "content": content})
            return
        if parsed.path == "/api/agent-log/search":
            # Búsqueda server-side sobre el exec.log COMPLETO (grep), así no hace
            # falta cargar todo el log en el browser para buscar. Devuelve nº de
            # línea + offset de byte (para saltar a la coincidencia con
            # center_byte) + el texto. grep sin shell (-- y args) → sin inyección.
            wik3_dir = resolve_engagement_dir(engagement)
            log_path = wik3_dir / "exec.log"
            q = (qs.get("q") or [""])[0]
            CAP = 500
            matches: list[dict] = []
            total = 0
            if q and log_path.is_file():
                try:
                    proc = subprocess.run(
                        ["grep", "-a", "-F", "-i", "-n", "-b", "--", q, str(log_path)],
                        capture_output=True, text=True, errors="replace", timeout=30,
                    )
                    for ln in proc.stdout.splitlines():
                        total += 1
                        if len(matches) >= CAP:
                            continue
                        p1 = ln.find(":")
                        p2 = ln.find(":", p1 + 1) if p1 >= 0 else -1
                        if p1 < 0 or p2 < 0:
                            continue
                        try:
                            line_no = int(ln[:p1]); byte_off = int(ln[p1 + 1:p2])
                        except ValueError:
                            continue
                        matches.append({"line": line_no, "byte": byte_off, "text": ln[p2 + 1:][:300]})
                except Exception:
                    pass
            self._json({"matches": matches, "total": total, "capped": total > CAP, "query": q})
            return

        if parsed.path == "/api/agent-log":
            # Per-slug: el logger BASH_ENV escribe a /workspace/wik3/<slug>/
            # exec.log resolviendo el slug en cada bash -c.
            # Servimos una VENTANA del log, no el archivo entero (cargar decenas
            # de MB trababa el tab por el túnel IAP + render del DOM):
            #   - por defecto: la cola (últimos tail_mb MB, default 4).
            #   - tail_mb=N: agranda la ventana ("cargar más arriba").
            #   - center_byte=N: centra la ventana en ese offset (saltar a una
            #     coincidencia de /api/agent-log/search).
            wik3_dir = resolve_engagement_dir(engagement)
            log_path = wik3_dir / "exec.log"
            try:
                tail_mb = int((qs.get("tail_mb") or ["4"])[0])
            except ValueError:
                tail_mb = 4
            tail_mb = max(1, min(tail_mb, 64))
            win = tail_mb * 1024 * 1024
            center_byte = None
            try:
                if qs.get("center_byte"):
                    center_byte = int(qs["center_byte"][0])
            except ValueError:
                center_byte = None
            active = log_path.is_file()
            lines: list[str] = []
            size = 0
            start_byte = 0
            truncated = False
            if active:
                try:
                    size = log_path.stat().st_size
                    if center_byte is not None:
                        start = max(0, center_byte - win // 2)
                    else:
                        start = max(0, size - win)
                    with log_path.open("rb") as f:
                        f.seek(start)
                        if start > 0:
                            f.readline()  # descarta primera línea parcial
                        start_byte = f.tell()
                        raw = f.read(win).decode("utf-8", errors="replace")
                    truncated = start_byte > 0
                    lines = raw.splitlines()
                except Exception as e:
                    lines = [f"[wik3-dashboard] error reading exec.log: {e}"]
            self._json({
                "lines": lines,
                "active": active,
                "size_bytes": size,
                "truncated": truncated,
                "start_byte": start_byte,
                "tail_mb": tail_mb,
                "path": str(log_path),
            })
            return
        if parsed.path == "/api/download":
            self._handle_download(qs, engagement)
            return
        if parsed.path == "/api/results-bundle":
            self._handle_results_bundle(engagement)
            return
        if parsed.path == "/api/attacks":
            self._handle_attacks_export(engagement)
            return
        if parsed.path == "/burp-ca.crt":
            self._handle_burp_ca_cert()
            return
        if parsed.path == "/burp-ca.p12":
            self._handle_burp_ca_p12()
            return
        if parsed.path.startswith("/screenshots/"):
            self._handle_screenshot(parsed.path, engagement)
            return
        if parsed.path in {"/", "/index.html"}:
            html = (SCRIPT_DIR / "dashboard.html").read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(html)
            return
        self.send_error(404)

    # ── handlers: engagement CRUD ────────────────────────────────────────
    def _handle_draft(self):
        body = self._read_json_body()
        prompt = (body.get("prompt") or "").strip()
        prior_yaml = body.get("prior_yaml")
        types_hint_raw = body.get("types_hint")
        types_hint: list[str] = []
        if isinstance(types_hint_raw, list):
            valid_types = {"blackbox", "webapp", "mobile", "internal", "cloud"}
            types_hint = [t for t in types_hint_raw if isinstance(t, str) and t in valid_types]
        if not prompt:
            self._json({"error": "prompt vacío"}, code=400)
            return
        try:
            data = _llm_generate(prompt, prior_yaml, types_hint=types_hint or None)
        except Exception as e:
            self._json({"error": f"LLM: {e}"}, code=502)
            return
        parsed = _parse_yaml_safe(data["yaml"])
        if parsed is None:
            self._json({"error": "el YAML generado no parsea", "yaml": data["yaml"]}, code=500)
            return
        # No persistimos todavía: el operador puede editar antes de aprobar.
        self._json({
            "slug": data["slug"],
            "yaml": data["yaml"],
            "parsed": parsed,
            "summary": data["summary"],
        })

    def _handle_create_engagement(self):
        body = self._read_json_body()
        slug = (body.get("slug") or "").strip()
        yaml_text = body.get("yaml") or ""
        parsed_in = body.get("parsed")
        display_name = (body.get("display_name") or "").strip() or slug
        if not SLUG_RE.match(slug):
            self._json({"error": "slug inválido"}, code=400)
            return
        if _engagement_path(slug).exists():
            self._json({"error": f"ya existe engagement {slug!r}"}, code=409)
            return

        if parsed_in is not None:
            try:
                yaml_text = _dump_yaml(parsed_in)
            except Exception as e:
                self._json({"error": f"no pude serializar parsed: {e}"}, code=400)
                return
            parsed = parsed_in
        else:
            parsed = _parse_yaml_safe(yaml_text)
            if parsed is None:
                self._json({"error": "yaml inválido (no parsea)"}, code=400)
                return

        errors = _validate_engagement(parsed)
        if errors:
            self._json({"error": "config inválida", "errors": errors}, code=400)
            return

        # Defaults seguros: siempre inyectamos en el YAML los campos de
        # safety + started_at si no vinieron explícitos. Read-only es el
        # default — el agente no destruye ni modifica datos salvo que el
        # operador lo desactive a mano.
        today = dt.date.today().isoformat()
        mutated = False
        if "started_at" not in parsed:
            parsed["started_at"] = today
            mutated = True
        if "safety" not in parsed or not isinstance(parsed.get("safety"), dict):
            parsed["safety"] = {"read_only_mode": True}
            mutated = True
        elif "read_only_mode" not in parsed["safety"]:
            parsed["safety"]["read_only_mode"] = True
            mutated = True
        if mutated:
            yaml_text = _dump_yaml(parsed)

        ENGAGEMENTS_DIR.mkdir(parents=True, exist_ok=True)
        _engagement_path(slug).write_text(yaml_text)
        _write_meta(slug, {
            "slug": slug,
            "display_name": display_name,
            "created_at": _now_iso(),
            "started_at": parsed.get("started_at", today),
            "read_only_mode": _is_read_only(parsed),
            "ttl_days": TTL_DAYS,
        })
        # Workspace dir (vacío) — sin esto, importar reportes, editar scope o
        # cualquier acción que use resolve_engagement_dir falla con 404 hasta
        # que el agente corre `load_engagement.sh` por primera vez.
        # `load_engagement.sh` también la crea — esta operación es idempotente.
        try:
            wik3_dir = WIK3_ROOT / slug
            wik3_dir.mkdir(parents=True, exist_ok=True)
            # Escribir scope.txt + out_of_scope.txt desde el YAML — el endpoint
            # GET /api/scope los lee de ahí, no del YAML. Sin esto el panel
            # aparece vacío hasta que el agente arranque y load_engagement.sh
            # los cree. load_engagement.sh los reescribe igual al arrancar, así
            # que escribirlos aquí es idempotente respecto al primer run.
            scope = parsed.get("scope") or {}
            domains = [d for d in (scope.get("domains") or []) if isinstance(d, str) and d.strip()]
            ips = [i for i in (scope.get("ips") or []) if isinstance(i, str) and i.strip()]
            urls = [u for u in (scope.get("urls") or []) if isinstance(u, str) and u.strip()]
            out_of_scope = [o for o in (scope.get("out_of_scope") or []) if isinstance(o, str) and o.strip()]
            _write_scope_list(wik3_dir / "scope.txt", domains + ips + urls)
            _write_scope_list(wik3_dir / "out_of_scope.txt", out_of_scope)
        except Exception:
            pass
        self._json({"ok": True, "slug": slug}, code=201)

    def _handle_get_engagement(self, slug: str):
        path = _engagement_path(slug)
        if not path.exists():
            self._json({"error": "no existe"}, code=404)
            return
        yaml_text = path.read_text()
        parsed = _parse_yaml_safe(yaml_text)
        meta = _read_meta(slug)
        self._json({
            "slug": slug,
            "yaml": yaml_text,
            "parsed": parsed,
            "meta": meta,
            "is_running": _is_unit_active(slug),
        })

    def _handle_update_engagement(self, slug: str):
        path = _engagement_path(slug)
        if not path.exists():
            self._json({"error": "no existe"}, code=404)
            return
        if _is_unit_active(slug):
            self._json({"error": "engagement está corriendo, parar primero"}, code=409)
            return
        body = self._read_json_body()
        parsed_in = body.get("parsed")
        yaml_text = body.get("yaml")
        if parsed_in is not None:
            try:
                yaml_text = _dump_yaml(parsed_in)
            except Exception as e:
                self._json({"error": f"no pude serializar parsed: {e}"}, code=400)
                return
            parsed = parsed_in
        elif yaml_text is not None:
            parsed = _parse_yaml_safe(yaml_text)
            if parsed is None:
                self._json({"error": "yaml inválido (no parsea)"}, code=400)
                return
        else:
            self._json({"error": "falta parsed o yaml"}, code=400)
            return

        errors = _validate_engagement(parsed)
        if errors:
            self._json({"error": "config inválida", "errors": errors}, code=400)
            return

        path.write_text(yaml_text)
        meta = _read_meta(slug)
        if "display_name" in body:
            meta["display_name"] = (body.get("display_name") or "").strip() or slug
        # Sincronizar campos derivados del YAML
        meta["read_only_mode"] = _is_read_only(parsed)
        if parsed.get("started_at"):
            meta["started_at"] = parsed["started_at"]
        _write_meta(slug, meta)
        self._json({"ok": True, "slug": slug})

    def _handle_delete_engagement(self, slug: str):
        if _is_unit_active(slug):
            self._json({"error": "engagement está corriendo, parar primero"}, code=409)
            return
        path = _engagement_path(slug)
        if not path.exists():
            self._json({"error": "no existe"}, code=404)
            return
        # Borra YAML + workspace + meta. Idempotente para residuos.
        try:
            path.unlink()
        except Exception:
            pass
        ws = WIK3_ROOT / slug
        if ws.is_dir():
            shutil.rmtree(ws, ignore_errors=True)
        meta_p = _meta_path(slug)
        if meta_p.exists():
            try:
                meta_p.unlink()
            except Exception:
                pass
        # Cleanup de residuos que antes sobrevivían al borrado (causaban units
        # 'failed' colgados, dirs parkeados huérfanos y el "slug X no existe" por
        # marker stale):
        # 1) copia parkeada (el delete no miraba PARK_DIR)
        try:
            parked = PARK_DIR / slug
            if parked.is_dir():
                shutil.rmtree(parked, ignore_errors=True)
        except Exception:
            pass
        # 2) unit systemd en 'failed' → reset-failed (si no, queda colgado)
        try:
            _systemctl("reset-failed", f"{UNIT_PREFIX}{slug}{UNIT_SUFFIX}", timeout=5)
        except Exception:
            pass
        # 3) symlink legacy 'current' + marker .active-slug, solo si apuntan al
        #    engagement que estamos borrando
        try:
            cur = WIK3_ROOT / "current"
            if cur.is_symlink() and os.readlink(cur) in (slug, str(WIK3_ROOT / slug)):
                cur.unlink()
        except Exception:
            pass
        try:
            marker = WIK3_ROOT / ".active-slug"
            if marker.is_file() and marker.read_text().strip() == slug:
                marker.unlink()
        except Exception:
            pass
        self._json({"ok": True, "slug": slug, "deleted": True})

    # ── mover engagement entre wik3s (lo orquesta el admin) ──────────────
    def _handle_admin_engagement_export(self, slug: str):
        """GET /admin/engagement-export?slug=  (bearer admin) — devuelve el yaml +
        un tar.gz del workspace (sin exec.log, que es enorme) en base64, para que
        el admin lo mueva a otra wik3. No borra nada acá (el delete va aparte)."""
        slug = (slug or "").strip()
        if not SLUG_RE.match(slug):
            self._json({"error": "slug inválido"}, code=400)
            return
        if _is_unit_active(slug):
            self._json({"error": "engagement está corriendo, parar primero"}, code=409)
            return
        yml = _engagement_path(slug)
        if not yml.exists():
            self._json({"error": "no existe"}, code=404)
            return
        ws = WIK3_ROOT / slug
        tar_b64 = ""
        try:
            if ws.is_dir():
                tmp = tempfile.NamedTemporaryFile(suffix=".tgz", delete=False).name
                subprocess.run(
                    ["tar", "czf", tmp, "--exclude=exec.log", "--exclude=*.tmp",
                     "-C", str(WIK3_ROOT), slug],
                    capture_output=True, timeout=180,
                )
                with open(tmp, "rb") as fh:
                    tar_b64 = base64.b64encode(fh.read()).decode()
                os.unlink(tmp)
        except Exception as e:
            self._json({"error": f"no pude empaquetar workspace: {e}"}, code=500)
            return
        self._json({
            "slug": slug,
            "yaml_b64": base64.b64encode(yml.read_bytes()).decode(),
            "tar_b64": tar_b64,
        })

    def _handle_admin_engagement_import(self):
        """POST /admin/engagement-import  (bearer admin) — recibe {slug, yaml_b64,
        tar_b64} y escribe el engagement en ESTA wik3. No pisa uno existente."""
        body = self._read_json_body() or {}
        slug = (body.get("slug") or "").strip()
        yaml_b64 = body.get("yaml_b64") or ""
        tar_b64 = body.get("tar_b64") or ""
        if not SLUG_RE.match(slug) or not yaml_b64:
            self._json({"error": "slug/yaml requeridos"}, code=400)
            return
        if _engagement_path(slug).exists() or (WIK3_ROOT / slug).exists():
            self._json({"error": f"ya existe un engagement '{slug}' en este box"}, code=409)
            return
        try:
            ENGAGEMENTS_DIR.mkdir(parents=True, exist_ok=True)
            _engagement_path(slug).write_bytes(base64.b64decode(yaml_b64))
            if tar_b64:
                WIK3_ROOT.mkdir(parents=True, exist_ok=True)
                tmp = tempfile.NamedTemporaryFile(suffix=".tgz", delete=False).name
                with open(tmp, "wb") as fh:
                    fh.write(base64.b64decode(tar_b64))
                subprocess.run(["tar", "xzf", tmp, "-C", str(WIK3_ROOT)],
                               capture_output=True, timeout=180)
                os.unlink(tmp)
        except Exception as e:
            self._json({"error": f"no pude importar: {e}"}, code=500)
            return
        self._json({"ok": True, "slug": slug, "imported": True})

    # ── handlers: run / stop ─────────────────────────────────────────────
    def _handle_run(self, slug: str):
        if not _engagement_path(slug).exists():
            self._json({"error": f"engagement {slug!r} no existe"}, code=404)
            return
        # Body opcional con hint: el operador puede pasar un mensaje libre
        # que el agente leerá al primer tool call. Útil para re-runs cuando
        # quieres direccionar al agente ("profundiza en mobile", "el cliente
        # desbloqueó IP X", "los retests de V-001/V-003 fallan, investigar").
        hint = ""
        body = {}
        try:
            body = self._read_json_body() or {}
            hint = (body.get("hint") or "").strip()
        except Exception:
            hint = ""
        # Config del modal de Run: max_iterations (default 2) + quick_test ("1
        # pasada rápida"). Se persisten al engagement.yaml — discovery_stats.sh
        # lee max_iterations cada iter y load_engagement escribe quick_test.txt
        # para que el workflow salte Senior Review en modo rápido. quick_test se
        # escribe SIEMPRE (true/false) para que un run completo resetee uno rápido
        # anterior.
        try:
            mi = body.get("max_iterations")
            quick = bool(body.get("quick"))
            p = _engagement_path(slug)
            cfg = _parse_yaml_safe(p.read_text()) or {}
            changed = False
            if mi is not None:
                mi = max(1, min(int(mi), 20))
                if cfg.get("max_iterations") != mi:
                    cfg["max_iterations"] = mi
                    changed = True
            if bool(cfg.get("quick_test")) != quick:
                cfg["quick_test"] = quick
                changed = True
            # "Explotar vulnerabilidades hasta el final" (default OFF). Se escribe
            # SIEMPRE (true/false) para que un run normal resetee uno anterior.
            etc = bool(body.get("exploit_to_completion"))
            if bool(cfg.get("exploit_to_completion")) != etc:
                cfg["exploit_to_completion"] = etc
                changed = True
            # Modo CTF (preset de benchmark, default OFF). load_engagement lo
            # coordina: fuerza exploit_to_completion ON y quick_test OFF.
            ctf = bool(body.get("ctf"))
            if bool(cfg.get("ctf")) != ctf:
                cfg["ctf"] = ctf
                changed = True
            if changed:
                p.write_text(_dump_yaml(cfg))
        except Exception:
            pass
        # Bloquear run si el scope esta vacio. Es valido crear engagements
        # sin scope (para importar reportes despues), pero correr el workflow
        # contra nada no tiene sentido.
        try:
            parsed = _parse_yaml_safe(_engagement_path(slug).read_text()) or {}
            scope = parsed.get("scope") or {}
            has_targets = any(
                isinstance(scope.get(k), list) and scope.get(k)
                for k in ("domains", "ips", "urls")
            )
            if not has_targets:
                self._json({
                    "error": "scope vacío — edita el engagement.yaml o importa un reporte antes de correr",
                }, code=409)
                return
        except Exception:
            pass
        active = _active_run_slug()
        if active and active != slug:
            self._json({
                "error": f"hay otro engagement corriendo: {active!r}",
                "active_slug": active,
            }, code=409)
            return
        if active == slug:
            self._json({"error": "ya está corriendo", "active_slug": slug}, code=409)
            return
        # Burp CA: el cert vive en /etc/wik3/burp-ca.crt (bakeada en la imagen
        # por setup.sh — ver scripts/wik3-burp-extract.sh). Lo copiamos a
        # WIK3_ROOT/.burp/ca.crt antes del `systemctl start`. Fabro mountea
        # la project root como /workspace en el container, así que el path
        # queda visible como /workspace/wik3/.burp/ca.crt — el prepare step
        # de workflow.toml lo instala con update-ca-certificates al inicio.
        host_cert = Path("/etc/wik3/burp-ca.crt")
        try:
            if host_cert.is_file() and host_cert.stat().st_size > 0:
                # (1) Para el container: copiar al workspace que Fabro
                # mountea como /workspace. El prepare step del workflow.toml
                # lo instala con update-ca-certificates al inicio del run.
                target_dir = WIK3_ROOT / ".burp"
                target_dir.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(host_cert, target_dir / "ca.crt")
                (target_dir / "ca.crt").chmod(0o644)
                # (2) Para el host: instalar en el trust store del sistema.
                # Sin esto, fabro CLI (que corre en el host y llama al LLM
                # via squid → Burp) ve un cert re-firmado por Burp y falla
                # con SSL_VERIFY_FAILED. update-ca-certificates --fresh es
                # idempotente — re-correrlo cuando el cert ya está
                # instalado es no-op.
                host_install = Path("/usr/local/share/ca-certificates/wik3-burp.crt")
                shutil.copyfile(host_cert, host_install)
                host_install.chmod(0o644)
                subprocess.run(
                    ["update-ca-certificates", "--fresh"],
                    capture_output=True, timeout=15,
                )
        except Exception as e:
            # No es fatal — el run arranca pero las llamadas via Burp van a
            # fallar TLS. Loggear y seguir.
            sys.stderr.write(f"[wik3-dashboard] WARN: no pude instalar burp-ca: {e}\n")

        # Hint: lo dejamos en convo/inbox.md ANTES del start. El scope_guard
        # del agente detecta inbox.md no vacío al primer tool call, lo mueve
        # a attention.md, bloquea el call, y el agente lee/procesa el msg
        # antes de seguir. Es el mismo mecanismo de "whisper" en runtime,
        # pero seteado pre-arranque.
        if hint:
            try:
                convo_dir = WIK3_ROOT / slug / "convo"
                convo_dir.mkdir(parents=True, exist_ok=True)
                inbox = convo_dir / "inbox.md"
                marker = "=== Operator hint (pre-run) ==="
                inbox.write_text(f"{marker}\n\n{hint}\n")
            except Exception as e:
                sys.stderr.write(f"[wik3-dashboard] WARN: no pude escribir hint: {e}\n")

        # Serialización: el aislamiento permite un solo engagement activo por VM.
        # Si OTRO run está realmente activo, devolver 409 claro en vez de dejar
        # fallar al checkout del ExecStartPre (que daría un 500 críptico).
        # Se consulta el estado REAL de systemd (_active_run_slug), no el marker
        # .active del parking — que puede quedar stale si un run falló sin liberar.
        active = _active_run_slug()
        if active and active != slug:
            self._json(
                {"error": f"engagement '{active}' ya está corriendo en esta VM — "
                          f"los runs se serializan (1 por VM). Detén ese run primero.",
                 "active_slug": active},
                code=409,
            )
            return

        # Run NORMAL: borra cualquier manifiesto de retest para que NO se trate
        # como retest (el gate del workflow es determinístico por ese archivo).
        try:
            (resolve_engagement_dir(slug) / "retest-targets.json").unlink()
        except Exception:
            pass

        unit = f"{UNIT_PREFIX}{slug}{UNIT_SUFFIX}"
        rc, _, err = _systemctl("start", unit)
        if rc != 0:
            self._json({"error": f"systemctl start: {err}"}, code=500)
            return
        self._json({"ok": True, "started": True, "slug": slug, "hint_set": bool(hint)})

    def _handle_agentic_retest(self, engagement: str):
        """POST /api/engagements/<slug>/retest-run (body {ids}) → arranca un run
        de wik3 en MODO RETEST: escribe el manifiesto retest-targets.json (el gate
        determinístico del workflow lo detecta) y arranca el unit. El agente solo
        re-prueba esas vulns."""
        if not _engagement_path(engagement).exists():
            self._json({"error": f"engagement {engagement!r} no existe"}, code=404)
            return
        body = self._read_json_body() or {}
        ids = body.get("ids")
        if not isinstance(ids, list) or not ids:
            self._json({"error": "ids requerido"}, code=400)
            return
        ids = [v for v in ids if isinstance(v, str) and re.match(r"^[A-Z]-[A-Za-z0-9_.\-]+$", v)]
        if not ids:
            self._json({"error": "ningún id válido"}, code=400)
            return
        active = _active_run_slug()
        if active and active != engagement:
            self._json({"error": f"otro engagement está corriendo: {active!r}", "active_slug": active}, code=409)
            return
        if active == engagement:
            self._json({"error": "este engagement ya está corriendo"}, code=409)
            return
        wik3_dir = resolve_engagement_dir(engagement)
        try:
            (wik3_dir / "retest-targets.json").write_text(
                json.dumps({"ids": ids, "requested_at": _now_iso()}, ensure_ascii=False))
        except Exception as e:
            self._json({"error": f"no pude escribir el manifiesto: {e}"}, code=500)
            return
        # Marca cada vuln objetivo como "running" → feedback inmediato en la UI.
        for vid in ids:
            try:
                subprocess.run(
                    ["bash", str(self._VULN_SH), "retest", vid, "--state", "running", "--evidence", ""],
                    capture_output=True, text=True, timeout=15,
                    env={**os.environ, "WIK3_DIR": str(wik3_dir)})
            except Exception:
                pass
        unit = f"{UNIT_PREFIX}{engagement}{UNIT_SUFFIX}"
        rc, _, err = _systemctl("start", unit)
        if rc != 0:
            try:
                (wik3_dir / "retest-targets.json").unlink()
            except Exception:
                pass
            self._json({"error": f"systemctl start: {err}"}, code=500)
            return
        self._json({"ok": True, "retesting": ids})

    def _handle_stop(self, slug: str):
        if not _is_unit_active(slug):
            self._json({"error": "no está corriendo", "active": False}, code=409)
            return
        unit = f"{UNIT_PREFIX}{slug}{UNIT_SUFFIX}"
        rc, _, err = _systemctl("stop", unit)
        if rc != 0:
            self._json({"error": f"systemctl stop: {err}"}, code=500)
            return
        # Stop interrumpe el run: si era un retest, las vulns no deben quedar
        # pegadas en "Reprobando". Limpia el estado "running" y el manifiesto.
        self._clear_running_retest(resolve_engagement_dir(slug))
        self._json({"ok": True, "stopped": True, "slug": slug})

    def _clear_running_retest(self, wik3_dir):
        """Quita el estado retest 'running' de las vulns (quedó interrumpido) y
        borra el manifiesto de retest. Best-effort."""
        try:
            (wik3_dir / "retest-targets.json").unlink()
        except Exception:
            pass
        vulns_dir = wik3_dir / "vulns"
        if not vulns_dir.is_dir():
            return
        for sub in vulns_dir.iterdir():
            mp = sub / "meta.json"
            if not mp.is_file():
                continue
            try:
                meta = json.loads(mp.read_text())
            except Exception:
                continue
            if isinstance(meta.get("retest"), dict) and meta["retest"].get("state") == "running":
                meta.pop("retest", None)
                try:
                    write_json(mp, meta)
                except Exception:
                    pass

    # ── handlers existentes ──────────────────────────────────────────────
    def _handle_admin_findings_export(self):
        """GET /admin/findings-export — flat list de findings de TODOS los
        engagements de esta wik3 con metadata (engagement_created_at,
        engagement_started_at, run_started_at, review). El admin lo consume
        para construir su local store + CSV export."""
        slugs = _list_slugs()
        engagements_meta = []
        findings_out = []
        for slug in slugs:
            wik3_dir = WIK3_ROOT / slug
            meta = _read_meta(slug) or {}
            run = latest_wik3_run(slug) or {}
            run_started_at = run.get("started_at") or ""
            # Tipos del engagement (blackbox/webapp/mobile/internal/cloud) — viven
            # en el engagement.yaml, no en el meta. El admin los usa para filtrar.
            eng_types = ["webapp"]
            try:
                ey = _parse_yaml_safe(_engagement_path(slug).read_text())
                if isinstance(ey, dict) and isinstance(ey.get("types"), list):
                    cleaned = [t for t in ey["types"] if isinstance(t, str) and t in ("blackbox", "webapp", "mobile", "internal", "cloud")]
                    if cleaned:
                        eng_types = cleaned
            except Exception:
                pass
            engagements_meta.append({
                "slug": slug,
                "display_name": meta.get("display_name") or slug,
                "created_at": meta.get("created_at") or "",
                "started_at": meta.get("started_at") or "",
                "run_started_at": run_started_at,
                "types": eng_types,
            })
            merged = list_vulns(wik3_dir)
            for f in merged:
                review = f.get("review") or {}
                findings_out.append({
                    "engagement_slug": slug,
                    "engagement_types": eng_types,
                    "engagement_display_name": meta.get("display_name") or slug,
                    "engagement_created_at": meta.get("created_at") or "",
                    "engagement_started_at": meta.get("started_at") or "",
                    "run_started_at": run_started_at,
                    "finding_id": f.get("id") or "",
                    "created_at": f.get("created_at") or "",
                    "severity": (f.get("severity") or "").lower(),
                    "title": f.get("title") or "",
                    "phase": f.get("phase") or "",
                    "affected": f.get("affected") if isinstance(f.get("affected"), list) else ([f["affected"]] if f.get("affected") else []),
                    "validation_status": f.get("validation_status") or "",
                    "review_status": review.get("status") or "pending",
                    "review_by": review.get("by") or "",
                    "review_at": review.get("at") or "",
                    "review_note": review.get("note") or "",
                })
        self._json({
            "instance": {"name": BOX_INSTANCE_NAME, "hacker_email": BOX_HACKER_EMAIL},
            "engagements": engagements_meta,
            "findings": findings_out,
            "generated_at": _now_iso(),
        })

    def _handle_admin_costs(self):
        """GET /admin/costs?since=<ISO|relative> — parsea journalctl de los
        wik3-engagement@<slug>.service y devuelve costo LLM USD por
        engagement y por nodo del workflow. Fuente: cada nodo del agente
        fabro imprime una línea como `✓ Surface Recon  $1.53   20m27s`."""
        from urllib.parse import urlparse, parse_qs
        qs = parse_qs(urlparse(self.path).query)
        since = (qs.get("since") or ["1 week ago"])[0]
        try:
            result = subprocess.run(
                ["journalctl", "-u", "wik3-engagement@*.service",
                 "--since", since, "--no-pager", "-o", "json",
                 "--output-fields=_SYSTEMD_UNIT,MESSAGE,__REALTIME_TIMESTAMP"],
                capture_output=True, text=True, timeout=30,
            )
        except subprocess.TimeoutExpired:
            self._json({"error": "journalctl timeout (>30s)"}, code=504)
            return
        except FileNotFoundError:
            self._json({"error": "journalctl no disponible en esta VM"}, code=503)
            return
        if result.returncode != 0:
            self._json({"error": f"journalctl rc={result.returncode}: {result.stderr.strip()[:200]}"}, code=500)
            return

        unit_re = re.compile(r"wik3-engagement@(.+?)\.service")
        cost_re = re.compile(r"^\s*[✓✗]\s+(.+?)\s+\$([0-9]+(?:\.[0-9]+)?)\s")
        by_engagement: dict[str, dict] = {}
        for line in result.stdout.splitlines():
            try:
                obj = json.loads(line)
            except Exception:
                continue
            unit = obj.get("_SYSTEMD_UNIT", "") or ""
            msg = obj.get("MESSAGE", "") or ""
            mu = unit_re.match(unit)
            if not mu:
                continue
            slug = mu.group(1)
            mc = cost_re.match(msg)
            if not mc:
                continue
            node = mc.group(1).strip()
            try:
                usd = float(mc.group(2))
            except Exception:
                continue
            eng = by_engagement.setdefault(slug, {"total_usd": 0.0, "by_node": {}, "node_runs": {}})
            eng["total_usd"] += usd
            eng["by_node"][node] = eng["by_node"].get(node, 0.0) + usd
            eng["node_runs"][node] = eng["node_runs"].get(node, 0) + 1

        total = sum(e["total_usd"] for e in by_engagement.values())
        self._json({
            "instance": {"name": BOX_INSTANCE_NAME, "hacker_email": BOX_HACKER_EMAIL},
            "since": since,
            "total_llm_usd": round(total, 4),
            "by_engagement": {
                slug: {
                    "total_usd": round(e["total_usd"], 4),
                    "by_node": {n: round(c, 4) for n, c in e["by_node"].items()},
                    "node_runs": e["node_runs"],
                } for slug, e in by_engagement.items()
            },
            "generated_at": _now_iso(),
        })

    def _handle_admin_summary(self):
        """GET /admin/summary — métricas agregadas de TODA la VM. admin lo
        consume para el dashboard global (máquina × validadas × tiempo).
        Resumen por engagement + totales del VM."""
        slugs = _list_slugs()
        totals = {
            "engagements": len(slugs),
            "passive": 0,
            "active": 0,
            "validated": 0,
            "imported": 0,
            "human_validated": 0,
            "review_by_status": {s: 0 for s in REVIEW_STATUSES},
            "human_validated_by_severity": {},
        }
        per_engagement = []
        active_slug = _active_run_slug()
        # "Última vez que corrió un engagement" = mtime más reciente de exec.log
        # entre todos los engagements. El agente escribe exec.log en cada bash
        # del run, así que su mtime marca la última actividad de un run.
        last_run_mtime = 0.0
        for slug in slugs:
            for cand in (WIK3_ROOT / slug / "exec.log", WIK3_ROOT / slug / "coverage" / "exec.log"):
                try:
                    m = cand.stat().st_mtime
                    if m > last_run_mtime:
                        last_run_mtime = m
                except OSError:
                    pass
        last_run_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(last_run_mtime)) if last_run_mtime else None
        for slug in slugs:
            wik3_dir = WIK3_ROOT / slug
            merged = list_vulns(wik3_dir)
            by_phase = {"passive": 0, "active": 0, "validated": 0, "imported": 0}
            for f in merged:
                by_phase[f.get("phase", "")] = by_phase.get(f.get("phase", ""), 0) + 1
            reviewed = [f for f in merged if (f.get("review") or {}).get("status") == "validated"]
            totals["passive"] += by_phase.get("passive", 0)
            totals["active"] += by_phase.get("active", 0)
            totals["validated"] += by_phase.get("validated", 0)
            totals["imported"] += by_phase.get("imported", 0)
            totals["human_validated"] += len(reviewed)
            for f in reviewed:
                sev = (f.get("severity") or "unknown").lower()
                totals["human_validated_by_severity"][sev] = (
                    totals["human_validated_by_severity"].get(sev, 0) + 1
                )
            for f in merged:
                s = (f.get("review") or {}).get("status") or "pending"
                if s in totals["review_by_status"]:
                    totals["review_by_status"][s] += 1
            per_engagement.append({
                "slug": slug,
                "passive": by_phase.get("passive", 0),
                "active": by_phase.get("active", 0),
                "validated": by_phase.get("validated", 0),
                "imported": by_phase.get("imported", 0),
                "human_validated": len(reviewed),
                "human_validated_by_severity": severity_count(reviewed),
                "active_run": active_slug == slug,
            })
        self._json({
            "instance": {
                "name": BOX_INSTANCE_NAME,
                "zone": BOX_INSTANCE_ZONE,
                "project_id": BOX_PROJECT_ID,
                "hacker_email": BOX_HACKER_EMAIL,
            },
            "version": version_info(),
            "totals": totals,
            "engagements": per_engagement,
            "active_run": active_slug,
            "last_run_at": last_run_at,
            "generated_at": _now_iso(),
        })

    _VULN_FILE_WHITELIST = {"info.md", "exploit.md", "retest.py", "reproduction.md", "report.md"}
    _VULN_REPORT_FILE = "report.md"   # "¿Cómo reportarla?" — markdown de reporte generado
    _VULN_FILE_MAX = 256 * 1024  # 256 KB por archivo
    _VULN_SH = SCRIPT_DIR.parent / "scripts" / "vuln.sh"
    _RETEST_TIMEOUT = 60  # segundos por retest.py
    _IMPORT_PDF_MAX = 32 * 1024 * 1024  # 32 MB — tope de la API de Anthropic para PDFs

    def _handle_import_report(self, engagement: str):
        """POST /api/engagements/<slug>/import — texto o PDF → Claude → vulns/.
        Body JSON: {text, pdf_b64, requires_auth, auth_text}.
        Devuelve {created, errors, scope_update, login_urls} o, si la auth no
        alcanza para loguearse, {auth_incomplete: true, missing: "..."}.

        Scope: ADITIVO. Al scope actual se le agregan (sin quitar nada) los hosts
        afectados de las vulns, lo que el reporte declare como scope y los hosts de
        las páginas de login. Así el retest (egress por squid, default-deny) alcanza
        los targets y el IdP. Se reporta en scope_update.added qué se agregó."""
        body = self._read_json_body()
        text = (body.get("text") or "").strip()
        pdf_b64 = (body.get("pdf_b64") or "").strip()
        requires_auth = bool(body.get("requires_auth"))
        # Un solo campo de texto libre con TODO lo de auth (creds + página de login
        # + cómo loguearse). Un LLM lo infiere y VALIDA si alcanza para loguearse.
        auth_text = body.get("auth_text")
        login_urls: list[str] = []
        if not text and not pdf_b64:
            self._json({"error": "text o pdf_b64 requerido"}, code=400)
            return
        if pdf_b64:
            try:
                pdf_len = len(base64.b64decode(pdf_b64, validate=False))
            except Exception:
                self._json({"error": "pdf_b64 inválido"}, code=400)
                return
            if pdf_len > self._IMPORT_PDF_MAX:
                self._json({"error": f"PDF demasiado grande ({pdf_len} bytes)"}, code=413)
                return
        wik3_dir = resolve_engagement_dir(engagement)
        if not wik3_dir.is_dir():
            self._json({"error": f"engagement {engagement!r} no existe"}, code=404)
            return

        # Auth: si el retest requiere login, procesamos el campo único ANTES de la
        # extracción de vulns (que es cara, ~5 min). El LLM infiere creds + página
        # de login + cómo loguearse y VALIDA si alcanza. Si NO alcanza, cortamos
        # acá y le pedimos al hacker que complete la info (no gastamos la extracción).
        if requires_auth:
            at = auth_text if isinstance(auth_text, str) else ""
            if len(at.encode("utf-8")) > self._RETEST_CREDS_MAX:
                self._json({"error": f"auth > {self._RETEST_CREDS_MAX} bytes"}, code=413)
                return
            have_key = bool(os.environ.get("ANTHROPIC_API_KEY", "").strip())
            if not at.strip():
                self._json({"auth_incomplete": True,
                            "missing": "Pega las credenciales y la página de login (o desmarca \"requiere autenticación\")."},
                           code=200)
                return
            parsed_auth = None
            if have_key:
                try:
                    parsed_auth = _llm_parse_auth(at)
                except Exception:
                    parsed_auth = None
            if parsed_auth is not None and not parsed_auth["complete"]:
                self._json({"auth_incomplete": True,
                            "missing": parsed_auth["missing"] or "Falta información de login: agrega la URL exacta de login y/o las credenciales.",
                            "login_urls": parsed_auth["login_urls"]},
                           code=200)
                return
            # Auth OK (o sin API key para validar → guardamos lo que haya).
            env_lines = parsed_auth["env"] if parsed_auth else []
            login_urls = parsed_auth["login_urls"] if parsed_auth else []
            how = parsed_auth["how_to_login"] if parsed_auth else ""
            # 1) creds → retest-creds.env
            creds_body = "\n".join(env_lines) + ("\n" if env_lines else "")
            if not creds_body.strip() and not have_key:
                creds_body = at  # fallback sin LLM: guardamos el texto crudo
            if creds_body.strip():
                creds_path = wik3_dir / self._RETEST_CREDS_FILE
                try:
                    tmp = creds_path.with_suffix(".env.tmp")
                    tmp.write_text(creds_body)
                    os.chmod(tmp, 0o600)
                    os.replace(tmp, creds_path)
                except Exception:
                    pass
            # 2) login (URLs + cómo loguearse) → retest-login.md (lo lee el retest)
            login_md = ""
            if login_urls:
                login_md += "# Páginas de login\n" + "\n".join(login_urls) + "\n"
            if how:
                login_md += "\n# Cómo loguearse\n" + how + "\n"
            if login_md:
                try:
                    (wik3_dir / self._RETEST_LOGIN_FILE).write_text(login_md)
                except Exception:
                    pass
            # 3) texto crudo → retest-auth.txt (para re-precargar el campo al editar)
            try:
                p = wik3_dir / self._RETEST_AUTH_FILE
                p.write_text(at)
                os.chmod(p, 0o600)
            except Exception:
                pass
        env_keys = sorted(self._load_retest_creds(wik3_dir).keys()) or None

        try:
            vulns, extra_meta = _llm_extract_vulns(
                text=text or None,
                pdf_b64=pdf_b64 or None,
                available_env_keys=env_keys,
            )
        except Exception as e:
            self._json({"error": f"LLM: {e}"}, code=502)
            return

        # ── Scope merge (ADITIVO) ────────────────────────────────────────────
        # Unimos al scope ACTUAL (nunca quitamos entries existentes):
        #   1) el scope declarado en el reporte,
        #   2) los hosts AFECTADOS de cada vuln (app3.foo.com, etc.),
        #   3) los hosts de las páginas de login que pegó el hacker.
        # Motivo: el retest egresa por squid (default-deny, dstdomain exact-match).
        # Un scope con sólo `foo.com` bare NO cubre `app3.foo.com` → el target
        # quedaba bloqueado. Metiendo los hosts EXACTOS al scope, squid los deja
        # pasar. Avisamos al hacker exactamente qué dominios se agregaron.
        scope_update: dict | None = None
        yaml_path = _engagement_path(engagement)
        try:
            parsed_yaml = _parse_yaml_safe(yaml_path.read_text()) or {}
        except Exception:
            parsed_yaml = {}
        cur_scope = parsed_yaml.get("scope") or {}

        def _norm_list(raw):
            out = []
            if isinstance(raw, list):
                for x in raw:
                    if isinstance(x, str):
                        n = _normalize_scope_entry(x)
                        if n:
                            out.append(n)
            return out

        cur_domains = _norm_list(cur_scope.get("domains"))
        cur_ips = _norm_list(cur_scope.get("ips"))
        cur_urls = _norm_list(cur_scope.get("urls"))
        existing = set(cur_domains) | set(cur_ips) | set(cur_urls)
        existing_hosts = {h for h in (_bare_host(e) for e in existing) if h}

        scope_from_report = extra_meta.get("scope") if isinstance(extra_meta, dict) else None
        srep = scope_from_report if isinstance(scope_from_report, dict) else {}
        rep_domains = _norm_list(srep.get("domains"))
        rep_ips = _norm_list(srep.get("ips"))
        rep_urls = _norm_list(srep.get("urls"))

        # Hosts afectados de las vulns + páginas de login → dominios bare.
        extra_hosts: set[str] = set()
        for v in vulns:
            aff = v.get("affected") or []
            aff = aff if isinstance(aff, list) else [aff]
            for a in aff:
                h = _bare_host(str(a))
                if h:
                    extra_hosts.add(h)
        login_hosts = {h for h in (_bare_host(lu) for lu in login_urls) if h}

        add_domains = [d for d in rep_domains if d not in existing]
        add_ips = [i for i in rep_ips if i not in existing]
        add_urls = [u for u in rep_urls if u not in existing]
        for h in sorted(extra_hosts | login_hosts):
            if h not in existing and h not in existing_hosts:
                add_domains.append(h)
                existing_hosts.add(h)

        added_all = add_domains + add_ips + add_urls
        if added_all:
            parsed_yaml.setdefault("scope", {})
            parsed_yaml["scope"]["domains"] = cur_domains + add_domains
            parsed_yaml["scope"]["ips"] = cur_ips + add_ips
            parsed_yaml["scope"]["urls"] = cur_urls + add_urls
            try:
                yaml_path.write_text(_dump_yaml(parsed_yaml))
            except Exception:
                pass
            # scope.txt para el scope_guard del agente.
            _write_scope_list(
                wik3_dir / "scope.txt",
                parsed_yaml["scope"]["domains"]
                + parsed_yaml["scope"]["ips"]
                + parsed_yaml["scope"]["urls"],
            )
            _refresh_squid_allowlist(engagement)
            scope_update = {
                "applied": True,
                "added": added_all,
                "added_domains": add_domains,
                "added_ips": add_ips,
                "added_urls": add_urls,
                "login_hosts": sorted(login_hosts),
            }

        created: list[dict] = []
        errors: list[dict] = []
        for v in vulns:
            title = (v.get("title") or "").strip()
            severity = (v.get("severity") or "").strip().lower()
            if not title or severity not in {"critical", "high", "medium", "low", "info"}:
                errors.append({"title": title, "error": "title o severity inválido"})
                continue
            affected = v.get("affected") or []
            if isinstance(affected, list):
                affected_str = ",".join(str(x) for x in affected)
            else:
                affected_str = str(affected)
            args = [
                "bash", str(self._VULN_SH), "add",
                "--title", title,
                "--severity", severity,
                "--phase", "imported",
                "--source", "imported",
                "--confidence", "likely",
                "--info", v.get("info") or "",
            ]
            if affected_str:
                args += ["--affected", affected_str]
            cvss = v.get("cvss")
            if isinstance(cvss, (int, float)):
                args += ["--cvss", str(float(cvss))]
            # Id del reporte (verbatim) → se muestra como referencia de la vuln.
            report_id = v.get("report_id")
            if isinstance(report_id, str) and report_id.strip():
                args += ["--ref", report_id.strip()[:80]]
            env = os.environ.copy()
            env["WIK3_DIR"] = str(wik3_dir)
            try:
                proc = subprocess.run(args, capture_output=True, text=True, timeout=30, env=env)
            except subprocess.TimeoutExpired:
                errors.append({"title": title, "error": "timeout en vuln.sh"})
                continue
            if proc.returncode != 0:
                errors.append({"title": title, "error": f"vuln.sh: {proc.stderr.strip()[:200]}"})
                continue
            vuln_id = proc.stdout.strip()
            vd = _find_vuln_dir(wik3_dir, vuln_id)
            # Guardar reproduction.md (el paso a paso del reporte) — es lo que el
            # nodo retest sigue al re-probar.
            repro = v.get("reproduction")
            if isinstance(repro, str) and repro.strip() and vd is not None:
                try:
                    (vd / "reproduction.md").write_text(repro)
                except Exception as e:
                    errors.append({"id": vuln_id, "error": f"no pude escribir reproduction.md: {e}"})
            # Guardar retest.py si vino.
            retest = v.get("retest")
            if isinstance(retest, str) and retest.strip() and vd is not None:
                try:
                    (vd / "retest.py").write_text(retest)
                except Exception as e:
                    errors.append({"id": vuln_id, "error": f"no pude escribir retest.py: {e}"})
            # Las vulns importadas de un reporte previo ya son hallazgos reales →
            # quedan VALIDADAS automáticamente (van directo a "Vuln Validadas").
            # Es una acción autorizada por el hacker (él importó el reporte), así
            # que pasamos WIK3_HUMAN_VALIDATE=1 — el gate de vuln.sh que impide al
            # agente auto-validar no aplica acá.
            try:
                subprocess.run(
                    ["bash", str(self._VULN_SH), "validate", vuln_id,
                     "--status", "validated", "--by", "import",
                     "--note", "Importada de un reporte previo"],
                    capture_output=True, text=True, timeout=15,
                    env={**env, "WIK3_HUMAN_VALIDATE": "1"},
                )
            except Exception:
                pass
            created.append({"id": vuln_id, "title": title, "severity": severity})
        resp = {"created": created, "errors": errors, "extracted_count": len(vulns)}
        if scope_update is not None:
            resp["scope_update"] = scope_update
        if login_urls:
            resp["login_urls"] = login_urls
        self._json(resp)

    def _handle_vuln_manual_draft(self, engagement: str):
        """POST /api/engagements/<slug>/vulns/draft — texto libre → LLM →
        JSON estructurado con los campos de la vuln. NO graba; el operador
        revisa/edita en la UI y luego /vulns/manual lo persiste."""
        body = self._read_json_body()
        description = (body.get("description") or "").strip()
        if not description:
            self._json({"error": "description requerida"}, code=400)
            return
        if len(description) > 30_000:
            self._json({"error": "description demasiado larga (>30k)"}, code=413)
            return
        wik3_dir = resolve_engagement_dir(engagement)
        if not wik3_dir.is_dir():
            self._json({"error": f"engagement {engagement!r} no existe"}, code=404)
            return
        try:
            draft = _llm_draft_vuln(description)
        except Exception as e:
            self._json({"error": f"LLM: {e}"}, code=502)
            return
        self._json({"draft": draft})

    def _handle_vuln_manual_create(self, engagement: str):
        """POST /api/engagements/<slug>/vulns/manual — persiste la vuln editada
        por el operador. Ejecuta vuln.sh add con los campos finales y escribe
        info.md. Devuelve {id, title, severity}."""
        body = self._read_json_body()
        title = (body.get("title") or "").strip()
        severity = (body.get("severity") or "medium").strip().lower()
        phase = (body.get("phase") or "active").strip().lower()
        confidence = (body.get("confidence") or "likely").strip().lower()
        affected = body.get("affected") or []
        info = (body.get("info") or "").strip()
        cvss = body.get("cvss")
        if not title:
            self._json({"error": "title requerido"}, code=400)
            return
        if severity not in ("critical", "high", "medium", "low", "info"):
            self._json({"error": f"severity inválida: {severity!r}"}, code=400)
            return
        if phase not in ("passive", "active", "validated"):
            self._json({"error": f"phase inválida: {phase!r}"}, code=400)
            return
        if confidence not in ("confirmed", "probable", "likely", "unlikely"):
            self._json({"error": f"confidence inválida: {confidence!r}"}, code=400)
            return
        if isinstance(affected, str):
            affected = [affected]
        affected = [str(a).strip() for a in affected if str(a).strip()]

        wik3_dir = resolve_engagement_dir(engagement)
        if not wik3_dir.is_dir():
            self._json({"error": f"engagement {engagement!r} no existe"}, code=404)
            return

        # Persistir info.md a un tmpfile y pasarlo a vuln.sh add via @path.
        # Mismo patrón que el import.
        try:
            tmp_info = wik3_dir / f".manual-vuln-info.{secrets.token_hex(4)}.md"
            tmp_info.write_text(info or "## Descripción\n\n—\n")
        except Exception as e:
            self._json({"error": f"no pude escribir info temp: {e}"}, code=500)
            return

        args = [
            "bash", str(self._VULN_SH), "add",
            "--title", title,
            "--severity", severity,
            "--phase", phase,
            "--confidence", confidence,
            "--info", f"@{tmp_info}",
        ]
        if affected:
            args += ["--affected", ",".join(affected)]
        if isinstance(cvss, (int, float)):
            args += ["--cvss", str(float(cvss))]
        env = os.environ.copy()
        env["WIK3_DIR"] = str(wik3_dir)
        try:
            proc = subprocess.run(args, capture_output=True, text=True, timeout=30, env=env)
        finally:
            try:
                tmp_info.unlink()
            except Exception:
                pass
        if proc.returncode != 0:
            self._json({"error": f"vuln.sh: {proc.stderr.strip()[:300]}"}, code=500)
            return
        vuln_id = proc.stdout.strip()
        self._json({"ok": True, "id": vuln_id, "title": title, "severity": severity})

    _CHAT_CTX_FILE = "convo/chat-llm.jsonl"
    _CHAT_FILE_READ_CAP = 100 * 1024     # 100 KB por archivo en read_engagement_file.
    _CHAT_FILE_PREVIEW_CHARS = 2000      # cuando el archivo excede el cap, devolvemos preview.
    _CHAT_MAX_TOOL_ITERS = 15            # cap del loop de tool use por turno.

    def _exec_tool_read_engagement_file(self, wik3_dir: Path, path: str, force: bool) -> str:
        """Lee un archivo del workspace del engagement. Devuelve string
        que se mete como tool_result. Validación de path traversal."""
        if not path:
            return "ERROR: path vacío"
        # Reject path traversal.
        if path.startswith("/") or ".." in path.split("/"):
            return f"ERROR: path inválido (absoluto o traversal): {path!r}"
        # Listing de directorio si termina en /
        is_dir_listing = path.endswith("/")
        target = (wik3_dir / path).resolve()
        # Asegurar que target está dentro de wik3_dir.
        try:
            target.relative_to(wik3_dir.resolve())
        except ValueError:
            return f"ERROR: path fuera del workspace: {path!r}"
        if not target.exists():
            return f"ERROR: path no existe: {path!r}"
        if is_dir_listing or target.is_dir():
            try:
                entries = []
                for sub in sorted(target.iterdir()):
                    kind = "dir" if sub.is_dir() else "file"
                    size = sub.stat().st_size if sub.is_file() else ""
                    size_str = f" ({size}B)" if size != "" else "/"
                    entries.append(f"  {sub.name}{size_str}")
                if not entries:
                    return f"(carpeta vacía: {path})"
                return f"Contenido de {path}:\n" + "\n".join(entries[:200])
            except Exception as e:
                return f"ERROR listando: {e}"
        # File read
        if not target.is_file():
            return f"ERROR: no es archivo regular: {path!r}"
        size = target.stat().st_size
        if size > self._CHAT_FILE_READ_CAP and not force:
            try:
                with target.open("rb") as f:
                    preview = f.read(self._CHAT_FILE_PREVIEW_CHARS).decode("utf-8", errors="replace")
            except Exception as e:
                return f"ERROR leyendo preview: {e}"
            return (
                f"WARNING: archivo grande ({size} bytes > {self._CHAT_FILE_READ_CAP} cap).\n"
                f"Preview (primeros {self._CHAT_FILE_PREVIEW_CHARS} chars):\n\n{preview}\n\n"
                f"---\nSi necesitas leerlo entero, llama de nuevo con force=true."
            )
        try:
            content = target.read_text(errors="replace")
        except Exception as e:
            return f"ERROR leyendo: {e}"
        return content

    def _exec_tool_grep_engagement(self, wik3_dir: Path, query: str) -> str:
        """grep recursivo (substring, case-insensitive) en el workspace del
        engagement. Sin shell (args directos) → sin inyección; -a para archivos
        con bytes binarios. Cap 200 coincidencias."""
        query = (query or "").strip()
        if not query:
            return "ERROR: query vacío"
        if not wik3_dir.is_dir():
            return "ERROR: workspace no existe"
        CAP = 200
        try:
            proc = subprocess.run(
                ["grep", "-rnaiF", "--", query, str(wik3_dir)],
                capture_output=True, text=True, errors="replace", timeout=30,
            )
        except Exception as e:
            return f"ERROR ejecutando grep: {e}"
        lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
        total = len(lines)
        base = str(wik3_dir.resolve())
        out = []
        for ln in lines[:CAP]:
            # path absoluto → relativo al workspace, recortar líneas largas
            out.append(ln.replace(base + "/", "").replace(base, "")[:300])
        head = f"{total} coincidencia(s)" + (f" (mostrando {CAP})" if total > CAP else "") + f' para "{query}":\n'
        return head + "\n".join(out) if out else f'Sin coincidencias para "{query}".'

    def _exec_tool_message_running_agent(self, engagement: str, message: str) -> str:
        """Envía un msg al inbox.md del agente. Si no está corriendo, error
        semántico que el LLM pueda comunicarle al operador."""
        if not message or not message.strip():
            return "ERROR: mensaje vacío"
        if not _is_unit_active(engagement):
            return (
                "ERROR: no hay agente corriendo este engagement. "
                "El mensaje NO se entregó. Sugiérele al operador: "
                "1) arrancar un Run con hint para que se procese al inicio del próximo run, "
                "o 2) esperar a que se arranque un run y reintentar."
            )
        wik3_dir = resolve_engagement_dir(engagement)
        convo = wik3_dir / "convo"
        convo.mkdir(parents=True, exist_ok=True)
        inbox = convo / "inbox.md"
        try:
            # Append, no overwrite — el scope_guard del agente lo procesa.
            with inbox.open("a") as f:
                ts = _now_iso()
                f.write(f"\n=== Mensaje del operador (via chat LLM, {ts}) ===\n{message.strip()}\n")
        except Exception as e:
            return f"ERROR escribiendo inbox: {e}"
        return f"✓ Mensaje entregado al inbox del agente. El agente lo va a leer en su próximo tool call."

    def _build_postmortem_context_DEPRECATED(self, engagement: str, opts: dict) -> tuple[str, dict]:
        """[DEPRECATED] Reemplazado por el approach de tool use — el LLM
        decide qué archivos leer via `read_engagement_file`. Esta función
        cargaba el contexto upfront según checkboxes. Se mantiene unused
        por si necesitamos referencia."""
        wik3_dir = resolve_engagement_dir(engagement)
        parts: list[str] = []
        dbg = {"included": [], "skipped": []}

        if opts.get("engagement", True):
            yaml_path = _engagement_path(engagement)
            if yaml_path.exists():
                try:
                    parts.append("## engagement.yaml\n\n```yaml\n" + yaml_path.read_text() + "\n```")
                    dbg["included"].append("engagement.yaml")
                except Exception:
                    dbg["skipped"].append("engagement.yaml (read error)")
            # summary.md (passive + active) si existen.
            for sub in ("passive/summary.md", "active/summary.md", "validated/summary.md", "senior_review/log.md"):
                p = wik3_dir / sub
                if p.is_file() and p.stat().st_size > 0:
                    try:
                        parts.append(f"## {sub}\n\n" + p.read_text(errors="replace"))
                        dbg["included"].append(sub)
                    except Exception:
                        dbg["skipped"].append(f"{sub} (read error)")

        if opts.get("vulns", False):
            vulns_dir = wik3_dir / "vulns"
            if vulns_dir.is_dir():
                vuln_blocks: list[str] = []
                for sub in sorted(vulns_dir.iterdir()):
                    if not sub.is_dir():
                        continue
                    meta_p = sub / "meta.json"
                    info_p = sub / "info.md"
                    if not meta_p.is_file():
                        continue
                    try:
                        meta = json.loads(meta_p.read_text())
                    except Exception:
                        continue
                    vid = meta.get("id") or sub.name
                    title = meta.get("title") or "(sin título)"
                    sev = meta.get("severity") or "?"
                    phase = meta.get("phase") or "?"
                    val = meta.get("validation_status") or "?"
                    rev = (meta.get("review") or {}).get("status") or "pending"
                    aff = meta.get("affected") or []
                    aff_str = ", ".join(aff) if isinstance(aff, list) else str(aff)
                    info = ""
                    if info_p.is_file():
                        try:
                            info = info_p.read_text(errors="replace")[:self._POSTMORTEM_INFO_MAX]
                        except Exception:
                            info = "(no se pudo leer info.md)"
                    vuln_blocks.append(
                        f"### {vid} — {title}\n"
                        f"- severity: {sev}\n"
                        f"- phase: {phase}\n"
                        f"- validation_status: {val}\n"
                        f"- review_status: {rev}\n"
                        f"- affected: {aff_str}\n\n"
                        f"{info}"
                    )
                if vuln_blocks:
                    parts.append("## Vulnerabilidades (" + str(len(vuln_blocks)) + ")\n\n" + "\n\n---\n\n".join(vuln_blocks))
                    dbg["included"].append(f"vulns ({len(vuln_blocks)})")
                else:
                    dbg["skipped"].append("vulns (vacío)")

        if opts.get("notes", False):
            notes_p = wik3_dir / "notes.jsonl"
            if notes_p.is_file():
                try:
                    raw = notes_p.read_text(errors="replace")
                    notes_lines = [l for l in raw.splitlines() if l.strip()]
                    if notes_lines:
                        parts.append("## notes.jsonl (observaciones no-vuln)\n\n```jsonl\n" + "\n".join(notes_lines) + "\n```")
                        dbg["included"].append(f"notes ({len(notes_lines)})")
                except Exception:
                    dbg["skipped"].append("notes.jsonl (read error)")

        if opts.get("exec_log", False):
            log_p = wik3_dir / "exec.log"
            if log_p.is_file():
                try:
                    # Tomar las últimas N bytes — el final es más relevante
                    # (lo más reciente del agente).
                    with log_p.open("rb") as f:
                        f.seek(0, 2)
                        size = f.tell()
                        if size > self._POSTMORTEM_EXEC_LOG_MAX:
                            f.seek(size - self._POSTMORTEM_EXEC_LOG_MAX)
                            head = "(... truncado: log más grande que cap; mostrando las últimas ~50k tokens ...)\n\n".encode("utf-8")
                        else:
                            f.seek(0)
                            head = b""
                        raw = head + f.read()
                    parts.append("## exec.log (shell del agente)\n\n```\n" + raw.decode("utf-8", errors="replace") + "\n```")
                    dbg["included"].append(f"exec.log ({len(raw)} bytes)")
                except Exception:
                    dbg["skipped"].append("exec.log (read error)")

        return "\n\n---\n\n".join(parts), dbg

    def _load_chat_history(self, engagement: str) -> list[dict]:
        """Memoria del chat = timeline UNIFICADO convo/log.jsonl, compartido
        entre el chat-assistant del proyecto y el agente que trabaja (lo que le
        dices al agente vía inbox también queda acá). Mapea from→role
        (user→user, resto→assistant), descarta entradas sin texto, coalesce
        turnos consecutivos del mismo rol (el API requiere alternancia) y
        arranca en 'user'. Cap a los últimos turnos para no inflar el contexto."""
        wik3_dir = resolve_engagement_dir(engagement)
        p = wik3_dir / "convo" / "log.jsonl"
        if not p.is_file():
            return []
        raw: list[tuple[str, str]] = []
        try:
            for line in p.read_text().splitlines():
                if not line.strip():
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                text = obj.get("text")
                if not isinstance(text, str) or not text.strip():
                    continue
                role = "user" if obj.get("from") == "user" else "assistant"
                raw.append((role, text))
        except Exception:
            return []
        raw = raw[-40:]
        out: list[dict] = []
        for role, text in raw:
            if out and out[-1]["role"] == role:
                out[-1]["content"] += "\n\n" + text
            else:
                out.append({"role": role, "content": text})
        while out and out[0]["role"] != "user":
            out.pop(0)
        return out

    def _append_chat_turn(self, engagement: str, role: str, content: str) -> None:
        wik3_dir = resolve_engagement_dir(engagement)
        (wik3_dir / "convo").mkdir(parents=True, exist_ok=True)
        # Historial Anthropic para que la conversación tenga memoria
        # entre turnos. Solo persistimos user + assistant final, no los
        # tool_use intermedios (ruido en el contexto).
        p = wik3_dir / self._CHAT_CTX_FILE
        ts = _now_iso()
        with p.open("a") as f:
            f.write(json.dumps({"ts": ts, "role": role, "content": content}, ensure_ascii=False) + "\n")
        # Timeline unificado (convo/log.jsonl). El PR A renderiza chat
        # turns con kind='chat' en el terminal.
        log_p = wik3_dir / "convo" / "log.jsonl"
        from_who = "user" if role == "user" else "agent"
        with log_p.open("a") as f:
            f.write(json.dumps({"ts": ts, "from": from_who, "kind": "chat", "text": content}, ensure_ascii=False) + "\n")

    def _handle_chat_message(self, engagement: str):
        """POST /api/engagements/<slug>/chat — chat con Opus 4.7 con tool use
        (read_engagement_file + message_running_agent). Funciona con agente
        running o stopped — el LLM decide qué leer y si mensajear al agente.
        Body: {message}. Devuelve {answer, tools_used, iterations}."""
        body = self._read_json_body()
        message = (body.get("message") or "").strip()
        if not message:
            self._json({"error": "message requerida"}, code=400)
            return
        if len(message) > 30_000:
            self._json({"error": "message demasiado larga"}, code=413)
            return
        wik3_dir = resolve_engagement_dir(engagement)
        if not wik3_dir.is_dir():
            self._json({"error": f"engagement {engagement!r} no existe"}, code=404)
            return

        # Cargamos el historial compartido ANTES de persistir el nuevo turn.
        history = self._load_chat_history(engagement)
        # Persistir el turn del operador (aparece ya en el timeline aunque el
        # LLM tarde).
        try:
            self._append_chat_turn(engagement, "user", message)
        except Exception as e:
            self._json({"error": f"no pude persistir pregunta: {e}"}, code=500)
            return

        # Build messages: historial + nueva pregunta. Coalesce si el último
        # turno ya era del operador (p. ej. un whisper al agente sin responder).
        messages: list[dict] = [{"role": t["role"], "content": t["content"]} for t in history]
        if messages and messages[-1]["role"] == "user":
            messages[-1]["content"] += "\n\n" + message
        else:
            messages.append({"role": "user", "content": message})

        tools_used: list[dict] = []
        final_text = ""
        try:
            for _ in range(self._CHAT_MAX_TOOL_ITERS):
                resp = _llm_chat_call(messages)
                content_blocks = resp.get("content") or []
                stop_reason = resp.get("stop_reason")
                tool_use_blocks = [b for b in content_blocks if b.get("type") == "tool_use"]
                if not tool_use_blocks:
                    # No más tools — extraer texto final.
                    text_parts = [b.get("text", "") for b in content_blocks if b.get("type") == "text"]
                    final_text = "\n".join(t for t in text_parts if t).strip()
                    break
                # Append assistant turn con todos los blocks (texto + tool_use).
                messages.append({"role": "assistant", "content": content_blocks})
                # Ejecutar cada tool y construir tool_result blocks.
                tool_results = []
                for tu in tool_use_blocks:
                    tool_id = tu.get("id")
                    name = tu.get("name")
                    args = tu.get("input") or {}
                    try:
                        if name == "read_engagement_file":
                            result = self._exec_tool_read_engagement_file(
                                wik3_dir,
                                str(args.get("path") or ""),
                                bool(args.get("force") or False),
                            )
                        elif name == "grep_engagement":
                            result = self._exec_tool_grep_engagement(
                                wik3_dir,
                                str(args.get("query") or ""),
                            )
                        elif name == "message_running_agent":
                            result = self._exec_tool_message_running_agent(
                                engagement,
                                str(args.get("message") or ""),
                            )
                        else:
                            result = f"ERROR: tool desconocido {name!r}"
                    except Exception as e:
                        result = f"ERROR: {e}"
                    tools_used.append({"tool": name, "args": args, "result_preview": (result or "")[:200]})
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": tool_id,
                        "content": result,
                    })
                messages.append({"role": "user", "content": tool_results})
            else:
                final_text = "(máximo de iteraciones de tool use alcanzado — el operador puede preguntar de nuevo con más contexto)"
        except urllib.error.HTTPError as e:
            try:
                err_body = e.read().decode("utf-8")
            except Exception:
                err_body = str(e)
            self._json({"error": f"LLM HTTP {e.code}: {err_body[:500]}"}, code=502)
            return
        except Exception as e:
            self._json({"error": f"LLM: {e}"}, code=502)
            return

        # Persistir respuesta final.
        if final_text:
            try:
                self._append_chat_turn(engagement, "assistant", final_text)
            except Exception:
                pass

        self._json({
            "ok": True,
            "answer": final_text,
            "tools_used": tools_used,
            "iterations": len(tools_used),
        })

    _PROXY_ENV_KEYS = ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy")

    def _retest_subprocess_env(self, retest_env):
        """Env para correr retest.py: hereda el del dashboard + las creds del
        operador, pero SIN proxy. Los retests salen DIRECTO por el Cloud NAT del
        host — NO por el squid del agente (172.17.0.1:3128 / 127.0.0.1:3128), que
        solo permite el scope del agente y devuelve 403 ("Tunnel connection failed")
        al target. El dashboard ya hace sus llamadas LLM con ProxyHandler({})."""
        env = os.environ.copy()
        env.update(retest_env or {})
        for k in self._PROXY_ENV_KEYS:
            env.pop(k, None)
        return env

    def _run_one_retest(self, sub, meta, retest_env):
        """Ejecuta el retest.py de UNA vuln (dir `sub`) con las env vars dadas.
        Devuelve {id,title,severity,status,evidence}. status ∈ {vulnerable,
        mitigated, inconclusive, no_retest, skipped, timeout, error}."""
        vid = meta.get("id", sub.name)
        base = {"id": vid, "title": meta.get("title", ""), "severity": meta.get("severity", "")}
        retest_path = sub / "retest.py"
        if not retest_path.is_file() or retest_path.stat().st_size == 0:
            return {**base, "status": "no_retest", "evidence": "sin retest.py"}
        if meta.get("retest_autorun") is False:
            return {**base, "status": "skipped",
                    "evidence": "retest_autorun=false (requiere acción manual — ver script)"}
        try:
            run_env = self._retest_subprocess_env(retest_env)
            proc = subprocess.run(
                ["python3", str(retest_path)],
                capture_output=True, text=True,
                timeout=self._RETEST_TIMEOUT, cwd=str(sub), env=run_env,
            )
            stdout = proc.stdout or ""
            parsed = None
            for line in reversed(stdout.splitlines()):
                line = line.strip()
                if not (line.startswith("{") and line.endswith("}")):
                    continue
                try:
                    cand = json.loads(line)
                    if isinstance(cand, dict) and "status" in cand:
                        parsed = cand
                        break
                except Exception:
                    continue
            if parsed is None:
                status = "error"
                evidence = f"sin línea JSON con status. exit={proc.returncode}. stderr: {proc.stderr.strip()[:200]}"
            else:
                status = str(parsed.get("status") or "error")
                if status not in {"vulnerable", "mitigated", "inconclusive"}:
                    status = "error"
                evidence = str(parsed.get("evidence") or "")
        except subprocess.TimeoutExpired:
            status = "timeout"
            evidence = f"retest.py > {self._RETEST_TIMEOUT}s"
        except Exception as e:
            status = "error"
            evidence = str(e)
        return {**base, "status": status, "evidence": evidence}

    def _retest_env_keys(self, src: str) -> list[str]:
        """Env vars WIK3_* que referencia un retest.py (para pedirlas en la UI)."""
        return sorted(set(re.findall(
            r'os\.(?:environ\.get|getenv|environ\[)\s*\(?\s*[\'"](WIK3_[A-Z0-9_]+)[\'"]', src)))

    def _handle_vuln_retest_run(self, engagement: str, vid: str):
        """POST /api/engagements/<slug>/vulns/<vid>/retest/run — corre el
        retest.py de UNA vuln. Body opcional {env:{KEY:val}} se persiste en
        retest-creds.env (se reutiliza después). Si faltan env vars que el script
        necesita, devuelve {needs_env:[...]} sin correr."""
        wik3_dir = resolve_engagement_dir(engagement)
        vd = _find_vuln_dir(wik3_dir, vid)
        if vd is None:
            self._json({"error": f"vuln {vid!r} no encontrada"}, code=404)
            return
        retest_path = vd / "retest.py"
        if not retest_path.is_file() or retest_path.stat().st_size == 0:
            self._json({"status": "no_retest", "evidence": "esta vuln no tiene retest.py — genéralo primero"})
            return
        try:
            src = retest_path.read_text()
        except Exception as e:
            self._json({"error": f"no pude leer retest.py: {e}"}, code=500)
            return
        body = self._read_json_body() or {}
        new_env = body.get("env") if isinstance(body.get("env"), dict) else {}
        creds = self._load_retest_creds(wik3_dir)
        if new_env:
            merged = dict(creds)
            for k, v in new_env.items():
                if isinstance(k, str) and isinstance(v, str) and k.strip() and v != "":
                    merged[k.strip()] = v
            try:
                (wik3_dir / self._RETEST_CREDS_FILE).write_text(
                    "\n".join(f"{k}={v}" for k, v in merged.items()) + "\n")
            except Exception:
                pass
            creds = merged
        needed = self._retest_env_keys(src)
        missing = [k for k in needed if k not in creds and not os.environ.get(k)]
        if missing:
            self._json({"needs_env": missing, "all_env": needed, "set_env": sorted(creds.keys())})
            return
        try:
            meta = json.loads((vd / "meta.json").read_text())
        except Exception:
            meta = {"id": vid}
        self._json(self._run_one_retest(vd, meta, creds))

    def _handle_vuln_bulk_delete(self, engagement: str):
        """POST /api/engagements/<slug>/vulns/delete (body {ids:[...]}) → borra
        cada vuln (carpeta + entradas legacy). Para el borrado por checkbox."""
        body = self._read_json_body() or {}
        ids = body.get("ids")
        if not isinstance(ids, list) or not ids:
            self._json({"error": "ids requerido"}, code=400)
            return
        wik3_dir = resolve_engagement_dir(engagement)
        deleted = 0
        for vid in ids:
            if isinstance(vid, str) and re.match(r"^[A-Z]-[A-Za-z0-9_.\-]+$", vid):
                if _delete_vuln(wik3_dir, vid):
                    deleted += 1
        self._json({"ok": True, "deleted": deleted})

    _VULN_CHAT_FILE = "chat.jsonl"
    _VULN_CHAT_MAX = 30  # turnos de historial enviados al LLM

    def _read_vuln_chat(self, path) -> list:
        msgs = []
        try:
            for line in path.read_text().splitlines():
                line = line.strip()
                if not line:
                    continue
                o = json.loads(line)
                if isinstance(o, dict) and o.get("role") in ("user", "assistant"):
                    m = {"role": o["role"], "content": o.get("content", ""), "ts": o.get("ts", "")}
                    if isinstance(o.get("files"), list):
                        m["files"] = o["files"]
                    msgs.append(m)
        except Exception:
            pass
        return msgs

    # Archivos que el chat por-vuln puede crear y compartir para descarga. El LLM
    # los emite como bloques [[FILE: nombre]] ... [[/FILE]]; los persistimos en
    # convo/shared/from_agent/ (los sirve /api/download?dir=from_agent).
    def _extract_chat_files(self, wik3_dir, vid: str, reply: str):
        """Extrae los bloques [[FILE:...]] del reply, los guarda y devuelve
        (reply_limpio, files[]). files = [{name, url}]."""
        pat = re.compile(r"\[\[FILE:\s*([^\]\n]+?)\s*\]\]\n?(.*?)\n?\[\[/FILE\]\]", re.S)
        files = []
        shared = wik3_dir / "convo" / "shared" / "from_agent"
        used = set()
        def _save(m):
            raw_name = (m.group(1) or "").strip()
            content = m.group(2) or ""
            safe = re.sub(r"[^A-Za-z0-9._-]", "_", raw_name)[:80] or "archivo.txt"
            # Prefijo con el vid para no pisar archivos de otras vulns/chats.
            safe = f"{vid}_{safe}"
            n, base = safe, safe
            i = 1
            while n in used:
                stem, _, ext = base.partition(".")
                n = f"{stem}_{i}.{ext}" if ext else f"{base}_{i}"
                i += 1
            used.add(n)
            try:
                shared.mkdir(parents=True, exist_ok=True)
                (shared / n).write_text(content)
            except Exception:
                return m.group(0)
            url = f"/api/download?engagement={wik3_dir.name}&dir=from_agent&file={n}"
            files.append({"name": raw_name or n, "stored": n, "url": url})
            return f"📎 **{raw_name or n}** (descargable abajo)"
        clean = pat.sub(_save, reply)
        return clean, files

    def _build_vuln_chat_system(self, wik3_dir, vid: str) -> str:
        vd = _find_vuln_dir(wik3_dir, vid)
        meta = {}
        def _rf(name):
            try:
                return (vd / name).read_text().strip()
            except Exception:
                return ""
        if vd is not None:
            try:
                meta = json.loads((vd / "meta.json").read_text())
            except Exception:
                meta = {}
        info_md, repro, exploit = _rf("info.md"), _rf("reproduction.md"), _rf("exploit.md")
        cases = meta.get("cases") if isinstance(meta.get("cases"), list) else []
        cases_txt = ""
        for i, c in enumerate(cases[:8], 1):
            if isinstance(c, dict):
                cases_txt += f"- caso {i}: {c.get('location','')}\n  evidencia: {str(c.get('evidence',''))[:400]}\n"
        ctx = (
            f"# Vulnerabilidad en contexto\n"
            f"- id: {meta.get('id', vid)}\n"
            f"- título: {meta.get('title','')}\n"
            f"- severidad: {meta.get('severity','')}\n"
            f"- afectado: {', '.join(meta.get('affected') or []) or '—'}\n"
            f"- validación IA: {meta.get('validation_status','')}\n"
            f"- revisión humana: {((meta.get('review') or {}).get('status') or 'pending')}\n\n"
            f"## ¿Qué es? (description)\n{meta.get('description','') or '(vacío)'}\n\n"
            f"## Impacto\n{meta.get('impact','') or '(vacío)'}\n\n"
            f"## info.md\n{info_md or '(vacío)'}\n\n"
            f"## reproduction.md\n{repro or '(vacío)'}\n\n"
            f"## exploit.md\n{exploit or '(vacío)'}\n\n"
            f"## casos\n{cases_txt or '(ninguno)'}\n"
        )
        return _LLM_VULN_CHAT_SYSTEM + "\n\n" + ctx

    def _handle_vuln_chat_get(self, engagement: str, vid: str):
        vd = _find_vuln_dir(resolve_engagement_dir(engagement), vid)
        msgs = self._read_vuln_chat(vd / self._VULN_CHAT_FILE) if vd is not None else []
        self._json({"messages": msgs})

    def _handle_vuln_report_howto(self, engagement: str, vid: str):
        """POST .../vulns/<vid>/report-howto — genera el markdown de "cómo
        reportarla": clasifica el template más parecido (o usa el general) y lo
        usa como ejemplo de estilo para redactar el reporte de ESTA vuln con sus
        datos reales. Persiste en report.md. Body opcional: {force:true}."""
        wik3_dir = resolve_engagement_dir(engagement)
        vd = _find_vuln_dir(wik3_dir, vid)
        if vd is None:
            self._json({"error": "vuln no encontrada"}, code=404)
            return
        if not os.environ.get("ANTHROPIC_API_KEY", "").strip():
            self._json({"error": "LLM no disponible (sin ANTHROPIC_API_KEY)"}, code=503)
            return
        body = self._read_json_body() or {}
        force = bool(body.get("force"))
        existing = vd / self._VULN_REPORT_FILE
        if existing.is_file() and not force:
            try:
                self._json({"report": existing.read_text(), "cached": True})
                return
            except Exception:
                pass

        def _rf(name):
            try:
                return (vd / name).read_text().strip()
            except Exception:
                return ""
        try:
            meta = json.loads((vd / "meta.json").read_text())
        except Exception:
            meta = {}
        info_md, repro, exploit = _rf("info.md"), _rf("reproduction.md"), _rf("exploit.md")
        cases = meta.get("cases") if isinstance(meta.get("cases"), list) else []
        cases_txt = ""
        for i, c in enumerate(cases[:8], 1):
            if isinstance(c, dict):
                cases_txt += f"- caso {i}: {c.get('location','')}\n  evidencia: {str(c.get('evidence',''))[:600]}\n"
        vuln_summary = (
            f"# Vulnerabilidad detectada\n"
            f"- id: {meta.get('id', vid)}\n"
            f"- título: {meta.get('title','')}\n"
            f"- severidad: {meta.get('severity','')}\n"
            f"- afectado: {', '.join(meta.get('affected') or []) or '—'}\n\n"
            f"## ¿Qué es?\n{meta.get('description','') or '(vacío)'}\n\n"
            f"## Impacto\n{meta.get('impact','') or '(vacío)'}\n\n"
            f"## info.md\n{info_md or '(vacío)'}\n\n"
            f"## reproduction.md\n{repro or '(vacío)'}\n\n"
            f"## exploit.md\n{exploit or '(vacío)'}\n\n"
            f"## casos\n{cases_txt or '(ninguno)'}\n"
        )
        # Plantillas por-tipo de reportes_offsec (report_templates/), no las 51 viejas.
        index = _load_report_type_index()
        tpl_file, matched, reason = _classify_report_template(
            vuln_summary, index, general="_PLANTILLA_BASE.md")
        tpl_path = REPORT_TEMPLATES_DIR / tpl_file
        try:
            tpl_content = tpl_path.read_text()
        except Exception:
            tpl_file = "_PLANTILLA_BASE.md"
            matched = False
            try:
                tpl_content = (REPORT_TEMPLATES_DIR / "_PLANTILLA_BASE.md").read_text()
            except Exception:
                tpl_content = ""
        gen_user = (
            vuln_summary
            + "\n\n# Plantilla de ejemplo (estilo Hackmetrix" + (" — molde general" if not matched else "") + ")\n"
            + tpl_content
        )
        try:
            report = _llm_complete(_LLM_REPORT_HOWTO_SYSTEM, gen_user, max_tokens=4000).strip()
        except Exception as e:
            self._json({"error": f"LLM falló: {e}"}, code=502)
            return
        if not report:
            self._json({"error": "el modelo no devolvió contenido"}, code=502)
            return
        try:
            (vd / self._VULN_REPORT_FILE).write_text(report)
        except Exception:
            pass
        # vuln_type legible del template elegido (para mostrar en la UI).
        tpl_type = next((e.get("vuln_type") for e in index if e.get("file") == tpl_file), None)
        self._json({
            "report": report,
            "template": tpl_file,
            "template_type": tpl_type,
            "matched": matched,
            "reason": reason,
            "cached": False,
        })

    # ── Reporte completo (tab "Reporte") ───────────────────────────────────
    _REPORT_FULL_FILE = "report_full.md"
    _REPORT_PDF_FILE = "report_full.pdf"

    def _validated_vulns(self, wik3_dir):
        """Vulns validadas por el hacker (review.status == validated)."""
        return [v for v in list_vulns(wik3_dir)
                if (v.get("review") or {}).get("status") == "validated"]

    def _report_type_templates(self, vulns) -> str:
        """Recolecta las plantillas por-tipo (report_templates/<cat>/*.md) que
        mejor matchean los títulos de las vulns validadas, por keywords. Devuelve
        su contenido concatenado (dedup) para guiar al LLM. Si no matchea ninguna,
        cae a _PLANTILLA_BASE.md."""
        picked: dict = {}
        try:
            allt = list(REPORT_TEMPLATES_DIR.glob("*/*.md"))
        except Exception:
            allt = []
        blob = " ".join((v.get("title") or "") + " " + " ".join(v.get("affected") or []) for v in vulns).lower()
        for p in allt:
            stem = p.stem.lower()
            # keywords del nombre del archivo (idor, xss, sqli, ssrf, ...)
            kws = [k for k in re.split(r"[-_]", stem) if len(k) >= 3]
            if any(k in blob for k in kws):
                try:
                    picked[p.name] = p.read_text()
                except Exception:
                    pass
        if not picked:
            try:
                picked["_PLANTILLA_BASE.md"] = (REPORT_TEMPLATES_DIR / "_PLANTILLA_BASE.md").read_text()
            except Exception:
                pass
        return "\n\n".join(f"<!-- plantilla: {n} -->\n{c}" for n, c in list(picked.items())[:8])

    def _handle_report_markdown(self, engagement: str):
        """POST .../report/markdown — genera ON-DEMAND el reporte completo estilo
        Hackmetrix (markdown) a partir de las vulns VALIDADAS, usando la plantilla
        de reporte completo + las plantillas por tipo. Persiste report_full.md.
        GET devuelve el report_full.md existente (sin regenerar)."""
        if not _report_tab_enabled():
            self._json({"error": "feature no habilitado"}, code=403)
            return
        wik3_dir = resolve_engagement_dir(engagement)
        out = wik3_dir / self._REPORT_FULL_FILE
        if self.command == "GET":
            if out.is_file():
                self._json({"markdown": out.read_text(), "exists": True})
            else:
                self._json({"markdown": "", "exists": False})
            return
        # POST → generar
        if not os.environ.get("ANTHROPIC_API_KEY", "").strip():
            self._json({"error": "LLM no disponible (sin ANTHROPIC_API_KEY)"}, code=503)
            return
        validated = self._validated_vulns(wik3_dir)
        if not validated:
            self._json({"error": "no hay vulnerabilidades validadas por el hacker todavía"}, code=409)
            return
        # Datos del engagement + estructura + plantillas por tipo.
        try:
            cfg = _parse_yaml_safe(_engagement_path(engagement).read_text()) or {}
        except Exception:
            cfg = {}
        scope = cfg.get("scope") or {}
        scope_txt = ", ".join((scope.get("domains") or []) + (scope.get("ips") or []) + (scope.get("urls") or [])) or "—"
        try:
            full_tpl = (REPORT_TEMPLATES_DIR / "_PLANTILLA_REPORTE_COMPLETO.md").read_text()
        except Exception:
            full_tpl = ""
        type_tpls = self._report_type_templates(validated)
        # Hallazgos: cada vuln validada con su info real (reusa report.md si ya existe).
        findings_ctx = []
        for v in validated:
            vd = _find_vuln_dir(wik3_dir, v.get("id") or "")
            rep = info = repro = ""
            if vd is not None:
                for nm, var in (("report.md", "rep"), ("info.md", "info"), ("reproduction.md", "repro")):
                    try:
                        txt = (vd / nm).read_text().strip()
                    except Exception:
                        txt = ""
                    if var == "rep": rep = txt
                    elif var == "info": info = txt
                    else: repro = txt
            repro_block = ("## Reproducción\n" + repro) if (repro and not rep) else ""
            findings_ctx.append(
                f"### {v.get('id','')} — {v.get('title','')} [{v.get('severity','')}]\n"
                f"afectado: {', '.join(v.get('affected') or []) or '—'}\n"
                f"{rep or info}\n{repro_block}"
            )
        user = (
            f"# Datos del engagement\n"
            f"- Cliente/Producto: {cfg.get('display_name') or engagement}\n"
            f"- Scope: {scope_txt}\n"
            f"- Fecha: {cfg.get('started_at') or ''}\n\n"
            f"# Plantilla del REPORTE COMPLETO (estructura a seguir EXACTA)\n{full_tpl}\n\n"
            f"# Plantillas por TIPO de vuln (formato de cada hallazgo en la sección 8)\n{type_tpls}\n\n"
            f"# Vulnerabilidades VALIDADAS a incluir ({len(validated)})\n" + "\n\n".join(findings_ctx)
        )
        try:
            md = _llm_complete(_LLM_REPORT_FULL_SYSTEM, user, max_tokens=8000).strip()
        except Exception as e:
            self._json({"error": f"LLM falló: {e}"}, code=502)
            return
        if not md:
            self._json({"error": "el modelo no devolvió contenido"}, code=502)
            return
        try:
            out.write_text(md)
            (wik3_dir / self._REPORT_PDF_FILE).unlink(missing_ok=True)  # el PDF viejo queda obsoleto
        except Exception:
            pass
        self._json({"markdown": md, "exists": True, "vulns": len(validated)})

    def _handle_report_html(self, engagement: str):
        """GET .../report/html — devuelve el reporte renderizado EXACTAMENTE como la
        app report_build (cover A4 + hoja body con el style.css real + marked),
        para mostrarlo en un iframe del tab Reporte. Gated igual que el reporte."""
        if not _report_tab_enabled():
            self.send_response(403)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<!doctype html><body>feature no habilitado</body>")
            return
        wik3_dir = resolve_engagement_dir(engagement)
        md_path = wik3_dir / self._REPORT_FULL_FILE
        md = md_path.read_text() if md_path.is_file() else ""

        def _ra_text(p):
            try:
                return (REPORT_ASSETS_DIR / p).read_text()
            except Exception:
                return ""

        def _ra_b64(p):
            try:
                return base64.b64encode((REPORT_ASSETS_DIR / p).read_bytes()).decode()
            except Exception:
                return ""

        css = _ra_text("style.css")
        marked_js = _ra_text("marked.umd.js")
        cover_b64 = _ra_b64("cover.png")
        logo_b64 = _ra_b64("logo.png")
        cover_html = ('<div class="sheet cover"><img src="data:image/png;base64,'
                      + cover_b64 + '"></div>') if cover_b64 else ""
        logo_html = ('<img class="pg-logo" src="data:image/png;base64,'
                     + logo_b64 + '">') if logo_b64 else ""
        empty_note = ('<p style="color:#888">Aún no se generó el reporte. Aprieta '
                      '<b>Generar reporte</b>.</p>') if not md.strip() else ""
        # CSS de pantalla (gris + hojas A4) — réplica de report_build/server.mjs.
        stage_css = (
            "body{margin:0;background:#5a5a5e;"
            "font-family:'Avenir Next',Helvetica,Arial,sans-serif;}"
            ".stage{padding:28px 16px 60px;display:flex;flex-direction:column;"
            "align-items:center;gap:20px;}"
            ".sheet{width:210mm;min-height:297mm;background:#fff;"
            "box-shadow:0 6px 28px rgba(0,0,0,.35);}"
            ".sheet.cover img{display:block;width:100%;height:297mm;object-fit:cover;}"
            ".sheet.body{position:relative;padding:28mm 18mm 22mm 18mm;}"
            ".sheet.body .pg-logo{height:9mm;margin-bottom:6mm;}"
            ".sheet.body .pg-foot{position:absolute;left:18mm;right:18mm;bottom:11mm;"
            "display:flex;justify-content:space-between;font-size:9pt;color:#777;}"
        )
        parts = [
            '<!doctype html><html lang="es"><head><meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1">',
            "<style>", stage_css, css, "</style></head><body>",
            '<div class="stage">', cover_html,
            '<div class="sheet body">', logo_html,
            '<div id="content">', empty_note, "</div>",
            '<div class="pg-foot"><span>Confidencial</span><span></span></div>',
            "</div></div>",
            "<script>", marked_js, "</script>",
            "<script>var MD=", json.dumps(md), ";",
            "if(MD&&window.marked){document.getElementById('content').innerHTML=",
            "(window.marked.parse?window.marked.parse(MD):window.marked(MD));}",
            "</script></body></html>",
        ]
        data = "".join(parts).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _handle_report_pdf(self, engagement: str):
        """GET .../report/pdf — genera el PDF (estilo Hackmetrix) desde
        report_full.md con Playwright (chromium ya instalado) y lo devuelve.
        Requiere que el markdown se haya generado antes."""
        if not _report_tab_enabled():
            self._json({"error": "feature no habilitado"}, code=403)
            return
        wik3_dir = resolve_engagement_dir(engagement)
        md_path = wik3_dir / self._REPORT_FULL_FILE
        if not md_path.is_file():
            self._json({"error": "genera primero el reporte (markdown)"}, code=409)
            return
        pdf_path = wik3_dir / self._REPORT_PDF_FILE
        script = SCRIPT_DIR.parent / "scripts" / "report_pdf.py"
        args = [str(script), str(md_path), str(pdf_path), str(REPORT_ASSETS_DIR)]
        # 1) host python3 (local-dev tiene playwright). 2) fallback: dentro de la
        # imagen del agente (la VM NO tiene playwright/chromium en el host; viven
        # en fabro-agent:latest). Montamos /opt/wik3-fabro para que los paths calcen.
        attempts = [["python3"] + args]
        docker = shutil.which("docker")
        if docker and str(script).startswith("/opt/wik3-fabro/"):
            attempts.append([
                docker, "run", "--rm", "--network", "none",
                "-v", "/opt/wik3-fabro:/opt/wik3-fabro",
                "fabro-agent:latest", "python3"] + args)
        last = ""
        for cmd in attempts:
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            except Exception as e:
                last = str(e)
                continue
            if r.returncode == 0 and pdf_path.is_file():
                last = ""
                break
            last = (r.stderr or r.stdout or "")
            # Solo cae al contenedor si el host no tiene playwright; otro error, corta.
            if "No module named 'playwright'" not in last:
                break
        if not pdf_path.is_file():
            self._json({"error": f"PDF falló: {last[-500:]}"}, code=500)
            return
        data = pdf_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "application/pdf")
        self.send_header("Content-Disposition", f'attachment; filename="reporte-{engagement}.pdf"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _handle_vuln_chat_post(self, engagement: str, vid: str):
        if not os.environ.get("ANTHROPIC_API_KEY", "").strip():
            self._json({"error": "LLM no disponible (sin ANTHROPIC_API_KEY)"}, code=503)
            return
        body = self._read_json_body() or {}
        msg = (body.get("message") or "").strip()
        if not msg:
            self._json({"error": "message requerido"}, code=400)
            return
        if len(msg) > 4000:
            self._json({"error": "message > 4KB"}, code=400)
            return
        wik3_dir = resolve_engagement_dir(engagement)
        vd = _find_vuln_dir(wik3_dir, vid)
        if vd is None:
            self._json({"error": f"vuln {vid!r} no encontrada"}, code=404)
            return
        path = vd / self._VULN_CHAT_FILE
        history = self._read_vuln_chat(path)
        api_msgs = [{"role": m["role"], "content": m["content"]} for m in history[-self._VULN_CHAT_MAX:]]
        api_msgs.append({"role": "user", "content": msg})
        try:
            reply = _llm_chat_plain(self._build_vuln_chat_system(wik3_dir, vid), api_msgs)
        except Exception as e:
            self._json({"error": f"LLM falló: {e}"}, code=502)
            return
        if not reply:
            reply = "(sin respuesta)"
        # Extrae archivos que el asistente quiera compartir y los persiste.
        reply, files = self._extract_chat_files(wik3_dir, vid, reply)
        ts = _now_iso()
        try:
            vd.mkdir(parents=True, exist_ok=True)
            asst = {"role": "assistant", "content": reply, "ts": ts}
            if files:
                asst["files"] = files
            with path.open("a") as f:
                f.write(json.dumps({"role": "user", "content": msg, "ts": ts}, ensure_ascii=False) + "\n")
                f.write(json.dumps(asst, ensure_ascii=False) + "\n")
        except Exception:
            pass
        self._json({"reply": reply, "ts": ts, "files": files})

    def _handle_vuln_describe(self, engagement: str, vid: str):
        """POST /api/engagements/<slug>/vulns/<vid>/describe — genera con el LLM
        la descripción ("¿Qué es?") + impacto de una vuln a partir de lo que haya
        (meta + info.md + reproduction.md + exploit.md + casos), lo persiste en
        meta.json y lo devuelve. La UI lo dispara cuando el "¿Qué es?" está vacío."""
        if not os.environ.get("ANTHROPIC_API_KEY", "").strip():
            self._json({"error": "LLM no disponible (sin ANTHROPIC_API_KEY)"}, code=503)
            return
        wik3_dir = resolve_engagement_dir(engagement)
        vd = _find_vuln_dir(wik3_dir, vid)
        if vd is None:
            self._json({"error": f"vuln {vid!r} no encontrada"}, code=404)
            return
        try:
            meta = json.loads((vd / "meta.json").read_text())
        except Exception:
            meta = {"id": vid}

        def _rf(name: str) -> str:
            try:
                return (vd / name).read_text().strip()
            except Exception:
                return ""

        info_md = _rf("info.md")
        repro_md = _rf("reproduction.md")
        exploit_md = _rf("exploit.md")
        cases = meta.get("cases") if isinstance(meta.get("cases"), list) else []
        cases_txt = ""
        for i, c in enumerate(cases[:8], 1):
            if not isinstance(c, dict):
                continue
            loc = str(c.get("location") or "")
            ev = str(c.get("evidence") or "")[:300]
            cases_txt += f"- caso {i}: {loc}\n  evidencia: {ev}\n"
        user_text = (
            f"Vulnerabilidad:\n"
            f"- id: {meta.get('id', '')}\n"
            f"- título: {meta.get('title', '')}\n"
            f"- severidad: {meta.get('severity', '')}\n"
            f"- afectado: {', '.join(meta.get('affected') or []) or '—'}\n\n"
            f"## info.md\n{info_md or '(vacío)'}\n\n"
            f"## reproduction.md\n{repro_md or '(vacío)'}\n\n"
            f"## exploit.md\n{exploit_md or '(vacío)'}\n\n"
            f"## casos\n{cases_txt or '(ninguno)'}\n"
        )
        try:
            raw = _llm_complete(_LLM_DESCRIBE_SYSTEM, user_text, max_tokens=1200)
        except Exception as e:
            self._json({"error": f"LLM falló: {e}"}, code=502)
            return
        data = _parse_json_object(raw)
        if not isinstance(data, dict):
            self._json({"error": "el modelo no devolvió JSON válido"}, code=502)
            return
        description = (data.get("description") or "").strip()
        impact = (data.get("impact") or "").strip()
        if not description:
            self._json({"error": "el modelo no devolvió descripción"}, code=502)
            return
        with _REVIEW_LOCK:
            try:
                meta = json.loads((vd / "meta.json").read_text())
            except Exception:
                pass
            meta["description"] = description
            if impact:
                meta["impact"] = impact
            try:
                write_json(vd / "meta.json", meta)
            except Exception as e:
                self._json({"error": f"no pude guardar meta.json: {e}"}, code=500)
                return
        self._json({"description": description, "impact": impact})

    def _handle_retest_run(self, engagement: str):
        """POST /api/engagements/<slug>/retest/run — ejecuta retest.py de cada
        vuln con timeout, mergea resultados, persiste a retest-runs/<ts>.jsonl,
        devuelve el resumen."""
        wik3_dir = resolve_engagement_dir(engagement)
        vulns_dir = wik3_dir / "vulns"
        if not vulns_dir.is_dir():
            self._json({"error": "no hay vulns/ — importa un reporte primero"}, code=404)
            return
        # Cargar creds del operador (env vars custom para los retests). El
        # operador las edita desde la UI (modal "🔑 Credenciales"). Si el
        # archivo no existe, los retests corren con env vars defaults.
        retest_env = self._load_retest_creds(wik3_dir)
        started = _now_iso()
        results: list[dict] = []
        for sub in sorted(vulns_dir.iterdir()):
            if not sub.is_dir() or not sub.name.startswith("V-"):
                continue
            meta_path = sub / "meta.json"
            if not meta_path.is_file():
                continue
            try:
                meta = json.loads(meta_path.read_text())
            except Exception:
                continue
            vid = meta.get("id", sub.name)
            title = meta.get("title", "")
            severity = meta.get("severity", "")
            retest_path = sub / "retest.py"
            if not retest_path.is_file() or retest_path.stat().st_size == 0:
                results.append({
                    "id": vid, "title": title, "severity": severity,
                    "status": "no_retest", "evidence": "sin retest.py",
                })
                continue
            # Respetar el flag retest_autorun de meta.json. El generator AI lo
            # setea en false cuando el unico camino de verificacion involucraria
            # acciones destructivas o ruidosas (POST a pagos, DELETE, brute,
            # fuzzing). Skipear evita disparar producción al hacer "Run retest".
            if meta.get("retest_autorun") is False:
                reason = "retest_autorun=false (requiere acción manual — ver script)"
                results.append({
                    "id": vid, "title": title, "severity": severity,
                    "status": "skipped", "evidence": reason,
                })
                continue
            try:
                run_env = self._retest_subprocess_env(retest_env)
                proc = subprocess.run(
                    ["python3", str(retest_path)],
                    capture_output=True, text=True,
                    timeout=self._RETEST_TIMEOUT,
                    cwd=str(sub),
                    env=run_env,
                )
                stdout = proc.stdout or ""
                # Buscar la ÚLTIMA línea que sea JSON con campo "status".
                parsed = None
                for line in reversed(stdout.splitlines()):
                    line = line.strip()
                    if not (line.startswith("{") and line.endswith("}")):
                        continue
                    try:
                        candidate = json.loads(line)
                        if isinstance(candidate, dict) and "status" in candidate:
                            parsed = candidate
                            break
                    except Exception:
                        continue
                if parsed is None:
                    status = "error"
                    evidence = f"sin línea JSON con status. exit={proc.returncode}. stderr: {proc.stderr.strip()[:200]}"
                else:
                    status = str(parsed.get("status") or "error")
                    if status not in {"vulnerable", "mitigated", "inconclusive"}:
                        status = "error"
                    evidence = str(parsed.get("evidence") or "")
            except subprocess.TimeoutExpired:
                status = "timeout"
                evidence = f"retest.py > {self._RETEST_TIMEOUT}s"
            except Exception as e:
                status = "error"
                evidence = str(e)
            results.append({
                "id": vid, "title": title, "severity": severity,
                "status": status, "evidence": evidence,
            })

        runs_dir = wik3_dir / "retest-runs"
        runs_dir.mkdir(parents=True, exist_ok=True)
        ts_safe = started.replace(":", "-")
        run_path = runs_dir / f"{ts_safe}.jsonl"
        with run_path.open("w") as f:
            for r in results:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        # Symlink "latest" → ese archivo.
        latest = runs_dir / "latest.jsonl"
        try:
            if latest.is_symlink() or latest.exists():
                latest.unlink()
            latest.symlink_to(run_path.name)
        except Exception:
            pass
        self._json({
            "started_at": started,
            "completed_at": _now_iso(),
            "total": len(results),
            "results": results,
            "run_file": run_path.name,
        })

    # ── Retest creds ────────────────────────────────────────────────────────
    # Archivo `retest-creds.env` en el workspace del engagement. Formato:
    # una línea por var `KEY=value` (comentarios con #). Permisos 600. Solo
    # el dashboard service lo lee y lo inyecta como env al subprocess que
    # corre retest.py. El generator AI también recibe los KEYS (no values)
    # para que escriba scripts que las usen con el nombre correcto.
    _RETEST_CREDS_FILE = "retest-creds.env"
    _RETEST_LOGIN_FILE = "retest-login.md"   # URLs de login + cómo loguearse
    _RETEST_AUTH_FILE = "retest-auth.txt"    # texto crudo de auth (para re-precargar)
    _RETEST_CREDS_MAX = 16 * 1024  # 16 KB

    @staticmethod
    def _parse_retest_creds(text: str) -> dict[str, str]:
        out: dict[str, str] = {}
        for line in (text or "").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            k, _, v = line.partition("=")
            k = k.strip()
            if not k or not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", k):
                continue
            # Soportar `KEY="value"` o `KEY=value`.
            v = v.strip()
            if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
                v = v[1:-1]
            out[k] = v
        return out

    def _load_retest_creds(self, wik3_dir) -> dict[str, str]:
        p = wik3_dir / self._RETEST_CREDS_FILE
        if not p.is_file():
            return {}
        try:
            return self._parse_retest_creds(p.read_text())
        except Exception:
            return {}

    def _handle_retest_creds_get(self, engagement: str):
        """GET /api/engagements/<slug>/retest/creds — devuelve el contenido
        completo (operador es el dueño del workspace, puede ver sus creds)."""
        wik3_dir = resolve_engagement_dir(engagement)
        p = wik3_dir / self._RETEST_CREDS_FILE
        text = ""
        if p.is_file():
            try:
                text = p.read_text()
            except Exception:
                text = ""
        parsed = self._parse_retest_creds(text)
        # Texto crudo de auth (campo único del import) para re-precargar al editar.
        auth_text = ""
        ap = wik3_dir / self._RETEST_AUTH_FILE
        if ap.is_file():
            try:
                auth_text = ap.read_text()
            except Exception:
                auth_text = ""
        # Login configurado (URLs + cómo loguearse).
        login_text = ""
        lp = wik3_dir / self._RETEST_LOGIN_FILE
        if lp.is_file():
            try:
                login_text = lp.read_text()
            except Exception:
                login_text = ""
        self._json({
            "text": text,
            "keys": sorted(parsed.keys()),
            "count": len(parsed),
            "auth_text": auth_text,
            "login_text": login_text,
            "has_login": bool(login_text.strip()),
        })

    def _handle_retest_creds_put(self, engagement: str):
        """PUT /api/engagements/<slug>/retest/creds — guarda el contenido como
        archivo .env (permisos 600). Devuelve los KEYS resultantes."""
        body = self._read_body()
        if len(body) > self._RETEST_CREDS_MAX:
            self._json({"error": f"contenido > {self._RETEST_CREDS_MAX} bytes"}, code=413)
            return
        text = body.decode("utf-8", errors="replace")
        # Si NO viene como KEY=value limpio, un LLM entiende el texto libre
        # ("user: x / pass: y", prosa, YAML…) y lo normaliza a env vars.
        normalized = False
        if text.strip() and not _looks_like_env(text) and os.environ.get("ANTHROPIC_API_KEY", "").strip():
            try:
                parsed_text = _llm_parse_creds(text)
                if parsed_text and _looks_like_env(parsed_text):
                    text = parsed_text
                    normalized = True
            except Exception:
                pass  # si el LLM falla, guardamos el texto tal cual
        wik3_dir = resolve_engagement_dir(engagement)
        wik3_dir.mkdir(parents=True, exist_ok=True)
        p = wik3_dir / self._RETEST_CREDS_FILE
        try:
            tmp = p.with_suffix(".env.tmp")
            tmp.write_text(text)
            os.chmod(tmp, 0o600)
            os.replace(tmp, p)
        except Exception as e:
            self._json({"error": f"no pude escribir: {e}"}, code=500)
            return
        parsed = self._parse_retest_creds(text)
        self._json({"ok": True, "keys": sorted(parsed.keys()), "count": len(parsed),
                    "normalized": normalized, "text": text})

    def _handle_retest_regenerate_all(self, engagement: str):
        """POST /api/engagements/<slug>/retest/regenerate-all — itera todas
        las vulns con id `[A-Z]-...` y regenera retest.py via LLM, usando
        las creds actuales como contexto. Bulk action que el operador
        dispara desde el panel Retests."""
        wik3_dir = resolve_engagement_dir(engagement)
        env_keys = sorted(self._load_retest_creds(wik3_dir).keys()) or None
        # Recolectar vulns con su meta + info. Soporta layout nuevo y legacy.
        targets: list[tuple[str, dict, str, "object"]] = []
        # Layout nuevo
        vulns_dir = wik3_dir / "vulns"
        if vulns_dir.is_dir():
            for sub in sorted(vulns_dir.iterdir()):
                if not sub.is_dir():
                    continue
                meta_path = sub / "meta.json"
                if not meta_path.is_file():
                    continue
                try:
                    meta = json.loads(meta_path.read_text())
                except Exception:
                    continue
                vid = meta.get("id") or sub.name
                info_md = ""
                info_path = sub / "info.md"
                if info_path.is_file():
                    try:
                        info_md = info_path.read_text()
                    except Exception:
                        info_md = ""
                targets.append((vid, meta, info_md, sub))
        # Fallback legacy: findings.json
        if not targets:
            for phase in ("passive", "active", "validated"):
                data = read_json(wik3_dir / phase / "findings.json")
                if not isinstance(data, list):
                    continue
                for f in data:
                    if not isinstance(f, dict):
                        continue
                    vid = f.get("id") or ""
                    if not re.match(r"^[A-Z]-[A-Za-z0-9_.\-]+$", vid):
                        continue
                    info_parts = []
                    for k in ("description", "impact", "recommendation", "reproduction"):
                        v = f.get(k)
                        if v:
                            info_parts.append(f"## {k}\n{v}")
                    targets.append((vid, f, "\n\n".join(info_parts), None))

        regenerated: list[dict] = []
        errors: list[dict] = []
        for vid, meta, info_md, vd in targets:
            try:
                content = _llm_generate_vuln_artifact(meta, info_md, "retest.py", env_keys)
            except Exception as e:
                errors.append({"id": vid, "error": str(e)[:200]})
                continue
            # Parsear el marker WIK3_AUTORUN.
            autorun = False
            try:
                first_line = content.lstrip().splitlines()[0] if content.strip() else ""
                m = re.match(r"^\s*#\s*WIK3_AUTORUN\s*:\s*(true|false)\s*$", first_line, re.IGNORECASE)
                if m:
                    autorun = m.group(1).lower() == "true"
            except Exception:
                pass
            # Decidir target_dir (legacy: crear vulns/<vid>/ lazy).
            target_dir = vd if vd is not None else (wik3_dir / "vulns" / vid)
            try:
                target_dir.mkdir(parents=True, exist_ok=True)
                (target_dir / "retest.py").write_text(content)
            except Exception as e:
                errors.append({"id": vid, "error": f"write: {e}"})
                continue
            # Actualizar meta.json con retest_autorun.
            meta_path = target_dir / "meta.json"
            try:
                cur = json.loads(meta_path.read_text()) if meta_path.is_file() else {}
            except Exception:
                cur = {}
            cur["retest_autorun"] = autorun
            try:
                tmp = meta_path.with_suffix(".json.tmp")
                tmp.write_text(json.dumps(cur, ensure_ascii=False, indent=2))
                os.replace(tmp, meta_path)
            except Exception:
                pass
            regenerated.append({"id": vid, "autorun": autorun, "bytes": len(content)})
        self._json({"regenerated": regenerated, "errors": errors})

    def _handle_retest_history(self, engagement: str):
        """GET /api/engagements/<slug>/retest — devuelve runs anteriores + el último."""
        wik3_dir = resolve_engagement_dir(engagement)
        runs_dir = wik3_dir / "retest-runs"
        runs: list[dict] = []
        if runs_dir.is_dir():
            for f in sorted(runs_dir.glob("*.jsonl"), reverse=True):
                if f.name == "latest.jsonl":
                    continue
                results = []
                try:
                    for line in f.read_text().splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        results.append(json.loads(line))
                except Exception:
                    continue
                # f.stem = "2026-05-25T18-04-48" (ts con `:` → `-` para
                # filename safety en _handle_retest_run). Reconvertir solo
                # la parte de tiempo (después de la T) para display ISO.
                stem_parts = f.stem.split("T", 1)
                if len(stem_parts) == 2:
                    ts_str = stem_parts[0] + "T" + stem_parts[1].replace("-", ":")
                else:
                    ts_str = f.stem
                runs.append({
                    "file": f.name,
                    "timestamp": ts_str[:19],
                    "total": len(results),
                    "by_status": _count_status(results),
                    "results": results,
                })
        self._json({"runs": runs, "latest": runs[0] if runs else None})

    def _vuln_file_resolve(self, engagement: str, vid: str, name: str, create: bool = False):
        """Resuelve el path del archivo de una vuln. Devuelve None si el
        nombre no está en el whitelist. Si la carpeta vulns/<vid>/ no existe
        y `create=True`, la crea (necesario para findings del layout legacy
        A-/P-/... que no tienen carpeta hasta que el operador edita algo)."""
        if name not in self._VULN_FILE_WHITELIST:
            return None
        if not re.match(r"^[A-Z]-[A-Za-z0-9_.\-]+$", vid):
            return None
        wik3_dir = resolve_engagement_dir(engagement)
        vd = _find_vuln_dir(wik3_dir, vid)
        if vd is not None:
            return vd / name
        if not create:
            # GET sin carpeta — devolvemos un path no-existente; el caller
            # responde con cuerpo vacío.
            return wik3_dir / "vulns" / vid / name
        # PUT sin carpeta — la creamos. El layout queda vulns/<vid>/ (sin
        # slug). Cuando se migre a V- canonical, se podra renombrar.
        target = wik3_dir / "vulns" / vid
        target.mkdir(parents=True, exist_ok=True)
        return target / name

    def _handle_vuln_file_get(self, engagement: str, vid: str, name: str):
        path = self._vuln_file_resolve(engagement, vid, name)
        if path is None:
            self._json({"error": "vuln o filename inválido"}, code=404)
            return
        if not path.is_file():
            # No existe aún (ej: retest.py opcional) — devolvemos vacío + 200
            # para que la UI muestre un textarea editable sin error.
            data = b""
        else:
            try:
                data = path.read_bytes()
            except Exception as e:
                self._json({"error": str(e)}, code=500)
                return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _handle_vuln_file_put(self, engagement: str, vid: str, name: str):
        path = self._vuln_file_resolve(engagement, vid, name, create=True)
        if path is None:
            self._json({"error": "vuln o filename inválido"}, code=404)
            return
        body = self._read_body()
        if len(body) > self._VULN_FILE_MAX:
            self._json({"error": f"archivo > {self._VULN_FILE_MAX} bytes"}, code=413)
            return
        try:
            tmp = path.with_suffix(path.suffix + ".tmp")
            tmp.write_bytes(body)
            os.replace(tmp, path)
        except Exception as e:
            self._json({"error": str(e)}, code=500)
            return
        self._json({"ok": True, "bytes": len(body)})

    def _handle_vuln_file_generate(self, engagement: str, vid: str, name: str):
        """POST /api/engagements/<slug>/vulns/<vid>/generate?name=retest.py
        Genera retest.py o exploit.md con Claude usando meta.json + info.md
        de la vuln como contexto. Sobrescribe el archivo existente."""
        if name not in {"retest.py", "exploit.md", "reproduction.md"}:
            self._json({"error": "name debe ser retest.py o exploit.md"}, code=400)
            return
        if not os.environ.get("ANTHROPIC_API_KEY", "").strip():
            self._json({"error": "LLM no disponible (sin ANTHROPIC_API_KEY)"}, code=503)
            return
        wik3_dir = resolve_engagement_dir(engagement)
        result = self._generate_vuln_artifact(wik3_dir, vid, name)
        code = result.pop("_code", 200)
        self._json(result, code=code)

    def _generate_vuln_artifact(self, wik3_dir, vid: str, name: str) -> dict:
        """Genera retest.py / exploit.md / reproduction.md para una vuln con el
        LLM (meta.json + info.md como contexto) y lo escribe a disco. Devuelve
        un dict con el resultado (con '_code' para el status HTTP en caso de
        error). Reutilizado por el endpoint /generate y por la auto-generación
        de retest.py al validar un finding."""
        # Contexto = layout nuevo (vulns/<id>) + legacy (findings.json) COMBINADOS.
        # OJO: para findings A-/P- suele existir un dir vulns/<id> STUB (solo
        # review/severity/retest_autorun, sin título/impacto) mientras la data
        # rica vive en findings.json. Si solo miráramos el dir, el generador
        # armaría reproduction.md/retest.py desde un contexto vacío → stub de
        # [VERIFICAR]. Por eso enriquecemos el meta del dir con el entry legacy.
        meta: dict = {}
        info_md = ""
        vd = _find_vuln_dir(wik3_dir, vid)
        if vd is not None:
            try:
                meta = json.loads((vd / "meta.json").read_text())
            except Exception:
                meta = {}
            try:
                info_md = (vd / "info.md").read_text()
            except Exception:
                info_md = ""
        # Entry legacy de findings.json (validated → active → passive: el más
        # completo primero). Rellena lo que el dir no tiene.
        legacy = None
        for sub in ("validated", "active", "passive"):
            data = read_json(wik3_dir / sub / "findings.json")
            if not isinstance(data, list):
                continue
            for entry in data:
                if isinstance(entry, dict) and entry.get("id") == vid:
                    legacy = entry
                    break
            if legacy:
                break
        if vd is None and legacy is None:
            return {"error": f"vuln {vid!r} no encontrada", "_code": 404}
        if legacy:
            aff = legacy.get("affected")
            if aff is not None and not isinstance(aff, list):
                aff = [aff]
            merge = {**legacy, "affected": aff} if aff is not None else dict(legacy)
            for k in ("title", "severity", "phase", "affected", "confidence",
                      "description", "impact", "recommendation", "fix",
                      "remediation", "reproduction", "cases"):
                if not meta.get(k) and merge.get(k):
                    meta[k] = merge[k]
        meta.setdefault("id", vid)
        # Si no hay info.md, sintetizar contexto desde el meta ya enriquecido.
        if not info_md.strip():
            parts = []
            for k in ("description", "impact", "recommendation", "fix", "remediation", "reproduction"):
                v = meta.get(k)
                if v:
                    parts.append(f"## {k}\n{v if isinstance(v, str) else json.dumps(v, ensure_ascii=False, indent=2)}")
            cases = meta.get("cases") if isinstance(meta.get("cases"), list) else []
            case_lines = [
                f"- {c.get('location', '')}: {str(c.get('evidence', ''))[:300]}"
                for c in cases if isinstance(c, dict)
            ]
            if case_lines:
                parts.append("## Casos\n" + "\n".join(case_lines))
            info_md = "\n\n".join(parts)
        # Para retest.py, pasar los KEYS de las creds que el operador definió
        # en /api/engagements/<slug>/retest/creds, así el LLM escribe el
        # script usando los nombres exactos que el runner va a inyectar.
        env_keys = None
        if name == "retest.py":
            env_keys = sorted(self._load_retest_creds(wik3_dir).keys()) or None
        try:
            content = _llm_generate_vuln_artifact(meta, info_md, name, env_keys)
        except Exception as e:
            return {"error": f"LLM falló: {e}", "_code": 502}
        # Asegurar carpeta (crea vulns/<vid>/ si no existe).
        target_dir = vd if vd is not None else (wik3_dir / "vulns" / vid)
        target_dir.mkdir(parents=True, exist_ok=True)
        path = target_dir / name
        try:
            tmp = path.with_suffix(path.suffix + ".tmp")
            tmp.write_text(content)
            os.replace(tmp, path)
        except Exception as e:
            return {"error": f"no pude escribir {name}: {e}", "_code": 500}
        # Para retest.py: parsear el marker WIK3_AUTORUN: true|false (1ra línea)
        # y persistirlo en meta.json. La UI lo expone como badge read-only y
        # _handle_retest_run respeta el flag (skip si false). Si el LLM no
        # emitió el marker, default conservador = false (no auto-run).
        autorun_result = None
        if name == "retest.py":
            autorun = False
            try:
                first_line = content.lstrip().splitlines()[0] if content.strip() else ""
                m = re.match(r"^\s*#\s*WIK3_AUTORUN\s*:\s*(true|false)\s*$", first_line, re.IGNORECASE)
                if m:
                    autorun = m.group(1).lower() == "true"
            except Exception:
                autorun = False
            meta_path = target_dir / "meta.json"
            try:
                cur_meta = json.loads(meta_path.read_text()) if meta_path.is_file() else {}
            except Exception:
                cur_meta = {}
            cur_meta["retest_autorun"] = autorun
            try:
                tmp = meta_path.with_suffix(".json.tmp")
                tmp.write_text(json.dumps(cur_meta, ensure_ascii=False, indent=2))
                os.replace(tmp, meta_path)
                autorun_result = autorun
            except Exception:
                pass
        resp = {"ok": True, "bytes": len(content.encode("utf-8")), "content": content}
        if autorun_result is not None:
            resp["retest_autorun"] = autorun_result
        return resp

    def _maybe_autogen_retest(self, wik3_dir, vid: str):
        """Al validar un finding (review=validated), genera su retest.py en
        background si todavía no existe — sin pisar uno hecho a mano. La
        llamada al LLM corre en un thread para no demorar la respuesta del
        endpoint de revisión."""
        try:
            vd = _find_vuln_dir(wik3_dir, vid)
            target = (vd / "retest.py") if vd is not None else (wik3_dir / "vulns" / vid / "retest.py")
            if target.is_file():
                return  # ya existe — no clobber
        except Exception:
            pass

        def _work():
            try:
                self._generate_vuln_artifact(wik3_dir, vid, "retest.py")
            except Exception:
                pass
        threading.Thread(target=_work, daemon=True).start()

    def _build_from_validated(self, wik3_dir) -> dict:
        """Regenera validated/chains.json con el LLM usando SOLO las
        vulnerabilidades validadas por el hacker (review=validated). El
        threat_model.md NO se toca: es el modelo de superficie que mantiene
        recon/passive/active y debe ser usable durante todo el engagement.
        Devuelve dict con '_code' en error."""
        if not os.environ.get("ANTHROPIC_API_KEY", "").strip():
            return {"error": "LLM no disponible (sin ANTHROPIC_API_KEY)", "_code": 503}
        findings = [f for f in list_vulns(wik3_dir)
                    if (f.get("review") or {}).get("status") == "validated"]
        if not findings:
            return {"error": "no hay vulnerabilidades validadas por el hacker todavía", "_code": 400}
        # Resumen de cada vuln validada (+ info.md recortado) como contexto.
        parts = []
        for f in findings:
            fid = f.get("id") or ""
            info = ""
            vd = _find_vuln_dir(wik3_dir, fid)
            if vd is not None:
                try:
                    info = (vd / "info.md").read_text()[:4000]
                except Exception:
                    info = ""
            aff = f.get("affected")
            aff = ", ".join(aff) if isinstance(aff, list) else (aff or "")
            parts.append(
                f"### {fid} — {f.get('title','')}\n"
                f"- severidad: {f.get('severity','')}\n"
                f"- afectado: {aff or '—'}\n"
                f"{info or '(sin info.md)'}\n"
            )
        memory = ""
        try:
            mp = wik3_dir / "memory.md"
            if mp.is_file():
                memory = mp.read_text()[:6000]
        except Exception:
            memory = ""
        ctx = (
            (f"## Contexto del objetivo (memory.md, recortado)\n{memory}\n\n" if memory else "")
            + "## Vulnerabilidades VALIDADAS por el hacker\n" + "\n".join(parts)
        )
        # Cadenas de ataque desde las validadas (best-effort: si el JSON no
        # parsea, no tocamos chains.json).
        chains_written = None
        try:
            raw = _llm_complete(_LLM_CHAINS_SYSTEM, ctx, max_tokens=4000)
            chains = _parse_json_array(raw)
            if isinstance(chains, list):
                (wik3_dir / "validated").mkdir(parents=True, exist_ok=True)
                p = wik3_dir / "validated" / "chains.json"
                tmp = p.with_suffix(".json.tmp")
                tmp.write_text(json.dumps(chains, ensure_ascii=False, indent=2))
                os.replace(tmp, p)
                chains_written = len(chains)
        except Exception:
            chains_written = None
        return {"ok": True, "validated": len(findings), "chains": chains_written}

    def _schedule_report_build(self, engagement: str, wik3_dir):
        """Dispara _build_from_validated en background, coalesciendo validaciones
        seguidas (ver _REPORT_BUILD_STATE)."""
        if not os.environ.get("ANTHROPIC_API_KEY", "").strip():
            return
        with _REPORT_BUILD_GUARD:
            st = _REPORT_BUILD_STATE.setdefault(engagement, {"running": False, "dirty": False})
            if st["running"]:
                st["dirty"] = True
                return
            st["running"] = True

        def _work():
            try:
                while True:
                    try:
                        self._build_from_validated(wik3_dir)
                    except Exception:
                        pass
                    with _REPORT_BUILD_GUARD:
                        st = _REPORT_BUILD_STATE.get(engagement) or {}
                        if st.get("dirty"):
                            st["dirty"] = False
                            continue
                        st["running"] = False
                        break
            except Exception:
                with _REPORT_BUILD_GUARD:
                    s = _REPORT_BUILD_STATE.get(engagement)
                    if s:
                        s["running"] = False
        threading.Thread(target=_work, daemon=True).start()

    def _handle_review_finding(self, engagement: str, fid: str):
        body = self._read_json_body()
        status = (body.get("status") or "").strip()
        note = (body.get("note") or "").strip()
        # severity es opcional: si viene, el hacker la esta overrideando.
        severity_raw = body.get("severity")
        severity = (severity_raw or "").strip().lower() if severity_raw else ""
        if status not in REVIEW_STATUSES:
            self._json({"error": f"status inválido: {status!r}"}, code=400)
            return
        if severity and severity not in SEVERITIES:
            self._json({"error": f"severity inválida: {severity!r}"}, code=400)
            return
        actor = self._auth_actor()
        wik3_dir = resolve_engagement_dir(engagement)
        review = {
            "status": status,
            "by": actor,
            "at": _now_iso(),
            "note": note,
        }
        meta_finding: dict | None = None
        legacy_finding: dict | None = None
        with _REVIEW_LOCK:
            # 1. Layout nuevo: vulns/<id>-*/meta.json (si existe el dir).
            vuln_dir = _find_vuln_dir(wik3_dir, fid)
            if vuln_dir is not None:
                meta_path = vuln_dir / "meta.json"
                try:
                    meta = json.loads(meta_path.read_text())
                except Exception:
                    meta = {}
                meta["review"] = dict(review)
                meta.setdefault("id", fid)
                if severity and severity != (meta.get("severity") or "").lower():
                    meta["severity"] = severity
                write_json(meta_path, meta)
                meta_finding = meta
            # 2. SIEMPRE sincronizar con los arrays legacy si el finding también
            #    vive ahí. Para A-/P-/F- el dashboard lee de findings.json
            #    (list_vulns solo mira V-*), así que la review escrita en un dir
            #    vulns/A-001 NO se vería en la tabla sin esto → el modal decía
            #    "falso positivo" pero la tabla seguía "pendiente". Mantener ambas
            #    fuentes en sync evita ese desajuste.
            for path in [
                wik3_dir / "passive" / "findings.json",
                wik3_dir / "active" / "findings.json",
                wik3_dir / "validated" / "findings.json",
            ]:
                data = read_json(path)
                if not isinstance(data, list):
                    continue
                changed = False
                for entry in data:
                    if isinstance(entry, dict) and entry.get("id") == fid:
                        entry["review"] = dict(review)
                        if severity and severity != (entry.get("severity") or "").lower():
                            entry["severity"] = severity
                        legacy_finding = entry
                        changed = True
                if changed:
                    write_json(path, data)
        # Preferir el entry legacy (más completo) para la respuesta; el modal lo
        # usa para refrescar el badge.
        updated_finding = legacy_finding or meta_finding
        if not updated_finding:
            self._json({"error": f"finding {fid!r} no encontrado"}, code=404)
            return
        # Al validar la vuln: auto-generar su retest.py (si falta) y regenerar
        # las cadenas de ataque desde el set de vulns validadas. (El threat_model
        # NO se toca — es el modelo de superficie de recon/active.) En background.
        if status == "validated" and os.environ.get("ANTHROPIC_API_KEY", "").strip():
            self._maybe_autogen_retest(wik3_dir, fid)
            self._schedule_report_build(engagement, wik3_dir)
        self._json({"finding": updated_finding})

    def _handle_admin_team_post(self):
        """POST /admin/team (bearer admin) — el admin empuja la tabla del equipo
        del TL (ya recortada a SU equipo). Se guarda con received_at del reloj de
        ESTE box para la verificación de frescura (la pestaña se oculta si no
        llega push hace ~5 min)."""
        body = self._read_json_body() or {}
        data = {
            "role": "TL" if (body.get("role") or "") == "TL" else "hacker",
            "team": str(body.get("team") or ""),
            "rows": body.get("rows") if isinstance(body.get("rows"), list) else [],
            "generated_at": body.get("generated_at") or "",
            "received_at": _now_iso(),
        }
        try:
            TEAM_PATH.parent.mkdir(parents=True, exist_ok=True)
            tmp = TEAM_PATH.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(data, ensure_ascii=False))
            os.replace(tmp, TEAM_PATH)
        except Exception as e:
            self._json({"error": str(e)}, code=500)
            return
        self._json({"ok": True})

    def _handle_team_get(self):
        """GET /api/team (auth hacker) — la UI del TL pide su tabla. fresh=False
        si no llegó push reciente o el rol no es TL → la UI oculta la pestaña."""
        try:
            data = json.loads(TEAM_PATH.read_text())
        except Exception:
            self._json({"fresh": False, "role": None, "rows": []})
            return
        fresh = False
        try:
            t = dt.datetime.strptime(data.get("received_at") or "", "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
            fresh = (dt.datetime.now(dt.timezone.utc) - t).total_seconds() <= TEAM_FRESH_SECS
        except Exception:
            fresh = False
        self._json({
            "fresh": bool(fresh and data.get("role") == "TL"),
            "role": data.get("role"),
            "team": data.get("team") or "",
            "rows": data.get("rows") or [],
            "generated_at": data.get("generated_at") or "",
        })

    def _handle_admin_message_post(self):
        """POST /admin/messages — el admin empuja un mensaje al hacker.
        Body: {text, from?}. Se persiste como unread; aparece en el dashboard
        del hacker como modal hasta que lo marca como leido."""
        body = self._read_json_body()
        text = (body.get("text") or "").strip() if isinstance(body, dict) else ""
        sender = (body.get("from") or "admin").strip() if isinstance(body, dict) else "admin"
        if not text:
            self._json({"error": "text requerido"}, code=400)
            return
        if len(text) > 8000:
            self._json({"error": "text > 8KB"}, code=400)
            return
        msg_id = secrets.token_hex(8)
        msg = {
            "id": msg_id,
            "ts": _now_iso(),
            "from": sender[:80],
            "text": text,
            "read_at": None,
            "read_by": None,
        }
        with _MESSAGES_LOCK:
            msgs = _read_messages()
            msgs.append(msg)
            _write_messages(msgs)
        self._json({"ok": True, "id": msg_id})

    def _handle_message_mark_read(self, msg_id: str):
        """POST /api/messages/<id>/read — el hacker marca el mensaje como
        leido. Idempotente: si ya estaba leido, no-op."""
        actor = self._auth_actor()
        with _MESSAGES_LOCK:
            msgs = _read_messages()
            found = False
            for m in msgs:
                if m.get("id") == msg_id:
                    found = True
                    if not m.get("read_at"):
                        m["read_at"] = _now_iso()
                        m["read_by"] = actor or ""
                    break
            if not found:
                self._json({"error": "mensaje no encontrado"}, code=404)
                return
            _write_messages(msgs)
        self._json({"ok": True, "id": msg_id})

    def _handle_scope_update(self, engagement: str):
        """POST /api/scope/update — bulk replace de scope.txt y out_of_scope.txt
        desde la UI. El hacker puede agregar/quitar hosts manualmente sin
        esperar a que el agente pida SCOPE_REQUEST. Persiste también en el
        YAML del engagement + refresca squid."""
        body = self._read_json_body()
        if not isinstance(body, dict):
            self._json({"error": "body debe ser JSON object"}, code=400)
            return
        scope_raw = body.get("scope")
        oos_raw = body.get("out_of_scope")
        if not isinstance(scope_raw, list) or not isinstance(oos_raw, list):
            self._json({"error": "scope y out_of_scope deben ser arrays"}, code=400)
            return
        if any(not isinstance(x, str) for x in scope_raw + oos_raw):
            self._json({"error": "entries deben ser strings"}, code=400)
            return
        actor = self._auth_actor()
        wik3_dir = resolve_engagement_dir(engagement)
        # Normaliza + dedupe antes de escribir, así devolvemos lo que quedó.
        scope_clean: list[str] = []
        seen_s: set[str] = set()
        for e in scope_raw:
            n = _normalize_scope_entry(e)
            if n and n not in seen_s:
                seen_s.add(n)
                scope_clean.append(n)
        oos_clean: list[str] = []
        seen_o: set[str] = set()
        for e in oos_raw:
            n = _normalize_scope_entry(e)
            if n and n not in seen_o:
                seen_o.add(n)
                oos_clean.append(n)
        _write_scope_list(wik3_dir / "scope.txt", scope_clean)
        _write_scope_list(wik3_dir / "out_of_scope.txt", oos_clean)
        yaml_warn = _replace_engagement_scope_yaml(engagement, scope_clean, oos_clean)
        squid_warn = _refresh_squid_allowlist(engagement)
        warnings = [w for w in (yaml_warn, squid_warn) if w]
        # Auto-resolver scope_request pendiente del agente si su host queda
        # cubierto por la nueva lista. Sin esto, el agente queda bloqueado en
        # ask_user.sh esperando una respuesta que ya está implícita.
        auto_resolved: dict | None = None
        try:
            convo_dir = wik3_dir / "convo"
            pending_path = convo_dir / "pending_agent.txt"
            if pending_path.is_file():
                pending_text = pending_path.read_text().strip()
                req = parse_scope_request(pending_text) if pending_text else None
                if req:
                    req_host = _normalize_scope_entry(req.get("add", ""))
                    if req_host and any(
                        req_host == s or req_host.endswith("." + s) for s in scope_clean
                    ):
                        inbox = convo_dir / "inbox.md"
                        reply = f"APPROVED: {req_host} cubierto por edición manual de scope por {actor or 'admin'}."
                        pending_path.write_text("")
                        inbox.write_text(reply)
                        with (convo_dir / "log.jsonl").open("a") as f:
                            f.write(json.dumps({
                                "ts": _now_iso(),
                                "from": "user",
                                "kind": "scope_decision",
                                "approved": True,
                                "add": req_host,
                                "text": reply,
                            }) + "\n")
                        auto_resolved = {"add": req_host}
        except Exception:
            pass
        # Log
        note_path = wik3_dir / "notes.jsonl"
        note = {
            "ts": _now_iso(),
            "stage": "scope-change",
            "title": "scope editado manualmente",
            "detail": f"{actor or 'admin'} actualizó scope ({len(scope_clean)}) / out_of_scope ({len(oos_clean)})"
                      + (f" · auto-resolvió SCOPE_REQUEST: {auto_resolved['add']}" if auto_resolved else ""),
            "tags": ["scope-change", "manual-edit"] + (["auto-resolved"] if auto_resolved else []),
        }
        try:
            with note_path.open("a") as f:
                f.write(json.dumps(note) + "\n")
        except Exception:
            pass
        self._json({
            "ok": True,
            "scope": scope_clean,
            "out_of_scope": oos_clean,
            "warnings": warnings,
            "auto_resolved_scope_request": auto_resolved,
        })

    def _handle_scope_decision(self, engagement: str, approve: bool):
        """POST /api/scope/(approve|reject) — el operador responde a un
        SCOPE_REQUEST. Si approve: appendea el host a scope.txt y manda
        APPROVED al agente via inbox.md. Si reject: solo manda REJECTED.
        En ambos casos se limpia pending_agent.txt (ask_user.sh hace lo
        mismo pero somos defensivos por si el agente no está pollando).
        """
        body = self._read_json_body()
        add = (body.get("add") or "").strip()
        reason = (body.get("reason") or "").strip()
        wik3_dir = resolve_engagement_dir(engagement)
        convo_dir = wik3_dir / "convo"
        convo_dir.mkdir(parents=True, exist_ok=True)
        inbox = convo_dir / "inbox.md"
        log_path = convo_dir / "log.jsonl"
        pending_path = convo_dir / "pending_agent.txt"
        actor = self._auth_actor()

        if approve:
            if not add:
                self._json({"error": "add (host) requerido"}, code=400)
                return
            scope_path = wik3_dir / "scope.txt"
            existing = ""
            if scope_path.is_file():
                existing = scope_path.read_text()
                if not existing.endswith("\n"):
                    existing += "\n"
            # Idempotente: no duplicar si ya está.
            lines = [l.strip() for l in existing.splitlines()]
            if add not in lines:
                scope_path.write_text(existing + add + "\n")
            # Sacar el host de out_of_scope.txt si estaba: OOS gana sobre scope,
            # así que sin esto la aprobación no lo desbloquearía de verdad.
            oos_path = wik3_dir / "out_of_scope.txt"
            if oos_path.is_file():
                add_norm = _normalize_scope_entry(add)
                kept = [l for l in oos_path.read_text().splitlines()
                        if l.strip() and _normalize_scope_entry(l) != add_norm]
                oos_path.write_text(("\n".join(kept) + "\n") if kept else "")
            # Persistir en el YAML del engagement: si no, al re-cargar la
            # engagement (squid-allowlist se regenera desde el YAML, no
            # desde scope.txt) el host se pierde.
            yaml_warn = _update_engagement_scope_yaml(engagement, add)
            # Refrescar el allowlist de squid + reload. Sin esto el host
            # pasa el scope_guard del agente pero squid lo bloquea con 403.
            squid_warn = _refresh_squid_allowlist(engagement)

            note_path = wik3_dir / "notes.jsonl"
            note = {
                "ts": _now_iso(),
                "stage": "scope-change",
                "title": f"scope ampliado: {add}",
                "detail": f"Aprobado por {actor or 'admin'}. Razón del agente / nota: {reason or '(sin nota)'}",
                "tags": ["scope-change", "approved"],
            }
            with note_path.open("a") as f:
                f.write(json.dumps(note) + "\n")
            extras = " ".join(w for w in (yaml_warn, squid_warn) if w)
            reply_text = f"APPROVED: {add} agregado a scope.txt y allowlist de squid. {reason} {extras}".strip()
        else:
            reply_text = f"REJECTED: no se aprobó. {reason}".strip()

        # Limpiar pending + entregar la respuesta al agente.
        try:
            pending_path.write_text("")
        except Exception:
            pass
        inbox.write_text(reply_text)
        log_entry = {
            "ts": _now_iso(),
            "from": "user",
            "kind": "scope_decision",
            "approved": approve,
            "add": add,
            "text": reply_text,
        }
        with log_path.open("a") as f:
            f.write(json.dumps(log_entry) + "\n")
        self._json({"ok": True, "approved": approve, "add": add if approve else None})

    def _handle_whisper(self, engagement: str):
        body = self._read_body().decode("utf-8", errors="replace")
        try:
            data = json.loads(body)
            text = (data.get("text") or "").strip()
        except Exception:
            text = body.strip()
        if not text:
            self._json({"error": "empty text"}, code=400)
            return
        wik3_dir = resolve_engagement_dir(engagement)
        inbox = wik3_dir / "convo" / "inbox.md"
        inbox.parent.mkdir(parents=True, exist_ok=True)
        inbox.write_text(text)
        # Registrar el mensaje en el timeline compartido (convo/log.jsonl) para
        # que aparezca en el chat y forme parte de la memoria común (el mismo
        # historial que lee el chat-assistant del proyecto).
        try:
            with (wik3_dir / "convo" / "log.jsonl").open("a") as f:
                f.write(json.dumps({"ts": _now_iso(), "from": "user", "kind": "chat", "text": text}, ensure_ascii=False) + "\n")
        except Exception:
            pass
        self._json({"ok": True, "delivered_to": str(inbox), "text_len": len(text)})

    # Tope de subida. Cubre APK/IPA/AAB grandes (apps móviles suelen pesar
    # cientos de MB). El camino de streaming escribe a disco en chunks, así
    # que la memoria del server es constante sin importar el tamaño.
    _UPLOAD_MAX = 1024 * 1024 * 1024  # 1 GB

    def _handle_upload(self, engagement: str):
        from urllib.parse import urlparse, parse_qs
        ctype = (self.headers.get("Content-Type") or "").lower()
        wik3_dir = resolve_engagement_dir(engagement)
        shared = wik3_dir / "convo" / "shared" / "from_user"
        shared.mkdir(parents=True, exist_ok=True)

        def _safe_name(name: str) -> str:
            return re.sub(r"[^A-Za-z0-9._-]", "_", name)[:120] or "file"

        def _unique_dest(safe: str):
            dest = shared / safe
            if dest.exists():
                safe = f"{int(time.time())}_{safe}"
                dest = shared / safe
            return dest, safe

        if "application/json" in ctype:
            # Camino legacy base64-en-JSON (archivos chicos: imágenes, etc.).
            try:
                data = json.loads(self._read_body().decode("utf-8", errors="replace"))
            except Exception:
                self._json({"error": "invalid json"}, code=400); return
            filename = (data.get("filename") or "").strip()
            content_b64 = data.get("content_b64") or ""
            description = (data.get("description") or "").strip()
            if not filename or not content_b64:
                self._json({"error": "filename + content_b64 required"}, code=400); return
            try:
                content = base64.b64decode(content_b64, validate=True)
            except Exception as e:
                self._json({"error": f"bad base64: {e}"}, code=400); return
            if len(content) > self._UPLOAD_MAX:
                self._json({"error": f"file too large (>{self._UPLOAD_MAX // (1024*1024)}MB)"}, code=413); return
            safe = _safe_name(filename)
            dest, safe = _unique_dest(safe)
            dest.write_bytes(content)
            size = len(content)
        else:
            # Camino streaming raw-binario (archivos grandes: APK/IPA/AAB). El
            # cuerpo ES el archivo crudo; filename y description vienen por query
            # param. Se escribe a disco en chunks, sin cargar todo en memoria ni
            # inflar ~33% con base64.
            qs = parse_qs(urlparse(self.path).query)
            filename = (qs.get("filename") or [""])[0].strip()
            description = (qs.get("description") or [""])[0].strip()
            if not filename:
                self._json({"error": "filename query param required (raw upload)"}, code=400); return
            length = int(self.headers.get("Content-Length", "0") or "0")
            if length <= 0:
                self._json({"error": "empty body (Content-Length 0)"}, code=400); return
            if length > self._UPLOAD_MAX:
                self._json({"error": f"file too large (>{self._UPLOAD_MAX // (1024*1024)}MB)"}, code=413); return
            safe = _safe_name(filename)
            dest, safe = _unique_dest(safe)
            size = 0
            try:
                with dest.open("wb") as fh:
                    remaining = length
                    while remaining > 0:
                        chunk = self.rfile.read(min(1024 * 1024, remaining))
                        if not chunk:
                            break
                        fh.write(chunk)
                        size += len(chunk)
                        remaining -= len(chunk)
            except Exception as e:
                try:
                    dest.unlink()
                except Exception:
                    pass
                self._json({"error": f"upload stream failed: {e}"}, code=500); return

        log_path = wik3_dir / "convo" / "log.jsonl"
        log_entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "from": "user",
            "kind": "file",
            "filename": safe,
            "size": size,
            "direction": "from_user",
            "description": description or None,
        }
        with log_path.open("a") as f:
            f.write(json.dumps(log_entry) + "\n")
        attention = wik3_dir / "convo" / "attention.md"
        with attention.open("a") as f:
            f.write(f"\n=== FILE uploaded by user ({log_entry['ts']}) ===\n\n")
            f.write(f"Filename: {safe} ({size} bytes)\n")
            f.write(f"Path: /workspace/wik3/{wik3_dir.name}/convo/shared/from_user/{safe}\n")
            if description:
                f.write(f"Description: {description}\n")
            f.write(
                "\nAccion: LEE EL ARCHIVO con 'cat', 'file', 'xxd', o lo que aplique. "
                "Despues respondele con 'say.sh' confirmando lo que viste.\n"
            )
        inbox = wik3_dir / "convo" / "inbox.md"
        inbox.write_text(f"[FILE] uploaded: {safe} ({size} bytes). Ver attention.md.")
        self._json({"ok": True, "saved_as": safe, "size": size})

    def _handle_download(self, qs: dict, engagement: str):
        direction = (qs.get("dir") or [""])[0]
        fname = (qs.get("file") or [""])[0]
        if direction not in {"from_user", "from_agent"} or not fname:
            self.send_error(400); return
        fname = re.sub(r"[^A-Za-z0-9._-]", "_", fname)
        wik3_dir = resolve_engagement_dir(engagement)
        path = wik3_dir / "convo" / "shared" / direction / fname
        if not path.exists() or not path.is_file():
            self.send_error(404); return
        ctype, _ = mimetypes.guess_type(str(path))
        ctype = ctype or "application/octet-stream"
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Disposition", f'attachment; filename="{fname}"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    # ── Burp CA download ─────────────────────────────────────────────────
    # La CA compartida vive bakeada en /etc/wik3/burp-ca.{crt,key} (ver
    # deploy/packer/setup.sh + scripts/wik3-burp-extract.sh). Estos
    # endpoints sirven el cert solo o un bundle con cert+key+README para
    # que el hacker la importe en su Burp local. Los paths son overridables
    # por env var para dev-local (no afecta prod).
    _BURP_CA_CRT = Path(os.environ.get("WIK3_BURP_CA_CRT") or "/etc/wik3/burp-ca.crt")
    _BURP_CA_KEY = Path(os.environ.get("WIK3_BURP_CA_KEY") or "/etc/wik3/burp-ca.key")

    def _handle_burp_ca_cert(self):
        path = type(self)._BURP_CA_CRT
        if not path.is_file() or path.stat().st_size == 0:
            self._json({"error": "no hay CA de Burp instalada en esta wik3"}, code=404)
            return
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "application/x-pem-file")
        self.send_header("Content-Disposition", 'attachment; filename="burp-ca.crt"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _handle_burp_ca_p12(self):
        # Sirve la CA directo como PKCS#12 (lo que Burp importa). Sin zip: el
        # hacker baja el .p12 y lo importa. El .p12 que produce OpenSSL 3.x es
        # PKCS#12 v3 válido — verificado con keytool en Java 8/11/17. Password: wik3.
        import subprocess
        crt = type(self)._BURP_CA_CRT
        key = type(self)._BURP_CA_KEY
        if not (crt.is_file() and crt.stat().st_size > 0 and key.is_file() and key.stat().st_size > 0):
            self._json({"error": "cert o key de la CA de Burp no presentes en esta wik3"}, code=404)
            return
        try:
            r = subprocess.run(
                ["openssl", "pkcs12", "-export", "-in", str(crt), "-inkey", str(key),
                 "-name", "wik3 Burp CA", "-passout", "pass:wik3"],
                capture_output=True, timeout=15)
        except Exception as e:
            self._json({"error": f"no pude generar el .p12: {e}"}, code=500)
            return
        if r.returncode != 0 or not r.stdout:
            self._json({"error": f"no pude generar el .p12: {r.stderr.decode(errors='replace')[:200]}"}, code=500)
            return
        p12 = r.stdout
        self.send_response(200)
        self.send_header("Content-Type", "application/x-pkcs12")
        self.send_header("Content-Disposition", 'attachment; filename="wik3-burp-ca.p12"')
        self.send_header("Content-Length", str(len(p12)))
        self.end_headers()
        self.wfile.write(p12)

    def _handle_attacks_export(self, engagement: str):
        """GET /api/attacks — CSV de ataques intentados (coverage/attempts.jsonl,
        escrito por coverage_log.sh attack): técnica, target, outcome, nota,
        timestamp. Sirve para el reporte de cobertura y queda también en el zip
        de resultados (attempts.jsonl crudo)."""
        import csv, io
        wik3_dir = resolve_engagement_dir(engagement)
        path = wik3_dir / "coverage" / "attempts.jsonl"
        rows = []
        if path.is_file():
            for line in path.read_text().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except Exception:
                    continue
                rows.append(e)
        # Orden: por timestamp ascendente.
        rows.sort(key=lambda r: r.get("ts", ""))
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["timestamp", "tecnica", "target", "outcome", "nota"])
        for r in rows:
            w.writerow([r.get("ts", ""), r.get("technique", ""), r.get("target", ""),
                        r.get("outcome", ""), r.get("note", "")])
        data = buf.getvalue().encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Disposition",
                         f'attachment; filename="wik3-ataques-{engagement}.csv"')
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _handle_results_bundle(self, engagement: str):
        """Zip con TODO el workspace del engagement (findings, chains,
        notes, evidence/, recon/, active/, creds/, exec.log, etc.) más
        engagement.yaml. Reemplaza el reporte markdown (deshabilitado).
        Filtros: skip symlinks (evitar loops), skip dirs de caché, cap
        global de 200 MB para evitar zips inmanejables.

        Sensible: el zip incluye `creds/vault.jsonl` y posibles secrets
        en `engagement.yaml` — son datos del cliente que el operador
        ya manejó. El README dentro del zip avisa esto.
        """
        import io, zipfile
        wik3_dir = resolve_engagement_dir(engagement)
        eng_yaml = ENGAGEMENTS_DIR / f"engagement.{engagement}.yaml"

        MAX_BUNDLE = 200 * 1024 * 1024  # 200 MB hard cap
        SKIP_DIR_NAMES = {".cache", "__pycache__", "node_modules", ".npm",
                          ".pytest_cache", ".mypy_cache"}

        buf = io.BytesIO()
        included: list[str] = []
        skipped: list[str] = []
        total_size = 0

        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, strict_timestamps=False) as zf:
            if wik3_dir.is_dir():
                for path in sorted(wik3_dir.rglob("*")):
                    if path.is_symlink():
                        continue  # evita loops del symlink `current`
                    if not path.is_file():
                        continue
                    # Skip dirs de caché (cualquier nivel).
                    if any(part in SKIP_DIR_NAMES for part in path.parts):
                        continue
                    try:
                        rel = path.relative_to(wik3_dir)
                        sz = path.stat().st_size
                    except Exception:
                        continue
                    if total_size + sz > MAX_BUNDLE:
                        skipped.append(f"workspace/{rel} ({sz} bytes)")
                        continue
                    total_size += sz
                    try:
                        zf.write(path, f"workspace/{rel}")
                        included.append(f"workspace/{rel}")
                    except Exception as e:
                        skipped.append(f"workspace/{rel} (error: {e})")

            # engagement.yaml vive fuera de wik3_dir, lo incluimos al root.
            if eng_yaml.is_file():
                try:
                    zf.write(eng_yaml, "engagement.yaml")
                    included.append("engagement.yaml")
                except Exception:
                    pass

            # README con guía de contenido.
            readme_lines = [
                "# wik3 — resultados del engagement",
                "",
                f"Engagement: `{engagement}`",
                f"Archivos incluidos: {len(included)}",
                f"Tamaño total: {total_size / 1024 / 1024:.1f} MB",
                "",
                "## Contenido",
                "",
                "El zip contiene el workspace completo del engagement bajo `workspace/`:",
                "",
                "- `workspace/passive/`, `workspace/active/`, `workspace/validated/` — findings + chains JSON.",
                "- `workspace/recon/` — evidencia recolectada en recon (subdominios, URLs, tech, etc.).",
                "- `workspace/notes.jsonl` — observaciones del agente.",
                "- `workspace/exec.log` — consola live del agente (cada bash -c + outputs).",
                "- `workspace/coverage/` — endpoints analizados, técnicas intentadas.",
                "- `workspace/creds/vault.jsonl` — **SENSIBLE**: credenciales validadas durante el run (JWTs, sesiones, etc.).",
                "- `workspace/convo/` — chat agente↔operador, archivos compartidos.",
                "- `engagement.yaml` — config del engagement (scope, credenciales iniciales, ROE).",
                "",
                "## Filtros aplicados",
                "",
                "- Symlinks skipeados (evita loops de `current/`).",
                "- Cachés skipeadas: `.cache/`, `__pycache__/`, `node_modules/`, etc.",
                "- Cap total: 200 MB. Archivos que excedan se skipean (ver lista abajo).",
                "",
            ]
            if skipped:
                readme_lines.append("## Archivos skipeados por cap de tamaño\n")
                for s in skipped[:50]:
                    readme_lines.append(f"- `{s}`")
                if len(skipped) > 50:
                    readme_lines.append(f"- ... y {len(skipped) - 50} más")
                readme_lines.append("")
            if not included:
                readme_lines.append("## No había workspace para empaquetar")
                readme_lines.append("")
                readme_lines.append("Probablemente el engagement no se corrió todavía.")
            zf.writestr("README.md", "\n".join(readme_lines).encode("utf-8"))

        data = buf.getvalue()
        self.send_response(200)
        self.send_header("Content-Type", "application/zip")
        self.send_header(
            "Content-Disposition",
            f'attachment; filename="wik3-results-{engagement}.zip"',
        )
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _handle_screenshot(self, path: str, engagement: str):
        name = path[len("/screenshots/"):]
        name = re.sub(r"[^\w.-]", "_", name)
        wik3_dir = resolve_engagement_dir(engagement)
        png_path = wik3_dir / "evidence" / "screenshots" / name
        if png_path.exists() and png_path.suffix == ".png":
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.send_header("Cache-Control", "public, max-age=30")
            self.end_headers()
            self.wfile.write(png_path.read_bytes())
        else:
            self.send_error(404)


# ════════════════════════════════════════════════════════════════════════════
# ════════════════════════════════════════════════════════════════════════════
# Squid deny watcher — detección DETERMINÍSTICA de hosts fuera de scope
# ════════════════════════════════════════════════════════════════════════════
# El agente egresa por squid (default-deny allowlist). Cuando squid bloquea un
# host (TCP_DENIED/403), el agente recibe un 403 genérico y NO siempre se da
# cuenta de que fue por scope — sobre todo en redirects del browser (un login
# que salta a un IdP/SSO como auth0). Este watcher sigue el access.log de squid
# y, ante cada host bloqueado durante un run activo, le inyecta al agente (canal
# whisper → scope_guard lo entrega y bloquea la próxima tool call) un aviso
# claro: "este host está fuera de scope" + cómo pedir su inclusión
# (request_scope.sh). Vale para retest Y para un engagement normal.
SQUID_ACCESS_LOG = Path(os.environ.get("WIK3_SQUID_ACCESS_LOG") or "/var/log/squid/access.log")
SQUID_WATCH_INTERVAL = 3  # segundos entre lecturas incrementales del log
_INBOX_LOCK = threading.Lock()


def _parse_squid_denied_host(line: str) -> str:
    """Host destino de una línea TCP_DENIED del access.log de squid. Formato:
    '<ts> <ms> <client> TCP_DENIED/403 <size> <METHOD> <target> ...'.
    CONNECT → target='host:port'; GET/POST → target='http://host/...'.
    Ignora tráfico loopback (es del propio host/dashboard, no del agente)."""
    parts = line.split()
    if len(parts) < 7:
        return ""
    if parts[2] in ("127.0.0.1", "::1", "-"):
        return ""
    target = parts[6]
    if parts[5].upper() == "CONNECT":
        return target.rsplit(":", 1)[0].strip().lower()
    return _bare_host(target)


def _inject_oos_notice(wik3_dir: Path, host: str) -> None:
    """Inyecta al agente (vía convo/inbox.md, que scope_guard entrega) un aviso de
    que `host` quedó fuera de scope, con la instrucción exacta para pedirlo."""
    msg = (
        "=== AVISO DE SCOPE (automático) ===\n"
        f"El host {host} está FUERA DE SCOPE: squid bloqueó tu conexión (TCP_DENIED/403). "
        "NO es una falla del target ni un WAF — es el allowlist de scope.\n\n"
        "Si lo NECESITAS (p.ej. el login redirige a este IdP/SSO, o es parte del flujo), pídelo así:\n"
        f'  bash /workspace/fabro/workflows/wik3/scripts/request_scope.sh "{host}" "<razón corta: por qué lo necesitas>"\n\n'
        "Si NO lo necesitas, ignóralo y sigue con lo que está in-scope."
    )
    convo = wik3_dir / "convo"
    try:
        convo.mkdir(parents=True, exist_ok=True)
    except Exception:
        return
    inbox = convo / "inbox.md"
    with _INBOX_LOCK:
        try:
            prev = inbox.read_text() if inbox.is_file() else ""
        except Exception:
            prev = ""
        body = (prev.rstrip() + "\n\n" + msg) if prev.strip() else msg
        try:
            inbox.write_text(body)
        except Exception:
            return
    try:
        with (convo / "log.jsonl").open("a") as f:
            f.write(json.dumps({"ts": _now_iso(), "from": "system", "kind": "scope_alert",
                                "host": host, "text": f"host fuera de scope detectado: {host}"},
                               ensure_ascii=False) + "\n")
    except Exception:
        pass


def _squid_deny_watcher_loop() -> None:
    """Bucle de fondo: sigue el access.log de squid y avisa al agente de cada host
    bloqueado por scope durante un run activo. Idempotente por (slug, host)."""
    log = SQUID_ACCESS_LOG
    offset = None      # None = sin inicializar → arrancamos desde el final
    inode = None
    notified: set = set()   # (slug, host) ya avisados en el run actual
    cur_slug = None
    while True:
        try:
            if log.is_file():
                st = log.stat()
                if offset is None or inode != st.st_ino:
                    # primer arranque o rotación del log: saltar al final (sin
                    # reprocesar denies históricos de runs anteriores).
                    inode = st.st_ino
                    offset = st.st_size
                else:
                    if st.st_size < offset:
                        offset = 0  # log truncado in-place
                    if st.st_size > offset:
                        with log.open("r", errors="replace") as f:
                            f.seek(offset)
                            chunk = f.read()
                            offset = f.tell()
                        slug = _active_run_slug()
                        if slug:
                            if slug != cur_slug:
                                cur_slug = slug
                                notified = {k for k in notified if k[0] == slug}
                            wik3_dir = resolve_engagement_dir(slug)
                            scope_hosts = _read_scope_list(wik3_dir / "scope.txt")
                            oos_hosts = _read_scope_list(wik3_dir / "out_of_scope.txt")
                            for line in chunk.splitlines():
                                if "TCP_DENIED" not in line:
                                    continue
                                h = _parse_squid_denied_host(line)
                                if not h:
                                    continue
                                key = (slug, h)
                                if key in notified:
                                    continue
                                # squid lo bloqueó pero scope.txt ya lo tiene 'in'
                                # (allowlist desincronizado) → no molestamos.
                                if _scope_state(h, scope_hosts, oos_hosts) == "in":
                                    continue
                                notified.add(key)
                                _inject_oos_notice(wik3_dir, h)
        except Exception:
            pass
        time.sleep(SQUID_WATCH_INTERVAL)


def main() -> int:
    global WIK3_ROOT, ENGAGEMENTS_DIR
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8888)
    ap.add_argument("--wik3-root", type=Path, default=WIK3_ROOT,
                    help="directorio raíz que contiene los workspaces por engagement")
    ap.add_argument("--engagements-dir", type=Path, default=ENGAGEMENTS_DIR,
                    help="directorio donde viven los engagement.<slug>.yaml")
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()
    WIK3_ROOT = args.wik3_root
    ENGAGEMENTS_DIR = args.engagements_dir

    # Watcher determinístico de hosts fuera de scope (sigue el access.log de squid).
    threading.Thread(target=_squid_deny_watcher_loop, daemon=True).start()

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    url = f"http://{args.host}:{args.port}/"
    print(f"wik3 dashboard: {url}", flush=True)
    print(f"  wik3_root:      {WIK3_ROOT}", flush=True)
    print(f"  engagements:    {ENGAGEMENTS_DIR}", flush=True)
    print(f"  fabro:          {FABRO_SERVER}", flush=True)
    print(f"  llm_available:  {bool(os.environ.get('ANTHROPIC_API_KEY', '').strip())}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
