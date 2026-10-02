#!/usr/bin/env python3
"""
admin — admin dashboard de la flota wik3.

Endpoints:
    GET /                          → dashboard.html
    GET /api/state                 → meta + inventario + métricas agregadas
    GET /api/wik3s                 → solo el inventario (lista de wik3s + summary inline)
    GET /api/wik3s/<vm>/summary    → proxy a /admin/summary de esa wik3
    GET /api/wik3s/<vm>/engagements → proxy a /admin/engagements
    GET /api/metrics               → métricas agregadas across the fleet

Auth:
    Basic auth con ADMIN_DASHBOARD_PASSWORD. Cualquier user, password fijo.

Comunicación con wik3s:
    HTTP interno via VPC (sin TLS — el deny-all-ingress + tag-based firewall
    es la capa de aislamiento). Bearer token compartido leído de
    /var/lib/admin/admin-token (generado en primer boot).

GCP API:
    REST directo via metadata token (sin gcloud CLI). El SA `admin-sa`
    tiene roles/compute.viewer.
"""
from __future__ import annotations

import argparse
import base64
import concurrent.futures
import csv
import datetime as dt
import hmac
import io
import json
import os
import re
import secrets
import shlex
import subprocess
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError

SCRIPT_DIR = Path(__file__).resolve().parent

DASHBOARD_PASSWORD = os.environ.get("ADMIN_DASHBOARD_PASSWORD", "").strip() or None
PROJECT_ID = os.environ.get("ADMIN_PROJECT_ID", "").strip() or None
INSTANCE_NAME = os.environ.get("ADMIN_INSTANCE_NAME", "").strip() or None
INSTANCE_ZONE = os.environ.get("ADMIN_INSTANCE_ZONE", "").strip() or None
ADMIN_EMAIL = os.environ.get("ADMIN_OPERATOR_EMAIL", "").strip() or None
ADMIN_TOKEN_PATH = Path(os.environ.get("ADMIN_TOKEN_PATH") or "/var/lib/admin/admin-token")

# Token bearer que se manda a /admin/* de cada wik3. Override por env para dev.
ADMIN_TOKEN = (os.environ.get("ADMIN_TOKEN") or "").strip()
if not ADMIN_TOKEN and ADMIN_TOKEN_PATH.is_file():
    try:
        ADMIN_TOKEN = ADMIN_TOKEN_PATH.read_text().strip()
    except Exception:
        ADMIN_TOKEN = ""

# Puerto donde escucha el dashboard de cada wik3.
WIK3_DASHBOARD_PORT = int(os.environ.get("ADMIN_WIK3_PORT", "8666"))
# Timeout por request a cada wik3 — 5s es generoso para una red VPC.
WIK3_TIMEOUT = float(os.environ.get("ADMIN_WIK3_TIMEOUT", "5"))

# Override opcional para dev-local: lista comma-separated de "name=url".
# Ej: ADMIN_WIK3_OVERRIDE="acme=http://127.0.0.1:18892,beta=http://127.0.0.1:18893"
WIK3_OVERRIDE = os.environ.get("ADMIN_WIK3_OVERRIDE", "").strip()

# ─── Provisioning (PR D) ────────────────────────────────────────────────────
WIK3_BUNDLE_PATH = Path(os.environ.get("ADMIN_WIK3_BUNDLE_PATH") or "/opt/admin/var/wik3-bundle.b64")
ALLOWED_DOMAIN = os.environ.get("ADMIN_ALLOWED_DOMAIN", "").strip()
WIK3_MACHINE_TYPE = os.environ.get("ADMIN_WIK3_MACHINE_TYPE", "e2-standard-4").strip()
WIK3_TTL_DAYS = os.environ.get("ADMIN_WIK3_TTL_DAYS", "60").strip()

# ─── Version info (PR G) ────────────────────────────────────────────────────
# admin-startup.sh persiste estos archivos al boot.
_ADMIN_COMMIT_PATH = Path(os.environ.get("ADMIN_COMMIT_PATH") or "/opt/admin/var/.admin-commit")
_ADMIN_WIK3_COMMIT_PATH = Path(os.environ.get("ADMIN_WIK3_COMMIT_PATH") or "/opt/admin/var/.wik3-commit")
_ADMIN_IMAGE_NAME_PATH = Path(os.environ.get("ADMIN_IMAGE_NAME_PATH") or "/opt/admin/var/.image-name")


def _read_short(path: Path) -> str:
    try:
        return path.read_text().strip()
    except Exception:
        return ""


ADMIN_COMMIT = _read_short(_ADMIN_COMMIT_PATH)
ADMIN_WIK3_COMMIT = _read_short(_ADMIN_WIK3_COMMIT_PATH)
ADMIN_IMAGE_NAME = _read_short(_ADMIN_IMAGE_NAME_PATH)

# ─── Branding (configurable en primer acceso) ───────────────────────────────
# El operador setea nombre + logo desde el dashboard la primera vez que entra.
# Si no está configurado, la UI muestra un wizard full-screen y oculta todo
# lo demás. Se persiste en /var/lib/admin/{brand.json, logo.<ext>}.
BRAND_DIR = Path(os.environ.get("ADMIN_BRAND_DIR") or "/var/lib/admin")
BRAND_JSON_PATH = BRAND_DIR / "brand.json"
_LOGO_EXT = {
    "image/png": "png",
    "image/jpeg": "jpg",
    "image/jpg": "jpg",
    "image/svg+xml": "svg",
    "image/webp": "webp",
}
_BG_EXT = {
    "image/png": "png",
    "image/jpeg": "jpg",
    "image/jpg": "jpg",
    "image/webp": "webp",
}
LOGO_MAX_BYTES = 1024 * 1024       # 1 MB
BG_MAX_BYTES = 3 * 1024 * 1024     # 3 MB

# Paleta por defecto. La UI permite override pero estos son los valores
# que aplica el CSS si el operador no toca nada en el wizard.
DEFAULT_PALETTE = {
    "bg":     "#0a0e1a",
    "panel":  "#10151f",
    "accent": "#22d3ee",
    "fg":     "#e2e8f0",
}
_HEX_RE = re.compile(r"^#[0-9a-fA-F]{3,8}$")


def _sanitize_palette(raw) -> dict:
    """Devuelve una paleta válida: tomamos los 4 keys conocidos y
    descartamos cualquier valor que no sea un hex color. Los faltantes
    quedan con el default."""
    out = dict(DEFAULT_PALETTE)
    if isinstance(raw, dict):
        for k in DEFAULT_PALETTE:
            v = raw.get(k)
            if isinstance(v, str) and _HEX_RE.match(v.strip()):
                out[k] = v.strip()
    return out


def read_brand() -> dict:
    if not BRAND_JSON_PATH.is_file():
        return {
            "configured": False,
            "name": "",
            "has_logo": False,
            "has_bg": False,
            "palette": dict(DEFAULT_PALETTE),
        }
    try:
        data = json.loads(BRAND_JSON_PATH.read_text())
    except Exception:
        return {
            "configured": False,
            "name": "",
            "has_logo": False,
            "has_bg": False,
            "palette": dict(DEFAULT_PALETTE),
        }
    logo_filename = data.get("logo_filename") or ""
    bg_filename = data.get("bg_filename") or ""
    return {
        "configured": True,
        "name": data.get("name") or "",
        "has_logo": bool(logo_filename) and (BRAND_DIR / logo_filename).is_file(),
        "has_bg": bool(bg_filename) and (BRAND_DIR / bg_filename).is_file(),
        "palette": _sanitize_palette(data.get("palette")),
        "configured_at": data.get("configured_at"),
        "configured_by": data.get("configured_by"),
    }


def _persist_image(prefix: str, content_b64: str, content_type: str, ext_map: dict, max_bytes: int) -> tuple[str, str]:
    """Guarda una imagen en BRAND_DIR como `<prefix>.<ext>`, borrando versiones
    previas con cualquier extensión. Devuelve (filename, content_type)."""
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


def write_brand(
    name: str,
    logo_b64: str,
    logo_content_type: str,
    bg_b64: str,
    bg_content_type: str,
    palette: dict,
    actor: str,
) -> None:
    BRAND_DIR.mkdir(parents=True, exist_ok=True)
    try:
        BRAND_DIR.chmod(0o755)
    except Exception:
        pass
    # Preservamos campos viejos (logo, bg) si el wizard se manda sin tocarlos.
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
        fn, ct = _persist_image("logo", logo_b64, logo_content_type, _LOGO_EXT, LOGO_MAX_BYTES)
        info["logo_filename"] = fn
        info["logo_content_type"] = ct
    elif prev.get("logo_filename"):
        info["logo_filename"] = prev["logo_filename"]
        info["logo_content_type"] = prev.get("logo_content_type") or "image/png"
    if bg_b64:
        fn, ct = _persist_image("bg", bg_b64, bg_content_type, _BG_EXT, BG_MAX_BYTES)
        info["bg_filename"] = fn
        info["bg_content_type"] = ct
    elif prev.get("bg_filename"):
        info["bg_filename"] = prev["bg_filename"]
        info["bg_content_type"] = prev.get("bg_content_type") or "image/png"
    tmp = BRAND_JSON_PATH.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(info, indent=2, ensure_ascii=False))
    os.replace(tmp, BRAND_JSON_PATH)


def _now_iso() -> str:
    return dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


# ─── Equipos / líderes (TL) ─────────────────────────────────────────────────
# Config en /var/lib/admin/teams.json. Modelo por-hacker:
#   {"teams": {"<id>": "<nombre>"},
#    "assignments": {"<email>": {"team": "<id>", "role": "TL"|"hacker"}}}
# El admin computa por equipo los pendientes-de-validar (30d) y EMPUJA a cada TL
# SOLO la tabla de SU equipo. Scoping forzado en el push: el payload se arma con
# los miembros del equipo del TL y nada más — el box nunca ve otros equipos.
TEAMS_JSON_PATH = BRAND_DIR / "teams.json"
_TEAM_PUSH_INTERVAL_SECS = int(os.environ.get("ADMIN_TEAM_PUSH_INTERVAL_SECS", "300"))


def read_teams() -> dict:
    try:
        data = json.loads(TEAMS_JSON_PATH.read_text())
        if isinstance(data, dict) and isinstance(data.get("teams"), dict) and isinstance(data.get("assignments"), dict):
            return data
    except Exception:
        pass
    return {"teams": {}, "assignments": {}}


def write_teams(data: dict) -> None:
    BRAND_DIR.mkdir(parents=True, exist_ok=True)
    out = {"teams": {str(k): str(v) for k, v in (data.get("teams") or {}).items()}, "assignments": {}}
    for email, a in (data.get("assignments") or {}).items():
        if not isinstance(a, dict):
            continue
        team = (a.get("team") or "").strip()
        role = "TL" if (a.get("role") or "").strip().upper() == "TL" else "hacker"
        if team:
            out["assignments"][email.strip().lower()] = {"team": team, "role": role}
    tmp = TEAMS_JSON_PATH.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(out, ensure_ascii=False, indent=2))
    os.replace(tmp, TEAMS_JSON_PATH)


def _members_by_team(cfg: dict) -> dict:
    by_team: dict[str, list[str]] = {}
    for email, a in (cfg.get("assignments") or {}).items():
        tid = (a.get("team") or "").strip()
        if tid:
            by_team.setdefault(tid, []).append(email.strip().lower())
    return {k: sorted(set(v)) for k, v in by_team.items()}


def _team_member_stats(emails: list[str]) -> list[dict]:
    """Por hacker (de un equipo): pendientes/total + desglose por ejercicio
    (pending/validated y última fecha de lanzamiento). Mismas exclusiones que el
    resto de las métricas del admin (consistencia para los TL):
    - cuentas de prueba/internas (METRICS_EXCLUDE_HACKERS),
    - vulns de reportes importados (_is_imported),
    - validadas con review_at previo a first_seen (importadas/recreadas),
    - data anterior a DATA_SINCE (8 jun) por first_seen / review_at.
    (Comparación lexicográfica de fechas ISO YYYY-MM-DD = cronológica.)"""
    since = DATA_SINCE
    emails = [e for e in emails if e.strip().lower() not in METRICS_EXCLUDE_HACKERS]
    agg = {e: {"hacker": e, "pending": 0, "total": 0, "_engs": {}} for e in emails}
    for rec in load_findings_store().values():
        h = (rec.get("hacker_email") or "").strip().lower()
        if h not in agg:
            continue
        if _is_imported(rec):
            continue   # reportes importados: no son trabajo de wik3
        rs = (rec.get("review_status") or "").strip().lower()
        fs = (rec.get("first_seen") or "")[:10]
        ra = (rec.get("review_at") or "")[:10]
        if rs == "validated" and fs and ra and ra < fs:
            continue   # validada antes de descubierta → importada/recreada, no cuenta
        # Agregado top-level: total/pending desde DATA_SINCE (por first_seen).
        if fs and fs >= since:
            agg[h]["total"] += 1
            if rs not in ("validated", "false_positive"):
                agg[h]["pending"] += 1
        # Desglose por ejercicio.
        slug = (rec.get("engagement_slug") or "").strip()
        if not slug:
            continue
        eng = agg[h]["_engs"].setdefault(slug, {
            "slug": slug,
            "display_name": slug,
            "pending": 0, "validated": 0, "last_run": "",
        })
        if rs == "validated":
            if ra >= since:
                eng["validated"] += 1
        elif rs != "false_positive":
            if (not fs) or fs >= since:
                eng["pending"] += 1
        dn = (rec.get("engagement_display_name") or "").strip()
        if dn:
            eng["display_name"] = dn
        # Última vez que se lanzó el ejercicio: máximo run_started_at.
        lr = (rec.get("run_started_at") or rec.get("engagement_started_at") or "")
        if lr and lr > eng["last_run"]:
            eng["last_run"] = lr
    rows = []
    for e in emails:
        a = agg[e]
        a["pct"] = round(100 * a["pending"] / a["total"]) if a["total"] else 0
        # Solo ejercicios con algo que mostrar en la ventana (pend/valid > 0).
        engs = [x for x in a.pop("_engs").values() if x["pending"] or x["validated"]]
        engs.sort(key=lambda x: (x["last_run"] or "", x["slug"]), reverse=True)
        a["engagements"] = engs
        rows.append(a)
    rows.sort(key=lambda r: (-r["pending"], r["hacker"]))
    return rows


def push_team_data() -> dict:
    """Por cada TL, EMPUJA a su box SOLO la tabla de su equipo (scoping forzado)."""
    cfg = read_teams()
    teams = cfg.get("teams", {})
    by_team = _members_by_team(cfg)
    box_by_email = {}
    for inst in list_wik3_instances():
        e = (inst.get("hacker_email") or "").strip().lower()
        if e and inst.get("_base_url"):
            box_by_email[e] = inst["_base_url"]
    pushed = 0
    for email, a in (cfg.get("assignments") or {}).items():
        if (a.get("role") or "").upper() != "TL":
            continue
        tid = (a.get("team") or "").strip()
        base = box_by_email.get(email.strip().lower())
        if not tid or not base:
            continue
        payload = {"role": "TL", "team": teams.get(tid, tid),
                   "rows": _team_member_stats(by_team.get(tid, [])), "generated_at": _now_iso()}
        try:
            code, _ = _wik3_post(base, "/admin/team", payload)
            if code and 200 <= code < 300:
                pushed += 1
        except Exception:
            pass
    return {"pushed": pushed}


def _team_push_loop() -> None:
    time.sleep(15)  # esperar a que el primer sync llene el cache
    while True:
        try:
            push_team_data()
        except Exception:
            pass
        time.sleep(_TEAM_PUSH_INTERVAL_SECS)


# ─── Local findings store (histórico de vulns) ──────────────────────────────
# Append-only por design: si una wik3 se destruye, sus findings siguen vivos
# en este store. Dedupe por (wik3_name, engagement_slug, finding_id) — la
# misma vuln no se duplica entre syncs, pero sí se actualiza (last_seen +
# review status). first_seen se preserva entre updates.
FINDINGS_STORE_PATH = Path(os.environ.get("ADMIN_FINDINGS_STORE") or "/var/lib/admin/findings.jsonl")
_STORE_LOCK = threading.Lock()

# Período de gracia para el prune del sync. Una wik3 puede responder 200 pero
# devolver un findings-export TRANSITORIAMENTE incompleto (p. ej. mientras un run
# reescribe los vulns/*/meta.json o el engagement.yaml). Si pruneáramos al primer
# sync en que un finding "falta", el conteo parpadearía (findings borrados y
# re-agregados ciclo a ciclo). En cambio solo borramos un finding ausente que
# lleve más de este umbral sin verse (last_seen). Un borrado real (engagement/vuln
# eliminado) igual se limpia pasado el período. Configurable con ADMIN_PRUNE_GRACE_SECONDS.
try:
    PRUNE_GRACE_SECONDS = int(os.environ.get("ADMIN_PRUNE_GRACE_SECONDS") or "1200")
except ValueError:
    PRUNE_GRACE_SECONDS = 1200

# GCP Compute Engine on-demand pricing (us-central1, mayo 2026).
# Precio por hora del machine type — sin sustained-use discounts (GCP los
# aplica automáticamente y reduce ~30% mensual cuando la VM corre full-time).
# Fuente: https://cloud.google.com/compute/all-pricing
GCP_HOURLY_USD = {
    "e2-standard-2":  0.0671,
    "e2-standard-4":  0.1342,
    "e2-standard-8":  0.2684,
    "e2-standard-16": 0.5368,
    "n2-standard-2":  0.0971,
    "n2-standard-4":  0.1942,
}
GCP_DEFAULT_HOURLY_USD = 0.1342  # fallback: e2-standard-4
_LAST_SYNC = {
    "at": None,
    "wik3s_total": 0,
    "wik3s_reachable": 0,
    "findings_total": 0,
    "added": 0,
    "updated": 0,
    "errors": [],
}


def _store_key(rec: dict) -> tuple:
    return (rec.get("wik3_name", ""), rec.get("engagement_slug", ""), rec.get("finding_id", ""))


def load_findings_store() -> dict:
    """Carga el JSONL como dict {(wik3, engagement, fid): record}."""
    if not FINDINGS_STORE_PATH.is_file():
        return {}
    out: dict = {}
    try:
        with FINDINGS_STORE_PATH.open() as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                out[_store_key(rec)] = rec
    except Exception:
        pass
    return out


def write_findings_store(store: dict) -> None:
    """Reescribe el JSONL completo (atómico)."""
    FINDINGS_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = FINDINGS_STORE_PATH.with_suffix(".jsonl.tmp")
    with tmp.open("w") as f:
        for rec in store.values():
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    os.replace(tmp, FINDINGS_STORE_PATH)


_VAL_SEVERITIES = ["critical", "high", "medium", "low", "info"]

# Fecha desde la cual el dashboard considera la data. Todo lo anterior (data vieja
# / de prueba) se ignora en las métricas. Configurable con ADMIN_DATA_SINCE.
# OJO: el frontend (dashboard.html) tiene la misma constante DATA_SINCE — si la
# cambias acá, cámbiala también allá.
DATA_SINCE = os.environ.get("ADMIN_DATA_SINCE", "2026-06-08")


def _eng_pass(rec, only, exclude, etype=None) -> bool:
    """Filtro por ejercicio (substring del engagement_slug) y por TIPO. Incluir
    solo `only` (substring) / solo `etype` (blackbox/webapp/mobile/internal/cloud),
    y descartar los que matchean `exclude`."""
    slug = (rec.get("engagement_slug") or "").lower()
    if only and only not in slug:
        return False
    if exclude and exclude in slug:
        return False
    if etype:
        types = [str(t).lower() for t in (rec.get("engagement_types") or [])]
        if etype not in types:
            return False
    return True


# Hackers excluidos de TODAS las métricas (cuentas de prueba/internas). El
# frontend (dashboard.html) tiene la misma lista — si la cambias acá, allá también.
METRICS_EXCLUDE_HACKERS = {
    e.strip().lower()
    for e in os.environ.get(
        "ADMIN_METRICS_EXCLUDE", ""
    ).split(",")
    if e.strip()
}


def _hacker_excluded(rec) -> bool:
    """True si el finding pertenece a un hacker excluido de las métricas."""
    return (rec.get("hacker_email") or "").strip().lower() in METRICS_EXCLUDE_HACKERS


def _is_imported(rec) -> bool:
    """True si el finding viene de un reporte IMPORTADO (no es trabajo de wik3):
    phase=imported (import del dashboard) o review_by=import. Fuera de métricas."""
    if (rec.get("phase") or "").strip().lower() == "imported":
        return True
    return (rec.get("review_by") or "").strip().lower() == "import"


def validation_by_week(weeks_back: int = 8, only: str | None = None, exclude: str | None = None, etype: str | None = None) -> dict:
    """Actividad de validación por SEMANA ISO (lunes), bucketeada por la fecha en
    que el hacker VALIDÓ la vuln (review_at) — NO por cuándo se descubrió. Mide el
    esfuerzo de validación semana a semana: un hacker que valida engagements viejos
    igual cuenta en la semana en que los validó. Devuelve las últimas N semanas
    (contiguas, terminando en la semana actual) × severidad + total, más el TIEMPO
    DE VALIDACIÓN (first_seen → review_at) agregado de toda la flota.
    Excluye importadas (review_by='import': auto-validadas, no son esfuerzo humano)."""
    import datetime
    def norm_sev(s):
        s = (s or "").strip().lower()
        if s in ("informative", "informational", "informativo"):
            s = "info"
        return s if s in _VAL_SEVERITIES else "info"
    def to_date(v):
        try:
            return datetime.date.fromisoformat(str(v)[:10])
        except Exception:
            return None
    def median(xs):
        if not xs:
            return None
        xs = sorted(xs)
        n = len(xs)
        m = n // 2
        return float(xs[m]) if n % 2 else round((xs[m - 1] + xs[m]) / 2.0, 1)
    def percentile(xs, p):
        if not xs:
            return None
        xs = sorted(xs)
        k = min(len(xs) - 1, int(round((p / 100.0) * (len(xs) - 1))))
        return float(xs[k])

    today = datetime.date.today()
    this_monday = today - datetime.timedelta(days=today.weekday())
    first_monday = this_monday - datetime.timedelta(days=7 * (weeks_back - 1))
    # Cutoff global: el dashboard no muestra data anterior a DATA_SINCE.
    since = to_date(DATA_SINCE)
    if since is not None:
        since_monday = since - datetime.timedelta(days=since.weekday())
        if since_monday > first_monday:
            first_monday = since_monday

    buckets: dict = {}     # monday -> {sev: count}  (validadas por review_at)
    found_week: dict = {}  # monday -> count  (descubiertas por first_seen)
    fp_week: dict = {}     # monday -> count  (descartadas como FP por review_at)
    week_ttv: dict = {}    # monday -> [días first_seen→review_at]
    ttv_all: list = []     # tiempo de validación de TODAS las validadas (cualquier fecha)
    for rec in load_findings_store().values():
        if _hacker_excluded(rec):
            continue   # cuentas listadas en METRICS_EXCLUDE_HACKERS: fuera de métricas
        if _is_imported(rec):
            continue   # vienen de reportes importados: no son trabajo de wik3
        if not _eng_pass(rec, only, exclude, etype):
            continue   # filtro por ejercicio
        # Descubiertas: bucketea por first_seen (cuándo wik3 la generó).
        fseen = to_date(rec.get("first_seen"))
        rat0 = to_date(rec.get("review_at"))
        if fseen is not None and not (rat0 is not None and rat0 < fseen):
            # review_at<first_seen → validada antes de descubierta = dato importado/
            # recreado, no una descubierta real de esa semana → no la contamos.
            fwk = fseen - datetime.timedelta(days=fseen.weekday())
            if first_monday <= fwk <= this_monday:
                found_week[fwk] = found_week.get(fwk, 0) + 1
        # FP: bucketea por review_at (cuándo el hacker lo descartó). Descartar
        # un FP también es trabajo de revisión → se muestra en el gráfico.
        if (rec.get("review_status") or "").strip().lower() == "false_positive":
            rat_fp = to_date(rec.get("review_at"))
            if rat_fp is not None and not (fseen is not None and rat_fp < fseen):
                fpwk = rat_fp - datetime.timedelta(days=rat_fp.weekday())
                if first_monday <= fpwk <= this_monday:
                    fp_week[fpwk] = fp_week.get(fpwk, 0) + 1
        # Validadas: bucketea por review_at (cuándo el hacker la validó).
        if (rec.get("review_status") or "").strip().lower() != "validated":
            continue
        rat = to_date(rec.get("review_at"))
        ttv_days = None
        if rat and fseen and (since is None or rat >= since):
            d = (rat - fseen).days
            if d >= 0:
                ttv_days = d
                ttv_all.append(d)
        if rat is None:
            continue
        if fseen is not None and rat < fseen:
            continue   # review_at previo a first_seen → importada con review viejo, no es validación real
        wk = rat - datetime.timedelta(days=rat.weekday())
        if wk < first_monday or wk > this_monday:
            continue
        sev = norm_sev(rec.get("severity"))
        buckets.setdefault(wk, {s: 0 for s in _VAL_SEVERITIES})[sev] += 1
        if ttv_days is not None:
            week_ttv.setdefault(wk, []).append(ttv_days)

    weeks = []
    cur = first_monday
    while cur <= this_monday:
        b = buckets.get(cur, {s: 0 for s in _VAL_SEVERITIES})
        row = {"week": cur.isoformat()}
        tot = 0
        for s in _VAL_SEVERITIES:
            row[f"validated_{s}"] = b[s]
            tot += b[s]
        row["validated_total"] = tot
        row["found_total"] = found_week.get(cur, 0)
        row["fp_total"] = fp_week.get(cur, 0)
        row["ttv_median_days"] = median(week_ttv.get(cur, []))
        weeks.append(row)
        cur = cur + datetime.timedelta(days=7)

    ttv = {
        "count": len(ttv_all),
        "median_days": median(ttv_all),
        "avg_days": round(sum(ttv_all) / len(ttv_all), 1) if ttv_all else None,
        "p90_days": percentile(ttv_all, 90),
    }
    return {"severities": _VAL_SEVERITIES, "weeks": weeks, "ttv": ttv}


# Actores en review_by que NO son review humano de un hacker: importaciones
# auto-validadas y descartes automáticos del agente.
_NON_HUMAN_REVIEWERS = {"import", "agent", "auto", ""}


def review_activity_by_hacker(only: str | None = None, exclude: str | None = None, etype: str | None = None) -> list:
    """Por hacker, enfocado en VALIDADAS (excluye importadas; el agente no valida).
    TODAS las métricas parten de DATA_SINCE (no ventanas rodantes):
    - validadas desde DATA_SINCE (por review_at).
    - tiempo promedio de validación (días first_seen → review_at) desde DATA_SINCE.
    - pendientes por validar desde DATA_SINCE: findings sin validar ni descartar.
    Se atribuye al hacker del engagement."""
    import datetime
    def to_date(v):
        try:
            return datetime.date.fromisoformat(str(v)[:10])
        except Exception:
            return None
    since = to_date(DATA_SINCE)  # ancla: todas las métricas parten de aquí
    H: dict = {}
    for rec in load_findings_store().values():
        if _hacker_excluded(rec):
            continue   # cuentas listadas en METRICS_EXCLUDE_HACKERS: fuera de métricas
        if _is_imported(rec):
            continue   # vienen de reportes importados: no son trabajo del hacker
        if not _eng_pass(rec, only, exclude, etype):
            continue   # filtro por ejercicio
        hacker = (rec.get("hacker_email") or rec.get("review_by") or "—").strip() or "—"
        h = H.setdefault(hacker, {"val_dates": [], "ttv": [], "pending": 0})
        rs = (rec.get("review_status") or "").strip().lower()
        if rs == "validated":
            rat = to_date(rec.get("review_at"))
            if rat is not None and (since is None or rat >= since):  # validadas desde DATA_SINCE
                fseen = to_date(rec.get("first_seen"))
                if fseen is not None and rat < fseen:
                    continue   # review_at previo a first_seen → importada con review viejo, no cuenta
                h["val_dates"].append(rat)
                # Tiempo de validación: días first_seen → review_at.
                if fseen:
                    d = (rat - fseen).days
                    if d >= 0:
                        h["ttv"].append(d)
        elif rs != "false_positive":
            fseen = to_date(rec.get("first_seen"))
            if since is None or (fseen is not None and fseen >= since):
                h["pending"] += 1   # ni validada ni descartada = pendiente por validar
    out = []
    for hacker, h in H.items():
        ttv = h["ttv"]
        out.append({
            "hacker": hacker,
            "validated_since": len(h["val_dates"]),
            "ttv_avg_days": round(sum(ttv) / len(ttv), 1) if ttv else None,
            "ttv_count": len(ttv),
            "pending": h["pending"],
        })
    out.sort(key=lambda r: (-r["validated_since"], r["hacker"]))
    return out


def sync_findings() -> dict:
    """Fetch /admin/findings-export de cada wik3 en paralelo y mergea el
    resultado en el local store. Devuelve metadata del sync."""
    now = _now_iso()
    instances = list_wik3_instances()

    def fetch(inst):
        base = inst.get("_base_url") or ""
        if not base:
            return (inst, None, "no internal IP")
        code, body = _wik3_get(base, "/admin/findings-export")
        if code != 200:
            return (inst, None, f"HTTP {code}")
        return (inst, body, None)

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        results = list(ex.map(fetch, instances))

    added = 0
    updated = 0
    reachable = 0
    errors: list[dict] = []
    with _STORE_LOCK:
        store = load_findings_store()
        reachable_wik3s: set = set()
        seen_keys: set = set()
        for inst, body, err in results:
            if err or not isinstance(body, dict):
                errors.append({"wik3": inst.get("name", "?"), "error": err or "no body"})
                continue
            reachable += 1
            wik3_name = inst.get("name") or ""
            reachable_wik3s.add(wik3_name)
            hacker = inst.get("hacker_email") or ""
            for f in body.get("findings", []) or []:
                affected = f.get("affected")
                if not isinstance(affected, list):
                    affected = [affected] if affected else []
                etypes = f.get("engagement_types")
                if not isinstance(etypes, list):
                    etypes = ["webapp"]
                rec = {
                    "wik3_name": wik3_name,
                    "hacker_email": hacker,
                    "engagement_slug": f.get("engagement_slug", ""),
                    "engagement_types": etypes,
                    "engagement_display_name": f.get("engagement_display_name", ""),
                    "engagement_created_at": f.get("engagement_created_at", ""),
                    "engagement_started_at": f.get("engagement_started_at", ""),
                    "run_started_at": f.get("run_started_at", ""),
                    "finding_id": f.get("finding_id", ""),
                    "severity": f.get("severity", ""),
                    "title": f.get("title", ""),
                    "phase": f.get("phase", ""),
                    "affected": [str(x) for x in affected],
                    "validation_status": f.get("validation_status", ""),
                    "review_status": f.get("review_status", ""),
                    "review_by": f.get("review_by", ""),
                    "review_at": f.get("review_at", ""),
                    "review_note": f.get("review_note", ""),
                    "created_at": f.get("created_at", ""),
                    "last_seen": now,
                }
                key = _store_key(rec)
                seen_keys.add(key)
                # first_seen = descubrimiento REAL de la vuln (created_at del meta),
                # NO la hora del primer sync. Así "descubiertas por semana" refleja
                # cuándo wik3 la generó, no cuándo el admin la sincronizó (engagements
                # sincronizados tarde no se amontonan en la semana actual). Fallback:
                # lo previo en el store, o ahora.
                ca = (f.get("created_at") or "").strip()
                prev_fs = store[key].get("first_seen", "") if key in store else ""
                rec["first_seen"] = ca or prev_fs or now
                if key in store:
                    updated += 1
                else:
                    added += 1
                store[key] = rec
        # Prune: para wik3s ALCANZABLES, borra del store lo que ya no reportan
        # (engagements/findings borrados por el hacker o el admin). Las wik3s NO
        # alcanzables se preservan — no pruneamos por una falla transitoria.
        # Período de gracia: un finding ausente solo se borra si lleva más de
        # PRUNE_GRACE_SECONDS sin verse (last_seen). Así un export transitoriamente
        # incompleto (200 pero parcial) NO borra findings — evita el parpadeo del
        # conteo. Un borrado real se limpia igual al superar el umbral.
        try:
            now_dt = dt.datetime.strptime(now, "%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            now_dt = dt.datetime.utcnow()
        def _age_seconds(ls: str) -> float:
            try:
                seen = dt.datetime.strptime(str(ls)[:20], "%Y-%m-%dT%H:%M:%SZ")
            except Exception:
                return float("inf")   # last_seen ilegible/ausente → tratar como viejo
            return (now_dt - seen).total_seconds()
        removed = 0
        deferred = 0
        for key in list(store.keys()):
            if store[key].get("wik3_name") in reachable_wik3s and key not in seen_keys:
                if _age_seconds(store[key].get("last_seen", "")) <= PRUNE_GRACE_SECONDS:
                    deferred += 1
                    continue   # ausente pero reciente → puede ser export parcial transitorio
                del store[key]
                removed += 1
        write_findings_store(store)
        total = len(store)
    _LAST_SYNC.update({
        "at": now,
        "wik3s_total": len(instances),
        "wik3s_reachable": reachable,
        "findings_total": total,
        "added": added,
        "updated": updated,
        "removed": removed,
        "deferred": deferred,
        "errors": errors,
    })
    return dict(_LAST_SYNC)


# ─── Auto-sync: periódico + lazy ────────────────────────────────────────────
# El store local sobrevive si la VM admin no se recrea, pero (a) si se recrea
# con --force se borra, y (b) las wik3s pueden reportar findings nuevos en
# cualquier momento. Dos defensas:
#   - Loop periódico (default 180s) que llama sync_findings() en background.
#   - Lazy trigger en /api/state: si la live total supera al store para
#     cualquier wik3 actual, dispara sync en background (debounce: 30s).
_BG_SYNC_INTERVAL_SECS = int(os.environ.get("ADMIN_SYNC_INTERVAL_SECS", "180"))
_LAZY_SYNC_DEBOUNCE_SECS = 30
_LAZY_SYNC_LOCK = threading.Lock()
_LAZY_SYNC_LAST = 0.0


def _safe_sync(reason: str) -> None:
    try:
        r = sync_findings()
        print(
            f"[admin] sync ({reason}): added={r['added']} updated={r['updated']} "
            f"removed={r['removed']} deferred={r.get('deferred', 0)} "
            f"reachable={r['wik3s_reachable']}/{r['wik3s_total']} total={r['findings_total']}",
            flush=True,
        )
    except Exception as e:
        print(f"[admin] sync ({reason}) failed: {e}", flush=True)


def _background_sync_loop() -> None:
    time.sleep(10)  # let the dashboard come up first
    while True:
        _safe_sync("periodic")
        time.sleep(_BG_SYNC_INTERVAL_SECS)


def _maybe_lazy_sync(merged: list[dict]) -> None:
    """Si live totals > store para cualquier wik3 del inventario actual,
    dispara sync en background. No bloquea al caller. Debounced."""
    global _LAZY_SYNC_LAST
    now = time.monotonic()
    with _LAZY_SYNC_LOCK:
        if now - _LAZY_SYNC_LAST < _LAZY_SYNC_DEBOUNCE_SECS:
            return
        live_by_wik3: dict[str, int] = {}
        for w in merged:
            name = w.get("name") or ""
            if not name:
                continue
            t = ((w.get("summary") or {}).get("totals") or {})
            rbs = t.get("review_by_status") or {}
            live_by_wik3[name] = sum(rbs.values())
        if not any(live_by_wik3.values()):
            return  # nada que sincronizar
        store_by_wik3: dict[str, int] = {}
        for rec in load_findings_store().values():
            n = rec.get("wik3_name") or ""
            store_by_wik3[n] = store_by_wik3.get(n, 0) + 1
        stale = any(live > store_by_wik3.get(n, 0) for n, live in live_by_wik3.items())
        if not stale:
            return
        _LAZY_SYNC_LAST = now
    threading.Thread(target=_safe_sync, args=("lazy",), daemon=True).start()
# Override de subprocess gcloud para tests — recibe la lista de args y devuelve
# (returncode, stdout, stderr). Producción: usa _real_gcloud.
_GCLOUD_RUNNER = None


def _real_gcloud(args: list[str], timeout: int = 120) -> tuple[int, str, str]:
    proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    return (proc.returncode, proc.stdout, proc.stderr)


def gcloud(args: list[str], timeout: int = 120) -> tuple[int, str, str]:
    runner = _GCLOUD_RUNNER or _real_gcloud
    print(f"[admin] gcloud {' '.join(shlex.quote(a) for a in args[1:])}", flush=True)
    return runner(args, timeout)


class ProvisionError(Exception):
    pass


def _slug_email(email: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", email.lower()).strip("-")


def _vm_name_for(email: str) -> str:
    ts = dt.datetime.utcnow().strftime("%Y%m%d%H%M")
    name = f"wik3-{_slug_email(email)}-{ts}"
    return name[:63]


def provision_wik3(email: str) -> dict:
    """Crea una wik3 nueva para `email`. Devuelve un dict con vm_name,
    dashboard_password e instrucciones para el hacker. Lanza ProvisionError
    si email inválido, ya existe wik3 para ese hacker, falta bundle, o
    gcloud falla.
    """
    email = (email or "").strip().lower()
    if not email or "@" not in email:
        raise ProvisionError("email requerido")
    if ALLOWED_DOMAIN and not email.endswith(f"@{ALLOWED_DOMAIN}"):
        raise ProvisionError(f"email debe terminar en @{ALLOWED_DOMAIN}")
    if not PROJECT_ID:
        raise ProvisionError("ADMIN_PROJECT_ID no configurado")
    if not INSTANCE_ZONE:
        raise ProvisionError("ADMIN_INSTANCE_ZONE no configurado")
    if not WIK3_BUNDLE_PATH.is_file():
        raise ProvisionError(f"wik3 bundle no encontrado en {WIK3_BUNDLE_PATH}")

    # Regla 1-por-hacker: si ya hay una wik3 con ese label, abortar.
    existing = [w for w in list_wik3_instances() if (w.get("hacker_email") or "").lower() == email]
    if existing:
        raise ProvisionError(f"ya existe wik3 para {email}: {existing[0]['name']}")

    vm_name = _vm_name_for(email)
    password = secrets.token_hex(16)
    region = re.sub(r"-[a-z]$", "", INSTANCE_ZONE)
    subnet = f"wik3-boxes-{region}"
    label_hacker = _slug_email(email)

    metadata_pairs = [
        f"hacker-email={email}",
        f"dashboard-password={password}",
        f"engagement-ttl-days={WIK3_TTL_DAYS}",
    ]
    if ADMIN_TOKEN:
        metadata_pairs.append(f"admin-token={ADMIN_TOKEN}")
    if ADMIN_WIK3_COMMIT:
        metadata_pairs.append(f"wik3-commit={ADMIN_WIK3_COMMIT}")

    args = [
        "gcloud", "compute", "instances", "create", vm_name,
        f"--project={PROJECT_ID}",
        f"--zone={INSTANCE_ZONE}",
        f"--machine-type={WIK3_MACHINE_TYPE}",
        "--image-family=wik3-box",
        f"--image-project={PROJECT_ID}",
        "--boot-disk-size=50GB",
        "--boot-disk-type=pd-ssd",
        "--network=wik3-boxes",
        f"--subnet={subnet}",
        f"--service-account=wik3-box@{PROJECT_ID}.iam.gserviceaccount.com",
        "--scopes=https://www.googleapis.com/auth/cloud-platform",
        "--tags=wik3-box",
        "--no-address",
        f"--metadata-from-file=wik3-bundle={WIK3_BUNDLE_PATH}",
        f"--metadata={','.join(metadata_pairs)}",
        f"--labels=hacker={label_hacker},purpose=pentesting",
        "--quiet",
    ]
    # Crear la VM puede tardar varios minutos cuando el bundle es grande
    # o la zona está saturada. 5 min cubre el peor caso observado.
    rc, _out, err = gcloud(args, timeout=300)
    if rc != 0:
        raise ProvisionError(f"gcloud create falló: {err.strip()[:500]}")

    # IAM:
    # - compute.viewer a nivel instancia → el hacker solo ve su VM (resuelve
    #   zona, password metadata, etc. via gcloud describe).
    # - iap.tunnelResourceAccessor a nivel proyecto sin condition → IAP NO
    #   soporta este role a nivel instancia (devuelve "Role not supported for
    #   this resource"). Intentamos antes con project + condition CEL
    #   `resource.name.endsWith('/<vm>')` pero el matcher devolvía 4033 not
    #   authorized en algunas cuentas (probable suffix de port en el
    #   resource.name de IAP TunnelInstance que el endsWith no matchea).
    #   El binding sin condition da acceso universal a tunneles del proyecto
    #   — aceptamos la concesión porque es lo único que GCP soporta bien hoy.
    rc, _out, err = gcloud([
        "gcloud", "compute", "instances", "add-iam-policy-binding", vm_name,
        f"--zone={INSTANCE_ZONE}", f"--project={PROJECT_ID}",
        f"--member=user:{email}",
        "--role=roles/compute.viewer",
        "--quiet",
    ], timeout=120)
    if rc != 0:
        raise ProvisionError(f"gcloud add-iam compute.viewer falló: {err.strip()[:500]}")

    rc, _out, err = gcloud([
        "gcloud", "projects", "add-iam-policy-binding", PROJECT_ID,
        f"--member=user:{email}",
        "--role=roles/iap.tunnelResourceAccessor",
        "--condition=None",
        "--quiet",
    ], timeout=120)
    if rc != 0:
        raise ProvisionError(f"gcloud add-iam iap.tunnelResourceAccessor falló: {err.strip()[:500]}")

    rc, out, _err = gcloud([
        "gcloud", "compute", "instances", "describe", vm_name,
        f"--zone={INSTANCE_ZONE}", f"--project={PROJECT_ID}",
        "--format=value(networkInterfaces[0].networkIP)",
    ], timeout=60)
    internal_ip = out.strip() if rc == 0 else ""

    return {
        "vm_name": vm_name,
        "internal_ip": internal_ip,
        "dashboard_password": password,
        "hacker_email": email,
        "hacker_command": f"./scripts/wik3-hacker.sh {vm_name}",
        "zone": INSTANCE_ZONE,
    }


def deprovision_wik3(vm_name: str) -> dict:
    """Destruye una wik3 + limpia su binding IAP en el proyecto."""
    if not re.match(r"^wik3-[a-z0-9-]{1,58}$", vm_name):
        raise ProvisionError(f"nombre de VM inválido: {vm_name!r}")
    if not PROJECT_ID:
        raise ProvisionError("ADMIN_PROJECT_ID no configurado")

    instances = list_wik3_instances()
    inst = next((i for i in instances if i.get("name") == vm_name), None)
    if not inst:
        raise ProvisionError(f"VM {vm_name} no encontrada")
    email = (inst.get("hacker_email") or "").lower()
    zone = inst.get("zone") or INSTANCE_ZONE

    # Limpieza de IAM. Hacemos best-effort de 3 cosas:
    # 1. Quitar el binding legacy a nivel proyecto con condition CEL
    #    (provision_wik3 anterior lo creaba — ya no, pero hay VMs viejas).
    # 2. Si es la ÚLTIMA wik3 del hacker, quitar el binding sin condition que
    #    le da acceso universal a tunneles. Si tiene otra VM activa, mantener.
    # gcloud es idempotente: si el binding no existe, devuelve no-op silencioso.
    if email and "@" in email:
        cond_title = f"tunnel-{vm_name}"[:62]
        cond_expr = (
            f"resource.type == 'iap.googleapis.com/TunnelInstance' && "
            f"resource.name.endsWith('/{vm_name}')"
        )
        # 1. Legacy con condition
        gcloud([
            "gcloud", "projects", "remove-iam-policy-binding", PROJECT_ID,
            f"--member=user:{email}",
            "--role=roles/iap.tunnelResourceAccessor",
            f"--condition=expression={cond_expr},title={cond_title}",
            "--quiet",
        ], timeout=60)
        # 2. Sin condition — solo si no quedan más wik3s del hacker
        others = [
            w for w in instances
            if w.get("name") != vm_name and (w.get("hacker_email") or "").lower() == email
        ]
        if not others:
            gcloud([
                "gcloud", "projects", "remove-iam-policy-binding", PROJECT_ID,
                f"--member=user:{email}",
                "--role=roles/iap.tunnelResourceAccessor",
                "--condition=None",
                "--quiet",
            ], timeout=60)

    rc, _out, err = gcloud([
        "gcloud", "compute", "instances", "delete", vm_name,
        f"--zone={zone}", f"--project={PROJECT_ID}",
        "--quiet",
    ], timeout=180)
    if rc != 0:
        raise ProvisionError(f"gcloud delete falló: {err.strip()[:500]}")
    return {"vm_name": vm_name, "deleted": True}


# ════════════════════════════════════════════════════════════════════════════
# GCP metadata + Compute API
# ════════════════════════════════════════════════════════════════════════════

_METADATA_ROOT = "http://metadata.google.internal/computeMetadata/v1"
_METADATA_HDR = {"Metadata-Flavor": "Google"}


def _gcp_access_token() -> str | None:
    """Token bearer fresco del metadata server. None si no estamos en GCP."""
    try:
        req = urllib.request.Request(
            f"{_METADATA_ROOT}/instance/service-accounts/default/token",
            headers=_METADATA_HDR,
        )
        with urllib.request.urlopen(req, timeout=3) as r:
            data = json.loads(r.read().decode("utf-8"))
            return data.get("access_token")
    except Exception:
        return None


def list_wik3_instances() -> list[dict]:
    """Lista VMs del proyecto con label `purpose=pentesting` (que es como
    deploy-box.sh marca cada wik3). Devuelve lista normalizada con
    name, zone, internal_ip, status, hacker_email, created_at."""
    if WIK3_OVERRIDE:
        out = []
        for chunk in WIK3_OVERRIDE.split(","):
            chunk = chunk.strip()
            if not chunk or "=" not in chunk:
                continue
            name, url = chunk.split("=", 1)
            out.append({
                "name": name.strip(),
                "zone": "local-dev",
                "internal_ip": "",
                "status": "RUNNING",
                "hacker_email": None,
                "created_at": None,
                "_base_url": url.strip(),
            })
        return out

    token = _gcp_access_token()
    if not token or not PROJECT_ID:
        return []
    url = (
        f"https://compute.googleapis.com/compute/v1/projects/{PROJECT_ID}/aggregated/instances"
        f"?filter=labels.purpose%3Dpentesting&maxResults=500"
    )
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read().decode("utf-8"))
    except Exception as e:
        print(f"[admin] error listing instances: {e}", flush=True)
        return []
    items = data.get("items", {})
    out = []
    for _, bucket in items.items():
        for inst in bucket.get("instances", []) or []:
            zone = (inst.get("zone") or "").split("/")[-1]
            nic = (inst.get("networkInterfaces") or [{}])[0]
            metadata_items = (inst.get("metadata") or {}).get("items") or []
            labels = inst.get("labels") or {}
            hacker_meta = next(
                (m.get("value") for m in metadata_items if m.get("key") == "hacker-email"),
                None,
            )
            out.append({
                "name": inst.get("name"),
                "zone": zone,
                "internal_ip": nic.get("networkIP") or "",
                "status": inst.get("status"),
                "hacker_email": hacker_meta or labels.get("hacker"),
                "created_at": inst.get("creationTimestamp"),
                "machine_type": (inst.get("machineType") or "").rsplit("/", 1)[-1],
                "_base_url": f"http://{nic.get('networkIP')}:{WIK3_DASHBOARD_PORT}",
            })
    out.sort(key=lambda x: x.get("name") or "")
    return out


# ════════════════════════════════════════════════════════════════════════════
# wik3 admin proxy
# ════════════════════════════════════════════════════════════════════════════

def _wik3_get(base_url: str, path: str, timeout: int | None = None) -> tuple[int, dict | None]:
    """GET a un wik3 con bearer token. Devuelve (status, json_body)."""
    if not ADMIN_TOKEN:
        return (503, {"error": "admin token no disponible en admin"})
    url = f"{base_url.rstrip('/')}{path}"
    req = urllib.request.Request(
        url,
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout or WIK3_TIMEOUT) as r:
            return (r.status, json.loads(r.read().decode("utf-8")))
    except HTTPError as e:
        try:
            body = json.loads(e.read().decode("utf-8"))
        except Exception:
            body = {"error": str(e)}
        return (e.code, body)
    except URLError as e:
        return (599, {"error": f"network: {e.reason}"})
    except Exception as e:
        return (599, {"error": str(e)})


def _wik3_post(base_url: str, path: str, payload: dict, timeout: int | None = None) -> tuple[int, dict | None]:
    """POST JSON a un wik3 con bearer token. Devuelve (status, json_body)."""
    if not ADMIN_TOKEN:
        return (503, {"error": "admin token no disponible en admin"})
    url = f"{base_url.rstrip('/')}{path}"
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Authorization": f"Bearer {ADMIN_TOKEN}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout or WIK3_TIMEOUT) as r:
            body = r.read().decode("utf-8")
            return (r.status, json.loads(body) if body else {})
    except HTTPError as e:
        try:
            body = json.loads(e.read().decode("utf-8"))
        except Exception:
            body = {"error": str(e)}
        return (e.code, body)
    except URLError as e:
        return (599, {"error": f"network: {e.reason}"})
    except Exception as e:
        return (599, {"error": str(e)})


def _wik3_delete(base_url: str, path: str, timeout: int | None = None) -> tuple[int, dict | None]:
    """DELETE a un wik3 con bearer token (para borrar el engagement en el origen
    tras moverlo)."""
    if not ADMIN_TOKEN:
        return (503, {"error": "admin token no disponible en admin"})
    url = f"{base_url.rstrip('/')}{path}"
    req = urllib.request.Request(
        url,
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}", "Accept": "application/json"},
        method="DELETE",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout or WIK3_TIMEOUT) as r:
            body = r.read().decode("utf-8")
            return (r.status, json.loads(body) if body else {})
    except HTTPError as e:
        try:
            body = json.loads(e.read().decode("utf-8"))
        except Exception:
            body = {"error": str(e)}
        return (e.code, body)
    except URLError as e:
        return (599, {"error": f"network: {e.reason}"})
    except Exception as e:
        return (599, {"error": str(e)})


def move_engagement(slug: str, from_vm: str, to_vm: str) -> tuple[int, dict]:
    """Mueve un engagement de una wik3 a otra: export del origen → import en
    destino → delete en origen. Si el import falla, NO borra el origen."""
    slug = (slug or "").strip()
    if not slug or not from_vm or not to_vm or from_vm == to_vm:
        return (400, {"error": "slug, from_vm y to_vm (distintos) requeridos"})
    insts = list_wik3_instances()
    src = next((i for i in insts if i.get("name") == from_vm), None)
    dst = next((i for i in insts if i.get("name") == to_vm), None)
    if not src or not src.get("_base_url"):
        return (404, {"error": f"origen {from_vm!r} no encontrado/alcanzable"})
    if not dst or not dst.get("_base_url"):
        return (404, {"error": f"destino {to_vm!r} no encontrado/alcanzable"})
    LONG = 240
    code, data = _wik3_get(src["_base_url"], f"/admin/engagement-export?slug={slug}", timeout=LONG)
    if code != 200 or not isinstance(data, dict) or not data.get("yaml_b64"):
        return (502, {"error": f"export del origen falló ({code})", "detail": data})
    code2, data2 = _wik3_post(dst["_base_url"], "/admin/engagement-import",
                              {"slug": slug, "yaml_b64": data["yaml_b64"], "tar_b64": data.get("tar_b64", "")},
                              timeout=LONG)
    if code2 != 200:
        return (502, {"error": f"import en destino falló ({code2}) — NO se borró el origen", "detail": data2})
    code3, data3 = _wik3_delete(src["_base_url"], f"/admin/engagements/{slug}", timeout=LONG)
    deleted = code3 == 200
    return (200, {"ok": True, "slug": slug, "from": from_vm, "to": to_vm,
                  "source_deleted": deleted,
                  "warning": None if deleted else f"movido pero no pude borrar el origen ({code3}); bórralo a mano"})


def fetch_wik3_summary(inst: dict) -> dict:
    """Trae /admin/summary y la mergea con la metadata del inventario."""
    base = inst.get("_base_url") or ""
    if not base:
        return {**inst, "summary": None, "summary_error": "no internal IP"}
    code, body = _wik3_get(base, "/admin/summary")
    if code == 200 and isinstance(body, dict):
        return {**inst, "summary": body, "summary_error": None}
    return {**inst, "summary": None, "summary_error": f"HTTP {code}: {body.get('error') if isinstance(body, dict) else body}"}


def fetch_wik3_costs(inst: dict, since_iso: str) -> dict:
    """Trae /admin/costs?since=<ISO> de la wik3 (parseo de journalctl del
    fabro agente). Devuelve {**inst, llm: {...}, llm_error: str|None}."""
    base = inst.get("_base_url") or ""
    if not base:
        return {**inst, "llm": None, "llm_error": "no internal IP"}
    from urllib.parse import quote
    code, body = _wik3_get(base, f"/admin/costs?since={quote(since_iso, safe='')}")
    if code == 200 and isinstance(body, dict):
        return {**inst, "llm": body, "llm_error": None}
    return {**inst, "llm": None, "llm_error": f"HTTP {code}: {body.get('error') if isinstance(body, dict) else body}"}


def aggregate_metrics(wik3s_with_summary: list[dict]) -> dict:
    """Suma de las métricas de todas las wik3s que respondieron."""
    totals = {
        "wik3s_total": len(wik3s_with_summary),
        "wik3s_reachable": 0,
        "engagements": 0,
        "passive": 0,
        "active": 0,
        "validated": 0,
        "imported": 0,
        "human_validated": 0,
        "review_by_status": {"pending": 0, "validated": 0, "false_positive": 0, "wont_fix": 0},
        "human_validated_by_severity": {},
    }
    by_hacker: dict[str, dict] = {}
    for w in wik3s_with_summary:
        s = w.get("summary")
        if not s:
            continue
        totals["wik3s_reachable"] += 1
        t = s.get("totals") or {}
        totals["engagements"] += t.get("engagements", 0)
        totals["passive"] += t.get("passive", 0)
        totals["active"] += t.get("active", 0)
        totals["validated"] += t.get("validated", 0)
        totals["imported"] += t.get("imported", 0)
        totals["human_validated"] += t.get("human_validated", 0)
        for k, v in (t.get("review_by_status") or {}).items():
            totals["review_by_status"][k] = totals["review_by_status"].get(k, 0) + v
        for k, v in (t.get("human_validated_by_severity") or {}).items():
            totals["human_validated_by_severity"][k] = totals["human_validated_by_severity"].get(k, 0) + v
        hacker = w.get("hacker_email") or "unknown"
        h = by_hacker.setdefault(hacker, {"wik3s": 0, "engagements": 0, "human_validated": 0})
        h["wik3s"] += 1
        h["engagements"] += t.get("engagements", 0)
        h["human_validated"] += t.get("human_validated", 0)
    return {"totals": totals, "by_hacker": by_hacker}


# ════════════════════════════════════════════════════════════════════════════
# HTTP handler
# ════════════════════════════════════════════════════════════════════════════

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _basic_auth_user(self) -> str:
        hdr = self.headers.get("Authorization", "")
        if hdr.startswith("Basic "):
            try:
                decoded = base64.b64decode(hdr[6:]).decode("utf-8", errors="replace")
                user, _, _ = decoded.partition(":")
                return user
            except Exception:
                return ""
        return ""

    def _check_auth(self) -> bool:
        if not DASHBOARD_PASSWORD:
            return True
        hdr = self.headers.get("Authorization", "")
        if hdr.startswith("Basic "):
            try:
                decoded = base64.b64decode(hdr[6:]).decode("utf-8", errors="replace")
                _, _, sent = decoded.partition(":")
                if hmac.compare_digest(sent, DASHBOARD_PASSWORD):
                    return True
            except Exception:
                pass
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="admin"')
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"Authentication required\n")
        return False

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

    def _handle_api_costs(self, qs: dict):
        """GET /api/costs?days=<N>. Devuelve costo LLM (parseado de los
        journals de cada wik3) + costo de compute estimado por las horas que
        cada wik3 estuvo viva durante el período. No incluye NAT/disk/IAP
        (típicamente <5% del total). Si una wik3 se creó dentro del período,
        las horas-running se ajustan al tiempo desde la creación."""
        try:
            days = int((qs.get("days") or ["7"])[0])
        except Exception:
            days = 7
        days = max(1, min(days, 90))

        now = dt.datetime.now(dt.timezone.utc)
        period_start = (now - dt.timedelta(days=days)).replace(microsecond=0)
        # journalctl no parsea microsegundos ni el sufijo "Z"; usamos el
        # formato "YYYY-MM-DD HH:MM:SS UTC" que sí acepta.
        since_iso = period_start.strftime("%Y-%m-%d %H:%M:%S UTC")

        instances = list_wik3_instances()
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
            results = list(ex.map(lambda i: fetch_wik3_costs(i, since_iso), instances))

        by_wik3 = []
        total_llm = 0.0
        total_compute = 0.0
        for inst in results:
            machine = inst.get("machine_type") or ""
            hourly = GCP_HOURLY_USD.get(machine, GCP_DEFAULT_HOURLY_USD)
            created_at_raw = inst.get("created_at") or ""
            effective_start = period_start
            if created_at_raw:
                try:
                    vm_created = dt.datetime.fromisoformat(created_at_raw.replace("Z", "+00:00"))
                    if vm_created > period_start:
                        effective_start = vm_created
                except Exception:
                    pass
            hours_active = max(0.0, (now - effective_start).total_seconds() / 3600.0)
            compute_usd = round(hourly * hours_active, 2)
            llm_body = inst.get("llm") or {}
            llm_usd = round(float(llm_body.get("total_llm_usd") or 0), 2)
            by_eng = llm_body.get("by_engagement") or {}
            by_wik3.append({
                "name": inst.get("name") or "?",
                "hacker_email": inst.get("hacker_email") or "",
                "machine_type": machine or "unknown",
                "hourly_usd": hourly,
                "hours_active": round(hours_active, 1),
                "compute_usd": compute_usd,
                "llm_usd": llm_usd,
                "total_usd": round(compute_usd + llm_usd, 2),
                "by_engagement": by_eng,
                "llm_error": inst.get("llm_error"),
            })
            total_llm += llm_usd
            total_compute += compute_usd

        by_wik3.sort(key=lambda x: x["total_usd"], reverse=True)

        self._json({
            "period_days": days,
            "since": since_iso,
            "now": now.isoformat().replace("+00:00", "Z"),
            "totals": {
                "llm_usd": round(total_llm, 2),
                "compute_usd": round(total_compute, 2),
                "grand_total_usd": round(total_llm + total_compute, 2),
            },
            "by_wik3": by_wik3,
            "notes": [
                "Compute es estimación on-demand sin sustained-use discounts (GCP los aplica auto, reduce ~30% mensual).",
                "No incluye NAT egress, disco persistente, IAP — típicamente <5% del total.",
                "LLM viene de los journals de wik3-engagement@*.service (cada nodo del agente fabro imprime su costo).",
                "No incluye llamadas LLM puntuales del dashboard wik3 (import, retest/exploit/reproduction/info gen) — típicamente <10% del LLM total.",
            ],
        })

    def do_POST(self):
        if not self._check_auth():
            return
        from urllib.parse import urlparse
        parsed = urlparse(self.path)
        if parsed.path == "/api/teams":
            body = self._read_json_body() or {}
            try:
                write_teams(body)
            except Exception as e:
                self._json({"error": f"no pude guardar: {e}"}, code=500)
                return
            # Push inmediato (scoped) tras guardar, para que el TL lo vea ya.
            threading.Thread(target=push_team_data, daemon=True).start()
            self._json({"ok": True, **read_teams()})
            return
        # Mover un engagement de una wik3 a otra.
        if parsed.path == "/api/move-engagement":
            body = self._read_json_body() or {}
            code, res = move_engagement(
                (body.get("slug") or ""), (body.get("from_vm") or ""), (body.get("to_vm") or ""))
            self._json(res, code=code)
            return
        if parsed.path == "/api/wik3s":
            body = self._read_json_body()
            email = (body.get("email") or "").strip().lower()
            try:
                result = provision_wik3(email)
                self._json(result, code=201)
            except ProvisionError as e:
                self._json({"error": str(e)}, code=400)
            except subprocess.TimeoutExpired:
                self._json({"error": "timeout en gcloud — la VM puede haber quedado a medio crear"}, code=504)
            except Exception as e:
                self._json({"error": f"unexpected: {e}"}, code=500)
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
                self._json({"error": "name es obligatorio"}, code=400)
                return
            if len(name) > 80:
                self._json({"error": "name max 80 chars"}, code=400)
                return
            actor = self._basic_auth_user()
            try:
                write_brand(name, logo_b64, logo_ct, bg_b64, bg_ct, palette, actor)
            except ValueError as e:
                self._json({"error": str(e)}, code=400)
                return
            except Exception as e:
                self._json({"error": f"no pude guardar el branding: {e}"}, code=500)
                return
            self._json({"ok": True, **read_brand()})
            return
        if parsed.path == "/api/sync":
            try:
                self._json(sync_findings())
            except Exception as e:
                self._json({"error": f"sync failed: {e}"}, code=500)
            return

        # Mensaje a una wik3 individual
        m = re.match(r"^/api/wik3s/([a-z0-9-]{1,63})/message$", parsed.path)
        if m:
            body = self._read_json_body()
            text = (body.get("text") or "").strip() if isinstance(body, dict) else ""
            if not text:
                self._json({"error": "text requerido"}, code=400)
                return
            instances = {i.get("name"): i for i in list_wik3_instances()}
            inst = instances.get(m.group(1))
            if not inst or not inst.get("_base_url"):
                self._json({"error": "wik3 no encontrada o sin IP"}, code=404)
                return
            sender = self._basic_auth_user() or "admin"
            code, resp = _wik3_post(inst["_base_url"], "/admin/messages", {"text": text, "from": sender})
            self._json({"wik3": inst.get("name"), "status": code, "response": resp}, code=200 if code == 200 else 502)
            return

        # Broadcast a TODAS las wik3s alcanzables
        if parsed.path == "/api/broadcast/message":
            body = self._read_json_body()
            text = (body.get("text") or "").strip() if isinstance(body, dict) else ""
            if not text:
                self._json({"error": "text requerido"}, code=400)
                return
            sender = self._basic_auth_user() or "admin"
            instances = [i for i in list_wik3_instances() if i.get("_base_url")]
            results: list[dict] = []
            def send(inst):
                code, resp = _wik3_post(inst["_base_url"], "/admin/messages", {"text": text, "from": sender})
                return {"wik3": inst.get("name"), "status": code, "ok": code == 200, "error": (resp or {}).get("error") if code != 200 else None}
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
                results = list(ex.map(send, instances))
            ok = sum(1 for r in results if r["ok"])
            self._json({"total": len(results), "ok": ok, "results": results})
            return

        self.send_error(404)

    def do_DELETE(self):
        if not self._check_auth():
            return
        from urllib.parse import urlparse
        parsed = urlparse(self.path)
        m = re.match(r"^/api/wik3s/([a-z0-9-]{1,63})$", parsed.path)
        if m:
            try:
                result = deprovision_wik3(m.group(1))
                self._json(result)
            except ProvisionError as e:
                self._json({"error": str(e)}, code=400)
            except subprocess.TimeoutExpired:
                self._json({"error": "timeout en gcloud delete"}, code=504)
            except Exception as e:
                self._json({"error": f"unexpected: {e}"}, code=500)
            return
        self.send_error(404)

    def do_GET(self):
        if not self._check_auth():
            return
        from urllib.parse import urlparse
        parsed = urlparse(self.path)
        path = parsed.path

        if path in {"/", "/index.html"}:
            html = (SCRIPT_DIR / "dashboard.html").read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(html)
            return

        if path == "/api/branding":
            self._json(read_brand())
            return
        if path == "/api/teams":
            cfg = read_teams()
            hackers = sorted({(i.get("hacker_email") or "").strip().lower()
                              for i in list_wik3_instances() if i.get("hacker_email")})
            self._json({"teams": cfg.get("teams", {}),
                        "assignments": cfg.get("assignments", {}),
                        "hackers": hackers})
            return
        if path in ("/branding/logo", "/branding/bg"):
            kind = path.rsplit("/", 1)[-1]
            info = read_brand()
            if not info.get("has_" + kind):
                self.send_error(404); return
            try:
                brand_data = json.loads(BRAND_JSON_PATH.read_text())
                fn = brand_data.get(f"{kind}_filename") or ""
                file_path = BRAND_DIR / fn
                if not file_path.is_file():
                    self.send_error(404); return
                data = file_path.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", brand_data.get(f"{kind}_content_type") or "image/png")
                self.send_header("Cache-Control", "public, max-age=300")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except Exception:
                self.send_error(500)
            return

        if path == "/api/state":
            instances = list_wik3_instances()
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
                merged = list(ex.map(fetch_wik3_summary, instances))
            _maybe_lazy_sync(merged)
            metrics = aggregate_metrics(merged)
            for m in merged:
                m.pop("_base_url", None)
            self._json({
                "admin": {
                    "instance_name": INSTANCE_NAME,
                    "project_id": PROJECT_ID,
                    "admin_email": ADMIN_EMAIL,
                    "admin_token_present": bool(ADMIN_TOKEN),
                    "version": {
                        "image": ADMIN_IMAGE_NAME,
                        "commit": ADMIN_COMMIT,
                        "wik3_commit_template": ADMIN_WIK3_COMMIT,
                    },
                },
                "wik3s": merged,
                "metrics": metrics,
            })
            return

        if path == "/api/validation-weekly":
            from urllib.parse import parse_qs
            q = parse_qs(parsed.query)
            only = (q.get("only", [""])[0] or "").strip().lower() or None
            exclude = (q.get("exclude", [""])[0] or "").strip().lower() or None
            etype = (q.get("type", [""])[0] or "").strip().lower() or None
            data = validation_by_week(only=only, exclude=exclude, etype=etype)
            data["hackers"] = review_activity_by_hacker(only=only, exclude=exclude, etype=etype)
            self._json(data)
            return

        if path == "/api/wik3s":
            instances = list_wik3_instances()
            for inst in instances:
                inst.pop("_base_url", None)
            self._json({"wik3s": instances})
            return

        if path == "/api/metrics":
            instances = list_wik3_instances()
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
                merged = list(ex.map(fetch_wik3_summary, instances))
            self._json(aggregate_metrics(merged))
            return

        if path == "/api/costs":
            from urllib.parse import parse_qs
            self._handle_api_costs(parse_qs(parsed.query))
            return

        if path == "/api/sync/status":
            self._json(dict(_LAST_SYNC))
            return

        if path == "/api/feedback/false-positives":
            # Feedback = vulns descartadas por el hacker CON NOTA explicando
            # por qué. Los descartes del agente (validation_status=false_positive)
            # sin nota humana son ruido — el agente no se enseña a sí mismo.
            # Sin nota tampoco aporta señal: solo "no" sin contexto.
            # Best-effort sync para frescura.
            try:
                sync_findings()
            except Exception as e:
                print(f"[admin] sync error during feedback: {e}", flush=True)
            with _STORE_LOCK:
                store = load_findings_store()
            items = []
            for rec in store.values():
                rs = (rec.get("review_status") or "").lower()
                note = (rec.get("review_note") or "").strip()
                if rs != "false_positive" or not note:
                    continue
                items.append({
                    "wik3_name": rec.get("wik3_name", ""),
                    "hacker_email": rec.get("hacker_email", ""),
                    "engagement_slug": rec.get("engagement_slug", ""),
                    "finding_id": rec.get("finding_id", ""),
                    "severity": rec.get("severity", ""),
                    "title": rec.get("title", ""),
                    "affected": rec.get("affected", []),
                    "phase": rec.get("phase", ""),
                    "review_by": rec.get("review_by", ""),
                    "review_at": rec.get("review_at", ""),
                    "review_note": note,
                    "first_seen": rec.get("first_seen", ""),
                    "last_seen": rec.get("last_seen", ""),
                })
            sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            items.sort(key=lambda r: (
                sev_order.get((r.get("severity") or "").lower(), 9),
                r.get("review_at") or "",
                r.get("finding_id") or "",
            ))
            self._json({"total": len(items), "items": items})
            return

        if path == "/api/export/false-positives.csv":
            # Mismo filtro que /api/feedback/false-positives: solo descartes
            # humanos con nota. Eso es feedback accionable; lo demás es ruido.
            try:
                sync_findings()
            except Exception as e:
                print(f"[admin] sync error during fp export: {e}", flush=True)
            with _STORE_LOCK:
                store = load_findings_store()
            buf = io.StringIO()
            w = csv.writer(buf, lineterminator="\n")
            w.writerow([
                "severity", "wik3_name", "hacker_email",
                "engagement_slug", "finding_id", "title", "affected",
                "phase", "review_by", "review_at", "review_note",
                "first_seen", "last_seen",
            ])
            sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            fps = []
            for rec in store.values():
                rs = (rec.get("review_status") or "").lower()
                note = (rec.get("review_note") or "").strip()
                if rs != "false_positive" or not note:
                    continue
                fps.append(rec)
            fps.sort(key=lambda r: (
                sev_order.get((r.get("severity") or "").lower(), 9),
                r.get("review_at") or "",
                r.get("finding_id") or "",
            ))
            for rec in fps:
                affected = rec.get("affected") or []
                if not isinstance(affected, list):
                    affected = [affected]
                w.writerow([
                    rec.get("severity", ""),
                    rec.get("wik3_name", ""),
                    rec.get("hacker_email", ""),
                    rec.get("engagement_slug", ""),
                    rec.get("finding_id", ""),
                    rec.get("title", ""),
                    "; ".join(str(x) for x in affected),
                    rec.get("phase", ""),
                    rec.get("review_by", ""),
                    rec.get("review_at", ""),
                    (rec.get("review_note") or "").strip(),
                    rec.get("first_seen", ""),
                    rec.get("last_seen", ""),
                ])
            data = buf.getvalue().encode("utf-8")
            stamp = dt.datetime.utcnow().strftime("%Y%m%d-%H%M")
            self.send_response(200)
            self.send_header("Content-Type", "text/csv; charset=utf-8")
            self.send_header("Content-Disposition", f'attachment; filename="wik3-false-positives-{stamp}.csv"')
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return

        if path == "/api/export/findings.csv":
            # Sync primero (best-effort: wik3s caídos no rompen el export).
            try:
                sync_findings()
            except Exception as e:
                print(f"[admin] sync error during export: {e}", flush=True)
            with _STORE_LOCK:
                store = load_findings_store()
            buf = io.StringIO()
            w = csv.writer(buf, lineterminator="\n")
            w.writerow([
                "engagement_created_at", "engagement_started_at", "run_started_at",
                "wik3_name", "hacker_email", "engagement_slug", "engagement_types",
                "severity", "title", "phase", "review_status",
                "review_by", "review_at",
                "finding_id", "first_seen", "last_seen",
            ])
            sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            records = sorted(
                store.values(),
                key=lambda r: (
                    r.get("engagement_created_at") or "",
                    r.get("engagement_slug", ""),
                    sev_order.get((r.get("severity") or "").lower(), 9),
                    r.get("finding_id", ""),
                ),
            )
            for rec in records:
                w.writerow([
                    rec.get("engagement_created_at", ""),
                    rec.get("engagement_started_at", ""),
                    rec.get("run_started_at", ""),
                    rec.get("wik3_name", ""),
                    rec.get("hacker_email", ""),
                    rec.get("engagement_slug", ""),
                    ",".join(rec.get("engagement_types") or []),
                    rec.get("severity", ""),
                    rec.get("title", ""),
                    rec.get("phase", ""),
                    rec.get("review_status", ""),
                    rec.get("review_by", ""),
                    rec.get("review_at", ""),
                    rec.get("finding_id", ""),
                    rec.get("first_seen", ""),
                    rec.get("last_seen", ""),
                ])
            data = buf.getvalue().encode("utf-8")
            stamp = dt.datetime.utcnow().strftime("%Y%m%d-%H%M")
            self.send_response(200)
            self.send_header("Content-Type", "text/csv; charset=utf-8")
            self.send_header("Content-Disposition", f'attachment; filename="wik3-findings-{stamp}.csv"')
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return

        m = re.match(r"^/api/engagements/([a-z0-9][a-z0-9-]{0,62})/([a-z0-9][a-z0-9-]{0,62})/findings$", path)
        if m:
            wik3_name, engagement_slug = m.group(1), m.group(2)
            with _STORE_LOCK:
                store = load_findings_store()
            sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            findings = sorted(
                (r for r in store.values()
                 if r.get("wik3_name") == wik3_name and r.get("engagement_slug") == engagement_slug),
                key=lambda r: (sev_order.get((r.get("severity") or "").lower(), 9), r.get("finding_id", "")),
            )
            self._json({"wik3_name": wik3_name, "engagement_slug": engagement_slug, "findings": findings})
            return

        # /api/wik3s/<vm-name>/<resource>
        m = re.match(r"^/api/wik3s/([a-z0-9][a-z0-9-]{1,62})/(summary|engagements|state)$", path)
        if m:
            vm_name, resource = m.group(1), m.group(2)
            instances = list_wik3_instances()
            inst = next((i for i in instances if i.get("name") == vm_name), None)
            if not inst:
                self._json({"error": f"wik3 '{vm_name}' no encontrada"}, code=404)
                return
            wik3_path = {
                "summary": "/admin/summary",
                "engagements": "/admin/engagements",
                "state": "/admin/state" + ("?" + parsed.query if parsed.query else ""),
            }[resource]
            code, body = _wik3_get(inst["_base_url"], wik3_path)
            self._json(body if isinstance(body, dict) else {"raw": body}, code=code)
            return

        # /api/wik3s/<vm>/engagements/<slug>/retest — history de retests de un engagement.
        m = re.match(r"^/api/wik3s/([a-z0-9][a-z0-9-]{1,62})/engagements/([a-z0-9][a-z0-9-]{0,40})/retest$", path)
        if m:
            vm_name, slug = m.group(1), m.group(2)
            instances = list_wik3_instances()
            inst = next((i for i in instances if i.get("name") == vm_name), None)
            if not inst:
                self._json({"error": f"wik3 '{vm_name}' no encontrada"}, code=404)
                return
            code, body = _wik3_get(inst["_base_url"], f"/admin/engagements/{slug}/retest")
            self._json(body if isinstance(body, dict) else {"raw": body}, code=code)
            return

        self.send_error(404)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, default=int(os.environ.get("ADMIN_PORT", "8080")))
    p.add_argument("--bind", default=os.environ.get("ADMIN_BIND", "0.0.0.0"))
    args = p.parse_args()
    print(
        f"[admin] dashboard on http://{args.bind}:{args.port} "
        f"(project={PROJECT_ID or 'n/a'}, admin_token={'set' if ADMIN_TOKEN else 'MISSING'})",
        flush=True,
    )
    threading.Thread(target=_background_sync_loop, daemon=True).start()
    threading.Thread(target=_team_push_loop, daemon=True).start()
    server = ThreadingHTTPServer((args.bind, args.port), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
