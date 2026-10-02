#!/usr/bin/env python3
"""
browse.py - Playwright wrapper para active_analyze (auth + SPA navigation).

Modos:
  login <login_url> <email> <pass> [--state-out /tmp/state.json]
      Hace login con heuristicas (multi-selector). Scrapea CSRF tokens automaticamente
      (input[name=user_token|csrf_token|_csrf|authenticity_token|...]). Al terminar
      guarda storageState (cookies + localStorage + sessionStorage) en JSON.

  fetch <url> [--state-in /tmp/state.json] [--method POST --data '...' --header 'K: V']
      Request autenticado cargando el state previamente guardado. Devuelve
      JSON con status, headers, body (primeros 8KB).

  eval <url> --script 'expr' [--state-in /tmp/state.json]
      Navega al URL (opcionalmente con state), ejecuta JS, devuelve el resultado serializable.

  form-login <form_url> --fields '{"user":"admin","pass":"x"}' \\
             [--submit-selector 'button[type=submit]'] [--state-out ...] \\
             [--captcha-img-selector 'img.captcha' --captcha-field captcha \\
              --captcha-refresh-selector '.refresh' --captcha-retries 3]
      Para forms tradicionales con tokens CSRF. Detecta el form, rellena los inputs
      que coincidan con los fields provistos, scrapea hidden tokens automaticamente.
      CAPTCHA de TEXTO: si pasas --captcha-img-selector + --captcha-field, saca un
      screenshot del <img> del captcha, lo lee con visión (LLM) y rellena el campo
      antes de enviar. Solo para captchas de texto simples (NO reCAPTCHA/hCaptcha).
      Lo importante: pasar el login UNA vez para guardar el storageState (cookie/
      token de sesión) con --state-out y reusarlo con `fetch --state-in` — no se
      resuelve el captcha en cada request.

Output: JSON a stdout. Errors a stderr con exit code != 0.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

# ─── Proxy (squid) ──────────────────────────────────────────────────────────
# browse.py va POR el squid forward-proxy, igual que el resto del sandbox: el
# contenedor del agente NO tiene egress directo a internet (todo sale por squid),
# así que sin proxy toda navegación de Playwright cuelga en timeout.
# Capturamos el proxy ANTES de limpiar el env y lo pasamos EXPLÍCITO a
# chromium.launch(proxy=...) — más confiable que el auto-config por env, que
# tiene quirks con CONNECT. El _scope_check() interno sigue como defensa (valida
# CADA URL: initial + redirects + crawl). ignore_https_errors=True en los
# contexts cubre el caso de que squid encadene a Burp (cert self-signed).
_PROXY = (
    os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
    or os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
    or os.environ.get("SANDBOX_HTTPS_PROXY") or os.environ.get("SANDBOX_HTTP_PROXY")
    or ""
).strip()
for _k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"):
    os.environ.pop(_k, None)

from playwright.sync_api import Page, sync_playwright


def _chromium_launch(p):
    """Lanza chromium ruteando por el squid proxy (si está configurado)."""
    if _PROXY:
        return p.chromium.launch(proxy={"server": _PROXY})
    return p.chromium.launch()

SCRIPT_DIR = Path(__file__).resolve().parent
DISCOVERY_APPEND = str(SCRIPT_DIR / "discovery_append.sh")


def _wik3_dir() -> Path:
    """Directorio del engagement activo: $WIK3_DIR (exportado por el exec-logger)
    o el marker /workspace/wik3/.active-slug. Reemplaza al symlink 'current'."""
    d = os.environ.get("WIK3_DIR")
    if d:
        return Path(d)
    try:
        slug = Path("/workspace/wik3/.active-slug").read_text().strip()
        if slug:
            return Path("/workspace/wik3") / slug
    except OSError:
        pass
    return Path("/workspace/wik3")


def _load_user_agent() -> str | None:
    """Lee user_agent.txt del workspace (escrito por load_engagement.sh).
    Si existe, override del Playwright default (que dice HeadlessChrome —
    delata scraper). load_engagement.sh siempre escribe algo: el UA del
    operador si lo seteó, sino un Chrome realista por default."""
    try:
        ua = (_wik3_dir() / "user_agent.txt").read_text().strip()
        return ua or None
    except Exception:
        return None


_UA = _load_user_agent()


# ─── Scope check interno ───────────────────────────────────────────────────
# Replica la lógica hostname-aware most-specific-wins de scope_guard.sh.
# Antes de cada page.goto() el agente valida la URL; si falla, abortamos
# con SystemExit y un mensaje claro. También se usa en respuesta a redirects:
# si la página HTTP 30x apunta a un host fuera de scope, no la seguimos.

def _wik3_root() -> Path:
    """Resuelve /workspace/wik3/<slug>/ del engagement activo (sin symlink current)."""
    return _wik3_dir()


def _hostname_only(url_or_host: str) -> str:
    """Extrae hostname (sin port, sin auth, sin path) — case-insensitive."""
    s = url_or_host.strip()
    if not s:
        return ""
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in s:
        s = s.split("@", 1)[1]
    if ":" in s:
        s = s.split(":", 1)[0]
    return s.lower()


def _host_match_len(host: str, listfile: Path) -> int:
    """Longitud del match más específico de `host` contra entries del archivo."""
    if not host or not listfile.is_file():
        return 0
    best = 0
    try:
        for raw in listfile.read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            line = line.split("#", 1)[0].strip()
            entry_host = _hostname_only(line)
            if not entry_host:
                continue
            ln = len(entry_host)
            if host == entry_host or host.endswith("." + entry_host):
                if ln > best:
                    best = ln
    except OSError:
        return 0
    return best


_OSINT_SUFFIXES = (
    "crt.sh", "nvd.nist.gov", "cve.mitre.org", "exploit-db.com",
    ".github.com", ".githubusercontent.com", "gitlab.com",
    "shodan.io", "censys.io", "archive.org", "web.archive.org",
    "alienvault.com", ".otx.alienvault.com", "commoncrawl.org",
    ".oast.live", ".oast.pro", ".oast.site", ".oast.online", ".oast.me", ".oast.fun",
    "projectdiscovery.io", "go.dev", "pkg.go.dev",
    "127.0.0.1", "localhost", "169.254.169.254",
)


def _is_external_osint(host: str) -> bool:
    h = host.lower()
    for suf in _OSINT_SUFFIXES:
        if suf.startswith("."):
            if h.endswith(suf):
                return True
        else:
            if h == suf or h.endswith("." + suf):
                return True
    return False


class ScopeViolation(SystemExit):
    """Aborta browse.py si una URL queda fuera de scope."""
    def __init__(self, url: str, reason: str):
        super().__init__(2)
        self.url = url
        self.reason = reason


def _scope_check(url: str, *, context: str = "navigation") -> None:
    """Valida URL contra scope.txt + out_of_scope.txt. Aborta si falla.

    `context`: "navigation" para gotos directos, "redirect" para 30x follow,
    "crawl" para links descubiertos. Solo cambia el mensaje de error.
    """
    if not url:
        return
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return  # data:, blob:, javascript: — no es network request al target
    host = (parsed.hostname or "").lower()
    if not host:
        return
    if _is_external_osint(host):
        return
    root = _wik3_root()
    scope_file = root / "scope.txt"
    oos_file = root / "out_of_scope.txt"
    scope_len = _host_match_len(host, scope_file)
    oos_len = _host_match_len(host, oos_file)
    if oos_len > 0 and oos_len >= scope_len:
        msg = f"BLOCK[browse.py {context}]: out_of_scope wins ({oos_len} ≥ {scope_len}) — {url}"
        print(msg, file=sys.stderr, flush=True)
        raise ScopeViolation(url, "out_of_scope")
    if scope_len == 0:
        msg = f"BLOCK[browse.py {context}]: URL fuera de scope — {url}"
        print(msg, file=sys.stderr, flush=True)
        raise ScopeViolation(url, "not_in_scope")


CSRF_HIDDEN_NAMES = [
    "user_token", "csrf_token", "csrfmiddlewaretoken", "_csrf", "_token",
    "authenticity_token", "__RequestVerificationToken", "csrf", "xsrf_token",
]


def _emit(obj: Any) -> None:
    print(json.dumps(obj, default=str), flush=True)


# ─── Request interception → discovery queue ──────────────────────────────────
#
# Toda navegacion via Playwright emite multiples requests (JS bundles, XHR/fetch,
# imagenes, docs). Los capturamos y se los pasamos a discovery_append.sh, que
# aplica filtro de scope y dedup. Asi cada login/fetch alimenta la exploracion.

# Resource types que NO vale la pena sumar como endpoints.
_SKIP_RESOURCE_TYPES = {"font", "websocket", "manifest", "texttrack"}


class RequestCollector:
    """Captura URLs de requests durante una sesion Playwright."""
    def __init__(self, source: str):
        self.source = source  # etiqueta para discovery_append
        self.seen: set[tuple[str, str]] = set()  # (url, method)

    def attach(self, page: Page):
        page.on("request", self._on_request)

    def _on_request(self, request):
        rt = request.resource_type or ""
        if rt in _SKIP_RESOURCE_TYPES:
            return
        key = (request.url, request.method)
        self.seen.add(key)

    def flush_to_discovery(self) -> dict:
        """Feed collected URLs al discovery queue. Retorna stats."""
        added = 0
        rejected = 0
        errors = 0
        env = os.environ.copy()
        for url, method in self.seen:
            # Tipo: file si termina en extension de archivo estatico, sino endpoint
            kind = "file" if any(url.endswith(ext) for ext in (".js", ".css", ".json", ".map", ".txt", ".xml", ".zip", ".tar", ".gz", ".bak", ".old", ".conf", ".env")) else "endpoint"
            try:
                r = subprocess.run(
                    ["bash", DISCOVERY_APPEND, kind, url, self.source],
                    capture_output=True, text=True, timeout=5, env=env,
                )
                out = (r.stdout or "").strip()
                if '"action":"added"' in out:
                    added += 1
                elif '"action":"duplicate"' in out:
                    pass
                elif '"reason"' in out:
                    rejected += 1
                else:
                    errors += 1
            except Exception:
                errors += 1
        return {
            "seen": len(self.seen),
            "added": added,
            "rejected_out_of_scope": rejected,
            "errors": errors,
        }


def _err(msg: str, code: int = 1) -> None:
    print(json.dumps({"error": msg}), file=sys.stderr, flush=True)
    sys.exit(code)


def _fill_first(page: Page, selectors: list[str], value: str) -> bool:
    for sel in selectors:
        try:
            if page.locator(sel).count():
                page.fill(sel, value)
                return True
        except Exception:
            continue
    return False


def _click_first(page: Page, selectors: list[str]) -> bool:
    for sel in selectors:
        try:
            if page.locator(sel).count():
                page.click(sel)
                return True
        except Exception:
            continue
    return False


def cmd_login(args):
    """Login con heuristicas de selectores email + password + submit."""
    collector = RequestCollector("browse:login")
    with sync_playwright() as p:
        browser = _chromium_launch(p)
        ctx = browser.new_context(ignore_https_errors=True, user_agent=_UA)
        page = ctx.new_page()
        collector.attach(page)
        try:
            _scope_check(args.login_url, context="login")
            page.goto(args.login_url, wait_until="networkidle", timeout=20000)
            _scope_check(page.url, context="login redirect")
            email_ok = _fill_first(page, [
                'input[type="email"]', 'input[name="email"]',
                'input[name="username"]', 'input[name="user"]',
                '#email', '#username', '#user',
            ], args.email)
            pass_ok = _fill_first(page, [
                'input[type="password"]', 'input[name="password"]',
                'input[name="pass"]', '#password', '#pass',
            ], args.password)
            if not (email_ok and pass_ok):
                _err(f"no pude encontrar inputs de login (email={email_ok} pass={pass_ok})")
            _click_first(page, [
                'button[type="submit"]', 'input[type="submit"]',
                'button:has-text("Login")', 'button:has-text("Log in")',
                'button:has-text("Sign in")', 'button:has-text("Ingresar")',
            ])
            try:
                page.wait_for_load_state("networkidle", timeout=10000)
            except Exception:
                pass

            final_url = page.url
            # Detectar signals de login fallido
            title = page.title()
            body_snippet = page.content()[:500]

            if args.state_out:
                ctx.storage_state(path=args.state_out)

            _emit({
                "ok": True,
                "final_url": final_url,
                "title": title,
                "state_saved": args.state_out,
                "body_snippet": body_snippet,
                "discovery": collector.flush_to_discovery(),
            })
        finally:
            browser.close()


def _solve_captcha_text(png_bytes: bytes) -> str | None:
    """Lee un captcha de TEXTO distorsionado de una imagen, usando el modelo de
    visión vía el proxy LiteLLM (mismo endpoint que see.py). Devuelve los
    caracteres leídos (sin espacios) o None si falla. Solo sirve para captchas de
    texto simples — NO para reCAPTCHA/hCaptcha (esos requieren otro enfoque)."""
    key = os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("OPENAI_API_KEY")
    if not key:
        return None
    base_url = (os.environ.get("ANTHROPIC_BASE_URL")
                or os.environ.get("OPENAI_BASE_URL")
                or "https://api.anthropic.com").rstrip("/")
    endpoint = f"{base_url}/messages" if base_url.endswith("/v1") else f"{base_url}/v1/messages"
    b64 = base64.b64encode(png_bytes).decode()
    prompt = ("Esta imagen es un CAPTCHA de texto distorsionado. Devuelve EXCLUSIVAMENTE "
              "los caracteres que ves, en una sola línea, sin espacios, sin comillas y "
              "sin ninguna explicación. Respeta mayúsculas/minúsculas si se distinguen.")
    body = {
        "model": os.environ.get("WIK3_VISION_MODEL", "claude-haiku-4-5"),
        "max_tokens": 32,
        "messages": [{"role": "user", "content": [
            {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": b64}},
            {"type": "text", "text": prompt},
        ]}],
    }
    req = urllib.request.Request(
        endpoint, data=json.dumps(body).encode(),
        headers={"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=45) as r:
            resp = json.loads(r.read().decode())
        parts = resp.get("content") or []
        txt = "".join(p.get("text", "") for p in parts if isinstance(p, dict))
        # El captcha es alfanumérico; limpia espacios/saltos y deja solo el token.
        txt = "".join(txt.split())
        return txt or None
    except Exception:
        return None


def _try_solve_captcha(page, img_selector: str, field: str, refresh_selector: str | None,
                       retries: int) -> dict:
    """Saca screenshot del <img> del captcha, lo resuelve con visión y rellena el
    campo. Reintenta pidiendo otro código (refresh) si el primero no da texto.
    Devuelve {solved, text, attempts}. El agente NO resuelve captchas en cada
    request: solo en el login, para obtener la cookie/token de sesión que se reusa."""
    attempts = 0
    for i in range(max(1, retries)):
        attempts += 1
        try:
            loc = page.locator(img_selector).first
            loc.wait_for(state="visible", timeout=8000)
            png = loc.screenshot()
        except Exception:
            return {"solved": False, "text": None, "attempts": attempts, "error": "captcha img no encontrada/visible"}
        text = _solve_captcha_text(png)
        if text and 3 <= len(text) <= 12:
            ok = _fill_first(page, [f'input[name="{field}"]', f'#{field}', f'input[id="{field}"]'], text)
            return {"solved": ok, "text": text, "attempts": attempts}
        # No salió claro: pide otro código si hay botón de refresh.
        if refresh_selector and i < retries - 1:
            try:
                page.locator(refresh_selector).first.click(timeout=4000)
                page.wait_for_timeout(800)
            except Exception:
                break
        else:
            break
    return {"solved": False, "text": None, "attempts": attempts}


def cmd_form_login(args):
    """Login para forms tradicionales con CSRF. Scrapea hidden inputs (tokens)."""
    fields = json.loads(args.fields)
    collector = RequestCollector("browse:form-login")
    with sync_playwright() as p:
        browser = _chromium_launch(p)
        ctx = browser.new_context(ignore_https_errors=True, user_agent=_UA)
        page = ctx.new_page()
        collector.attach(page)
        try:
            _scope_check(args.form_url, context="form-login")
            page.goto(args.form_url, wait_until="networkidle", timeout=20000)
            _scope_check(page.url, context="form-login redirect")

            # Rellenar cada field por nombre
            filled = {}
            for name, value in fields.items():
                sels = [f'input[name="{name}"]', f'#{name}']
                filled[name] = _fill_first(page, sels, str(value))

            # Extraer hidden tokens (CSRF-like)
            hidden_tokens = {}
            for name in CSRF_HIDDEN_NAMES:
                try:
                    loc = page.locator(f'input[name="{name}"]')
                    if loc.count():
                        val = loc.first.get_attribute("value")
                        if val:
                            hidden_tokens[name] = val
                except Exception:
                    pass

            # Captcha de TEXTO (opcional): screenshot del <img> → visión → rellena.
            # Solo para captchas de texto simples. Lo importante es pasar el login
            # UNA vez para capturar la cookie/token (storageState) y reusarla.
            captcha = None
            if args.captcha_img_selector and args.captcha_field:
                captcha = _try_solve_captcha(
                    page, args.captcha_img_selector, args.captcha_field,
                    args.captcha_refresh_selector, args.captcha_retries)

            # Click submit
            sel = args.submit_selector or 'button[type="submit"], input[type="submit"]'
            _click_first(page, [sel])
            try:
                page.wait_for_load_state("networkidle", timeout=10000)
            except Exception:
                pass

            if args.state_out:
                ctx.storage_state(path=args.state_out)

            _emit({
                "ok": True,
                "final_url": page.url,
                "title": page.title(),
                "fields_filled": filled,
                "hidden_tokens_captured": hidden_tokens,
                "captcha": captcha,
                "state_saved": args.state_out,
                "body_snippet": page.content()[:500],
                "discovery": collector.flush_to_discovery(),
            })
        finally:
            browser.close()


def cmd_fetch(args):
    """Request autenticado (carga storageState previo)."""
    _scope_check(args.url, context="fetch")
    headers = dict(h.split(":", 1) for h in (args.header or []))
    headers = {k.strip(): v.strip() for k, v in headers.items()}
    with sync_playwright() as p:
        browser = _chromium_launch(p)
        ctx_kw = {"ignore_https_errors": True, "user_agent": _UA}
        if args.state_in and Path(args.state_in).exists():
            ctx_kw["storage_state"] = args.state_in
        ctx = browser.new_context(**ctx_kw)
        try:
            resp = ctx.request.fetch(
                args.url,
                method=args.method,
                data=args.data,
                headers=headers or None,
            )
            _scope_check(resp.url, context="fetch redirect")
            body = resp.text()
            _emit({
                "ok": resp.ok,
                "status": resp.status,
                "url": resp.url,
                "headers": dict(resp.headers),
                "body": body[:8192],
                "body_truncated": len(body) > 8192,
                "body_length": len(body),
            })
        finally:
            browser.close()


def cmd_eval(args):
    """Navega y ejecuta JS en el DOM."""
    collector = RequestCollector("browse:eval")
    with sync_playwright() as p:
        browser = _chromium_launch(p)
        ctx_kw = {"ignore_https_errors": True, "user_agent": _UA}
        if args.state_in and Path(args.state_in).exists():
            ctx_kw["storage_state"] = args.state_in
        ctx = browser.new_context(**ctx_kw)
        page = ctx.new_page()
        collector.attach(page)
        try:
            _scope_check(args.url, context="eval")
            page.goto(args.url, wait_until="domcontentloaded", timeout=20000)
            _scope_check(page.url, context="eval redirect")
            result = page.evaluate(args.script)
            _emit({
                "ok": True,
                "url": page.url,
                "result": result,
                "discovery": collector.flush_to_discovery(),
            })
        finally:
            browser.close()


def cmd_crawl(args):
    """Navega una URL (opcionalmente con state), espera network idle, clickea
    links internos del mismo host hasta max_pages. Interceptea todos los requests
    y los alimenta al discovery queue. Util para descubrir endpoints de una SPA."""
    collector = RequestCollector("browse:crawl")
    visited: set[str] = set()
    to_visit = [args.url]
    with sync_playwright() as p:
        browser = _chromium_launch(p)
        ctx_kw = {"ignore_https_errors": True, "user_agent": _UA}
        if args.state_in and Path(args.state_in).exists():
            ctx_kw["storage_state"] = args.state_in
        ctx = browser.new_context(**ctx_kw)
        page = ctx.new_page()
        collector.attach(page)
        try:
            from urllib.parse import urlparse
            origin = urlparse(args.url)
            origin_host = f"{origin.scheme}://{origin.netloc}"
            pages_done = 0
            while to_visit and pages_done < args.max_pages:
                url = to_visit.pop(0)
                if url in visited:
                    continue
                visited.add(url)
                # Scope check: cada link descubierto se valida antes de
                # navegar. Si está fuera de scope, se omite (no abortamos
                # todo el crawl, solo skipeamos ese link).
                try:
                    _scope_check(url, context="crawl")
                except ScopeViolation:
                    continue
                try:
                    page.goto(url, wait_until="networkidle", timeout=15000)
                    _scope_check(page.url, context="crawl redirect")
                except ScopeViolation:
                    raise   # esto sí aborta — el redirect lo trajo a OOS
                except Exception:
                    continue
                pages_done += 1
                # Extract internal links
                try:
                    hrefs = page.evaluate(
                        "() => Array.from(document.querySelectorAll('a[href]')).map(a => a.href)"
                    )
                    for h in hrefs or []:
                        if h.startswith(origin_host) and h not in visited:
                            to_visit.append(h)
                except Exception:
                    pass
            _emit({
                "ok": True,
                "pages_visited": pages_done,
                "pages_queued": len(to_visit),
                "discovery": collector.flush_to_discovery(),
            })
        finally:
            browser.close()


def main() -> int:
    ap = argparse.ArgumentParser(prog="browse.py")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_login = sub.add_parser("login")
    p_login.add_argument("login_url"); p_login.add_argument("email"); p_login.add_argument("password")
    p_login.add_argument("--state-out")
    p_login.set_defaults(func=cmd_login)

    p_form = sub.add_parser("form-login")
    p_form.add_argument("form_url")
    p_form.add_argument("--fields", required=True, help='JSON: {"user":"admin","pass":"x"}')
    p_form.add_argument("--submit-selector")
    p_form.add_argument("--state-out")
    # Captcha de TEXTO: si el login lo tiene, pasa el selector del <img> y el name
    # del input; browse lo lee con visión y rellena antes de enviar.
    p_form.add_argument("--captcha-img-selector", help='CSS del <img> del captcha, ej. "img.captcha" o "#captcha-img"')
    p_form.add_argument("--captcha-field", help="name/id del input donde va el código del captcha")
    p_form.add_argument("--captcha-refresh-selector", help='opcional: CSS del botón "mostrar otro código" para reintentar')
    p_form.add_argument("--captcha-retries", type=int, default=3)
    p_form.set_defaults(func=cmd_form_login)

    p_fetch = sub.add_parser("fetch")
    p_fetch.add_argument("url")
    p_fetch.add_argument("--method", default="GET")
    p_fetch.add_argument("--data", default=None)
    p_fetch.add_argument("--header", action="append", default=[])
    p_fetch.add_argument("--state-in")
    p_fetch.set_defaults(func=cmd_fetch)

    p_eval = sub.add_parser("eval")
    p_eval.add_argument("url")
    p_eval.add_argument("--script", required=True)
    p_eval.add_argument("--state-in")
    p_eval.set_defaults(func=cmd_eval)

    p_crawl = sub.add_parser("crawl")
    p_crawl.add_argument("url")
    p_crawl.add_argument("--state-in")
    p_crawl.add_argument("--max-pages", type=int, default=10)
    p_crawl.set_defaults(func=cmd_crawl)

    args = ap.parse_args()
    try:
        args.func(args)
    except Exception as e:
        _err(f"{type(e).__name__}: {e}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
