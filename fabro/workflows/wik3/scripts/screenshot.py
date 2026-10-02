#!/usr/bin/env python3
"""
screenshot.py - Helper de Playwright para capturar evidencia de findings.

Modos:
    screenshot.py request  <FID> <url> [--method POST --data '...' --header 'K: V']
    screenshot.py login    <FID> <login_url> <email> <password>
    screenshot.py js-exec  <FID> <url> --script 'localStorage.setItem(...)'
    screenshot.py sequence <FID> <json-file-con-pasos>
    screenshot.py batch    <jobs.json>    # Recomendado: N jobs con un solo browser

Formato de jobs.json (batch):
    [
      {"fid": "A-001", "kind": "request", "url": "http://t/x"},
      {"fid": "A-002", "kind": "request", "url": "http://t/y", "method": "POST", "data": "...", "headers": {"X": "Y"}},
      {"fid": "A-003", "kind": "login", "login_url": "...", "email": "...", "password": "..."},
      {"fid": "A-004", "kind": "js-exec", "url": "...", "script": "..."},
      {"fid": "A-005", "kind": "sequence", "steps": [{"action": "goto", ...}]}
    ]

Output:
    $WIK3_DIR/evidence/screenshots/<FID>.png
    $WIK3_DIR/evidence/screenshots/<FID>.caption.txt
    (batch) $WIK3_DIR/evidence/screenshots/errors.log
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import traceback
from pathlib import Path
from typing import Any

from playwright.sync_api import (
    BrowserContext,
    Page,
    Playwright,
    TimeoutError as PwTimeoutError,
    sync_playwright,
)


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


OUT_DIR = _wik3_dir() / "evidence" / "screenshots"


def _load_user_agent() -> str | None:
    """Lee user_agent.txt del workspace (escrito por load_engagement.sh).
    Override del Playwright default (que dice HeadlessChrome y delata)."""
    try:
        ua = (_wik3_dir() / "user_agent.txt").read_text().strip()
        return ua or None
    except Exception:
        return None


_UA = _load_user_agent()
ERROR_LOG = OUT_DIR / "errors.log"


def save(page: Page, fid: str, caption: str) -> Path:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    png = OUT_DIR / f"{fid}.png"
    cap = OUT_DIR / f"{fid}.caption.txt"
    page.screenshot(path=str(png), full_page=True)
    cap.write_text(caption, encoding="utf-8")
    return png


def run_request(ctx: BrowserContext, job: dict[str, Any]) -> Path:
    fid = job["fid"]
    url = job["url"]
    method = (job.get("method") or "GET").upper()
    data = job.get("data")
    headers = job.get("headers") or {}
    page = ctx.new_page()
    try:
        if method == "GET":
            page.goto(url, wait_until="domcontentloaded", timeout=15000)
        else:
            resp = ctx.request.fetch(url, method=method, data=data, headers=headers or None)
            body = resp.text()
            page.set_content(
                f"<h3>{method} {url}</h3>"
                f"<p><b>Status:</b> {resp.status}</p>"
                f"<pre style='background:#111;color:#0f0;padding:12px;"
                f"white-space:pre-wrap;font-family:monospace'>{body[:4000]}</pre>"
            )
        return save(page, fid, f"{method} {url}")
    finally:
        page.close()


def run_login(ctx: BrowserContext, job: dict[str, Any]) -> Path:
    fid = job["fid"]
    login_url = job["login_url"]
    email = job["email"]
    password = job["password"]
    page = ctx.new_page()
    try:
        page.goto(login_url, wait_until="networkidle", timeout=20000)
        for sel in ['input[type="email"]', 'input[name="email"]', "#email"]:
            if page.locator(sel).count():
                page.fill(sel, email)
                break
        for sel in ['input[type="password"]', 'input[name="password"]', "#password"]:
            if page.locator(sel).count():
                page.fill(sel, password)
                break
        for sel in ['button[type="submit"]', 'button:has-text("Login")', 'button:has-text("Log in")']:
            if page.locator(sel).count():
                page.click(sel)
                break
        try:
            page.wait_for_load_state("networkidle", timeout=10000)
        except PwTimeoutError:
            pass
        return save(page, fid, f"LOGIN {login_url} as {email}")
    finally:
        page.close()


def run_js_exec(ctx: BrowserContext, job: dict[str, Any]) -> Path:
    fid = job["fid"]
    url = job["url"]
    script = job["script"]
    page = ctx.new_page()
    try:
        page.goto(url, wait_until="domcontentloaded", timeout=15000)
        page.evaluate(script)
        page.wait_for_timeout(1000)
        return save(page, fid, f"JS_EXEC {url}: {script[:200]}")
    finally:
        page.close()


def run_sequence(ctx: BrowserContext, job: dict[str, Any]) -> Path:
    fid = job["fid"]
    steps = job.get("steps") or json.loads(Path(job["steps_file"]).read_text())
    caption_parts = []
    page = ctx.new_page()
    try:
        for i, step in enumerate(steps):
            a = step["action"]
            if a == "goto":
                page.goto(step["url"], wait_until=step.get("wait", "domcontentloaded"), timeout=20000)
            elif a == "fill":
                page.fill(step["selector"], step["value"])
            elif a == "click":
                page.click(step["selector"])
            elif a == "evaluate":
                page.evaluate(step["script"])
            elif a == "wait":
                page.wait_for_timeout(int(step.get("ms", 1000)))
            elif a == "set_storage":
                page.evaluate(f"localStorage.setItem('{step['key']}', '{step['value']}')")
            else:
                raise ValueError(f"unknown action: {a}")
            caption_parts.append(
                f"{i+1}. {a} {step.get('url') or step.get('selector') or step.get('script','')[:80]}"
            )
        return save(page, fid, "\n".join(caption_parts))
    finally:
        page.close()


KIND_HANDLERS = {
    "request": run_request,
    "login": run_login,
    "js-exec": run_js_exec,
    "sequence": run_sequence,
}


def with_browser(fn):
    """Spin up browser, create context, run fn(ctx), teardown."""
    def wrapper(job: dict[str, Any]) -> Path:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            ctx = browser.new_context(ignore_https_errors=True, user_agent=_UA)
            try:
                return fn(ctx, job)
            finally:
                ctx.close()
                browser.close()
    return wrapper


# --- CLI single-shot modes ---

def cmd_request(args):
    headers = dict(h.split(":", 1) for h in (args.header or []))
    headers = {k.strip(): v.strip() for k, v in headers.items()}
    job = {
        "fid": args.fid, "url": args.url, "method": args.method,
        "data": args.data, "headers": headers,
    }
    png = with_browser(run_request)(job)
    print(f"saved: {png}")


def cmd_login(args):
    job = {
        "fid": args.fid, "login_url": args.login_url,
        "email": args.email, "password": args.password,
    }
    png = with_browser(run_login)(job)
    print(f"saved: {png}")


def cmd_js_exec(args):
    job = {"fid": args.fid, "url": args.url, "script": args.script}
    png = with_browser(run_js_exec)(job)
    print(f"saved: {png}")


def cmd_sequence(args):
    job = {"fid": args.fid, "steps_file": args.steps_file}
    png = with_browser(run_sequence)(job)
    print(f"saved: {png}")


# --- CLI batch mode ---

def cmd_batch(args):
    jobs = json.loads(Path(args.jobs_file).read_text())
    if not isinstance(jobs, list):
        raise SystemExit("jobs.json must be a JSON array")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    errors: list[str] = []
    ok = 0
    t0 = time.monotonic()

    with sync_playwright() as p:
        browser = p.chromium.launch()
        ctx = browser.new_context(ignore_https_errors=True, user_agent=_UA)
        try:
            for i, job in enumerate(jobs, 1):
                fid = job.get("fid", f"job-{i}")
                kind = job.get("kind")
                handler = KIND_HANDLERS.get(kind)
                if handler is None:
                    errors.append(f"{fid}: unknown kind '{kind}'")
                    print(f"[{i}/{len(jobs)}] {fid} SKIP unknown kind {kind}", flush=True)
                    continue
                start = time.monotonic()
                try:
                    png = handler(ctx, job)
                    dt = time.monotonic() - start
                    print(f"[{i}/{len(jobs)}] {fid} OK {dt:.1f}s -> {png.name}", flush=True)
                    ok += 1
                except Exception as e:
                    dt = time.monotonic() - start
                    msg = f"{fid}: {type(e).__name__}: {e}"
                    errors.append(msg)
                    print(f"[{i}/{len(jobs)}] {fid} FAIL {dt:.1f}s {type(e).__name__}: {e}", flush=True)
                    ERROR_LOG.write_text(
                        (ERROR_LOG.read_text() if ERROR_LOG.exists() else "")
                        + f"{fid}\n{traceback.format_exc()}\n\n"
                    )
        finally:
            ctx.close()
            browser.close()

    total = time.monotonic() - t0
    print(f"\nDone: {ok}/{len(jobs)} in {total:.1f}s ({total/max(len(jobs),1):.1f}s avg)")
    if errors:
        print(f"Errors: {len(errors)} (see {ERROR_LOG})")
    # exit 0 siempre: errores parciales no deben abortar el nodo
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(prog="screenshot.py")
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("request")
    r.add_argument("fid"); r.add_argument("url")
    r.add_argument("--method", default="GET")
    r.add_argument("--data", default=None)
    r.add_argument("--header", action="append", default=[])
    r.set_defaults(func=cmd_request)

    l = sub.add_parser("login")
    l.add_argument("fid"); l.add_argument("login_url")
    l.add_argument("email"); l.add_argument("password")
    l.set_defaults(func=cmd_login)

    j = sub.add_parser("js-exec")
    j.add_argument("fid"); j.add_argument("url")
    j.add_argument("--script", required=True)
    j.set_defaults(func=cmd_js_exec)

    s = sub.add_parser("sequence")
    s.add_argument("fid"); s.add_argument("steps_file")
    s.set_defaults(func=cmd_sequence)

    b = sub.add_parser("batch")
    b.add_argument("jobs_file")
    b.set_defaults(func=cmd_batch)

    args = ap.parse_args()
    rc = args.func(args)
    return int(rc or 0)


if __name__ == "__main__":
    sys.exit(main())
