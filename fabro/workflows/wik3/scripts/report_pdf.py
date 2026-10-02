#!/usr/bin/env python3
"""report_pdf.py — renderiza el reporte (markdown) a PDF estilo Hackmetrix.

Uso: report_pdf.py <report_full.md> <out.pdf> <report_assets_dir>

Reusa los assets de marca (cover.png, logo.png, style.css) y marked.umd.js que
viajan en el bundle (report_assets/). Convierte el markdown a HTML con marked
DENTRO del chromium headless (el mismo que usa browse.py vía Playwright), agrega
la portada y los estilos, e imprime a PDF A4. Sin Node ni puppeteer.
"""
from __future__ import annotations

import base64
import json
import re
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright


def _b64(path: Path) -> str:
    try:
        return base64.b64encode(path.read_bytes()).decode()
    except Exception:
        return ""


def main() -> int:
    if len(sys.argv) < 4:
        print("uso: report_pdf.py <md> <out.pdf> <assets_dir>", file=sys.stderr)
        return 2
    md_path, out_pdf, assets = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
    md = md_path.read_text()
    # Placeholder de captura (marcador !§ INSERTAR IMAGEN (desc) §! de los prompts)
    # → caja estilizada, no el marcador crudo, en el PDF entregable.
    md = re.sub(
        r"!§\s*INSERTAR IMAGEN\s*\(?\s*(.*?)\s*\)?\s*§!",
        lambda m: '<div class="img-ph">🖼 Aquí va una captura'
        + (": " + m.group(1) if m.group(1).strip() else "") + "</div>",
        md, flags=re.S)
    style = ""
    try:
        style = (assets / "style.css").read_text()
    except Exception:
        pass
    marked_js = ""
    try:
        marked_js = (assets / "marked.umd.js").read_text()
    except Exception:
        pass
    cover_b64 = _b64(assets / "cover.png")
    logo_b64 = _b64(assets / "logo.png")

    cover_html = (
        f'<div class="cover-page"><img src="data:image/png;base64,{cover_b64}"></div>'
        if cover_b64 else ""
    )
    logo_html = (
        f'<img class="brand-logo" src="data:image/png;base64,{logo_b64}">'
        if logo_b64 else ""
    )
    html = f"""<!doctype html><html lang="es"><head><meta charset="utf-8">
<style>
{style}
.cover-page {{ page-break-after: always; margin:0; }}
.cover-page img {{ width:100%; height:100%; object-fit:cover; display:block; }}
.brand-logo {{ height:34px; margin:0 0 18px; }}
body {{ margin:0; }}
#content {{ padding: 0 14mm; }}
.img-ph {{ margin:6px 0; padding:8px 12px; border:1px dashed #999; border-radius:6px; background:#f5f5f5; color:#666; font-style:italic; font-size:.92em; }}
</style></head>
<body>
{cover_html}
<div id="content">{logo_html}</div>
<script>{marked_js}</script>
<script>
  const MD = {json.dumps(md)};
  const html = (window.marked ? (window.marked.parse ? window.marked.parse(MD) : window.marked(MD)) : MD);
  document.getElementById('content').insertAdjacentHTML('beforeend', html);
</script>
</body></html>"""

    with sync_playwright() as p:
        browser = p.chromium.launch(args=["--no-sandbox"])
        page = browser.new_page()
        page.set_content(html, wait_until="networkidle")
        page.pdf(
            path=str(out_pdf),
            format="A4",
            print_background=True,
            margin={"top": "16mm", "bottom": "16mm", "left": "0mm", "right": "0mm"},
        )
        browser.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
