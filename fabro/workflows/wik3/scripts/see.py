#!/usr/bin/env python3
"""see.sh - el agente analiza una imagen con un prompt.

Uso:
    see.sh <image-path> "describe la imagen"
    see.sh screenshot.png "que endpoint admin se ve en esta captura?"
    see.sh dump.png "extrae todos los emails y hashes visibles"

Llama al endpoint `/v1/messages` (formato Anthropic nativo) de LiteLLM.
Este endpoint bypassea la middleware OpenAI-compat del proxy, que estaba
inyectando parametros como `reasoning_effort` que el backend Bedrock/Claude
rechaza. Usa el mismo OPENAI_API_KEY y OPENAI_BASE_URL que el resto del
workflow — LiteLLM acepta la virtual key por ambos caminos.

Requiere OPENAI_API_KEY y OPENAI_BASE_URL en el env del sandbox.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

MIME_BY_EXT = {
    "png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg",
    "gif": "image/gif", "webp": "image/webp",
}

MAX_IMAGE_BYTES = 20 * 1024 * 1024


def main() -> int:
    ap = argparse.ArgumentParser(prog="see.sh")
    ap.add_argument("image", help="path a la imagen (png/jpg/gif/webp)")
    ap.add_argument("prompt", help="que queres saber sobre la imagen")
    ap.add_argument("--model", default="claude-haiku-4-5",
                    help="default: claude-haiku-4-5 (vision barato via LiteLLM → Bedrock Claude).")
    ap.add_argument("--max-tokens", type=int, default=1024)
    args = ap.parse_args()

    # Prefer ANTHROPIC_* (provider principal via LiteLLM /v1/messages).
    # Fallback a OPENAI_* para retrocompat — LiteLLM acepta el mismo key en
    # ambos paths y el endpoint /v1/messages sigue siendo el mismo.
    key = os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("OPENAI_API_KEY")
    if not key:
        print("error: ANTHROPIC_API_KEY (ni OPENAI_API_KEY fallback) esta en el env", file=sys.stderr)
        return 2

    base_url = (os.environ.get("ANTHROPIC_BASE_URL")
                or os.environ.get("OPENAI_BASE_URL")
                or "https://api.anthropic.com").rstrip("/")
    # Si el BASE_URL ya termina en /v1 (convencion Fabro), solo appenda
    # /messages; si no (proxies que exponen raiz), appenda /v1/messages.
    endpoint = f"{base_url}/messages" if base_url.endswith("/v1") else f"{base_url}/v1/messages"

    img_path = Path(args.image)
    if not img_path.is_file():
        print(f"error: no existe el archivo '{args.image}'", file=sys.stderr)
        return 2

    data = img_path.read_bytes()
    if len(data) > MAX_IMAGE_BYTES:
        print(f"error: imagen muy grande ({len(data)} bytes > {MAX_IMAGE_BYTES}). "
              f"Redimensiona antes con imagemagick/sips.", file=sys.stderr)
        return 2

    ext = img_path.suffix.lower().lstrip(".")
    mime = MIME_BY_EXT.get(ext)
    if not mime:
        print(f"error: extension no soportada '.{ext}' (usa png/jpg/gif/webp)", file=sys.stderr)
        return 2

    b64 = base64.b64encode(data).decode()

    body = {
        "model": args.model,
        "max_tokens": args.max_tokens,
        "messages": [{
            "role": "user",
            "content": [
                {"type": "image", "source": {"type": "base64", "media_type": mime, "data": b64}},
                {"type": "text", "text": args.prompt},
            ],
        }],
    }

    req = urllib.request.Request(
        endpoint,
        data=json.dumps(body).encode(),
        headers={
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            resp = json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        err_body = e.read().decode(errors="replace")[:800]
        print(f"HTTP {e.code}: {err_body}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"error: {type(e).__name__}: {e}", file=sys.stderr)
        return 1

    # Anthropic response: {content: [{type: "text", text: "..."}], usage: {...}}
    text = "".join(c.get("text", "") for c in resp.get("content", []) if c.get("type") == "text")
    usage = resp.get("usage", {})
    print(text)
    print(f"\n--- [see.sh: model={args.model}, in={usage.get('input_tokens')}tok, out={usage.get('output_tokens')}tok, endpoint={endpoint}]",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
