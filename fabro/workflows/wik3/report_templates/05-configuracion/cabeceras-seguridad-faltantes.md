# Missing Security Headers (CWE-693) - {{Baja}}

| Campo | Valor |
|---|---|
| **CVSS Vector** | `CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N` |
| **CVSS Score** | `{{2.1}}` |
| **CWE** | [CWE-693 – Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html) |
| **OWASP** | A05:2021 – Security Misconfiguration |
| **Estado** | {{Abierto}} |

## Descripción

La aplicación no envía cabeceras de seguridad que el navegador usa como mecanismos de
defensa (HSTS, X-Content-Type-Options, X-Frame-Options/CSP frame-ancestors,
Referrer-Policy, Permissions-Policy). Su ausencia no es explotable por sí sola pero reduce
las defensas frente a clickjacking, MIME sniffing, fuga vía Referer y degradación de TLS.

## Componentes Afectados

- `{{https://app.cliente.com/}}` (todas las respuestas)

## Detalles

Se analizaron las cabeceras de respuesta y se constató la ausencia de las siguientes.

**Paso 1 — Inspección de cabeceras**

```bash
curl -sI https://app.cliente.com/ 
# ó: shcheck.py https://app.cliente.com
```

```http
HTTP/1.1 200 OK
Server: nginx
Content-Type: text/html
# Faltan: Strict-Transport-Security, X-Content-Type-Options,
#         X-Frame-Options / Content-Security-Policy (frame-ancestors),
#         Referrer-Policy, Permissions-Policy
```

> _Figura {{N}}: respuesta sin las cabeceras de seguridad recomendadas._

## Impacto

Incrementa la superficie de ataque del lado del cliente: clickjacking (sin
X-Frame-Options/CSP), MIME sniffing (sin X-Content-Type-Options), degradación a HTTP
(sin HSTS) y fuga de URLs vía Referer.

## Remediación

Configurar en el servidor/aplicación al menos:

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Content-Type-Options: nosniff
Content-Security-Policy: frame-ancestors 'none'; default-src 'self'
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

## Referencias

- https://cwe.mitre.org/data/definitions/693.html
- https://owasp.org/www-project-secure-headers/
- https://owasp.org/Top10/A05_2021-Security_Misconfiguration/
