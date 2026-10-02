# Use of GET Request with Sensitive Data in Query String (CWE-598) - {{Alta | Media}}

| Campo | Valor |
|---|---|
| **CVSS Vector** | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` |
| **CVSS Score** | `{{8.7}}` |
| **CWE** | [CWE-598 – Use of GET Request Method With Sensitive Query Strings](https://cwe.mitre.org/data/definitions/598.html) |
| **OWASP** | A04:2021 – Insecure Design |
| **Estado** | {{Abierto}} |

## Descripción

La aplicación transmite datos sensibles (credenciales, tokens, API keys, PII) como
parámetros en la **query string** de peticiones GET. Estas URLs quedan registradas en
logs de servidores y proxies, en el historial del navegador, en la cabecera `Referer`
hacia terceros y en sistemas de caché, exponiendo el dato sensible más allá del canal cifrado.

## Componentes Afectados

- `{{https://app.cliente.com/api/...?api_key=...}}`
- **Parámetros:** `{{api_key}}`, `{{token}}`, `{{password}}`

## Detalles

Se observó que el `{{api_key / token}}` se envía en la URL de una petición GET.

**Paso 1 — Petición con el dato sensible en la query string**

```http
GET /api/data?api_key=SECRET_API_KEY_12345&user=victima HTTP/1.1
Host: app.cliente.com
```

> _Figura {{N}}: la API key viaja en la URL, quedando expuesta en logs, historial y Referer._

**Evidencia complementaria**

- Log del servidor/proxy: `... "GET /api/data?api_key=SECRET_API_KEY_12345 ..."`
- Cabecera `Referer` enviada a recursos de terceros incluyendo la URL completa.

## Impacto

El dato sensible queda registrado en múltiples ubicaciones fuera del control de la
aplicación (logs, historial, Referer, caché), permitiendo su recuperación por personal o
terceros no autorizados y derivando en uso indebido de credenciales o fuga de información.

## Remediación

- Transmitir datos sensibles en el **cuerpo** de peticiones POST/PUT, nunca en la URL.
- Usar cabeceras (`Authorization`) para tokens/API keys.
- Configurar `Referrer-Policy` restrictiva y evitar el cacheo de respuestas sensibles.
- Rotar cualquier credencial que se haya expuesto en URLs/logs.

## Referencias

- https://cwe.mitre.org/data/definitions/598.html
- https://owasp.org/Top10/A04_2021-Insecure_Design/
