# Insecure Credential Distribution via Long-Lived Reusable Pre-Signed URLs (CWE-522) - {{Media}}

| Campo | Valor |
|---|---|
| **CVSS Vector** | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` |
| **CVSS Score** | `{{7.1}}` |
| **CWE** | [CWE-522 – Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html) |
| **OWASP** | A04:2021 – Insecure Design |
| **Estado** | {{Abierto}} |

## Descripción

La aplicación distribuye credenciales o archivos sensibles mediante URLs pre-firmadas
(p. ej. AWS S3 pre-signed URLs) con un tiempo de expiración excesivo y/o reutilizables.
Al ser portadoras (cualquiera con la URL accede), una expiración larga amplía la ventana
en la que un tercero que intercepte o reciba la URL —vía logs, Referer, reenvío— puede
descargar el recurso sin autenticación adicional.

## Componentes Afectados

- `{{https://bucket.s3.amazonaws.com/credentials.json?X-Amz-Expires=604800&...}}`
- **Parámetros:** `{{X-Amz-Expires}}`, `{{X-Amz-Signature}}`

## Detalles

Se identificó que la URL pre-firmada para descargar `{{credentials.json}}` tiene una
expiración de `{{7 días}}` y puede reutilizarse múltiples veces.

**Paso 1 — Obtención de la URL pre-firmada**

```http
POST /api/credentials/provision HTTP/1.1
Host: app.cliente.com
Authorization: Bearer {{TOKEN}}
```

```http
HTTP/1.1 200 OK
{
  "url":"https://bucket.s3.amazonaws.com/credentials.json?X-Amz-Expires=604800&X-Amz-Signature=..."
}
```

**Paso 2 — Descarga reutilizable sin autenticación (incluso días después)**

```bash
curl "https://bucket.s3.amazonaws.com/credentials.json?X-Amz-Expires=604800&X-Amz-Signature=..."
# devuelve el archivo de credenciales — sin token, repetidas veces
```

> _Figura {{N}}: la URL pre-firmada descarga las credenciales sin autenticación, dentro de una ventana de 7 días._

## Impacto

Cualquier actor que obtenga la URL (logs, Referer, reenvío, caché) puede descargar las
credenciales o el recurso sensible durante toda la ventana de validez, sin autenticarse,
facilitando el acceso no autorizado.

## Remediación

- Minimizar la expiración de las URLs pre-firmadas (minutos, no días) según el caso de uso.
- Emitir URLs de un solo uso o vincularlas a la sesión/IP del solicitante cuando sea posible.
- Evitar distribuir credenciales por este medio; preferir intercambios autenticados y de corta vida.
- No registrar las URLs pre-firmadas en logs ni exponerlas en Referer.

## Referencias

- https://cwe.mitre.org/data/definitions/522.html
- https://docs.aws.amazon.com/AmazonS3/latest/userguide/ShareObjectPreSignedURL.html
- https://owasp.org/Top10/A04_2021-Insecure_Design/
