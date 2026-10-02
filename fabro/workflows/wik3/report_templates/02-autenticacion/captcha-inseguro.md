# Improper CAPTCHA Implementation (CWE-804) - {{Media}}

| Campo | Valor |
|---|---|
| **CVSS Vector** | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N` |
| **CVSS Score** | `{{6.9}}` |
| **CWE** | [CWE-804 – Guessable CAPTCHA](https://cwe.mitre.org/data/definitions/804.html) |
| **OWASP** | A04:2021 – Insecure Design |
| **Estado** | {{Abierto}} |

## Descripción

El CAPTCHA se valida solo en el frontend o de forma opcional en el servidor, por lo que
puede omitirse eliminando el parámetro del token, reutilizando un token ya validado, o
ignorando el resultado de la verificación. Esto neutraliza el control anti-automatización
y reabre la puerta a fuerza bruta y abuso de recursos.

## Componentes Afectados

- `{{https://app.cliente.com/api/login}}` · `{{/password/reset}}`
- **Parámetros:** `{{captchaToken}}`, `{{recaptcha_response}}`

## Detalles

Se comprobó que al **eliminar** el parámetro `{{captchaToken}}` de la petición, el
servidor procesa la solicitud igualmente, evidenciando que el CAPTCHA no se valida del
lado del servidor.

**Paso 1 — Petición legítima con token de CAPTCHA**

```http
POST /api/login HTTP/1.1
Host: app.cliente.com
Content-Type: application/json

{"email":"victima@cliente.com","password":"{{****}}","captchaToken":"03AGd..."}
```

**Paso 2 — Misma petición sin el parámetro de CAPTCHA**

```http
POST /api/login HTTP/1.1
Host: app.cliente.com
Content-Type: application/json

{"email":"victima@cliente.com","password":"{{****}}"}
```

```http
HTTP/1.1 200 OK
// la petición se procesa igual sin el token → CAPTCHA eludido
```

> _Figura {{N}}: la solicitud se procesa correctamente sin el token de CAPTCHA._

## Impacto

Al eludirse el CAPTCHA, los flujos protegidos (login, recuperación, registro) quedan
expuestos a automatización: fuerza bruta, enumeración y abuso de recursos / envío masivo.

## Remediación

- Validar el token de CAPTCHA **en el servidor** contra el proveedor en cada petición y
  rechazar si está ausente, vencido o ya usado (tokens de un solo uso).
- Vincular el token al flujo/usuario/acción y no aceptar la operación sin verificación exitosa.
- Combinar con rate-limiting como defensa en profundidad.

## Referencias

- https://cwe.mitre.org/data/definitions/804.html
- https://developers.google.com/recaptcha/docs/verify
- https://owasp.org/Top10/A04_2021-Insecure_Design/
