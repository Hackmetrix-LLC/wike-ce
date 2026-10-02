# User Enumeration (CWE-204) - {{Media | Baja}}

| Campo | Valor |
|---|---|
| **CVSS Vector** | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N` |
| **CVSS Score** | `{{6.9}}` |
| **CWE** | [CWE-204 – Observable Response Discrepancy](https://cwe.mitre.org/data/definitions/204.html) |
| **OWASP** | A07:2021 – Identification and Authentication Failures |
| **Estado** | {{Abierto}} |

## Descripción

La aplicación revela si una cuenta existe a través de diferencias observables en sus
respuestas: mensajes de error distintos ("usuario no existe" vs "contraseña incorrecta"),
códigos de estado, o **tiempos de respuesta** diferentes. Esto permite a un atacante
construir una lista de usuarios válidos para dirigir ataques de fuerza bruta, phishing o
credential stuffing.

## Componentes Afectados

- `{{https://app.cliente.com/api/login}}` · `{{/password/reset}}` · `{{/register}}`
- **Parámetros:** `{{email}}`, `{{username}}`

## Detalles

Se observó que la respuesta del servidor difiere según si el usuario existe o no.

**Caso 1 — Usuario existente**

```http
POST /password/reset HTTP/1.1
Host: app.cliente.com
Content-Type: application/json

{"email":"existe@cliente.com"}
```

```http
HTTP/1.1 200 OK
{"message":"Se ha enviado un correo de recuperación"}
```

**Caso 2 — Usuario inexistente**

```http
POST /password/reset HTTP/1.1
Host: app.cliente.com
Content-Type: application/json

{"email":"noexiste@cliente.com"}
```

```http
HTTP/1.1 404 Not Found
{"message":"El usuario no existe"}   // respuesta distinta → enumeración posible
```

> _Figura {{N}}: discrepancia en la respuesta que permite distinguir cuentas válidas._

## Impacto

Permite construir un listado de usuarios válidos, aumentando la eficacia de ataques de
fuerza bruta, phishing dirigido y credential stuffing.

## Remediación

- Devolver respuestas y códigos de estado **uniformes** en login, registro y recuperación
  (p. ej. siempre "si el correo existe, recibirás instrucciones").
- Igualar los tiempos de respuesta para evitar enumeración temporal.
- Aplicar rate-limiting y CAPTCHA en los endpoints afectados.

## Referencias

- https://cwe.mitre.org/data/definitions/204.html
- https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#authentication-and-error-messages
- https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
