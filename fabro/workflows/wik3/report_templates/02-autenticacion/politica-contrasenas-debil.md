# Weak Password Policy (CWE-521) - {{Media}}

| Campo | Valor |
|---|---|
| **CVSS Vector** | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N` |
| **CVSS Score** | `{{6.9}}` |
| **CWE** | [CWE-521 – Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html) |
| **OWASP** | A07:2021 – Identification and Authentication Failures |
| **Estado** | {{Abierto}} |

## Descripción

La aplicación permite establecer contraseñas que no cumplen requisitos mínimos de
robustez (longitud, complejidad, exclusión de contraseñas comunes/filtradas). Esto
facilita ataques de fuerza bruta y adivinación, especialmente si además falta
rate-limiting.

## Componentes Afectados

- `{{https://app.cliente.com/register}}` · `{{/account/change-password}}`
- **Parámetros:** `{{password}}`

## Detalles

Se comprobó que el sistema acepta contraseñas triviales como `{{12345678}}`,
sin exigir complejidad ni rechazar contraseñas comunes.

**Paso 1 — Registro/cambio de contraseña con valor débil**

```http
POST /account/change-password HTTP/1.1
Host: app.cliente.com
Authorization: Bearer {{TOKEN}}
Content-Type: application/json

{"password":"12345678"}
```

```http
HTTP/1.1 200 OK

{"status":"password updated"}   // la contraseña trivial es aceptada
```

> _Figura {{N}}: la aplicación acepta una contraseña que no cumple requisitos mínimos._

## Impacto

Las contraseñas débiles incrementan drásticamente la probabilidad de toma de cuenta vía
fuerza bruta o credential stuffing, comprometiendo la seguridad de los usuarios y sus datos.

## Remediación

- Exigir longitud mínima (≥ 12 caracteres) y validar contra listas de contraseñas
  comunes/filtradas (p. ej. HaveIBeenPwned).
- Seguir las recomendaciones de NIST SP 800-63B (priorizar longitud, permitir frases de paso).
- Mostrar un medidor de robustez y combinar con MFA y rate-limiting.

## Referencias

- https://cwe.mitre.org/data/definitions/521.html
- https://pages.nist.gov/800-63-3/sp800-63b.html
- https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
