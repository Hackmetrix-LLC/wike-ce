# Broken Function Level Authorization (CWE-285) - {{Crítica | Alta}}

| Campo | Valor |
|---|---|
| **CVSS Vector** | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N` |
| **CVSS Score** | `{{8.7}}` |
| **CWE** | [CWE-285 – Improper Authorization](https://cwe.mitre.org/data/definitions/285.html) |
| **OWASP** | A01:2021 – Broken Access Control / API5:2023 – BFLA |
| **Estado** | {{Abierto}} |

## Descripción

La autorización a nivel de función rota (BFLA) ocurre cuando la aplicación no verifica
que el rol del usuario autenticado tenga permiso para invocar una **función o endpoint
administrativo/privilegiado**. A diferencia del IDOR (acceso a *datos* de otros), aquí
el problema es el acceso a *funcionalidad* reservada: un usuario de bajo privilegio
invoca directamente endpoints de administración, internos o de otro rol porque el
control de acceso solo existe en el frontend (la UI oculta el botón, pero la API responde).

## Componentes Afectados

- `{{https://app.cliente.com/internal/payout/balance}}`
- `{{POST /admin/users/create}}`
- **Roles involucrados:** {{usuario estándar → función de administrador}}

## Detalles

Se comprobó que un usuario con rol `{{estándar}}` puede invocar funciones reservadas a
`{{administrador}}` enviando la petición directamente a la API, sin que el backend valide
el rol.

**Paso 1 — Autenticación como usuario de bajo privilegio**

```http
POST /api/login HTTP/1.1
Host: app.cliente.com
Content-Type: application/json

{"email":"usuario@cliente.com","password":"{{****}}"}
```

**Paso 2 — Invocación directa de la función privilegiada**

```http
POST /internal/payout/balance HTTP/1.1
Host: app.cliente.com
Authorization: Bearer {{TOKEN_USUARIO_ESTANDAR}}
Content-Type: application/json

{"account":"{{...}}","amount":{{...}}}
```

```http
HTTP/1.1 200 OK

{"status":"ok"}   // la operación privilegiada se ejecuta sin validar el rol
```

> _Figura {{N}}: el backend ejecuta la función administrativa para un usuario sin privilegios._

## Impacto

Un usuario con privilegios mínimos puede ejecutar operaciones administrativas o internas
({{crear usuarios, mover saldos, aprobar pagos, modificar configuración}}), lo que rompe
la segregación de funciones y puede derivar en fraude, escalada de privilegios y
compromiso total de la lógica de negocio.

## Remediación

- Aplicar verificación de autorización por rol **en el servidor** para cada función,
  con un modelo deny-by-default.
- No exponer endpoints internos/administrativos en la misma superficie sin control de rol.
- Centralizar las reglas de autorización (middleware/policy) en lugar de validar ad-hoc.
- Cubrir cada endpoint privilegiado con pruebas automatizadas de control de acceso por rol.

## Referencias

- https://cwe.mitre.org/data/definitions/285.html
- https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/
- https://owasp.org/Top10/A01_2021-Broken_Access_Control/
