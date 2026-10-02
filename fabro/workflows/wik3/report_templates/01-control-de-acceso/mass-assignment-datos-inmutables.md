# Account Takeover via Modification of Assumed-Immutable Data (CWE-471) - {{Crítica | Alta}}

| Campo | Valor |
|---|---|
| **CVSS Vector** | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` |
| **CVSS Score** | `{{8.7}}` |
| **CWE** | [CWE-471 – Modification of Assumed-Immutable Data (MAID)](https://cwe.mitre.org/data/definitions/471.html) |
| **OWASP** | A01:2021 – Broken Access Control |
| **Estado** | {{Abierto}} |

## Descripción

La aplicación asume que ciertos campos son inmutables (identificador de cuenta, email,
tenant, rol) y no protege su modificación, permitiendo que el atacante los altere vía
**mass assignment** o manipulación directa de la petición. Modificar un campo asumido
inmutable —como el email o el ID de otra cuenta— puede permitir tomar control de cuentas
ajenas o asociar recursos a un tenant distinto.

## Componentes Afectados

- `{{https://app.cliente.com/account/profile}}`
- **Parámetros:** `{{email}}`, `{{account_id}}`, `{{user_id}}`

## Detalles

Se comprobó que es posible cambiar el `{{email}}` / `{{account_id}}` de una cuenta hacia
el de otro usuario, tomando control de la misma.

**Paso 1 — Inicio de sesión con la cuenta del atacante**

```http
POST /api/login HTTP/1.1
Host: app.cliente.com
Content-Type: application/json

{"email":"atacante@cliente.com","password":"{{****}}"}
```

**Paso 2 — Modificación del campo asumido inmutable hacia la víctima**

```http
PATCH /account/profile HTTP/1.1
Host: app.cliente.com
Authorization: Bearer {{TOKEN_ATACANTE}}
Content-Type: application/json

{"account_id":"{{ID_VICTIMA}}","email":"victima@cliente.com"}
```

```http
HTTP/1.1 200 OK

{"account_id":"{{ID_VICTIMA}}","email":"victima@cliente.com","updated":true}
```

> _Figura {{N}}: la cuenta de la víctima queda asociada al atacante / recurso reasignado._

## Impacto

Un atacante puede tomar control de cuentas de otros usuarios o reasignar recursos entre
cuentas/tenants, derivando en toma de cuenta (ATO), fraude y fuga de información.

## Remediación

- Usar listas blancas de campos editables (binding explícito); nunca permitir mass
  assignment de campos sensibles (`id`, `email`, `role`, `tenant`).
- Tratar identificadores y email como inmutables salvo en flujos dedicados con
  reverificación (p. ej. confirmación por correo + contraseña actual).
- Validar pertenencia del recurso al usuario autenticado en el servidor.

## Referencias

- https://cwe.mitre.org/data/definitions/471.html
- https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html
- https://owasp.org/Top10/A01_2021-Broken_Access_Control/
