# Exposure of Sensitive Information to an Unauthorized Actor (CWE-200) - {{Alta | Media | Baja}}

| Campo | Valor |
|---|---|
| **CVSS Vector** | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` |
| **CVSS Score** | `{{8.7}}` |
| **CWE** | [CWE-200 – Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html) (rel. CWE-538, CWE-548) |
| **OWASP** | A01:2021 – Broken Access Control / A05 – Security Misconfiguration |
| **Estado** | {{Abierto}} |

## Descripción

La aplicación expone información sensible a actores no autorizados: PII, datos
financieros, detalles de infraestructura, rutas internas, mensajes de error verbosos,
listados de directorios o archivos de configuración. Esta exposición facilita ataques
posteriores y puede constituir una fuga de datos por sí misma.

## Componentes Afectados

- `{{https://app.cliente.com/api/.../detalle}}` · {{/.git, /backup, /actuator, etc.}}
- **Parámetros / recursos:** {{respuesta JSON, headers, archivos expuestos}}

## Detalles

Se identificó que el endpoint `{{...}}` devuelve más información de la necesaria / expone
datos sensibles a un usuario sin autorización.

**Paso 1 — Petición que expone la información**

```http
GET /api/usuarios/{{id}}/detalle HTTP/1.1
Host: app.cliente.com
Authorization: Bearer {{TOKEN}}
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "nombre":"...","rut":"...","direccion":"...","saldo":"...",
  "internal_path":"/var/app/...","db_host":"10.0.0.5"   // datos sensibles innecesarios
}
```

> _Figura {{N}}: la respuesta expone PII / detalles de infraestructura no autorizados._

## Impacto

La fuga de PII o de información técnica facilita fraude, suplantación, ingeniería social y
sirve de reconocimiento para ataques dirigidos a la infraestructura, además de posibles
incumplimientos normativos (protección de datos, PCI DSS).

## Remediación

- Devolver únicamente los campos estrictamente necesarios (principio de mínima exposición).
- Aplicar control de acceso por objeto y por campo en cada endpoint.
- Deshabilitar listados de directorio, mensajes de error verbosos y exposición de
  archivos sensibles (`.git`, backups, configuración).
- Clasificar y enmascarar datos sensibles en respuestas y logs.

## Referencias

- https://cwe.mitre.org/data/definitions/200.html
- https://owasp.org/Top10/A01_2021-Broken_Access_Control/
- https://owasp.org/Top10/A05_2021-Security_Misconfiguration/
