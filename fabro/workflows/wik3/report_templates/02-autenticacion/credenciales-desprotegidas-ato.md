# Insufficiently Protected Credentials enabling Account Takeover (CWE-522) - {{Crítica}}

| Campo | Valor |
|---|---|
| **CVSS Vector** | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` |
| **CVSS Score** | `{{8.7}}` |
| **CWE** | [CWE-522 – Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html) (rel. CWE-256, CWE-798) |
| **OWASP** | A07:2021 – Identification and Authentication Failures |
| **Estado** | {{Abierto}} |

## Descripción

Las credenciales (contraseñas, tokens, secretos, claves de API) se almacenan o transmiten
sin protección adecuada: en texto plano, con hashing débil/reversible, en respuestas de
la API, en logs, en el repositorio de código o en almacenamiento del cliente. Cualquier
acceso a ese punto permite recuperarlas y tomar control de las cuentas.

## Componentes Afectados

- `{{https://app.cliente.com/api/profile}}` · {{repositorio Git / logs / localStorage}}
- **Parámetros:** `{{password}}`, `{{api_key}}`, `{{secret}}`

## Detalles

Se identificó que {{las contraseñas se devuelven en texto plano en la respuesta de la API /
se almacenan sin hashing / hay secretos hardcodeados en el repositorio}}.

**Paso 1 — Petición que expone la credencial**

```http
GET /api/profile HTTP/1.1
Host: app.cliente.com
Authorization: Bearer {{TOKEN}}
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "email":"victima@cliente.com",
  "password":"P4ssw0rd-en-texto-plano"   // credencial expuesta en la respuesta
}
```

> _Figura {{N}}: la API devuelve la contraseña del usuario en texto plano._

**Paso 2 — Reutilización para tomar la cuenta**

```http
POST /api/login HTTP/1.1
Host: app.cliente.com
Content-Type: application/json

{"email":"victima@cliente.com","password":"P4ssw0rd-en-texto-plano"}
```

> _Figura {{N+1}}: acceso exitoso a la cuenta de la víctima con la credencial recuperada._

## Impacto

Permite la toma de cuentas (ATO) de forma directa y, si las contraseñas se reutilizan
entre servicios, compromete cuentas externas de los usuarios. Si los secretos expuestos
son de infraestructura, puede escalar a compromiso de sistemas backend.

## Remediación

- Nunca almacenar ni transmitir contraseñas en texto plano; usar hashing fuerte y salteado
  (bcrypt/argon2/scrypt) y no devolverlas en ninguna respuesta.
- Mantener secretos fuera del código (gestor de secretos / variables de entorno) y rotar
  los que se hayan expuesto.
- Cifrar credenciales en tránsito (TLS) y reposo; evitar registrarlas en logs.
- Forzar reseteo de credenciales comprometidas y monitorear filtraciones.

## Referencias

- https://cwe.mitre.org/data/definitions/522.html
- https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
