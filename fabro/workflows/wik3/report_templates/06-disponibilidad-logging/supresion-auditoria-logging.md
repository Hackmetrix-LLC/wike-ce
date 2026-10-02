# Client-Controlled Audit Suppression / Insufficient Logging (CWE-778) - {{Media | Baja}}

| Campo | Valor |
|---|---|
| **CVSS Vector** | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N` |
| **CVSS Score** | `{{7.1}}` |
| **CWE** | [CWE-778 – Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html) (rel. CWE-284) |
| **OWASP** | A09:2021 – Security Logging and Monitoring Failures |
| **Estado** | {{Abierto}} |

## Descripción

La aplicación permite que un parámetro controlado por el cliente desactive el registro,
las notificaciones o la auditoría de una acción (p. ej. `shouldNotify:"NO"`), o
directamente no registra eventos de seguridad relevantes. Un atacante puede así ejecutar
operaciones sensibles evadiendo el monitoreo y la respuesta ante incidentes.

## Componentes Afectados

- `{{https://app.cliente.com/api/transaction}}`
- **Parámetros:** `{{shouldNotify}}`, `{{audit}}`, `{{silent}}`

## Detalles

Se observó que enviar `{{shouldNotify:"NO"}}` suprime la notificación/registro de la
operación, que de otro modo se auditaría.

**Paso 1 — Operación con auditoría/notificación activa (comportamiento esperado)**

```http
POST /api/transaction HTTP/1.1
Host: app.cliente.com
Authorization: Bearer {{TOKEN}}
Content-Type: application/json

{"amount":1000,"shouldNotify":"YES"}
```

**Paso 2 — Misma operación suprimiendo la auditoría desde el cliente**

```http
POST /api/transaction HTTP/1.1
Host: app.cliente.com
Authorization: Bearer {{TOKEN}}
Content-Type: application/json

{"amount":1000,"shouldNotify":"NO"}
```

```http
HTTP/1.1 200 OK
// la transacción se ejecuta sin generar notificación ni registro de auditoría
```

> _Figura {{N}}: la operación sensible se realiza sin dejar rastro en el monitoreo._

## Impacto

Permite a un atacante operar sin ser detectado, dificultando la detección de fraude, la
respuesta ante incidentes y el análisis forense, y debilitando los controles de
cumplimiento.

## Remediación

- Generar el registro/auditoría **del lado del servidor**, sin depender de parámetros
  controlables por el cliente.
- Registrar todos los eventos de seguridad relevantes (autenticación, autorización,
  operaciones sensibles) de forma íntegra e inalterable.
- Centralizar logs, protegerlos contra manipulación y configurar alertas/monitoreo.

## Referencias

- https://cwe.mitre.org/data/definitions/778.html
- https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/
