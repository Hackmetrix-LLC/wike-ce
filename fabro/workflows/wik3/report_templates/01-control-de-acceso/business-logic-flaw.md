# Business Logic Flaw / Improper Input Validation (CWE-1284) - {{Crítica | Alta}}

| Campo | Valor |
|---|---|
| **CVSS Vector** | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` |
| **CVSS Score** | `{{8.6}}` |
| **CWE** | [CWE-1284 – Improper Validation of Specified Quantity in Input](https://cwe.mitre.org/data/definitions/1284.html) |
| **OWASP** | A04:2021 – Insecure Design |
| **Estado** | {{Abierto}} |

## Descripción

Una falla de lógica de negocio surge cuando la aplicación valida el *formato* de los
datos pero no las *reglas de negocio* que deberían cumplirse (rangos, signos, límites,
secuencia de pasos). Un atacante puede manipular valores —montos, cantidades, estados—
para producir resultados que el flujo legítimo nunca permitiría, como inflar saldos,
obtener montos negativos o saltarse validaciones de proceso.

## Componentes Afectados

- `{{https://app.cliente.com/api/payout/request}}`
- **Parámetros:** `{{amount}}`, `{{quantity}}`, `{{balance}}`

## Detalles

Se identificó que el endpoint `{{/payout/request}}` no valida los límites de negocio del
parámetro `{{amount}}`, permitiendo {{valores negativos / desproporcionados}} para inflar
el saldo de forma arbitraria.

**Paso 1 — Operación legítima**

```http
POST /api/payout/request HTTP/1.1
Host: app.cliente.com
Authorization: Bearer {{TOKEN}}
Content-Type: application/json

{"amount": 100.00}
```

**Paso 2 — Manipulación del valor fuera de los límites de negocio**

```http
POST /api/payout/request HTTP/1.1
Host: app.cliente.com
Authorization: Bearer {{TOKEN}}
Content-Type: application/json

{"amount": -100000.00}
```

```http
HTTP/1.1 200 OK

{"balance": 100000.00}   // el saldo se infla en lugar de rechazar la operación
```

> _Figura {{N}}: el sistema acepta el valor inválido y altera el saldo._

## Impacto

Permite fraude financiero directo: inflar saldos, generar pagos indebidos o evadir
límites de negocio, con impacto económico y reputacional para la organización.

## Remediación

- Validar en el servidor todas las reglas de negocio: rangos, signos, máximos/mínimos,
  consistencia de estado y secuencia de pasos.
- Aplicar validación tanto sintáctica como semántica de cada entrada numérica/monetaria.
- Implementar controles de doble verificación y conciliación para operaciones financieras.

## Referencias

- https://cwe.mitre.org/data/definitions/1284.html
- https://owasp.org/www-community/vulnerabilities/Business_logic_vulnerability
- https://owasp.org/Top10/A04_2021-Insecure_Design/
