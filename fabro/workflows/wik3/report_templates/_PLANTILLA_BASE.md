<!--
PLANTILLA BASE DE HALLAZGO / PoC — Hackmetrix OffSec
Estructura derivada de los reportes finales (Forpay, WeWow, Buk, Somos Radar, Rockebot).
Copia este bloque, renómbralo y completa los campos entre {{ }}.
Orden de secciones idéntico al usado en "Detalles Técnicos" de los reportes.
Borra los comentarios HTML antes de entregar.
-->

# {{Nombre del hallazgo}} (CWE-{{XXX}}) - {{Crítica | Alta | Media | Baja | Informativa}}

| Campo | Valor |
|---|---|
| **CVSS Vector** | `CVSS:4.0/AV:{{N}}/AC:{{L}}/AT:{{N}}/PR:{{N}}/UI:{{N}}/VC:{{H}}/VI:{{H}}/VA:{{H}}/SC:{{N}}/SI:{{N}}/SA:{{N}}` |
| **CVSS Score** | `{{0.0}}` |
| **CWE** | [CWE-{{XXX}}](https://cwe.mitre.org/data/definitions/{{XXX}}.html) |
| **OWASP** | {{p. ej. A01:2021 – Broken Access Control / API5:2023}} |
| **Estado** | {{Abierto / Remediado / Mitigado / Aceptado}} |

## Descripción

{{Explicación conceptual del TIPO de vulnerabilidad: qué es, por qué ocurre, cómo se
explota en general. Texto reutilizable entre clientes — no incluyas aquí detalles del
sistema específico, eso va en "Detalles".}}

## Componentes Afectados

- `{{https://app.cliente.com/endpoint}}`
- **Parámetros / cabeceras:** `{{param1}}`, `{{param2}}`, `{{Authorization}}`

## Detalles

{{Hallazgo específico sobre este cliente + Prueba de Concepto reproducible.
Usa pasos numerados. Cuando haya varios vectores, divídelos en "Caso 1", "Caso 2"...
Transcribe los requests/responses HTTP crudos (no solo capturas) y referencia las
figuras de evidencia.}}

**Paso 1 — {{acción}}**

```http
{{MÉTODO}} {{/ruta}} HTTP/1.1
Host: {{app.cliente.com}}
Authorization: Bearer {{TOKEN}}
Content-Type: application/json

{{body}}
```

**Paso 2 — {{acción}}**

```http
HTTP/1.1 200 OK
Content-Type: application/json

{{respuesta que evidencia la explotación}}
```

> _Figura {{N}}: {{descripción de la captura de evidencia}}._

## Impacto

{{Consecuencia concreta para el negocio: fraude, toma de cuenta, fuga de PII, DoS,
incumplimiento normativo (PCI DSS, etc.). Menciona encadenamiento con otros hallazgos
si aplica.}}

## Remediación

- {{Recomendación accionable 1}}
- {{Recomendación accionable 2}}

## Referencias

- {{https://cwe.mitre.org/data/definitions/XXX.html}}
- {{https://owasp.org/...}}
- {{https://hackmetrix.com/blog/...}}
