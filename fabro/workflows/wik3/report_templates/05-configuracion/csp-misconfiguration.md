# Content Security Policy Misconfiguration (CWE-693) - {{Baja}}

| Campo | Valor |
|---|---|
| **CVSS Vector** | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N` |
| **CVSS Score** | `{{5.1}}` |
| **CWE** | [CWE-693 – Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html) (rel. CWE-16) |
| **OWASP** | A05:2021 – Security Misconfiguration |
| **Estado** | {{Abierto}} |

## Descripción

La Content-Security-Policy está ausente o configurada de forma permisiva
(`unsafe-inline`, `unsafe-eval`, `*`, o esquemas amplios como `data:`), lo que anula su
función de mitigar XSS e inyección de contenido. Una CSP débil deja de actuar como defensa
en profundidad frente a la ejecución de scripts no confiables.

## Componentes Afectados

- `{{https://app.cliente.com/}}`
- **Cabecera:** `{{Content-Security-Policy}}`

## Detalles

Se observó que la CSP permite `unsafe-inline`/`unsafe-eval`, habilitando la ejecución de
scripts inline.

**Paso 1 — Inspección de la directiva CSP**

```bash
curl -sI https://app.cliente.com/ | grep -i content-security-policy
```

```http
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' *
# 'unsafe-inline' y 'unsafe-eval' permiten ejecutar JS inline/eval → CSP inefectiva contra XSS
```

> _Figura {{N}}: política CSP permisiva que no mitiga la ejecución de scripts no confiables._

## Impacto

Una CSP débil no protege frente a XSS ni inyección de contenido; si existe un XSS, la
política no impide la ejecución del payload, eliminando una capa clave de defensa.

## Remediación

- Definir una CSP estricta: eliminar `unsafe-inline`/`unsafe-eval`, evitar comodines `*`.
- Usar nonces o hashes para scripts/estilos inline necesarios.
- Especificar `default-src 'self'`, `object-src 'none'`, `base-uri 'self'`,
  `frame-ancestors 'none'`, y endurecer iterativamente con `Content-Security-Policy-Report-Only`.

## Referencias

- https://cwe.mitre.org/data/definitions/693.html
- https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html
- https://owasp.org/Top10/A05_2021-Security_Misconfiguration/
