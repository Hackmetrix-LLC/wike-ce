# Using Components with Known Vulnerabilities (CWE-937) - {{Baja | Media}}

| Campo | Valor |
|---|---|
| **CVSS Vector** | `CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` |
| **CVSS Score** | `{{7.3}}` |
| **CWE** | [CWE-937 – Using Components with Known Vulnerabilities](https://cwe.mitre.org/data/definitions/937.html) (rel. CWE-1104) |
| **OWASP** | A06:2021 – Vulnerable and Outdated Components |
| **Estado** | {{Abierto}} |

## Descripción

La aplicación utiliza componentes (librerías, frameworks, servidores, dependencias) en
versiones desactualizadas con vulnerabilidades públicas conocidas (CVE). Un atacante puede
identificar la versión expuesta y aprovechar exploits ya publicados, sin necesidad de
descubrir vulnerabilidades nuevas.

## Componentes Afectados

- `{{nginx 1.18.0}}` · `{{jQuery 1.12.4}}` · `{{libreria X v.Y}}`
- **CVE asociados:** `{{CVE-XXXX-YYYY}}`

## Detalles

Se identificaron versiones de componentes con vulnerabilidades conocidas mediante el
análisis de respuestas y recursos.

**Paso 1 — Identificación de versiones**

```bash
curl -sI https://app.cliente.com | grep -i server          # banner del servidor
# Inspección de JS/dependencias del frontend, /package.json expuesto, etc.
# Cotejo contra bases de CVE (NVD) y herramientas (retire.js, OWASP Dependency-Check)
```

```text
Server: nginx/1.18.0
jQuery v1.12.4   → CVE-XXXX-YYYY (XSS)
```

> _Figura {{N}}: versión desactualizada del componente con CVE público asociado._

## Impacto

Según la vulnerabilidad del componente, el impacto puede ir desde XSS/exposición de
información hasta ejecución remota de código, reutilizando exploits públicos.

## Remediación

- Mantener un inventario de dependencias (SBOM) y actualizar a versiones soportadas/parcheadas.
- Integrar análisis de composición de software (SCA) en el pipeline (Dependency-Check, Snyk, retire.js).
- Eliminar dependencias no utilizadas y ocultar banners de versión.

## Referencias

- https://cwe.mitre.org/data/definitions/937.html
- https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/
- https://nvd.nist.gov/
