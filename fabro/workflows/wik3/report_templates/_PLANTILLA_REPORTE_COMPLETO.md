<!--
PLANTILLA DE REPORTE COMPLETO — Hackmetrix OffSec
Estructura derivada de los reportes finales (Forpay, WeWow, Buk, Somos Radar, Rockebot):
portada → ejecutivo → convenciones → metodología → alcance → tabla de vulnerabilidades →
resumen de hallazgos → conclusiones → DETALLES TÉCNICOS (un hallazgo por sección) → apéndices.

Para cada hallazgo de "Detalles Técnicos", copia la plantilla del tipo correspondiente
desde la carpeta por categoría (ver README.md) y pégala bajo la sección 8.
Reemplaza los {{placeholders}} y borra los comentarios <!-- --> antes de entregar.
-->

# Informe de Pentesting — {{Cliente}} / {{Aplicación o Módulo}}

| | |
|---|---|
| **Cliente** | {{Cliente}} |
| **Alcance** | {{WebApp / API / Infra}} — {{nombre}} |
| **Tipo de prueba** | {{Gray-box / Black-box / White-box}} |
| **Fechas de ejecución** | {{dd/mm/aaaa}} – {{dd/mm/aaaa}} |
| **Versión del documento** | {{1.0}} |
| **Clasificación** | Confidencial |
| **Autor(es)** | Equipo OffSec — Hackmetrix |
| **Estándares** | OWASP Testing Guide v4 · OWASP Top 10 · ASVS · ({{PCI DSS}}) |

> **Aviso de confidencialidad.** Este documento contiene información sensible sobre la
> seguridad de {{Cliente}} y está destinado únicamente a sus destinatarios autorizados.
> Su divulgación, copia o distribución no autorizada está prohibida.

---

## Control de versiones

| Versión | Fecha | Autor | Cambios |
|---|---|---|---|
| {{1.0}} | {{dd/mm/aaaa}} | {{Nombre}} | Versión inicial |

---

## 1. Resumen Ejecutivo

{{Resumen no técnico orientado a la gerencia: contexto del encargo, qué se evaluó, postura
de seguridad general y los riesgos más relevantes en lenguaje de negocio. 2–4 párrafos.}}

**Riesgo general del ejercicio:** **{{Crítico | Alto | Medio | Bajo}}**

{{Frase de cierre: principales causas raíz y recomendación estratégica de alto nivel.}}

### 1.1 Distribución de hallazgos por severidad

| Severidad | Cantidad | % |
|---|---|---|
| 🔴 Crítica | {{0}} | {{0%}} |
| 🟠 Alta | {{0}} | {{0%}} |
| 🟡 Media | {{0}} | {{0%}} |
| 🟢 Baja | {{0}} | {{0%}} |
| ⚪ Informativa | {{0}} | {{0%}} |
| **Total** | **{{0}}** | **100%** |

<!-- Insertar gráfico de torta de distribución por severidad. -->

---

## 2. Objetivos

- Identificar y explotar vulnerabilidades en {{el alcance}} desde la perspectiva de un atacante.
- Evaluar el impacto real de los hallazgos sobre la confidencialidad, integridad y disponibilidad.
- Entregar recomendaciones de remediación priorizadas por riesgo.
- {{Aportar evidencia para cumplimiento (p. ej. PCI DSS / QSA), si aplica.}}

---

## 3. Convenciones de Valoración (Severidad)

Se utiliza **CVSS v4.0** combinado con una capa cualitativa de criticidad por impacto de
negocio. El vector/score **base** mide la técnica; la **criticidad final** refleja el impacto
de negocio. Cuando el hallazgo afecta datos o activos sensibles (PII/PHI, financiero,
credenciales, acceso masivo) se elevan los requisitos de seguridad en el vector
**environmental** (`CR:H`/`IR:H`/`AR:H`), lo que sube el score legítimamente — p. ej. un IDOR
de score base *Alto* se reporta como *Crítico* si expone PII de otros usuarios. La criticidad
final puede ser MAYOR que el rango del score base según el contexto del negocio.

| Severidad | Rango CVSS | Color | Descripción |
|---|---|---|---|
| Crítica | 9.0 – 10.0 | 🔴 | Compromiso directo / explotación trivial de alto impacto |
| Alta | 7.0 – 8.9 | 🟠 | Impacto significativo, explotable |
| Media | 4.0 – 6.9 | 🟡 | Impacto moderado o explotación condicionada |
| Baja | 0.1 – 3.9 | 🟢 | Impacto limitado / defensa en profundidad |
| Informativa | 0.0 | ⚪ | Observación sin riesgo directo |

---

## 4. Metodología

El ejercicio se ejecutó bajo un enfoque **{{Gray-box}}**, siguiendo:

- **OWASP Web Security Testing Guide v4** / **OWASP API Security Top 10**
- **OWASP Top 10**
- **OWASP ASVS** como referencia de controles
- Pruebas mayoritariamente manuales, apoyadas en herramientas (ver Apéndice).

Fases: reconocimiento → mapeo de la superficie → identificación de vulnerabilidades →
explotación → post-explotación / impacto → documentación.

---

## 5. Alcance

**En alcance:**

- `{{https://app.cliente.com}}`
- `{{api.cliente.com, otros dominios/endpoints}}`

**Fuera de alcance:**

- {{Ataques de denegación de servicio destructivos, ingeniería social a personal, etc.}}

**Credenciales / accesos provistos:** {{roles de prueba entregados}}

**Ventana de pruebas:** {{horario / restricciones}}

---

## 6. Tabla de Vulnerabilidades

| # | Hallazgo | Tipo (CWE) | Severidad | CVSS | Estado |
|---|---|---|---|---|---|
| 1 | {{Insecure Direct Object Reference}} | CWE-{{639}} | 🔴 Crítica | {{9.0}} | {{Abierto}} |
| 2 | {{...}} | CWE-{{...}} | 🟠 Alta | {{7.5}} | {{Abierto}} |
| 3 | {{...}} | CWE-{{...}} | 🟡 Media | {{5.5}} | {{Abierto}} |
| 4 | {{...}} | CWE-{{...}} | 🟢 Baja | {{3.5}} | {{Abierto}} |

---

## 7. Resumen de Hallazgos (narrativa)

{{Relato técnico del recorrido del ataque: cómo se encadenaron los hallazgos, cuál fue el
camino de mayor impacto (p. ej. IDOR → fuga de PII, o credenciales filtradas → RCE) y qué
controles fallaron de forma transversal. 2–4 párrafos.}}

---

## 8. Detalles Técnicos

<!--
Una subsección por hallazgo, en orden de severidad descendente.
Pega aquí la plantilla del tipo correspondiente (carpeta 01-06) y completa sus campos.
Cada hallazgo mantiene: Título (CWE) - Severidad → CVSS Vector → CVSS Score → Descripción
→ Componentes Afectados → Detalles (PoC) → Impacto → Remediación → Referencias.
-->

### 8.1 {{Nombre del hallazgo}} (CWE-{{XXX}}) - {{Severidad}}

{{Pegar contenido de la plantilla por tipo.}}

---

### 8.2 {{Nombre del hallazgo}} (CWE-{{XXX}}) - {{Severidad}}

{{...}}

---

<!-- Repetir 8.N por cada hallazgo. -->

---

## 9. Conclusiones Generales

{{Postura de seguridad final, causas raíz comunes (p. ej. validación solo en frontend,
ausencia de control de acceso por objeto, falta de rate-limiting), y hoja de ruta de
remediación priorizada (corto / mediano / largo plazo).}}

---

## Apéndice I — Ataques Intentados

Pruebas realizadas que **no** derivaron en hallazgo o fueron correctamente mitigadas por
la aplicación (evidencia de cobertura).

| Prueba | Resultado | Comentario |
|---|---|---|
| {{File upload (PHP)}} | Mitigado | {{rechazado por validación de tipo}} |
| {{Manipulación de JWT (alg=none, claims)}} | Mitigado | {{validado en backend}} |
| {{SQL / XML / XXE injection}} | Sin éxito | {{...}} |
| {{Host Header Injection}} | Sin riesgo | {{...}} |

---

## Apéndice II — Cobertura OWASP Top 10

| Categoría OWASP | Cubierta | Hallazgos asociados |
|---|---|---|
| A01 – Broken Access Control | ✅ | {{#1, #2}} |
| A02 – Cryptographic Failures | {{✅/—}} | {{...}} |
| A03 – Injection | {{✅/—}} | {{...}} |
| A04 – Insecure Design | {{✅/—}} | {{...}} |
| A05 – Security Misconfiguration | {{✅/—}} | {{...}} |
| A06 – Vulnerable & Outdated Components | {{✅/—}} | {{...}} |
| A07 – Identification & Auth Failures | {{✅/—}} | {{...}} |
| A08 – Software & Data Integrity Failures | {{✅/—}} | {{...}} |
| A09 – Logging & Monitoring Failures | {{✅/—}} | {{...}} |
| A10 – SSRF | {{✅/—}} | {{...}} |

---

## Apéndice III — Metodologías, Herramientas y Referencias

**Metodologías:** OWASP WSTG v4 · OWASP API Security Top 10 · OWASP Top 10 · OWASP ASVS.

**Herramientas utilizadas:** {{Burp Suite, nmap, ffuf, Swaks, MxToolbox, shcheck, Hashcat, retire.js, ...}}

**Referencias:**

- https://owasp.org/www-project-web-security-testing-guide/
- https://owasp.org/www-project-top-ten/
- https://cwe.mitre.org/
- https://www.first.org/cvss/
- {{https://hackmetrix.com/blog/...}}

---

## Apéndice IV — Glosario

| Término | Definición |
|---|---|
| CVSS | Common Vulnerability Scoring System — métrica estándar de severidad. |
| CWE | Common Weakness Enumeration — catálogo de tipos de debilidad. |
| PoC | Prueba de Concepto — demostración reproducible de la explotación. |
| {{...}} | {{...}} |
