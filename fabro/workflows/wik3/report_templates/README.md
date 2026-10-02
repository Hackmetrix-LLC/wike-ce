# Plantillas de PoC por tipo de vulnerabilidad — Hackmetrix OffSec

Plantillas en Markdown para documentar hallazgos y pruebas de concepto (PoC) en reportes
de pentest. La estructura está derivada de los reportes finales reales del equipo
(Forpay, WeWow, Buk, Somos Radar, Rockebot), de modo que cada plantilla respeta el mismo
orden de secciones y estilo de PoC que ya usamos.

## Cómo usar

1. Copia la plantilla del tipo de vulnerabilidad correspondiente.
2. Reemplaza todos los placeholders `{{ ... }}` con los datos reales del hallazgo.
3. Ajusta el **vector y score CVSS** y la **severidad** (criticidad por contexto de
   negocio puede diferir del rango CVSS, como en los reportes).
4. En **Detalles**, transcribe los requests/responses HTTP crudos y referencia las
   figuras de evidencia (`Figura N`). Usa "Caso 1 / Caso 2" cuando haya varios vectores.
5. Borra los comentarios `<!-- -->` antes de entregar.

> ¿Tipo de vulnerabilidad no listado? Parte de [`_PLANTILLA_BASE.md`](_PLANTILLA_BASE.md).

## Plantillas base

- 📄 **[Reporte completo](_PLANTILLA_REPORTE_COMPLETO.md)** — informe end-to-end (ejecutivo +
  convenciones + metodología + alcance + tabla de vulnerabilidades + detalles técnicos +
  apéndices). En la sección 8 se pegan los hallazgos usando las plantillas por tipo.
- 🧩 **[Plantilla base de hallazgo](_PLANTILLA_BASE.md)** — estructura de un único hallazgo/PoC
  para tipos no listados.

### Flujo de trabajo sugerido
1. Parte del **reporte completo** y rellena las secciones ejecutivas (1–7).
2. Por cada hallazgo, copia la **plantilla por tipo** correspondiente y pégala en la sección 8.
3. Completa la **tabla de vulnerabilidades** (sección 6) y los apéndices.

## Estructura común de un hallazgo

`Título (CWE-XXX) - Severidad` → CVSS Vector → CVSS Score → Descripción (genérica del tipo)
→ Componentes Afectados (URLs + parámetros) → **Detalles (PoC)** → Impacto → Remediación →
Referencias.

## Índice de plantillas

### 01 · Control de acceso
- [IDOR (CWE-639)](01-control-de-acceso/idor.md)
- [Broken Function Level Authorization / BFLA (CWE-285)](01-control-de-acceso/bfla-broken-function-level-authorization.md)
- [Escalada de privilegios por falta de validación servidor (CWE-602)](01-control-de-acceso/escalada-privilegios-validacion-servidor.md)
- [Mass Assignment / modificación de datos inmutables (CWE-471)](01-control-de-acceso/mass-assignment-datos-inmutables.md)
- [Business Logic Flaw / validación de entrada (CWE-1284)](01-control-de-acceso/business-logic-flaw.md)

### 02 · Autenticación
- [Bypass de MFA (CWE-287)](02-autenticacion/bypass-mfa.md)
- [Fuerza bruta / falta de rate-limiting (CWE-307)](02-autenticacion/fuerza-bruta-rate-limiting.md)
- [Política de contraseñas débil (CWE-521)](02-autenticacion/politica-contrasenas-debil.md)
- [CAPTCHA inseguro (CWE-804)](02-autenticacion/captcha-inseguro.md)
- [Enumeración de usuarios (CWE-204)](02-autenticacion/enumeracion-usuarios.md)
- [Credenciales desprotegidas → Account Takeover (CWE-522)](02-autenticacion/credenciales-desprotegidas-ato.md)

### 03 · Inyección y lado cliente
- [Cross-Site Scripting / XSS (CWE-79)](03-inyeccion-cliente/xss.md)
- [Content Spoofing / HTML Injection (CWE-345)](03-inyeccion-cliente/content-spoofing-html-injection.md)
- [CSV / Formula Injection (CWE-1236)](03-inyeccion-cliente/csv-formula-injection.md)

### 04 · Exposición de datos
- [Exposición de información sensible (CWE-200)](04-exposicion-datos/exposicion-informacion-sensible.md)
- [Datos sensibles en la URL / GET (CWE-598)](04-exposicion-datos/datos-sensibles-en-url.md)
- [Credenciales vía Pre-Signed URLs (CWE-522)](04-exposicion-datos/presigned-urls-credenciales.md)

### 05 · Configuración
- [Email Spoofing por DMARC (CWE-345)](05-configuracion/email-spoofing-dmarc.md)
- [CORS mal configurado (CWE-942)](05-configuracion/cors-misconfiguration.md)
- [Cabeceras de seguridad faltantes (CWE-693)](05-configuracion/cabeceras-seguridad-faltantes.md)
- [CSP mal configurada (CWE-693)](05-configuracion/csp-misconfiguration.md)
- [Componentes con vulnerabilidades conocidas (CWE-937)](05-configuracion/componentes-vulnerables-conocidos.md)
- [Servicios remotos/administrativos expuestos (CAPEC-555)](05-configuracion/servicios-expuestos-rdp.md)

### 06 · Disponibilidad y registro
- [Consumo no controlado de recursos / DoS (CWE-400)](06-disponibilidad-logging/consumo-recursos-dos.md)
- [Supresión de auditoría / logging insuficiente (CWE-778)](06-disponibilidad-logging/supresion-auditoria-logging.md)

## Convenciones de severidad (referencia)

| Severidad | CVSS | Color |
|---|---|---|
| Crítica | 9.0 – 10.0 | 🔴 |
| Alta | 7.0 – 8.9 | 🟠 |
| Media | 4.0 – 6.9 | 🟡 |
| Baja | 0.1 – 3.9 | 🟢 |
| Informativa | 0.0 | ⚪ |

> Nota: en los reportes, la criticidad final puede ajustarse por impacto de negocio aunque
> el score CVSS sugiera otro rango. Documenta el criterio cuando difiera.
