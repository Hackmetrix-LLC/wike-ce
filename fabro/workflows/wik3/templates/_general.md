### Descripción

La vulnerabilidad **{{ NOMBRE_VULNERABILIDAD }}** se presenta debido a que {{ DESCRIBIR LA CAUSA RAÍZ Y EL COMPORTAMIENTO INSEGURO DE LA APLICACIÓN O INFRAESTRUCTURA }}. [REDACTAR] una explicación general del tipo de debilidad, cómo se origina y por qué representa un riesgo de seguridad.

{{ AGREGAR CONTEXTO ADICIONAL SOBRE EL FUNCIONAMIENTO ESPERADO VS. EL COMPORTAMIENTO VULNERABLE, SI APLICA }}

### Componentes Afectados

- https://www.cliente_url.com/modulo1/afectado1?id=1&time=now
    - Parámetro Afectado: {{ PARAMETRO }}
- {{ AGREGAR COMPONENTES, ENDPOINTS, RECURSOS O ACTIVOS AFECTADOS }}

### Detalles

El equipo de Hackmetrix identificó la vulnerabilidad **{{ NOMBRE_VULNERABILIDAD }}**, la cual se presenta debido a que {{ DETALLAR EL HALLAZGO ESPECÍFICO }}.

A continuación, se detalla paso a paso cómo fue posible identificar y/o explotar dicha vulnerabilidad:

**Paso 1:** [REDACTAR] {{ DESCRIBIR LA ACCIÓN REALIZADA }}

*HTTP Request:*

```
§ REQUEST EXAMPLE §
```

*HTTP Response:*

```
§ RESPONSE EXAMPLE §
```

**Paso 2:** [REDACTAR] {{ DESCRIBIR LA EVIDENCIA / PRUEBA DE CONCEPTO }}

!§ INSERTAR IMAGEN (Descripción de la evidencia) §!

### Impacto

{{ Agregar conclusión de impacto dependiendo de la lógica del negocio del cliente }}

Mediante la explotación de esta vulnerabilidad, un atacante podría [REDACTAR] {{ DESCRIBIR EL IMPACTO SOBRE CONFIDENCIALIDAD, INTEGRIDAD Y/O DISPONIBILIDAD }}.

### Remediación

Hackmetrix recomienda {{ DESCRIBIR LA MEDIDA DE MITIGACIÓN PRINCIPAL }}. [REDACTAR]

Adicionalmente, se recomienda:

- {{ RECOMENDACIÓN 1 }}
- {{ RECOMENDACIÓN 2 }}
- {{ RECOMENDACIÓN 3 }}

### Referencias

- CWE-{{ NUMERO }}: https://cwe.mitre.org/data/definitions/{{ NUMERO }}.html
- {{ REFERENCIA OWASP O FUENTE ADICIONAL }}: {{ URL }}
