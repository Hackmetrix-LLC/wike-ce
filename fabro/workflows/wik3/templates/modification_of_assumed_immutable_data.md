### Descripción

Esto ocurre cuando un input particular, suficientemente crítico para el correcto funcionamiento de la aplicación, es modificable gracias a que las protecciones utilizadas son insuficientes. Ciertos recursos son a menudo asumidos como inmutables cuando no lo son, como campos de formularios en aplicaciones web. Esto puede derivar en vulnerabilidades de múltiples criticidades, pudiendo escalar fácilmente en un Broken Access Control (CWE-284).

### Componentes Afectados

- https://www.cliente_url.com/modulo1/afectado1?id=1&time=now
    - Parámetro Afectado:  id
- https://www.cliente_url.com/modulo2/afectado2?cat=1&dir=/
    - Parámetro Afectado:  dir

### Detalles

El equipo de Hackmetrix encontró la vulnerabilidad de **Modification of Assumed-Immutable Data**, donde puede ser modificado un campo que está bloqueado desde el **frontend**. A continuación, mostramos la prueba de concepto realizada para comprobar esta vulnerabilidad.

**Paso 1:** [REDACTAR]

### Impacto

Mediante esta vulnerabilidad, un usuario podría llegar a editar campos que no deberían ser editables, y realizar consultas a nombre de otra persona que pueden poner en riesgo los datos confidenciales de la empresa.

### Remediación

El control solo es efectivo si se aplica en el lado del servidor, donde un atacante es incapaz de modificar la verificación del mismo.

Para mitigar este tipo de vulnerabilidades, Hackmetrix recomienda:

- Denegar el acceso a la funcionalidad de forma predeterminada.
- Utilizar listas de control de acceso y mecanismos de autenticación basados en roles.
- Evitar “solo ocultar” ciertas funciones peligrosas.

### Referencias

- CWE-471: https://cwe.mitre.org/data/definitions/471.html
- Hackmetrix Blog: https://blog.hackmetrix.com/broken-access-control/
- Broken Access Control: https://www.owasp.org/index.php/Top_10-2017_A5-Broken_Access_Control

