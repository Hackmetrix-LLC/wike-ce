### Descripción

La vulnerabilidad **Lack of Server-Side Validations**, la cual se produce debido a que existen controles en el frontend que luego no son aplicados en el backend.

Cuando el servidor se basa en mecanismos de protección ubicados en el lado del cliente, un atacante puede modificar el comportamiento del lado del cliente para evitar los mecanismos de protección, lo que da como resultado interacciones potencialmente inesperadas entre el cliente y el servidor. Las consecuencias variarán, dependiendo de lo que los mecanismos estén tratando de proteger.

### Componentes Afectados

- https://www.cliente_url.com/modulo1/afectado1?id=1&time=now
    - Parámetro Afectado:  id
- https://www.cliente_url.com/modulo2/afectado2?cat=1&dir=/
    - Parámetro Afectado:  dir

### Detalles

El equipo de AppSec detectó la vulnerabilidad **Lack of Server-Side Validations**, la cual se produce debido a que existen controles en el frontend que luego no son aplicados en el backend.

A continuación se encuentra de manera detallada, como fue posible explotar dicha vulnerabilidad:

[REDACTAR]

### Impacto

[REDACTAR]

### Remediación

Hackmetrix recomienda implementar los controles del lado del servidor.

### Referencias

- CWE-602: https://cwe.mitre.org/data/definitions/602.html

