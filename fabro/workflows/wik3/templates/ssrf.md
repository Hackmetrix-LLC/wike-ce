### Descripción

La falsificación de solicitudes del lado del servidor (también conocida como SSRF) es una vulnerabilidad de seguridad web que permite a un atacante inducir a la aplicación del lado del servidor a realizar solicitudes HTTP a un dominio arbitrario elegido por el atacante.

En un ataque SSRF típico, el atacante puede hacer que el servidor establezca una conexión con servicios solo internos dentro de la infraestructura de la organización. En otros casos, pueden obligar al servidor a conectarse a sistemas externos arbitrarios, lo que podría filtrar datos confidenciales, como credenciales de autorización.

Un ataque SSRF exitoso a menudo puede resultar en acciones no autorizadas o acceso a datos dentro de la organización, ya sea en la propia aplicación vulnerable o en otros sistemas de back-end con los que la aplicación puede comunicarse. En algunas situaciones, la vulnerabilidad SSRF podría permitir que un atacante realice una ejecución de comando arbitraria.

Una explotación de SSRF que provoca conexiones a sistemas externos de terceros puede dar lugar a ataques posteriores maliciosos que parecen originarse en la organización que aloja la aplicación vulnerable.

### Componentes Afectados

- https://www.cliente_url.com/modulo1/afectado1?id=1&time=now
    - Parámetro Afectado:  id
- https://www.cliente_url.com/modulo2/afectado2?cat=1&dir=/
    - Parámetro Afectado:  dir

### Detalles

El equipo de Hackmetrix detectó la vulnerabilidad Server-Side Request Forgery (SSRF) la cual se presenta debido a que se identificó un endpoint de la aplicación que permite realizar solicitudes HTTP a servicios externos o internos. Mediante la misma, es posible [REDACTAR]

**Paso 1:** Hackmetrix inició sesión con el usuario [REDACTAR]

### Impacto

[REDACTAR]

### Remediación

Hackmetrix recomienda seguir los siguientes puntos para remediar la vulnerabilidad SSRF:

- Validación de entrada: Implementar una validación adecuada de todas las entradas del usuario que puedan ser utilizadas para construir solicitudes HTTP. Asegúrate de que solo se permitan las URL válidas y se rechacen las solicitudes a recursos internos o no autorizados.
- Filtro de direcciones IP: Configurar un filtro de direcciones IP para restringir las solicitudes a recursos internos. Esto puede ayudar a prevenir ataques desde direcciones IP maliciosas o no autorizadas.
- Lista blanca de URLs: Considerar utilizar una lista blanca de URL para permitir únicamente las solicitudes a recursos confiables y bloquear todas las demás. Esto ayuda a prevenir la explotación de SSRF al restringir las solicitudes solo a dominios y recursos específicos que sean necesarios para el funcionamiento de tu aplicación.

### Referencias

- Server-side request forgery (SSRF): https://portswigger.net/web-security/ssrf
- CWE-918: https://cwe.mitre.org/data/definitions/918.html

