### Descripción

La vulnerabilidad Content Spoofing hace referencia a la modificación del contenido original de recursos web o cadenas de texto, a través de las funciones del aplicativo. Esta vulnerabilidad permite modificar correos electrónicos que se emiten hacia el usuario, el cual es receptor de emails generados por el servidor de correos electrónicos. En consecuencia se pueden enviar emails al usuario final, con mensajes modificados. Abusar de esta funcionalidad podría inducir a un usuario del aplicativo a dirigirse a sitios web externos, por lo tanto, es posible emitir distribuir phishing, generar SPAM y degradar la confianza e imagen del aplicativo e incluso comprometer la disponibilidad del servicio de emails.

### Componentes Afectados

- https://www.cliente_url.com/modulo1/afectado1?id=1&time=now
    - Parámetro Afectado:  id
- https://www.cliente_url.com/modulo2/afectado2?cat=1&dir=/
    - Parámetro Afectado:  dir

### Detalles

[REDACTAR]

### Impacto

{{ Agregar conclusión de impacto dependiendo de la lógica del negocio del cliente }}

### Remediación

Para mitigar este tipo de vulnerabilidad, el equipo de Hackmetrix recomienda realizar una validación de la casilla de correo remitente. Es decir, permitir solo ingresar la dirección de correo del usuario que se encuentra logueado en la aplicación. De esta manera se podría evitar el envió de correos modificados a diferentes cuentas de emails por parte de un atacante utilizando correos falsos.

### References

- CAPEC-148: Content Spoofing: https://capec.mitre.org/data/definitions/148.html
- CWE-345: https://cwe.mitre.org/data/definitions/345.html

