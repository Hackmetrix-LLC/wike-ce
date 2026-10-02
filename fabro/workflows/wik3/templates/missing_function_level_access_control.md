### Descripción

Se conoce como autorización al proceso por el cual se determina si un usuario posee acceso a un recurso y/o funcionalidad determinada, en función de sus privilegios y permisos, o cualquier otra especificación de control de acceso que pudiese aplicarse sobre el recurso. Cuando estas verificaciones de control no se aplican, o estan implementadas de forma incorrecta, los usuarios pueden acceder a datos o realizar distintas acciones que no deberian. Esto puede llevar a una amplia gama de problemas, incluyendo entre ellos: exposición de información, denegación de servicio y ejecución de código arbitrario.

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

Se recomienda que la aplicación tenga un módulo de autorización consistente. Con frecuencia, dicha protección es proporcionada por uno o más componentes externos al código de la aplicación. Los mecanismos de aplicación deben denegar todos los accesos de forma predeterminada, requiriendo concesiones explícitas a roles específicos para acceder a cada función.

### Referencias

- OWASP Proactive Controls: https://www.owasp.org/index.php/OWASP_Proactive_Controls
- Access Control Cheat Sheet: https://www.owasp.org/index.php/Access_Control_Cheat_Sheet
- CWE-862: Missing Authorization: https://cwe.mitre.org/data/definitions/862.html
- OWASP Access Control: https://www.owasp.org/index.php/Category:Access_Control

