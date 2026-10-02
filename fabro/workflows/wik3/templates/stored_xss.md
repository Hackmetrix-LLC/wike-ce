### Descripción

Las Stored Cross-Site Scripting se producen cuando el servidor devuelve los datos proporcionados a una aplicación web por un usuario como parte de la respuesta sin estar debidamente codificados.

Los ataques de Stored Cross-Site Scripting ocurren cuando los datos ingresan a la aplicación web a través de una fuente no confiable, la mayoría de las veces una solicitud web, y luego la entrada se incluye y se refleja en el contenido dinámico que se genera sin validarse para contenido malicioso. Un atacante puede usar XSS para enviar un script malicioso a un usuario desprevenido. El navegador del usuario final no tiene forma de saber que el script no debe ser confiable y ejecutara el script. Debido a que cree que el script provino de una fuente confiable, el script malicioso puede acceder a cualquier cookie, tokens de sesión u otra información confidencial retenida por el navegador y utilizada con ese sitio. Estos scripts pueden incluso reescribir el contenido de la página HTML.

Un usuario malintencionado podría aprovechar esta vulnerabilidad para crear un enlace al dominio de la aplicación que contiene un payload útil de ataque. Este enlace podría publicarse en un foro público o enviarse como parte de un correo electrónico de suplantación de identidad (phishing) a un objetivo confiado. El alcance de los ataques que pueden lanzarse de esta manera es extremadamente amplio, desde el secuestro de la sesión hasta atacar la red interna y comprometer la estación de trabajo de la víctima.

### Componentes Afectados

- https://www.cliente_url.com/modulo1/afectado1?id=1&time=now
    - Parámetro Afectado:  id
- https://www.cliente_url.com/modulo2/afectado2?cat=1&dir=/
    - Parámetro Afectado:  dir

### Detalles

El equipo ofensivo de Hackmetrix halló la vulnerabilidad Cross-Site Scripting en…

A continuación, se detallan los pasos seguidos para explotar esta vulnerabilidad:

[REDACTAR]

### Impacto

Un usuario malintencionado puede …

[REDACTAR]

### Remediación

La prevención confiable de las vulnerabilidades de los Cross-Site Scripting requiere la codificación de todos los caracteres especiales HTML en datos potencialmente maliciosos. Esto generalmente se hace directamente antes de que se muestren mediante aplicaciones web (o scripts del lado del cliente), y muchos lenguajes de programación tienen funciones o bibliotecas integradas que proporcionan esta codificación (en este contexto, también llamada entrecomillado o escape). Tenga en cuenta que la codificación adecuada debe aplicarse dependiendo de dónde se encuentren los datos proporcionados por el usuario. Por ejemplo, los datos que aparecen dentro de un bloque HTML deben estar codificados en HTML, mientras que los datos que aparecen dentro de un bloque JavaScript deben estar codificados en JavaScript.

Por otra parte, la Política de Seguridad de Contenido (CSP) es una capa adicional de seguridad que ayuda a detectar y mitigar ciertos tipos de ataques, incluidos los Cross-Site Scripting (XSS) y los ataques de inyección de datos. Para habilitar CSP, debe configurar su servidor web para que devuelva el encabezado HTTP de la Política de seguridad de contenido, puede consultar con el link de referencia para poder implementarlo.

Por último, pero no menos importante, HttpOnly es un indicador adicional que se puede incluir en un encabezado de respuesta HTTP Set-Cookie. El uso del indicador HttpOnly al generar una cookie ayuda a mitigar el riesgo de que el script del lado del cliente acceda a la cookie protegida.

### Referencias

- Hackmetrix Blog: https://blog.hackmetrix.com/xss-cross-site-scripting/
- XSS Prevention Cheat Sheet: https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet_Prevention_Cheat_Sheet)
- CWE-79: Cross-site Scripting: https://cwe.mitre.org/data/definitions/79.html
- OWASP cross-site scripting (XSS): https://www.owasp.org/index.php/XSS
- How to setup CSP in 3 steps: https://blog.sucuri.net/2023/04/how-to-set-up-a-content-security-policy-csp-in-3-steps.html
- Implementing Content Security Policy: https://hacks.mozilla.org/2016/02/implementing-content-security-policy/

