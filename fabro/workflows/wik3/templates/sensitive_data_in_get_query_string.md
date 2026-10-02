### Descripción

Se pudo observar que la aplicación utiliza el método HTTP GET para procesar solicitudes que incluyen información sensible en la cadena de consulta. Las URL’s pueden registrarse en varios lugares, como el navegador del usuario, el servidor web y cualquier servidor proxy de avance o retroceso entre los dos puntos finales. Las URL también pueden mostrarse en pantalla, marcarse o incluso enviarse por correo electrónico por parte de los usuarios. De esta forma, el uso de tokens de sesión en la URL aumenta el riesgo de que sean capturados por un atacante.

### Componentes Afectados

- https://www.cliente_url.com/modulo1/afectado1?id=1&time=now
    - Parámetro Afectado:  id
- https://www.cliente_url.com/modulo2/afectado2?cat=1&dir=/
    - Parámetro Afectado:  dir

### Detalles

El equipo de AppSec de Hackmetrix identificó la vulnerabilidad **Use of GET Request Method With Sensitive Query Strings** la cual se presenta debido a que la aplicación envía el AuthToken por medio del método HTTP GET. A continuación, se puede observar la URL en cuestión, mediante la siguiente solicitud:

*HTTP Response:*

```
[ACA VA LA REQUEST]
```

*HTTP Response:*

```
[ACA VA LA RESPONSE]
```

### Impacto

La URL podría guardarse en el historial del navegador, pasarse a través de Referers a otros sitios web, almacenarse en registros web o registrarse de otro modo en otras fuentes. Debido a que la URL contiene información confidencial, los atacantes podrían llegar a obtener esta URL y utilizarla para [REDACTAR].

### Remediación

Se recomienda que las aplicaciones utilicen un mecanismo alternativo para transmitir tokens de sesión, como las cookies HTTP o los campos ocultos en los formularios que se envían mediante el método POST.

### Referencias

- CWE-598 – https://cwe.mitre.org/data/definitions/598.html
- Session token in URL – https://portswigger.net/kb/issues/00500700_session-token-in-url

