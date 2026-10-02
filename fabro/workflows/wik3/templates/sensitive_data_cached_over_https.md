### Descripción

A menos que se indique lo contrario, los navegadores pueden almacenar una copia local en caché del contenido recibido de los servidores web. Algunos navegadores, incluido Internet Explorer, almacenan contenido de caché a través de HTTPS. Si la información sensible de las respuestas de la aplicación se almacena en la memoria caché local, otros usuarios que tengan acceso al mismo dispositivo podrán recuperarla en el futuro.

Los navegadores a menudo almacenan información en caché del lado del cliente. Esto le permite a otros usuarios la exfiltración de datos personales o sensibles (como pueden ser contraseñas o números de tarjetas de crédito). Las ubicaciones con mayor riesgo a que esto suceda incluyen terminales públicas, como pueden ser las de bibliotecas y cafés de Internet.

### Componentes Afectados

- https://www.cliente_url.com/modulo1/afectado1?id=1&time=now
    - Parámetro Afectado:  id
- https://www.cliente_url.com/modulo2/afectado2?cat=1&dir=/
    - Parámetro Afectado:  dir

### Detalles

Como se puede ver en la siguiente solicitud, el servidor no devuelve los encabezados:

```
Cache-control: no-store
Pragma: no-cache
```

Por lo que el navegador se encargara de almacenar el contenido de la respuesta dentro de la cache local.

*HTTP Request:*

```
 § REQUEST EXAMPLE §
```

*HTTP Response:*

```
 § RESPONSE EXAMPLE §
```

### Impacto

Un atacante que tenga acceso a la memoria cache del navegador cuya víctima sea un usuario del aplicativo, podría acceder a las respuestas de las solicitudes que estén almacenadas en la memoria.

### Remediación

Las aplicaciones deben devolver directivas de almacenamiento en caché que indiquen a los navegadores que no almacenen copias locales de datos confidenciales. Esto se puede lograr configurando el servidor web para evitar el almacenamiento en caché de rutas relevantes dentro de la raíz web. Alternativamente, la mayoría de las plataformas de desarrollo web permiten controlar las directivas de almacenamiento en caché del servidor desde scripts individuales. Lo ideal es que el servidor web devuelva los siguientes encabezados HTTP en todas las respuestas que contengan contenido sensible:

```
Cache-control: no-store
Pragma: no-cachep.
```

### Referencias

- Cache-Control: https://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.9
- CWE-524: Information Exposure Through Caching: https://cwe.mitre.org/data/definitions/524.html
- CWE-525: Information Exposure Through Browser Caching: https://cwe.mitre.org/data/definitions/525.html
