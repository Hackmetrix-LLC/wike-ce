### Descripción

Muchas aplicaciones web utilizan la redirección de URL para dirigir a un usuario a otro sitio o página dentro del mismo sitio. Algunos sitios web permiten manipular el valor de la URL. Un atacante podría abusar de esta funcionalidad para engañar a los usuarios a que ingresen información confidencial en un sitio web malicioso, mientras que el usuario cree que navega dentro de un sitio web confiable. Esta vulnerabilidad se aplica a todas las aplicaciones que utilizan redirecciones via URL.

### Componentes Afectados

- https://www.cliente_url.com/modulo1/afectado1?id=1&time=now
    - Parámetro Afectado:  id
- https://www.cliente_url.com/modulo2/afectado2?cat=1&dir=/
    - Parámetro Afectado:  dir

### Detalles

El equipo de AppSec encontró una vulnerabilidad de riesgo medio, denominada **Open Redirect**. Por medio de dicha vulnerabilidad, fue posible realizar una redirección desde el sitio vulnerable **§SITIO VULNERABLE§** hacia un sitio malicioso controlado por Hackmetrix.

*HTTP Request:*

```
§REQUEST EXAMPLE§
```

*HTTP Response:*

```
§RESPONSE EXAMPLE§
```

### Impacto

{{ Agregar conclusión de impacto dependiendo de la lógica del negocio del cliente }}

### Remediación

Para evitar este tipo de problemas, evite usar redireccionamientos por completo, si es posible. Si las redirecciones son necesarias, evite las redirecciones basadas en la entrada del usuario. Si la entrada del usuario es necesaria para los redireccionamientos, utilice una lista blanca de direcciones permitidas y a su vez, realice una validación al momento de recibir la entrada de una URL no permitida por parte del usuario.

### Referencias

- CWE-601: URL Redirection to Untrusted Site: https://cwe.mitre.org/data/definitions/601.html
- Open redirection: https://portswigger.net/kb/issues/00500100_open-redirection-reflected
