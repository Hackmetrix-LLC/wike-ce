### Descripción

La vulnerabilidad de **Unverified Password Change** se presenta debido a que al configurar una nueva contraseña para un usuario, el producto no requiere el conocimiento de la contraseña original ni el uso de otra forma de autenticación.

### Componentes Afectados

- https://www.cliente_url.com/modulo1/afectado1?id=1&time=now
    - Parámetro Afectado:  id
- https://www.cliente_url.com/modulo2/afectado2?cat=1&dir=/
    - Parámetro Afectado:  dir

### Detalles

Hackmetrix ha detectado que la política de contraseñas implementada no es robusta, por lo que fue posible configurar una nueva contraseña sin utilizar la contraseña actual del usuario.

A continuación se encuentra de manera detallada, como fue posible explotar dicha vulnerabilidad.

**Paso 1:** Hackmetrix procedió a iniciar sesión con el usuario **§[USER]§**, como puede verse a continuación:

*HTTP Request:*

```
HTTP REQUEST EXAMPLE
```

*HTTP Response:*

```
HTTP RESPONSE EXAMPLE
```

**Paso 2:** Luego de iniciar sesión, el equipo de AppSec identificó que no se solicitaba la clave actual del usuario para cambiar la clave, como puede observarse a continuación:

!PIC DEL DASHBOARD PARA CAMBIAR CLAVE!

**Paso 3:** Luego de identificar mediante la UI que no se solicitaba la contraseña actual, Hackmetrix procedió cambiar la contraseña del usuario **§[USER]§** mediante la siguiente solicitud HTTP:

*HTTP Request:*

```
HTTP REQUEST EXAMPLE
```

A lo cual se obtuvo como respuesta:

*HTTP Response:*

```
HTTP RESPONSE EXAMPLE
```

Como se puede observar en la solicitud anterior, fue posible cambiar la clave del usuario, sin utilizar la clave actual del mismo.

ERASEME

### Impacto

A partir de esta situación, un atacante con acceso a la cuenta de la víctima podría modificar su contraseña sin necesidad de tener conocimiento de la contraseña inicial de la víctima.

### Remediación

Hackmetrix recomienda solicitar la contraseña actual del usuario, antes de permitir el cambio de la misma.

### Referencias

- https://cwe.mitre.org/data/definitions/620.html
