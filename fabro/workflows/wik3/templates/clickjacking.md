### Descripción

El “clickjacking” es un término que abarca múltiples técnicas las cuales pueden utilizarse para inducir al usuario a que haga click involuntariamente en un elemento de la web que ha sido oscurecido u oculto, dando lugar a una transacción no deseada.

Se utiliza una combinación de hojas de estilo, iframes y elementos de formulario para hacer creer al usuario que está escribiendo en una página inocua, cuando en realidad lo hace en un marco invisible controlado por el adversario. Un ataque de Clickjacking exitoso podría eludir aquellas protecciones de CSRF que confirman las transacciones con el usuario.

### Componentes Afectados

- https://www.cliente_url.com/modulo1/afectado1?id=1&time=now
    - Parámetro Afectado:  id
- https://www.cliente_url.com/modulo2/afectado2?cat=1&dir=/
    - Parámetro Afectado:  dir

### Detalles

El equipo de AppSec detectó que la aplicación no posee las protecciones necesarias para prevenir ataques de Clickjacking.

Para evidenciar esto, se envío la siguiente solicitud HTTP:

*HTTP Request:*

```
REQUEST EXAMPLE
```

*HTTP Response:*

```
RESPONSE EXAMPLE
```

ERASEME

### Impacto

Un atacante externo podría registrar dominios convincentes para inducir a los usuarios de la aplicación a introducir sus credenciales y poder hacer uso del aplicativo embebido, sin ningún tipo de restricción.

### Remediación

Hay tres mecanismos principales que se pueden utilizar para defenderse contra estos ataques:

- Evitar que el navegador cargue la página en un frame utilizando las cabeceras HTTP “X-Frame-Options” o “Content Security Policy (frame-ancestors)”.
- Evitar que se incluyan cookies de sesión cuando la página se carga en un frame utilizando el atributo de cookies “SameSite”.
- Implementar código JavaScript en la página para intentar evitar que se cargue en un frame (conocido como “frame-buster”).Se debe tener cuenta que estos mecanismos son independientes entre sí, y que siempre que sea posible deberán implementarse uno o más, con el fin de proporcionar una mayor defensa a la aplicación.

### Referencias

- Improper Restriction of Rendered UI Layers or Frames https://cwe.mitre.org/data/definitions/1021.html
- Clickjacking Defense Cheat Sheet https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html
- Clickjacking https://owasp.org/www-community/attacks/Clickjacking
