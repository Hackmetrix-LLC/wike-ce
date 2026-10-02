### Descripción

La recuperación de un registro de usuario se produce en el sistema en función de algún valor clave que está bajo el control de dicho usuario. Esta clave, normalmente, identificaría al registro relacionado con el usuario almacenado en el sistema y se utilizaría para buscar ese registro y presentarlo. En algunas ocasiones, el proceso de autorización no verifica correctamente el acceso a datos asociados a un usuario. Es por esto, que no asegura que quien realiza la operación tenga los derechos suficientes para garantizar el acceso a la información solicitada, omitiendo de esta forma a cualquier otra verificación de autorización presente en el sistema.

La clave bajo el control del usuario puede ser: un campo oculto en el formulario HTML, un parámetro de URL o una variable de cookie sin cifrar. En cada uno de estos casos, será posible manipular el valor de la clave. Por ejemplo: los atacantes pueden observar en lugares donde se recuperan datos específicos del usuario (como pueden ser las pantallas de búsqueda) y determinar si la clave del elemento que se está buscando es controlable de manera externa.

Se puede observar esta debilidad en sistemas que utilizan identificadores de sesión secuenciales, o fáciles de adivinar, los cuales permiten a un usuario cambiar fácilmente su sesión a la de otro usuario y así leer/modificar sus datos.

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

Los desarrolladores deben usar referencias indirectas ya que, el mapeo directo puede ser adivinado fácilmente por los atacantes. Se debe evitar la exposición de objetos privados a los usuarios como: nombres de archivos, URLs internas/externas, y keys de bases de datos.

Si un objeto debe ser usado directamente, el equipo de desarrollo debe asegurar a través de métodos de validación que el usuario este autorizado para ver aquello a lo que intenta acceder. En los casos de los directorios transversales, se debe determinar qué archivos son accesibles por un usuario y garantizarle los privilegios a los mismos.

### Referencias

- Hackmetrix Reference IDOR: https://blog.hackmetrix.com/insecure-direct-object-reference/
- Prevention Cheat Sheet: https://www.owasp.org/index.php/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet
- Testing for IDOR: https://www.owasp.org/index.php/Testing_for_Insecure_Direct_Object_References_(OTG-AUTHZ-004))
- How to find IDOR: https://www.bugcrowd.com/how-to-find-idor-insecure-direct-object-reference-vulnerabilities-for-large-bounty-rewards/

