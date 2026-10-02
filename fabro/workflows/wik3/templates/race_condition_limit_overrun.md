### Descripción

Las condiciones de carrera son un tipo común de vulnerabilidad estrechamente relacionado con los fallos en la lógica de negocio. Ocurren cuando los sitios web procesan peticiones concurrentemente sin las protecciones adecuadas. Esto puede llevar a que varios hilos distintos interactúen con los mismos datos al mismo tiempo, dando lugar a una "colisión" que provoca un comportamiento no intencionado en la aplicación.

### Componentes Afectados

- https://www.cliente_url.com/modulo1/afectado1?id=1&time=now
    - Parámetro Afectado:  id

### Detalles

[REDACTAR]

### Impacto

{{ Agregar conclusión de impacto dependiendo de la lógica del negocio del cliente }}

### Remediación

**Bloqueos o locks**

La clave para prevenir esta vulnerabilidad es sincronizar o controlar el orden de las operaciones en las funciones y acciones vulnerables. Como vimos, esto puede lograrse mediante bloqueos o *locks*.

La mayoría de los lenguajes de programación tienen esta función incorporada para los datos. Por ejemplo, Python tiene *threading.Lock,* Go tiene *sync.Mutex*. De todas formas, si el lenguaje tiene capacidades asíncronas o de multihilo incorporadas, es muy probable que tenga un mecanismo de bloqueo disponible.

**Políticas de seguridad ACID**

Por otro lado, te recomendamos asegurar las transacciones de la base de datos implementando políticas y normativas de seguridad como ACID (Atomicity, Consistency, Isolation and Durability).

En bases de datos, las ACID son las características de los parámetros que permiten clasificar las transacciones de los sistemas de gestión de bases de datos.

- Atomicity: una transacción se realiza correctamente o se revierte.
- Consistency: al finalizar una transacción, la base de datos es estructuralmente consistente (sin errores o datos no válidos). De lo contrario, vuelve al estado consistente anterior.
- Isolation: las transacciones no interfieren entre sí.
- Durability: El resultado de aplicar una transacción es permanente, incluso en presencia de fallas.

**Implementación de un Token CSRF**

Un valor único, secreto e impredecible que genera la aplicación del lado del servidor y se transmite al cliente de tal manera que se incluye en la siguiente solicitud realizada por el cliente. Cuando se realiza la siguiente solicitud, la aplicación del lado del servidor la valida o la rechaza dependiendo de si incluye el token esperado o no. 

### Referencias

- Hackmetrix Reference Race Condition: https://blog.hackmetrix.com/race-condition/
- CWE-367: https://cwe.mitre.org/data/definitions/367.html
- CWE-362: https://cwe.mitre.org/data/definitions/362.html
- PortSwigger Reference: https://portswigger.net/web-security/race-conditions

