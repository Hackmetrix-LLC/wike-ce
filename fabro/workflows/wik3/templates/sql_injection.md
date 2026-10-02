### Descripción

El lenguaje de consulta estructurado (SQL) es un lenguaje de computadora diseñado para la recuperación y administración de datos en bases de datos relacionales. Cuando se usa una entrada suministrada por el usuario dentro de las sentencias de SQL sin aplicar primero la validación apropiada, un adversario puede crear una entrada maliciosa que será interpretada por el motor SQL de la base de datos.

Al diseñar cuidadosamente una carga útil, un adversario podría modificar el significado de la declaración SQL original (por ejemplo, seleccionando más campos o campos diferentes de los previstos) o ejecutar varias declaraciones SQL en lugar de solo la que la aplicación fue diseñada originalmente para invocar.

### Componentes Afectados

- https://www.cliente_url.com/modulo1/afectado1?id=1&time=now
    - Parámetro Afectado:  id
- https://www.cliente_url.com/modulo2/afectado2?cat=1&dir=/
    - Parámetro Afectado:  dir

### Detalles

El equipo de seguridad de Hackmetrix encontró que el parámetro *§VULNERABLE PARAMETER§* es vulnerable a un ataque de **SQL Injection**. Mediante la explotación de esta vulnerabilidad, fue posible ejecutar consultas arbitrarias en la base de datos **§DATABASE NAME§**, pudiendo extraer información sensible como por ejemplo: **§EXAMPLES§**.

A continuación se detallaran los pasos de como el equipo de AppSec logro explotar satisfactoriamente dicha vulnerabilidad.

### Impacto

{{ Agregar conclusión de impacto dependiendo de la lógica del negocio del cliente }}

### Remediación

El primer paso hacia la protección contra la inyección de SQL es el uso de un filtro de validación de entrada de la lista blanca. Por ejemplo, si se espera que un campo contenga solo dígitos, se debe descartar cualquier entrada que contenga cualquier otra cosa (puede valer la pena alertar a los administradores de que se detectó una solicitud sospechosa). O si un campo de código postal solo debe contener caracteres alfanuméricos, la entrada que contenga cualquier otro carácter debe ser descartada. La lista blanca es la primera línea de defensa y no es específica de la inyección de SQL, debe utilizarse para validar los datos proporcionados por el usuario antes de que la aplicación los utilice.

En el nivel de SQL, la aplicación no debe usar concatenación de cadenas para construir las sentencias de SQL que requiere. Un enfoque alternativo (y seguro) es utilizar consultas SQL parametrizadas. Esta técnica impone la separación entre la estructura de la declaración SQL y los datos que utiliza. Cada declaración SQL se define dejando marcadores de posición para los datos que se suministrarán en tiempo de ejecución. Por ejemplo (en pseudo código):

```
query = 'SELECT * FROM users WHERE username = @Login'
```

En el tiempo de ejecución, el contenido se especifica para cada uno de los marcadores de posición:

```
query.parameters.add ('@Login', http_params ['username'])
```

La estructura de la declaración SQL se define en el primer paso, mientras que los datos se proporcionan en el segundo. Independientemente de la entrada que se suministre en la segunda etapa, la estructura de la declaración SQL permanecerá intacta. Todos los lenguajes y marcos de desarrollo web admiten el uso de consultas parametrizadas, consulte la documentación de su marco para obtener detalles de implementación.

Evite utilizar otras técnicas ineficaces, como escapar los caracteres de comillas o aplicar límites de longitud, ya que se han desarrollado una serie de medidas para evitarlos. Tenga en cuenta que para que el uso de consultas parametrizadas sea efectivo, deben usarse de manera consistente y en toda la aplicación. Si una sola instancia de concatenación de cadenas se deja sin marcar o si la concatenación de cadenas se mezcla con el uso de consultas parametrizadas, la aplicación aún puede ser vulnerable.

Finalmente, una defensa frecuentemente citada es usar procedimientos almacenados para el acceso a la base de datos. Si bien los procedimientos almacenados pueden proporcionar beneficios de seguridad, no se garantiza que prevengan los ataques de inyección de SQL. Los mismos tipos de vulnerabilidades que surgen en las consultas estándar de SQL dinámico pueden surgir si cualquier SQL se construye dinámicamente dentro de procedimientos almacenados. Además, incluso si el procedimiento es correcto, la inyección de SQL puede surgir si el procedimiento se invoca de forma insegura utilizando datos controlables por el usuario.

### Referencias

- Hackmetrix Reference SQL Injection: https://blog.hackmetrix.com/sql-injection/
- CWE-89: SQL Injection: http://cwe.mitre.org/data/definitions/89.html
- SQL Injection Prevention Cheat Sheet: https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet
- SQL Injection Attacks by Example: http://www.unixwiz.net/techtips/sql-injection.html
- OWASP SQL injection page: https://www.owasp.org/index.php/SQL_Injection

