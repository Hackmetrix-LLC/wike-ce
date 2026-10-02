### Descripción

CVS Formula Injection ocurre cuando un aplicativo embebe un ingreso de datos inseguro dentro de archivos CSV.

Cuando un programa de hojas de cálculo, como Microsoft Excel, es usado para abrir un CSV, todas las celdas que comienzan con el caracter “=” van a ser interpretadas por el software como una formula. Un atacante podria utilizar esta vulnerabilidad para realizar tres ataques clave:

- Tomar control del equipo del usuario aprovechándose de vulnerabilidades conocidas del software.
- Tomar control del equipo del usuario explotando la tendencia del usuario de ignorar las advertencias de seguridad.
- Exfiltrar contenido del archivo u otros archivos abiertos.

### Componentes Afectados

- https://www.cliente_url.com/modulo1/afectado1?id=1&time=now
    - Parámetro Afectado:  id
- https://www.cliente_url.com/modulo2/afectado2?cat=1&dir=/
    - Parámetro Afectado:  dir

### Detalles

El equipo de AppSec encontró que al [REDACTAR], es posible generar un payload para que se ejecute al momento de abrir el archivo exportado por la aplicación.

A continuación se detallaran los pasos de cómo el equipo de Hackmetrix logró explotar satisfactoriamente dicha vulnerabilidad modificando el campo [REDACTAR]. En esta prueba de concepto, vamos a utilizar la herramienta Burp Collaborator de la suite de herramientas Burp Suite.

**Paso 1:** enviamos una petición, modificando el campo [REDACTAR] con el payload del atacante.

*HTTP Request:*

```jsx

```

Como se puede ver en la petición anterior, se usó el siguiente payload en forma de PoC para aprovecharse de dicha vulnerabilidad.

*Payload:*

```

```

Este payload, una vez se ejecuta, envía una petición de ping hacia el Burp Collaborator que se encuentra en el sistema del atacante.

Como respuesta se obtuvo lo siguiente:

*HTTP Response:*

```

```

**Paso 2:** Luego de [REDACTAR], podemos exportar la planilla. Una vez abierta, el software nos advierte de la siguiente forma. Un usuario inadvertido, puede dar paso al payload malicioso.

(IMAGEN DE ADVERTENCIA DE EXCEL)

**Paso 3:** Una vez permitido, el payload genera una petición hacia la dirección del Burp Collaborator. Desde el Burp Collaborator podemos ver cómo se recibieron las peticiones correspondientes.

(IMAGEN DE LA RECEPCION DEL BURP COLLABORATOR)

### Impacto

De esta forma, un usuario malintencionado podria tomar control de los equipos utilizados por aquellos usuarios con permisos de descarga del archivo de productos, robar credenciales del usuario afectado, informacion sensible del negocio o el usuario a la cual se tenga acceso; eliminar informacion relevante a la que el usuario tenga acceso, o cambiar los datos de la plataforma a los que tenga acceso ese usuario.

### Remediación

Este ataque es difícil de mitigar. Para poder remediarlo, es importante poder asegurarse que las celdas no comiencen o contengan con ninguno de estos caracteres:

- Igual a (=)
- Suma (+)
- Resta (-)
- At (@)
- Tab (0×09)
- Carriage return (0×0D)

También se puede agregar, a las lineas que comiencen con dichos caracteres, el simbolo de comilla simple (’) para que no los reconozca como formula sino como texto.

Por otro lado, es importante evitar el ingreso de separadores por parte del usuario como coma (,) o punto y coma (;). Un atacante podría utilizar estos caracteres para saltearse las protecciones mencionadas anteriormente.

### References

- CWE-89: Improper Neutralization of Formula Elements in a CSV File: https://cwe.mitre.org/data/definitions/1236.html
- OWASP CSV Injection: https://owasp.org/www-community/attacks/CSV_Injection
