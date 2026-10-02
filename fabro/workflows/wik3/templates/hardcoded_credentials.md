### Descripción

El software contiene credenciales codificadas, como pueden ser una contraseña o una clave criptográfica, las cuales utiliza como método de autenticación entrante y comunicación saliente de componentes externos. De ser accedidas por un atacante, la información contenida en estos archivos podría ser utilizada para ganar acceso a otros recursos de la red y/o para incrementar el impacto y el alcance que un usuario malintencionado podría tener en ella.

### Remediación

Se recomienda eliminar las credenciales codificadas de los archivos que se descargan del lado del cliente. En caso de que la aplicación debiera contener credenciales codificadas, o bien, que estas no pudieran eliminarse, realice verificaciones de control de acceso mediante el cumplimiento de los métodos de autenticación y, limite la cantidad de entidades que puedan acceder a la función que requiere dichas credenciales de manera codificada.

### Detalles

Durante el ejercicio, el equipo de Hackmetrix encontró multiples archivos de configuración los cuales contienen credenciales hardcodeadas.

A continuación se detallaran los servidores afectados junto a los archivos que contienen credenciales hardcodeadas:

```
 § WIP §
```

### Impacto

{{ Agregar conclusión de impacto dependiendo de la lógica del negocio del cliente }}

### Referencias

- CWE-798: Use of Hard-coded Credentials: https://cwe.mitre.org/data/definitions/798.html
- OWASP: Use of hard-coded password: https://www.owasp.org/index.php/Use_of_hard-coded_password

