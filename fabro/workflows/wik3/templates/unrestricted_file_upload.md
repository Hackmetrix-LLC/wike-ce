### Descripción

Los Upload de Archivos representan un riesgo significativo para las aplicaciones. El primer paso en muchos ataques es lograr cargar código malicioso al sistema atacado para lograr tomar control del servidor. Si un atacante ataque logra cargar archivos maliciosos en el sistema y encuentra una forma de ejecutarlos lograría manipular el comportamiento de la aplicación a gusto.

Las consecuencias de la carga de archivos sin restricciones pueden variar, puede derivar en la toma de control total del sistema, o en una sobre escritura de la base de datos de la aplicación, entre otros ataques . Esto dependerá de lo que la aplicación haga con el archivo cargado.

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

Para mitigar este tipo de vulnerabilidad, el equipo de AppSec recomienda crear un whitelist de extensiones, es decir, solo permitir la carga de los tipos de archivos que desea cargar en el servidor, por ejemplo, si desea cargar imágenes, verifique que la extensión corresponde a png, jpg o gif, de lo contrario evita la carga. También se recomienda filtrar los caracteres ../ para evitar ataques del tipo Directory Traversal.

### Referencias

- Hackmetrix Reference Arbitrary File Upload: https://blog.hackmetrix.com/arbitrary-file-upload/
- Unrestricted File Upload in Apple Server: https://medium.com/@jonathanbouman/how-i-hacked-apple-com-unrestricted-file-upload-bcda047e27e3
- CWE-434: https://cwe.mitre.org/data/definitions/434.html
- Unrestricted File Upload: https://www.owasp.org/index.php/Unrestricted_File_Upload

