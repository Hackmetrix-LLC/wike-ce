### Descripción

El software construye todo o parte de un segmento de código utilizando una entrada influenciada externamente, pero no neutraliza o sanitiza incorrectamente los elementos especiales que podrían modificar la sintaxis o el comportamiento del segmento de código deseado.

La inyección puede resultar en pérdida o corrupción de datos o denegación de acceso. La inyección a veces puede llevar a la toma de control completa del host.

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

Refactorice el segmento del programa para que no tenga que generar código dinámicamente.

Supongamos que toda la entrada es maliciosa. Use una estrategia de validación de entrada “aceptar el bueno conocido”, es decir, use una lista blanca de entradas aceptables que se ajusten estrictamente a las especificaciones. Rechace cualquier entrada que no se ajuste estrictamente a las especificaciones, o transforme en algo que lo haga.

Al realizar la validación de entrada, tenga en cuenta todas las propiedades potencialmente relevantes, incluida la longitud, el tipo de entrada, el rango completo de valores aceptables, entradas extra o faltantes, la sintaxis, la coherencia en todos los campos relacionados y el cumplimiento de las reglas comerciales.

### Referencias

- Hackmetrix Reference Blog: https://blog.hackmetrix.com/command-injection/
- OWASP Code Injection: https://www.owasp.org/index.php/Code_Injection
- Remote Code Execution: https://www.bugcrowd.com/resources/glossary/remote-code-execution-rce/
- Arbitrary code execution: https://en.wikipedia.org/wiki/Arbitrary_code_execution
