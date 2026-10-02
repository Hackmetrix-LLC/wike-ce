### Descripción

El control de acceso, o a veces llamado autorización, trata sobre cómo una aplicación web otorga el acceso a ciertos contenidos y funciones para algunos usuarios en la aplicación. Estas comprobaciones se realizan después del proceso de autenticación y rigen lo que los usuarios “autorizados” pueden hacer. El control de acceso parece un problema simple, pero es complejo de implementar correctamente. El modelo de control de acceso de una aplicación web está estrechamente relacionado con el contenido y las funciones que proporciona el sitio. No obstante, los usuarios pueden encontrarse en varios grupos o roles con diferentes habilidades o privilegios.

Con frecuencia, los desarrolladores subestiman la dificultad de implementar un mecanismo de control de acceso confiable. Muchos de estos esquemas no son diseñados deliberadamente, sino que se encuentran evolucionando junto con el sitio web. En estos casos, las reglas de control de acceso se insertan en varias ubicaciones en el código. A medida que el sitio se acerca a la implementación, la colección de reglas ad hoc se vuelve tan difícil de manejar que es casi imposible de entender.

Muchos de estos esquemas de control de acceso defectuosos no son difíciles de descubrir y explotar. En ocasiones, todo lo que se requiere es elaborar una solicitud de funciones o contenido que no se debe otorgar. Una vez que se descubre una falla, las consecuencias de un esquema de control de acceso defectuoso pueden ser devastadoras. Además de poder acceder a contenido no autorizado, un atacante podría cambiar o eliminar contenido, ejecutar funciones no autorizadas o incluso acceder a la administración del sitio.

Un tipo específico de problema de control de acceso son las interfaces administrativas. Dichas funciones se usan con frecuencia para permitir que los administradores del sitio gestionen eficientemente a los usuarios, datos y contenido. En muchos casos, los sitios admiten una variedad de roles administrativos para permitir una granularidad más fina sobre la gestión del sitio. Debido a su poder, estas interfaces son con frecuencia los objetivos principales para un atacante.

### Componentes Afectados

- https://www.cliente_url.com/modulo1/afectado1?id=1&time=now
    - Parámetro Afectado:  id
- https://www.cliente_url.com/modulo2/afectado2?cat=1&dir=/
    - Parámetro Afectado:  dir

### Detalles

[REDACTAR]

### Impacto

{{ Agregar conclución de impacto dependiendo de la logica del negocio del cliente }}

### Remediación

El control de acceso solo es efectivo si se aplica en el lado del servidor, donde un atacante es incapaz de modificar la verificación del mismo.

Para mitigar este tipo de vulnerabilidades, Hackmetrix recomienda:

- Denegar el acceso a la funcionalidad de forma predeterminada.
- Utilizar listas de control de acceso y mecanismos de autenticación basados en roles.
- Evitar “solo ocultar” ciertas funciones peligrosas.

### Referencias

- All About Broken Access Control: https://medium.com/@insightfulrohit/all-about-broken-access-control-cf6ec98a990b
