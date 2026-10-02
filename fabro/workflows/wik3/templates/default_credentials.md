### Descripción

A menudo, las aplicaciones web hacen uso de software de código abierto o comercial. Estas aplicaciones, en su configuración inicial, no se encuentran debidamente parametrizadas y las credenciales predeterminadas proporcionadas para la autenticación y configuración, en muchos casos, nunca se cambian. Estas credenciales por defecto pueden encontrarse públicas en internet y son bien conocidas por los atacantes, que pueden usarlas para obtener acceso a varios tipos de aplicaciones configuradas de la misma manera.

Además, en muchas situaciones, cuando se crea una nueva cuenta en una aplicación, se genera una contraseña predeterminada (con algunas características estándar). Si esta contraseña es predecible y el usuario no procede a cambiarla luego del primer acceso, puede que un atacante acceda sin autorización a la aplicación.

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

Hackmetrix recomienda establecer una fuerte política de contraseñas, tanto dentro del entorno productivo como en el entorno de testing.

### Referencias

- TA13-175A: https://www.us-cert.gov/ncas/alerts/TA13-175A
- Default credentials: https://www.cert.govt.nz/it-specialists/critical-controls/default-credentials/
- Default credentials vulnerability: https://en.wikipedia.org/wiki/Default_Credential_vulnerability
- Testing for default credentials: https://www.owasp.org/index.php/Testing_for_default_credentials_(OTG-AUTHN-002))

