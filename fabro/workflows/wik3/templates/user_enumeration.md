### Descripción

La vulnerabilidad User Enumeration, se produce cuando el aplicativo recibe un campo determinado, como puede ser una dirección de email o un nombre de usuario, o cualquier dato foráneo a una cuenta y el aplicativo despliega una respuesta o mensaje notificando el estado de presencia o ausencia del usuario. Es decir que, pudiendo discernir entre los distintos mensajes un atacante puede crear una lista de correos o nombres de usuarios válidos para iniciar sesión en la aplicación.

### Componentes Afectados

- https://www.cliente_url.com/modulo1/afectado1?id=1&time=now
    - Parámetro Afectado:  id
- https://www.cliente_url.com/modulo2/afectado2?cat=1&dir=/
    - Parámetro Afectado:  dir

### Detalles

El equipo de AppSec detectó la vulnerabilidad **User Enumeration**, la cual permite determinar la existencia de un usuario en el sistema, conociendo su [§REDACTAR§(correo electrónico)].

A continuación se encuentra de manera detallada, como fue posible explotar dicha vulnerabilidad:

El equipo de Hackmetrix procedió a enviar la siguiente solicitud la cual permite [§REDACTAR§]:

*HTTP Request:*

```
§HTTP REQUEST EXAMPLE§
```

A lo que se obtiene como respuesta, que dicho usuario [§ya existe§] en la plataforma:

*HTTP Response:*

```
§RESPONSE EXAMPLE§
```

ERASEME

### Impacto

Mediante esta vulnerabilidad un atacante podría enumerar los usuarios existentes en el sistema.

### Remediación

Hackmetrix recomienda no emitir mensajes que den a conocer el estado de los usuarios válidos en la aplicación. Para lograr esto es necesario desplegar mensajes genéricos, en respuesta a los intentos de inicio de sesión, desbloqueo de contraseña, reenvió de instrucciones de confirmación, etc. Un ejemplo de mensajes podría ser el siguiente:

***Si el correo electrónico es válido, por favor revise su bandeja de entrada.***

Adicionalmente es recomendable implementar un desafío lógico o captcha el cual sirva para mitigar las pruebas de fuerza bruta, lo cual conlleva a una posible enumeración de usuarios del aplicativo.

### Referencias

- CWE-204: https://cwe.mitre.org/data/definitions/204.html
- CWE-307: https://cwe.mitre.org/data/definitions/307.html

