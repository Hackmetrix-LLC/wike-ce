### Descripción

La vulnerabilidad Insufficient Session Expiration se da cuando el tiempo de vida de la sesión es demasiado largo o cuando la sesión no finaliza correctamente después de que el usuario realice un cierre de sesión en el aplicativo. Esto podría significar un problema si, por ejemplo, un usuario malintencionado utiliza el botón de retroceso en un navegador para acceder a páginas web a las que la víctima accedió previamente.

Las aplicaciones web deben invalidar la sesión después de que haya transcurrido un tiempo inactivo predefinido (un tiempo de espera) y proporcionar a los usuarios medios para invalidar sus propias sesiones como puede ser, por ejemplo, la función de cierre de sesión. Esta debe ser visible para el usuario, debe invalidar explícitamente la sesión y no permitir la reutilización del token de sesión. Estas simples medidas ayudan a mantener la vida útil de un ID de sesión y protegerse así contra este tipo de ataques.

### Componentes Afectados

- https://www.cliente_url.com/modulo1/afectado1?id=1&time=now
    - Parámetro Afectado:  id
- https://www.cliente_url.com/modulo2/afectado2?cat=1&dir=/
    - Parámetro Afectado:  dir

### Detalles

El equipo de seguridad de Hackmetrix detectó la vulnerabilidad **Insufficient Session Expiration**, la cual permitió reutilizar §[LA COOKIE O EL TOKEN]§ de sesión de un usuario determinado. Cuando este inicia sesión en la aplicación, se genera §[UNA COOKIE O UN TOKEN]§ de sesión la cual no expira luego de que el usuario realiza un cierre de sesión en la aplicación §[VERIFICAR Y REDACTAR]§.

A continuación se encuentra de manera detallada, como fue posible explotar dicha vulnerabilidad:

§[REDACTAR A MEDIDA]§

### Impacto

Un periodo de vigencia extenso en §[LOS TOKENS O LAS COOKIES]§ de sesión incrementa las posibilidades de que un atacante consiga y reutilice dichos/as §[TOKENS O COOKIES]§, pudiendo de esta forma realizar suplantación de identidad durante el periodo de vida de estos.

### Remediación

§[ESCENARIO CON TOKEN DE SESION]§

Hackmetrix recomienda invalidar el token de sesión de los usuarios una vez que estos cierren sesión en el aplicativo y otorgarle a estos un periodo de vida no demasiado extenso. Por otra parte, se recomienda también realizar el proceso de invalidación del lado del servidor.

§[ESCENARIO CON JWTS]§

Hackmetrix recomienda la implementación de JWT (JSON Web Tokens) mediante una estrategia que distinga claramente entre el **Token de Acceso** y el **Refresh Token**, optimizando así la seguridad y la experiencia del usuario en su sistema:

- **Token de Acceso (Access Token):** Este token se utiliza para autenticar y autorizar las solicitudes de los usuarios en aplicaciones o APIs. Debe tener una duración corta, típicamente de unos pocos minutos a unas pocas horas, para reducir el riesgo en caso de que sea comprometido. Permite el acceso a recursos protegidos de manera eficiente.
- **Refresh Token:** Este token de más larga duración se usa para obtener nuevos tokens de acceso sin que el usuario necesite volver a autenticarse. Los refresh tokens aumentan la seguridad al minimizar la frecuencia con la que los usuarios deben ingresar sus credenciales, mientras permiten mantener una sesión activa a través de tokens de acceso de corta duración.

A continuación, se detalla el flujo de autenticación y autorización mediante JWTs con Tokens y Refresh Tokens:

1. **Inicio de Sesión:** El usuario inicia sesión proporcionando sus credenciales (como usuario y contraseña) al sistema de autenticación.
2. **Emisión de Tokens:** El sistema de autenticación valida las credenciales y, si son correctas, emite dos cosas: un Token de Acceso, que tiene una duración corta (De 10 minutos a 60 minutos) y se utiliza para acceder a recursos protegidos, y un Refresh Token, que tiene una duración más larga y se usa para obtener nuevos tokens de acceso una vez que el actual expira.
3. **Acceso a Recursos Protegidos:** Con el Token de Acceso, el cliente puede hacer solicitudes a endpoints protegidos para obtener o modificar recursos. Cada solicitud debe incluir el Token de Acceso para su autenticación.
4. **Verificación del Token de Acceso:** El servidor o endpoint protegido verifica la validez del Token de Acceso con cada solicitud. Si el token es válido, el servidor proporciona el recurso solicitado.
5. **Expiración del Token de Acceso:** El cliente sigue utilizando el Token de Acceso para solicitudes hasta que este expira. Debido a la corta duración del Token de Acceso, este paso se repite varias veces, alternando entre el uso del token y la verificación de su validez por parte del servidor.
6. **Renovación del Token de Acceso:** Una vez que el Token de Acceso expira, el cliente utiliza el Refresh Token para solicitar un nuevo Token de Acceso sin necesidad de volver a ingresar credenciales. Este paso es crucial para mantener la sesión del usuario activa sin interrupciones.
7. **Emisión de Nuevos Tokens:** El sistema de autenticación verifica el Refresh Token y, si es válido, emite un nuevo Token de Acceso y, opcionalmente, un nuevo Refresh Token. Este proceso ayuda a mantener la seguridad, limitando la ventana de tiempo en la que un token comprometido puede ser utilizado.
8. **Ciclo de Renovación:** El cliente repite el proceso de solicitar recursos protegidos con el nuevo Token de Acceso y solicitar nuevos tokens cuando estos expiran, utilizando el Refresh Token.
9. **Re-autenticación Necesaria:** Cuando el Refresh Token finalmente expira o en casos donde el usuario cierra sesión explícitamente, es necesario volver a iniciar el proceso de autenticación desde el principio, ingresando nuevamente las credenciales del usuario.

Este flujo también se puede observar en el siguiente diagrama:

!Untitled

La implementación del flujo asegura que los usuarios puedan acceder a recursos protegidos de manera segura, mientras mantiene una experiencia de usuario fluida al minimizar la necesidad de ingresar repetidamente credenciales. También proporciona un mecanismo para mantener la seguridad mediante la limitación de la vida útil de los tokens de acceso y la posibilidad de revocar el acceso mediante la gestión de refresh tokens.

Por otra parte, Hackmetrix también recomienda la implementación de una Blacklist para aquellos Token de Acceso y Refresh Tokens que deban ser invalidados cuando se cierre la sesión de un usuario o cuando se realice una acción crítica sobre el usuario, tal como un cambio de clave o la deshabilitación del mismo. También se recomienda realizar una limpieza de la Blacklist (De acuerdo a la duración del Refresh Token para evitar almacenar tokens inútiles.

De manera alternativa, en caso de que no se posible la implementación de un sistema de JWTs con Refresh Token, Hackmetrix recomienda que el tiempo de vida del JWT no sea mayor a 24 Horas.

§[RECORDAR ELIMINAR LA OPCION QUE NO CORRESPONDA]§

### Referencias

- CWE-613: https://cwe.mitre.org/data/definitions/613.html
- Insufficient Session Expiration: https://www.owasp.org/index.php/OWASP_Periodic_Table_of_Vulnerabilities_-_Insufficient_Session_Expiration
- JWT Refresh Token – Spring Security: https://medium.com/spring-boot/jwt-refresh-token-spring-security-c5b4646cdbd9
- Refresh token con autenticación JWT. Implementación en Node.js: https://ahorasomos.izertis.com/solidgear/refresh-token-autenticacion-jwt-implementacion-nodejs/
- Django Rest Framework y JWT para autenticar usuarios: https://coffeebytes.dev/django-rest-framework-y-jwt-para-autenticar-usuarios/
- JWT Auth + Refresh Tokens in Rails: https://gist.github.com/jesster2k10/e626ee61d678350a21a9d3e81da2493e


