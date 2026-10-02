### Descripción

La vulnerabilidad **Insufficient Protection Against Brute Forcing** se presenta debido a que no existe un mecanismo de control que impida realizar ataques de tipo fuerza bruta, tales como un captcha. En este caso, el software no limita adecuadamente el número o la frecuencia con la que se realizan algunas interacciones, como puede ser el número de solicitudes entrantes.

Esto puede permitirle a un usuario a que realice acciones con más frecuencia de la esperada, pudiendo el actor ser un usuario malintencionado o un proceso automatizado, como un virus o un bot. Esta debilidad podría utilizarse para causar una denegación de servicio, permitir que los usuarios ejecuten reiteradas veces una solicitud (como podría ser una encuesta), o en el caso de una rutina de autenticación, podría no limitar el número de veces que un atacante puede intentar registrarse con claves erróneas

### Componentes Afectados

- https://www.cliente_url.com/modulo1/afectado1?id=1&time=now
    - Parámetro Afectado:  id
- https://www.cliente_url.com/modulo2/afectado2?cat=1&dir=/
    - Parámetro Afectado:  dir

### Detalles

El equipo de Hackmetrix detectó que no existe ningún mecanismo de control que impida que se realice múltiples solicitudes a la hora de §[iniciar sesión en el aplicativo]§. Dicha vulnerabilidad puede permitir que un atacante logre generar credenciales válidas para utilizarse en el aplicativo, o hasta afectar la disponibilidad del mismo.

A modo de prueba de concepto, el equipo de AppSec utilizó el módulo **Intruder** de la herramienta **BurpSuite** para generar un ataque de fuerza bruta mediante un diccionario pequeño, simulando un ataque de fuerza bruta a pequeña escala.

§ INSERTAR IMAGEN (Ataque de Fuerza Bruta Controlado) §

Como se puede ver en la imagen anterior, la respuesta HTTP correspondiente al valor §**CLAVE_CORRECTA**§ difiere con §[el número de estado de respuesta, teniendo un código de estado 200, contra las demás respuestas con código de estado 401]§. Al examinar la respuesta, puede verse que se inició sesión en el aplicativo con las credenciales deducidas durante el ataque.

A continuación, se detalla la solicitud de inicio de sesión original, la cual se reenvió reiteradas veces, modificando cada vez el valor correspondiente al parámetro §_NOMBRE-PARAMETRO_§:

*HTTP Request:*

```
§HTTP REQUEST EXAMPLE§
```

*HTTP Response:*

```
§HTTP RESPONSE EXAMPLE§
```

### Impacto

Un atacante podría realizar ataques de fuerza bruta contra el sistema hasta conseguir autenticarse como un usuario válido en los aplicativos o realizar una denegación de servicio.

### Remediación

Hackmetrix recomienda la implementación de desafíos lógicos o CAPTCHA como reCAPTCHA v2 o versión 3. ReCAPTCHA v2 puede ser una opción adecuada si se desea una fácil implementación o si se necesita una interacción más clara para verificar la autenticidad de los usuarios. Por otro lado, reCAPTCHA v3 es ideal si se prefiere una verificación invisible y se busca simplificar la experiencia del usuario sin ningún desafío manual.

§EVALUAR SI ES CONVENIENTE AGREGAR RECOMENDACION DE RATE LIMIT]§

De forma alternativa, Hackmetrix también recomienda evaluar la implementación de un mecanismo de Rate Limit. Este mecanismo permite controlar la cantidad de solicitudes que un usuario puede realizar en un determinado período de tiempo sobre una API. Estos límites pueden establecerse de diversas maneras, como:

- **Rate limit por usuario:** Cada usuario tiene asignado un límite de solicitudes en un tiempo determinado. Esto asegura una distribución equitativa de los recursos entre los usuarios.
- **Rate limit por IP:** Se establece un límite de solicitudes para cada dirección IP que accede al servicio. Esto previene abusos de recursos por parte de direcciones IP individuales.

Los Rate Limits por usuario son más precisos para controlar el acceso de usuarios individuales, pero requieren identificar y autenticar a cada usuario, lo cual puede ser complejo en algunos casos. Los Rate Limits por IP son más fáciles de implementar, pero pueden afectar a varios usuarios si comparten la misma dirección IP.

Para implementar efectivamente el Rate Limiting, existen dos algoritmos clave: **Token Bucket** y **Fixed Window Counter**, que pueden aplicarse tanto a usuarios individuales como a direcciones IP, ofreciendo una estrategia adaptable para regular el acceso a las APIs.

A continuación, se detalla el funcionamiento de cada uno de los algoritmos:

**Token Bucket**

El algoritmo de **Token Bucket** ofrece flexibilidad y control preciso, permitiendo ráfagas de solicitudes al comienzo, pero limitándolas a una tasa constante a lo largo del tiempo. Funciona con un bucket lleno de tokens que se consumen con cada solicitud. Los tokens se reponen constantemente, y si el bucket se vacía, las solicitudes adicionales se rechazan hasta que se acumulen más tokens.

Un ejemplo práctico de este algoritmo se observa cuando una aplicación emplea una API de correo, y los usuarios tienen un límite de 5 envíos rápidos, disponiendo de un token que se renueva cada 15 minutos hasta restablecer la cuota total de 5 tokens. Si se supera este límite, los usuarios deben esperar a acumular más tokens para poder enviar correos adicionales. Este sistema permite realizar campañas de envío intensivo inicialmente, seguidas de períodos de espera, promoviendo así un uso equilibrado y previniendo el envío de spam.

El algoritmo de **Token Bucket** tiene como ventaja principal que brinda control preciso de la velocidad de llegada de solicitudes y permite ráfagas cortas de solicitudes más rápidas. Sin embargo, presenta la desventaja de que puede ser complejo de implementar y no es adecuado para aplicaciones que requieren respuestas inmediatas. El equipo de Hackmetrix recomienda implementar este algoritmo cuando se necesita permitir cierta flexibilidad en el uso, como permitir ráfagas de solicitudes intermitentes. También es ideal para APIs o servicios que manejan cargas de trabajo variables.

A continuación, se detalla una recomendación de política de Rate-Limit con el algoritmo **Token Bucket**:

- **Capacidad Máxima:** 5 tokens por cliente, permitiendo hasta 5 envíos inmediatos.
- **Reposición de Tokens:** 1 token se repone cada 15 minutos, garantizando una recuperación gradual de la capacidad de envío.
- **Máximo Acumulable:** Los tokens no pueden exceder un máximo de 5 en el bucket, manteniendo un límite en el número de envíos rápidos.

**Fixed Window Counter**

El algoritmo de **Fixed Window Counter** divide el tiempo en ventanas fijas (por ejemplo, minutos o horas) y cuenta las solicitudes en cada ventana. Se establece un límite máximo de solicitudes permitidas por ventana. Si las solicitudes exceden este límite, las nuevas solicitudes dentro de esa ventana se rechazan hasta que comienza la siguiente ventana.

Un ejemplo práctico del algoritmo **Fixed Window Counter** se puede observar en una API de envío de correos, donde cada cliente puede enviar un máximo de 10 correos por hora. Si un cliente alcanza este límite enviando 10 correos al inicio de la hora, no podrá enviar más hasta que comience la siguiente hora. Este método establece un límite definido, previniendo el exceso en el envío de correos y promoviendo un uso justo y equitativo de los recursos de la API.

Este algoritmo tiene como ventaja que es simple de implementar y efectivo para limitar la tasa de solicitudes de forma constante. Sin embargo, no es adecuado para manejar ráfagas cortas de solicitudes más rápidas. El equipo de Hackmetrix recomienda implementar este algoritmo para aplicaciones que requieran una política de rate limiting simple y directa. Este algoritmo es ideal cuando el tráfico es relativamente uniforme o cuando las ráfagas de tráfico no son una preocupación principal.

A continuación, se detalla una recomendación de política de Rate-Limit con el algoritmo **Fixed Window Counter**:

- **Por segundo:** 1-5 solicitudes por segundo para endpoints críticos o sensibles.
- **Por minuto:** 60-300 solicitudes por minuto para servicios web o APIs con tráfico moderado.
- **Por hora:** 1000-5000 solicitudes por hora para aplicaciones con tráfico menos frecuente pero que pueden tener picos ocasionales.

A continuación, se recomienda una solución para §[DEJAR SOLO TECNOLOGIAS QUE USA EL CLIENTE]§

§[BORRAR LO QUE NO CORRESPONDA]§

**AWS (Amazon Web Services)**

- **API Gateway**
    - **Algoritmo:** Token Bucket
    - **Tipo de límites:** Permite límites por usuario y por etapa de API.
    - **Notas adicionales:** Se pueden establecer cuotas con límites máximos de uso en un período de tiempo determinado. Es posible personalizar los límites por ruta y método HTTP.
- **Application Load Balancer (ALB)**
    - **Algoritmo:** No aplica específicamente algoritmos de control de tasa, pero puede integrarse con servicios que lo hacen (AWS WAF).
    - **Tipo de límites:** No se aplica directamente; se centra en la distribución del tráfico.
    - **Notas adicionales:** Aunque ALB no implementa directamente la limitación de tasa, puede trabajar conjuntamente con WAF para aplicar reglas de control de acceso y tasa.
- **WAF (Web Application Firewall)**
    - **Algoritmo:** No específicamente documentado para control de tasa.
    - **Tipo de límites:** Permite configurar reglas que pueden limitar solicitudes por IP y otras identidades.
    - **Notas adicionales:** AWS WAF permite la creación de reglas personalizadas que pueden ayudar a gestionar y mitigar tráfico no deseado o potencialmente peligroso.

**Google Cloud Platform (GCP)**

- **Cloud Armor**
    - **Algoritmo:** No específicamente documentado para control de tasa.
    - **Tipo de límites:** Principalmente límites por IP.
    - **Notas adicionales:** Cloud Armor proporciona seguridad y protección contra una variedad de amenazas, incluyendo DDoS, con reglas que pueden incluir la limitación de tasa.
- **API Gateway**
    - **Algoritmo:** Principalmente Token Bucket.
    - **Tipo de límites:** Permite límites por usuario y por clave de API.
    - **Notas adicionales:** GCP API Gateway facilita la gestión de APIs con control de acceso y limitación de tasa para proteger los backend services.

**Microsoft Azure**

- **API Management**
    - **Algoritmo:** Tanto Token Bucket como Fixed Window Counter.
    - **Tipo de límites:** Permite límites por usuario y por suscripción.
    - **Notas adicionales:** Azure API Management ofrece políticas de limitación de tasa muy flexibles, permitiendo un control granular sobre el tráfico de las APIs.
- **Application Gateway**
    - **Algoritmo:** No aplica directamente control de tasa.
    - **Tipo de límites:** Se centra más en la distribución de carga y gestión de tráfico.
    - **Notas adicionales:** Aunque no se especializa en limitación de tasa, puede configurarse para mejorar la seguridad y el rendimiento de las aplicaciones web.

**Cloudflare**

- **Algoritmo:** Implementa un enfoque avanzado de control de tasa, no limitado a un único algoritmo.
- **Tipo de límites:** Permite límites por IP y, en algunos casos, configuraciones más específicas.
- **Notas adicionales:** Cloudflare ofrece protección avanzada contra ataques DDoS y control de tasa para prevenir el abuso, manteniendo la disponibilidad de los sitios web.

**Nginx**

- **Algoritmo:** Token Bucket y Leaky Bucket.
- **Tipo de límites:** Permite límites por IP, servidor y ubicación.
- **Notas adicionales:** Nginx facilita la configuración de control de tasa muy flexible, permitiendo a los administradores de sistemas y desarrolladores gestionar eficazmente el tráfico web y prevenir el sobrecarga de los servidores.

Los algoritmos y tipos de límites pueden variar según la configuración y la versión de los servicios. Es esencial ajustar los límites de Rate Limiting según las necesidades específicas de la aplicación y el negocio, garantizando un equilibrio efectivo entre la protección del sistema y la experiencia del usuario.

§[BORRAR LO QUE NO CORRESPONDA]§

### Referencias

- CWE-287: https://cwe.mitre.org/data/definitions/287.html
- reCAPTCHA V2: https://developers.google.com/recaptcha/docs/display?hl=es-419
- reCAPTCHA V3: https://developers.google.com/recaptcha/docs/v3?hl=es-419
- Create rate limiting rules via API in Cloudfare: https://developers.cloudflare.com/waf/rate-limiting-rules/create-api/
- Set up global rate limiting with AWS WAF: https://faun.pub/set-up-global-rate-limiting-with-aws-waf-in-5-minutes-bd43a9309683
- How to Rate Limit in NGINX: https://www.linuxcapable.com/how-to-rate-limit-in-nginx/
- Rate limiting in Azure API Management: https://learn.microsoft.com/en-us/microsoft-cloud/dev/dev-proxy/concepts/implement-rate-limiting-azure-api-management
- Configure rate limiting with Google Cloud Armor: https://cloud.google.com/armor/docs/configure-rate-limiting

