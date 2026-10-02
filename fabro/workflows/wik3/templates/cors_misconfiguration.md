### Descripción

Cross-origin resource sharing (CORS) es un mecanismo del navegador web que permite el acceso controlado a recursos ubicados por fuera de un dominio determinado. Extiende y agrega flexibilidad a same-origin policy (SOP). Sin embargo, también permite efectuar ataques basados en dominios cruzados, si la política CORS de un sitio web se encuentra mal configurada e implementada. CORS no es una protección contra ataques de origen cruzado como, por ejemplo: Ataques del tipo Cross-Site Request Forgery (CSRF).

### Componentes Afectados

- https://www.cliente_url.com/modulo1/afectado1?id=1&time=now
    - Parámetro Afectado:  id
- https://www.cliente_url.com/modulo2/afectado2?cat=1&dir=/
    - Parámetro Afectado:  dir

### Detalles

El equipo de AppSec detectó que la aplicación implementa **CORS** de una forma insegura. Hackmetrix halló la posibilidad de modificar la cabecera HTTP Origin pudiendo obtener de esta manera una respuesta de origen cruzado desde un dominio determinado.

A continuación, se encuentra de forma detallada como fue posible identificar dicha vulnerabilidad:

**Paso 1:** Por medio de la siguiente solicitud HTTP, es posible ver como se envió la cabecera **Origin** con el valor modificado a **https://evil.com**:

*HTTP Request:*

```
HTTP REQUEST
```

Obteniendo como respuesta:

*HTTP Response:*

```
HTTP RESPONSE
```

Como se evidencia en la respuesta HTTP, el servidor envió los siguientes encabezados:

```
Access-Control-Allow-Origin: http://attacker.com
Access-Control-Allow-Credentials: true
```

De esta forma, un atacante podría forzar a la aplicación a que permitiera el acceso desde el origen solicitado: **https://evil.com**

A continuación, podemos observar un posible escenario de ataque mediante el cual un atacante podría exfiltrar información de un usuario de **§EMPRESA§**:

§LA SIGUIENTE IMAGEN ES MODELO, CONTIENE INFO SENSIBLE DE LA EMPRESA VULNERABLE! MODIFICAR TOTALMENTE EN CASO DE DEJAR§

!Untitled

### Impacto

Un atacante puede aprovechar esta debilidad para obtener información relevante desde un origen cruzado, como también generar solicitudes que solo debería poder efectuar un usuario válido en el aplicativo

### Remediación

Hackmetrix recomienda realizar una verificación de la cabecera HTTP Origin a través de una lista blanca de dominios de confianza.

### Referencias

- CWE-942: Overly Permissive Cross-domain Whitelist: https://cwe.mitre.org/data/definitions/942.html
- CORS: https://portswigger.net/web-security/cors
- Exploiting CORS misconfigurations: https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties

