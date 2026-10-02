### Descripción

Un aspecto importante del desarrollo seguro de aplicaciones es evitar la fuga de información. Los problemas de divulgación de información pueden dar a un atacante una gran comprensión del funcionamiento interno de una aplicación. El propósito de revisar los encabezados de respuesta del servidor HTTP es asegurar que el servidor web no filtre información que pueda usarse para realizar ataques adicionales. Por ejemplo, buscando explotaciones de la tecnología que se utiliza en función de la tecnología y el uso de la versión.

### Componentes Afectados

- https://www.cliente_url.com/modulo1/afectado1?id=1&time=now
    - Parámetro Afectado:  id
- https://www.cliente_url.com/modulo2/afectado2?cat=1&dir=/
    - Parámetro Afectado:  dir

### Detalles

Hackmetrix identificó que a través de los Header HTTP, el sistema envía información acerca de las tecnologías utilizadas en el sitio, como el tipo de servidor utilizado.

La misma puede ser explotada a través de la siguiente solicitud HTTP:

*HTTP Request:*

```
 § HTTP REQUEST §
```

Como se puede observar, en la respuesta se revela información del tipo y la versión del servidor:

*HTTP Response:*

```
 § HTTP RESPONSE §
```

### Impacto

Un atacante podría utilizar esta vulnerabilidad para reducir el tiempo de testing logrando conocer por adelantado las tecnologías utilizadas para desarrollar la plataforma y generando estrategias de ataque especificas para estas tecnologías.

### Remediación

Se recomienda eliminar todos los encabezados potencialmente inseguros. En este caso particular, para ##### § TECNOLOGÍA § #####, esto se puede lograr con el siguiente ejemplo:

Node JS:

```
app.use(function (req, res, next) {
res.removeHeader("X-Powered-By");
next();
});
```

Nginx:

Se recomienda añadir las siguientes líneas al archivo nginx.conf para evitar la fuga de información de la cabecera server de su respuesta HTTP:

```
server_tokens off;
proxy_hide_header Server;
```

Luego, reiniciar Nginx y verificar que la cabecera **Server** no se encuentre dentro de la respuesta HTTP del servidor.

ASP.NET:

Para eliminar la cabecera X-Powered-By, Hackmetrix recomienda agregar el siguiente código dentro del nodo <system.webServer> en el archivo Web.config

```
<httpProtocol>
  <customHeaders>
    <remove name="X-Powered-By" />
  </customHeaders>
</httpProtocol>
```

Para eliminar el valor de la cabecera **Server**, se recomienda agregar el siguiente código en el fichero Web.config

```
<rewrite>
  <outboundRules rewriteBeforeCache="true">
    <rule name="Remove Server header">
      <match serverVariable="RESPONSE_Server" pattern=".+" />
      <action type="Rewrite" value="" />
    </rule>
  </outboundRules>
</rewrite>
```

PHP: § VERIFICAR QUE SEA → X-Powered-By: PHP/Version §

Se recomienda añadir el siguiente comando al fichero php.ini

```
if (function_exists('header_remove')) {
    header_remove('X-Powered-By'); // PHP 5.3+
} else {
    @ini_set('expose_php', 'off');
}
```

### Referencias

- Fingerprint Web Server: https://www.owasp.org/index.php/Fingerprint_Web_Server_(OTG-INFO-002))
- CWE-200: Information Exposure: https://cwe.mitre.org/data/definitions/200.html
- Shhh… don’t let your response headers talk too loudly: https://www.troyhunt.com/shhh-dont-let-your-response-headers/
- CAPEC-170: Web Application Fingerprinting: https://capec.mitre.org/data/definitions/170.html

