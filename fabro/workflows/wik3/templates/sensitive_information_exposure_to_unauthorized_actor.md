### Descripción

Se ha identificado la presencia de información expuesta, de manera pública, la cual revela datos sensibles acerca de la infraestructura interna. La gravedad de esto puede variar ampliamente, dependiendo del tipo de información sensible que se revela y los beneficios que está pueda proporcionarle a un atacante. En este caso los recursos se hacen accesibles a actores no autorizados.

### Componentes Afectados

- https://www.cliente_url.com/modulo1/afectado1?id=1&time=now
    - Parámetro Afectado:  id
- https://www.cliente_url.com/modulo2/afectado2?cat=1&dir=/
    - Parámetro Afectado:  dir

### Detalles

[REDACTED]

### Impacto

[REDACTED]

### Remediación

Hackmetrix recomienda no exponer de manera pública los §##RECURSO QUE CORRESPONDA##§, ya que los mismos pueden contener información sensible que debería estar protegida.

### Referencias

- Exposure of Sensitive Information to an Unauthorized Actor – https://cwe.mitre.org/data/definitions/200.html
- CWE-548: https://cwe.mitre.org/data/definitions/548.html
- CWE-538: https://cwe.mitre.org/data/definitions/538.html

