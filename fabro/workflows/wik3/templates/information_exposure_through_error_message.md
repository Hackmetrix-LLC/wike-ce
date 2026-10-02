### Descripción

Se ha observado la presencia de distintos mensajes de error presentados a los usuarios, los cuales revelan información sensible acerca de la infraestructura de los servicios afectados. Algunas condiciones de error en las aplicaciones producen mensajes, generando así stack traces (listado de excepciones de memoria), que pueden revelar información sensible acerca de las funciones e infraestructura de los servicios afectados.

Los errores que exponen este tipo de datos pueden permitirle a un usuario malintencionado identificar información adicional sobre la infraestructura (tipo de servidor web utilizado, versión, etc.), y utilizar dicha información para generar ataques de mayor precisión, complejidad e impacto.

### Componentes Afectados

- https://www.cliente_url.com/modulo1/afectado1?id=1&time=now
    - Parámetro Afectado:  id
- https://www.cliente_url.com/modulo2/afectado2?cat=1&dir=/
    - Parámetro Afectado:  dir

### Detalles

El equipo de AppSec identificó la vulnerabilidad **Information Exposure Through an Error Message** la cual se presenta debido a que §[se expone el stack trace al momento de generarse un error en la aplicación]§.

A continuación, podemos generar un error mediante la siguiente solicitud:

*HTTP Request:*

```
§HTTP REQUEST EXAMPLE§
```

*HTTP Response:*

```
§HTTP RESPONSE EXAMPLE§
```

### Impacto

A través de la información expuesta, un atacante podría ampliar su rango de ataque, combinando ciertos datos de importancia como lo son: Directorios internos del servidor web, nombres de tablas y base de datos. Utilizando este tipo de información, un atacante podría ser capaz de explotar de manera satisfactoria, otro tipo de vulnerabilidades presentes en la aplicación.

### Remediación

Hackmetrix recomienda no mostrar mensajes de error al usuario cuando se genera una excepción, ya que no debe revelarse información detallada como los stack traces. En cambio, deben mostrarse mensajes de error personalizados para no causar ninguna fuga de información.

### Referencias

- CWE-209: https://cwe.mitre.org/data/definitions/209.html

