### Descripción

Se puede observar que la aplicación no controla adecuadamente la asignación y el mantenimiento de un recurso limitado. Esto puede permitirle a un ataque a que influya sobre la cantidad de recursos consumidos, generando de esta forma impacto o incluso agotamiento de los recursos disponibles dentro del servidor.

Si un atacante aprovechara la asignación de estos recursos limitados, y no se controlase el número o el tamaño de los mismos, podría derivar en denegación de servicio y consumir los recursos disponibles. Es posible que esto suceda de igual forma con recursos externos que interactúan con la aplicación vulnerable, como por ejemplo: El uso de un recurso externo para el envío de emails. En este caso, un atacante podría ejecutar el envío de emails masivos, logrando alterar significativamente el servicio utilizado.

### Componentes Afectados

- https://www.cliente_url.com/modulo1/afectado1?id=1&time=now
    - Parámetro Afectado:  id
- https://www.cliente_url.com/modulo2/afectado2?cat=1&dir=/
    - Parámetro Afectado:  dir

### Detalles

El equipo de Hackmetrix identificó la vulnerabilidad Uncontrolled Resource Consumption, la cual se presenta debido a que fue identificada una API Key, la cual puede ser utilizada en Google Maps para generar gastos no deseados a la empresa.

A continuación, se encuentra de manera detallada, como fue posible identificar dicha vulnerabilidad:

**Paso 1:** El equipo de Hackmetrix inició sesión con el usuario [REDACTED].

**Paso 2:** Luego de iniciar sesión, se identificó la siguiente solicitud la cual contiene la API Key de Google Maps:

*HTTP Request:*

```
ACA VA LA REQUEST
```

*HTTP Response:*

```
ACA VA LA RESPONSE
```

**Paso 3:** Hackmetrix procedió a verificar si la API Key de Google Maps se encontraba configurada de manera incorrecta, utilizando la herramienta **gmapsapiscanner**, como se observa a continuación:

PIC DE GMAPSAPISCANNER

Como se observa previamente, la herramienta nos informa que es posible utilizar la misma para consumir servicios de Google Maps, generando costos no deseados a la empresa. A continuación, podemos ver la tabla de referencia que indica para que servicios de Google Maps puede ser utilizada y cuales serían sus costos asociados:

PIC DE TABLA DE GMAPSAPISCANNER

### Impacto

Mediante esta vulnerabilidad, un atacante podría abusar de la API Key de Google Maps para generar costos no deseados a la empresa.

### Remediación

El equipo de Hackmetrix recomienda implementar las siguientes medidas para remediar la vulnerabilidad:

- Revisión y Limitación de Permisos de la API Key: Es importante asegurarse de que la API Key tenga únicamente los permisos necesarios para su funcionamiento. Esto implicaría habilitar solo las APIs relacionadas con mapas y deshabilitar cualquier otra API que no se este utilizando.
- Restricción por Dominio: Para evitar que otros sitios o personas utilicen tu API Key sin autorización, la API Key debe ser restringida para que solo funcione en tu propio dominio y subdominios si es necesario. La API Key puede ser restringida a una plataforma específica (Android o iOS) o sitios específicos (dirección IP pública y sitio web).
- Establecimiento de Cuotas: Hackmetrix recomienda configurar los límites en la cantidad de solicitudes que pueden hacerse con la API Key en un período de tiempo determinado, esto ayudará a evitar un uso excesivo y gastos no planificados.

### Referencias

- CWE-400: Uncontrolled Resource Consumption: https://cwe.mitre.org/data/definitions/400.html
- Resource Exhaustion: https://www.cvedetails.com/cwe-details/400/Uncontrolled-Resource-Consumption-039-Resource-Exhaustion.html
- Google Maps API Key Restriction: https://developers.google.com/maps/api-security-best-practices

