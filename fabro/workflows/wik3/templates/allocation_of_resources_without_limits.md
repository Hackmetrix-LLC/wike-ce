### Descripción

La vulnerabilidad **Allocation of Resources Without Limits** se presenta debido a que la API no está protegida contra una cantidad excesiva de llamadas o tamaños de payloads. Los atacantes pueden usar esto para realizar un ataque de denegación de servicio (DoS) y fallas de autenticación como ataques de fuerza bruta.

### Componentes Afectados

- https://www.cliente_url.com/modulo1/afectado1?id=1&time=now
    - Parámetro Afectado:  id
- https://www.cliente_url.com/modulo2/afectado2?cat=1&dir=/
    - Parámetro Afectado:  dir

### Detalles

Hackmetrix identificó que en la aplicación es vulnerable **Allocation of Resources Without Limits** debido a que es posible solicitarle al servidor recuperar una gran cantidad de información la cual podría generar una denegación de servicio (DoS) o una denegación de billetera (Denial of Wallet).

§[REDACTED]§

### Impacto

Con la explotación de dicha vulnerabilidad, un usuario malintencionado podría utilizar esta vulnerabilidad para afectar el rendimiento del servidor API, lo que llevaría a la denegación de servicio (DoS). También, al consumir recursos del servidor, el autoscaling podría ejecutarse automáticamente generando costos no deseados.

### Remediación

Hackmetrix recomienda establecer un límite en la frecuencia con que un cliente puede llamar a la API dentro de un marco de tiempo definido para evitar la sobrecarga de recursos. Además, es crucial validar del lado del servidor, la correcta implementación de la paginación, asegurando que los parámetros relacionados con el número de registros devueltos por cada consulta estén bien gestionados. Por último, es fundamental realizar una revisión exhaustiva en todos los endpoints de la aplicación que utilicen paginación para asegurar que se apliquen estas medidas de manera consistente en toda la aplicación.

### Referencias

- CWE-770: https://cwe.mitre.org/data/definitions/770.html

