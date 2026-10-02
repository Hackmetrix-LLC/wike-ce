### Descripción

El equipo de Offensive Security de Hackmetrix ha evidenciado que la aplicación no cuenta con protección contra las capturas de pantalla que pueden realizar los usuarios y/o aplicaciones de terceros, lo que expone la información confidencial de los usuarios a terceros.

### Componentes Afectados

- https://www.cliente_url.com/modulo1/afectado1?id=1&time=now
    - Parámetro Afectado:  id
- https://www.cliente_url.com/modulo2/afectado2?cat=1&dir=/
    - Parámetro Afectado:  dir

### Detalles

Al analizar la aplicación se pudo observar que al poner la aplicación en *background* es posible realizar una captura de pantalla de la información que ésta presenta. A continuación, podemos observar como fue posible poner la aplicación en *background* en donde se muestra §[DETALLAR LA INFO SENSIBLE QUE SE EXPONE]§ y fue posible tomar un Screenshot de dicha información:

 §INSERTAR IMAGEN (Captura de pantalla de la información de la aplicación) §

ERASEME

### Impacto

Un agente malicioso ya sea un usuario o aplicación móvil podría realizar capturas de pantallas y obtener los detalles financieros o personales de la persona que hace uso de la aplicación en su dispositivo

### Remediación

Implementar la propiedad SECURE FLAG para el componente WindowManager.LayoutParams

### Referencias

- CWE-922: Insecure Storage of Sensitive Informationhttps://cwe.mitre.org/data/definitions/922.html
- WindowManager.LayoutParams: http://developer.android.com/reference/android/view/WindowManager.LayoutParams.html#FLAG_SECURE

