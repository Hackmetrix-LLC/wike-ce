### Descripción

Se ha observado que la política de contraseñas presenta debilidades. Ante este escenario, la probabilidad de éxito de ataques como fuerza bruta o adivinación de contraseñas se ve incrementada, permitiendo de esta forma el acceso no autorizado a la aplicación.

Es aconsejable implementar una regla de validación para las configuraciones que modifiquen el atributo de contraseñas en todo el aplicativo, aceptando como mínimo 14 dígitos combinados entre caracteres especiales, mayúsculas y minúsculas, o políticas similares. En caso de tener una política de contraseñas ya definida, implementarla correctamente para que el aplicativo la cumpla.

### Componentes Afectados

- https://www.cliente_url.com/modulo1/afectado1?id=1&time=now
    - Parámetro Afectado:  id
- https://www.cliente_url.com/modulo2/afectado2?cat=1&dir=/
    - Parámetro Afectado:  dir

### Detalles

El equipo de OffSec identificó la vulnerabilidad **Weak Password Policy** la cual se presenta ya que se ha detectado que la política de contraseñas implementada no es robusta, por lo que fue posible configurar contraseñas de §[x cantidad de caracteres, únicamente numéricos]§.

A continuación, se encuentra de manera detallada, como fue posible identificar dicha vulnerabilidad:

[REDACTAR]

### Impacto

Partiendo de esta situación, un usuario puede iniciar sesión en el aplicativo con una clave trivial, incrementando esto las probabilidades de que un atacante obtenga las credenciales de acceso de un usuario legítimo de la plataforma por medio de ataques de fuerza bruta.

### Remediación

Hackmetrix recomienda analizar la posibilidad técnica y de negocio de definir e implementar una política de contraseñas. Esto es fundamental para proteger los activos digitales y la información confidencial de una empresa.

Las directivas claras y robustas al momento de la gestión de contraseñas reducen significativamente el riesgo de compromisos en los servicios mediante ataques de baja complejidad, como la reutilización de contraseñas predecibles.

Una contraseña segura es la primera línea de defensa contra amenazas cibernéticas, y su implementación adecuada contribuye a mantener la integridad, confidencialidad y disponibilidad de los datos críticos de la organización. A continuación, una política de contraseñas segura debe contemplar los siguientes puntos:

1. **Longitud y Complejidad:**
    - Todas las contraseñas deben tener una longitud mínima de 14 caracteres.
    - Deben contener una combinación de los siguientes elementos:
        - Letras mayúsculas (A-Z).
        - Letras minúsculas (a-z).
        - Números (0-9).
        - Caracteres especiales (Por ejemplo, !, @, #, $, %, etc.).
2. **Cambio Regular de Contraseña:**
    - Se requiere el cambio de contraseña al menos cada 90 días.
    - Las contraseñas anteriores no deben ser reutilizadas en un período de al menos 8 cambios de contraseña.
3. **Protección de Contraseñas:**
    - Las contraseñas no deben compartirse con nadie, incluidos colegas, supervisores o personal de soporte técnico.
    - Las contraseñas no deben ser almacenadas en archivos de texto sin cifrar o en cualquier otro medio no seguro.

Además, se recomienda implementar los siguientes puntos con la finalidad de proporcionar a una base sólida para garantizar la seguridad de las cuentas del usuario y proteger datos sensibles contra accesos no autorizados provocados por parte de las acciones de los usuarios legítimos:

1. **Autenticación de Dos Factores (2FA):**
    - Se recomienda encarecidamente utilizar la autenticación de dos factores siempre que sea posible, especialmente para el acceso a sistemas críticos o sensibles.
2. **Lista Negra de Contraseñas:**
    - Mantener y aplicar una lista negra de contraseñas que contenga combinaciones comúnmente utilizadas, fácilmente predecibles o comprometidas en brechas de seguridad anteriores.
    - Prohibir el uso de contraseñas que figuren en la lista negra en cualquier sistema o aplicación dentro de la red de la organización.
    - Utilizar como referencia listas de contraseñas comunes publicadas en internet, como lo es, por ejemplo, https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/10-million-password-list-top-1000.txt.
3. **Elementos Prohibidos:**
    - Evitar el establecimiento de contraseñas que contengan uno o más de los siguientes elementos:
    - Información personal relacionada con el usuario, como nombres, fechas de nacimiento, lugares de nacimiento, cargos, etc.
    - Números de teléfono, números de casa o números de calle.
    - Nombres de familiares, cónyuges, hijos u otros seres queridos.

### Referencias

- CWE-521: https://cwe.mitre.org/data/definitions/521.html

