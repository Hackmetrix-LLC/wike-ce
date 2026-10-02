### Descripción

Algunos lenguajes de programación, como Python o Javascript, vienen con un método fácil, más o menos oficial, de instalar dependencias para sus proyectos. Estos instaladores suelen estar vinculados a repositorios de códigos públicos donde cualquiera puede cargar libremente paquetes de códigos para que otros los utilicen.

Estas herramientas son:

- Node: npm y el registro npm
- Python: pip usa PyPI (Python Package Index)
- Ruby: gem utiliza RubyGems.

Al descargar y usar un paquete de cualquiera de estas fuentes, básicamente está confiando en que su editor ejecutará el código en su máquina. Entonces, esta confianza ciega puede ser explotada por actores malintencionados.

Ninguno de los servicios de alojamiento de paquetes puede garantizar que todo el código que cargan sus usuarios esté libre de malware. Investigaciones anteriores han demostrado que el typosquatting, un ataque que se aprovecha de errores tipográficos en los nombres de paquetes populares puede ser increíblemente eficaz para obtener acceso a PC aleatorias en todo el mundo. Otras rutas de los dependency supply-chain attacks conocidas incluyen el uso de varios métodos para comprometer los paquetes existentes o la carga de código malicioso con los nombres de dependencias que ya no existen.

El gestor de paquetes npm permite que código arbitrario se ejecute automáticamente al instalar el paquete, lo que permite crear fácilmente un paquete Node que recopile información básica sobre cada máquina en la que está instalado a través de su script de preinstalación, por ejemplo.

Desde errores puntuales cometidos por los desarrolladores en sus propias máquinas, hasta servidores de compilación internos o basados en la nube mal configurados, hasta tuberías de desarrollo sistémicamente vulnerables, una cosa esta clara: ocupar nombres de paquetes internos válidos es un método casi seguro para entrar en las redes de organizaciones, obteniendo la ejecución remota de código y posiblemente permitiendo a los atacantes agregar puertas traseras durante las compilaciones.

### Componentes Afectados

- https://www.cliente_url.com/modulo1/afectado1?id=1&time=now
    - Parámetro Afectado:  id
- https://www.cliente_url.com/modulo2/afectado2?cat=1&dir=/
    - Parámetro Afectado:  dir

### Detalles

El equipo de seguridad de Hackmetrix identificó que [CLIENTE] expone los nombres de paquetes propios de la empresa, los cuales no se encuentran registrados en fuentes públicas como pueden ser npmjs. Este, en conjunto con otros factores, permiten explotar una vulnerabilidad Dependency Confusion.

Mediante la explotación de este hallazgo, es posible obtener ejecución remota de comandos en los ordenadores de los desarrolladores de la empresa e incluso en el servidor que implemente el paquete.

A continuación, se detalla paso a paso cómo se puede identificar y explotar la vulnerabilidad.

**Paso 1:** A través de técnicas de OSINT y búsqueda avanzada en GitHub se detectó la presencia de varios repositorios públicos en GitHub pertenecientes a [CLIENTE], que, si navegamos hacia el siguiente repositorio: [GIT]/package.json, podemos encontrar el archivo package.json:

[redactar]

### Impacto

Un atacante puede tomar control de todos los servicios que interactúen con los paquetes de [Cliente], logrando ejecución remota de comandos, en el contexto del usuario que instale dicho paquete, afectando críticamente la confidencialidad, integridad y disponibilidad de la información e infraestructura de la organización.

### Remediación

En base al caso identificado, el equipo de Hackmetrix recomienda implementar el uso de un prefijo de alcance en combinación con la configuración del registro que permite especificar la fuente de origen de cada paquete que se instala o actualiza. Esto permite prevenir ataques de sustitución a través del registro público. Estas opciones se pueden configurar para cada proyecto o una máquina completa usando un archivo “.npmrc”.

Utilice las funciones de verificación del lado del cliente. Más allá de la protección que ofrece la administración cuidadosa de las fuentes, los administradores de paquetes proporcionan funciones adicionales de verificación del lado del cliente para proteger contra supply chain attacks. Entre ellas se incluyen opciones como la fijación de versiones y la verificación de la integridad. La fijación de versiones se recomienda como la mitigación de referencia y es compatible con la mayoría de clientela. Especificar versiones precisas para paquetes y dependencias transitivas, en lugar que un rango abierto (“3.5.4” en lugar de “> = 3.5” o “3.5. *”), mitigará el ataque de actualización o degradación. Sin embargo, no evitarán un índice comprometido de servir un paquete alternativo y afirmar que es la misma versión.

### Referencias

- Dependency Confusion: https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610
- Dependency Confusion Exploitation: https://www.blazeinfosec.com/post/dependency-confusion-exploitation/
- 3 Ways to Mitigate Risk When Using Private Package Feeds: https://azure.microsoft.com/en-gb/resources/3-ways-to-mitigate-risk-using-private-package-feeds/
- Dependency Confusion: A new thir-party risk for the software factory:https://www.contrastsecurity.com/security-influencers/dependency-confusion-a-new-third-party-risk-for-the-software-factory
- Detect and prevent dependency confusion attacks on npm to maintain supply chain security:https://snyk.io/blog/detect-prevent-dependency-confusion-attacks-npm-supply-chain-security/

