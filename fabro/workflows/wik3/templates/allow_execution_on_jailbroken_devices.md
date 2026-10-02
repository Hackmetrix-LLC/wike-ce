### Descripción

La vulnerabilidad Allow Execution on Jailbroken Devices se refiere a una brecha de seguridad que permite la ejecución de código o aplicaciones en dispositivos móviles que han sido sometidos a un proceso de jailbreak. Un jailbreak es una modificación no autorizada del sistema operativo de un dispositivo, como un smartphone o una tableta, que elimina las restricciones impuestas por el fabricante o el proveedor del sistema operativo.

Los dispositivos jailbroken tienen la capacidad de ejecutar software y realizar acciones que normalmente estarían prohibidas por el sistema operativo original. Esto incluye la instalación de aplicaciones no aprobadas por la tienda oficial de aplicaciones, el acceso a partes sensibles del sistema y la capacidad de alterar configuraciones críticas.

La vulnerabilidad Allow Execution on Jailbroken Devices podría surgir cuando una aplicación o servicio no valida adecuadamente si el dispositivo en el que se está ejecutando ha sido jailbreakeado o no. Como resultado, un atacante podría aprovechar esta situación para ejecutar código malicioso en el dispositivo, aprovechando la mayor libertad de acceso y control que tienen los dispositivos jailbroken.

Esta vulnerabilidad plantea riesgos significativos para la seguridad y privacidad de los usuarios, ya que podría permitir la instalación de malware, el robo de información personal o la toma de control del dispositivo. Los desarrolladores de aplicaciones y sistemas operativos deben implementar medidas de seguridad sólidas para detectar y prevenir la ejecución en dispositivos jailbroken, a fin de garantizar la integridad y la seguridad de los usuarios.

### Componentes Afectados

- https://www.cliente_url.com/modulo1/afectado1?id=1&time=now
    - Parámetro Afectado:  id
- https://www.cliente_url.com/modulo2/afectado2?cat=1&dir=/
    - Parámetro Afectado:  dir

### Detalles

Hackmetrix detectó la vulnerabilidad **Allow Execution on Jailbroken Device**. La aplicación **§APP NOMBRE§** puede ejecutarse sobre un dispositivo que ha sido sometido a un proceso de Jailbreak. A través de esta vulnerabilidad, fue posible acceder a directorios y archivos de configuración propios del aplicativo.

Con el fin de evidenciar dicha vulnerabilidad, el equipo de AppSec ejecutó los siguientes pasos:

**Paso 1:** Se realizaron las pruebas sobre la aplicación **§APP NOMBRE§**, desde un dispositivo móvil iOS con Jailbreak:

!§IMAGEN DE APP§(Aplicación instalada en dispositivo para pruebas)!

**Paso 2:** Hackmetrix accedió a la consola del dispositivo, por medio SSH en donde fue posible acceder a los archivos de la aplicación **§APP NOMBRE§**:

!§IMAGEN DE APP§(Acceso a los archivos de la aplicación)!

### Impacto

Si la aplicación mobile de **§APP NOMBRE§** es instalada en un dispositivo que se encuentra Jailbreakado, otras aplicaciones maliciosas podrían acceder al contenido del directorio de la aplicación. De esta manera, un atacante podría exfiltrar archivos internos que contengan información sensible almacenada por la aplicación.

### Remediación

Hackmetrix recomienda utilizar la biblioteca Jail Monkey para identificar si el dispositivo se encuentra Jailbreakeado. A continuación, se puede observar el pseudo-código, que permite identificar si la aplicación está corriendo en un dispositivo Jailbreakeado:

*Code:*

```
import JailMonkey from 'jail-monkey'if (JailMonkey.isJailBroken()) {
  // Alertar al usuario o denegar el uso de la app
}
```

[§REEMPLAZAR EN CASO DE APP EN REACT NATIVE§]

El equipo de AppSec recomienda aplicar un método interno que controle la existencia de un usuario con privilegios de root, al momento de ejecutar la aplicación a fines de evitar su acceso o ejecución. Para realizarlo se recomienda hacer uso de Jail Monkey, una librería basada en RootBeer para identificar sí el dispositivo Android o iOS se encuentra rooteado o con jailbreak. Esta librería puede ser instalada de la siguiente forma:

```
npm i jail-monkey --save
react-native link # Not required as of React Native 0.60.0
```

Luego, es necesario importar y llamar a la librería:

```
import JailMonkey from 'jail-monkey'if (JailMonkey.isJailBroken()) {
  // Alternative behaviour for jail-broken/rooted devices.
}
```

Para más información, se recomienda recurrir al repositorio original: https://github.com/GantMan/jail-monkey

### Referencias

- Jail-Mokey: https://github.com/GantMan/jail-monkey
- Jailbreak Detection: https://hanifmhd.medium.com/how-secure-is-your-mobile-app-part-2-setup-android-ios-f3f13810adb
- CWE-250: Execution with Unnecessary Privileges: https://cwe.mitre.org/data/definitions/250.html

