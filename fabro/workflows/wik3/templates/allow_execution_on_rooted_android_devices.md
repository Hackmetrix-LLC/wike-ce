### Descripción

La vulnerabilidad Allow Rooted Android Device, trata sobre cómo una aplicación móvil, permite su ejecución ante un usuario con máximos privilegios de sistema, pudiendo de esta manera acceder a funciones restringidas y alterar el correcto funcionamiento de la aplicación. Esta al no contar con método propio, que realice una validación del entorno en donde será ejecutada, es susceptible a la modificación de configuración propia del aplicativo, en consecuencia de la modificación de archivos o directorios de configuración. A su vez es posible divulgar información, luego de que la aplicación sea ejecutada en un entorno modificado o no oficial.

La aplicación luego de ser instalada y al momento de ser ejecutada para iniciar una sesión debe validar si el entorno donde se esta ejecutando es un entorno oficial y fiable. Ya que al permitir una ejecución en un dispositivo con un usuario de privilegios altos como “root”, puede reducirse a una perdida o robo de datos del usuario, alteraciones de comportamientos, análisis forenses sobre un dispositivo perdido o extraviado.

En nivel de impacto depende del ultimo usuario que usó la aplicación al momento de una posible perdida del equipo. Es importante aclarar que es posible aprovechar esta vulnerabilidad desde un software de terceros que permita la ejecución de comandos, dado el contexto un atacante con acceso físico sería capaz de recopilar información sensible como primer foco de ataque.

### Componentes Afectados

- https://www.cliente_url.com/modulo1/afectado1?id=1&time=now
    - Parámetro Afectado:  id
- https://www.cliente_url.com/modulo2/afectado2?cat=1&dir=/
    - Parámetro Afectado:  dir

### Detalles

Hackmetrix detectó la vulnerabilidad **Allow Rooted Android Devices**. La aplicación **§APP NOMBRE§** puede ejecutarse sobre un dispositivo con privilegios de root. A través de esta vulnerabilidad, fue posible acceder a directorios y archivos de configuración propios del aplicativo.

Con el fin de evidenciar dicha vulnerabilidad, el equipo de AppSec ejecutó los siguientes pasos:

**Paso 1:** Se realizaron las pruebas sobre la aplicación **§APP NOMBRE§**, desde un dispositivo móvil rooteado:

!§IMAGEN DE APP§(Aplicación instalada en dispositivo para pruebas)!

**Paso 2:** Hackmetrix accedió a la consola del dispositivo, por medio de la herramienta **adb** (Android Debug Bridge), donde se ejecutó el siguiente comando, el cual se encargó de mostrar el proceso relacionado a la aplicación mobile de **§PROYECTO§**. Esto proceso se realizó con el fin de corroborar y evidenciar que la aplicación se encontraba corriendo dentro del dispositivo de prueba.

```
$ adb shell
# ps|grep -i 'NOMBRE APP'
u0_a72    2771  292   1162428 323952    ep_poll f7355d75 S com.example.app
```

**Paso 3:** Luego, para comprobar los privilegios del dispositivo, se ejecutó el comando **id**, el cual devuelve el identificador perteneciente al usuario del sistema.

```
# id
uid=0(root) gid=0(root) groups=0(root)
```

Como puede observarse, el dispositivo corría con privilegios de usuario root, es decir con máximos privilegios dentro del sistema.

### Impacto

Si la aplicación mobile de **§APP NOMBRE§** es instalada en un dispositivo que posee privilegios de usuario root, otras aplicaciones maliciosas podrían acceder al contenido del directorio **/data/data/§APP NOMBRE§/**. De esta manera, un atacante podría exfiltrar archivos internos que contengan información sensible almacenada por la aplicación.

### Remediación

El equipo de AppSec recomienda aplicar un método interno que controle la existencia de un usuario con privilegios de root, al momento de ejecutar la aplicación a fines de evitar su acceso o ejecución. Para realizarlo se recomienda hacer uso de la librería RootBeer, la cual a través de la siguiente clase y métodos internos es capaz de realizar un checkeo previo de características de sistema que detectan la presencia de un usuario con altos privilegios:

```
RootBeer rootBeer = new RootBeer(context);
if (rootBeer.isRooted()) {
    nopermitirLogin();
} else {
    permitirLogin();
}
```

En el caso de encontrar la presencia de vectores que permitan privilegios de **root**, se ejecutaría la función de ejemplo “NopermitirLogin”.

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

[§REEMPLAZAR EN CASO DE APP EN FLUTTER§]

El equipo de AppSec recomienda aplicar un método interno que controle la existencia de un usuario con privilegios de JailBreak/Root, al momento de ejecutar la aplicación a fines de evitar su acceso o ejecución. Para realizarlo se recomienda hacer uso de la librería RootBeer para dispositivos Android y IOSSecuritySuite para dispositivos iOS.

```
import 'package:flutter_jailbreak_detection/flutter_jailbreak_detection.dart';
 bool jailbroken = await FlutterJailbreakDetection.jailbroken;
 bool developerMode = await FlutterJailbreakDetection.developerMode; // android only.
```

### Referencias

- Executing with Unnecessary Privileges: https://cwe.mitre.org/data/definitions/250.html

