### Descripción

Con la finalidad de rastrear código y observar advertencias o errores en el proceso de desarrollo, comúnmente se utiliza el método Logging. En algunas ocasiones, los desarrolladores incluyen información sensible dentro de los registros de log. Cuando esto ocurre, otras aplicaciones pueden obtener acceso a dichos registros para obtener datos confidenciales.

### Componentes Afectados

- https://www.cliente_url.com/modulo1/afectado1?id=1&time=now
    - Parámetro Afectado:  id
- https://www.cliente_url.com/modulo2/afectado2?cat=1&dir=/
    - Parámetro Afectado:  dir

### Detalles

El equipo de AppSec detectó la vulnerabilidad **Insecure Logging**. Por medio de dicha vulnerabilidad se logró acceder a información sensible dentro de los logs generados por la aplicación durante el

tiempo de ejecución.

A continuación, a modo de PoC, se evidenciará cómo fue posible acceder a información sensible dentro de los logs generados por la aplicación **§com.test.package§**.

**Paso 1:** Hackmetrix realizó pruebas sobre la aplicación **§com.test.package§**, desde un dispositivo móvil rooteado:

INSERTAR IMAGEN (Aplicación instalada en dispositivo para pruebas)

**Paso 2:** Mediante la herramienta ADB (Android Debug Brigde), se logró acceder a los logs generados por la aplicación, utilizando el siguiente comando:

*Code:*

```
root@:/data/data/§com.test.package§ # logcat
```

A continuación, es posible observar la salida de dicha herramienta, en donde se puede visualizar datos sensibles tales como contraseñas y transferencias:

*Code:*

```
§PEGAR_LOG§
```

### Impacto

Un atacante que posea acceso al dispositivo, podría obtener acceso a información sensible del usuario como los datos de tarjeta. Asimismo, este tipo de vulnerabilidad podría ser aprovechada por una aplicación maliciosa que se encargue de capturar los logs generados por la aplicación **§com.test.package§** y enviarlos a un servidor controlado por el atacante.

### Remediación

Hackmetrix recomienda no mostrar datos sensibles (Como Cookies, Passwords, Tokens de Sesión, etc) en los registros de los logs. Para ello, es vital poder identificar donde se generan logs de manera insegura. A continuación, se detallan algunos de los métodos que generan logs en §[Kotlin / Flutter / React Native]§:

§[BORRAR ESCENARIOS QUE NO APLIQUEN]§

§[KOTLIN]§

Métodos de la clase **android.util.Log**:

- Log.v(String tag, String message): Log de verbose.
- Log.d(String tag, String message): Log de debug.
- Log.i(String tag, String message): Log de información.
- Log.w(String tag, String message): Log de advertencia.
- Log.e(String tag, String message): Log de error.
- Log.wtf(String tag, String message): Log de error fatal.

Métodos de la clase **java.util.logging.Logger** (si se redirigen a logcat):

- Logger.finest(String message): Log con nivel finest.
- Logger.finer(String message): Log con nivel finer.
- Logger.fine(String message): Log con nivel fine.
- Logger.config(String message): Log con nivel config.
- Logger.info(String message): Log con nivel info.
- Logger.warning(String message): Log con nivel warning.
- Logger.severe(String message): Log con nivel severe.

A continuación, podemos ver un ejemplo de un logging inseguro utilizando la clase **android.util.Log** y **java.util.logging.Logger**:

*Code:*

```
// Evitar registrar información sensible en Android
import android.util.Log;
import java.util.logging.*;public class Main {
    private static final Logger logger = Logger.getLogger(Main.class.getName());    public static void main(String[] args) {
        // Configurar un AndroidHandler para enviar logs a logcat (NO RECOMENDADO)
        Handler androidHandler = new AndroidHandler();
         androidHandler.setLevel(Level.ALL);
        logger.addHandler(androidHandler);        // Datos de ejemplo: usuario y token
        String usuario = "usuario_ejemplo";
        String token = "token_ejemplo";        // Logging inseguro utilizando java.util.logging.Logger para el usuario
        logger.info("Usuario logueado: " + usuario);
        // Logging inseguro utilizando android.util.Log para el token
        Log.i("MiApp", "Token de autenticación: " + token);
    }
} }
```

§[FIN DE KOTLIN]§

§[FLUTTER]§

Métodos que generan logs en **Flutter**:

- print()
- debug_print().

A continuación, podemos ver un ejemplo de un logging inseguro en **Flutter**:

*Code:*

```
import 'package:flutter/foundation.dart'; // Necesario para debugPrintvoid main() {
  // Datos de ejemplo: usuario y token
  String usuario = "usuario_ejemplo";
  String token = "token_ejemplo";  // Logging inseguro utilizando print para el usuario
  print("Usuario logueado: $usuario");  // Logging inseguro utilizando debugPrint para el token
  debugPrint("Token de autenticación: $token");
}
```

En Flutter también se puede utilizar el paquete ‘logger’ para gestionar los logs. A continuación, se encuentra un ejemplo de una implementación de código con el paquete logger de manera insegura:

*Code:*

```
import 'package:logger/logger.dart';
final Logger logger = Logger();void main() {
  // Datos de ejemplo: usuario y token
  String usuario = "usuario_ejemplo";
  String token = "token_ejemplo";  // Logging inseguro utilizando logger para el usuario
  logger.i("Usuario logueado: $usuario");  // Logging inseguro utilizando logger para el token
  logger.i("Token de autenticación: $token");
}
```

§[FIN DE FLUTTER]§

§[REACT NATIVE]§

Métodos que generan logs en **React Native**:

- console.log()
- console.warn()
- console.error()
- console.info()
- console.debug()

A continuación, podemos ver un ejemplo de un logging inseguro utilizando la clase ‘console.log’:

*Code:*

```
function main() {
  // Datos de ejemplo: usuario y token
  const usuario = "usuario_ejemplo";
  const token = "token_ejemplo";  // Logging inseguro utilizando console.log para el usuario
  console.log(`Usuario logueado: ${usuario}`);  // Logging inseguro utilizando console.log para el token
  console.log(`Token de autenticación: ${token}`);
}
main();
```

En React Native, se puede utilizar la biblioteca ‘react-native-logs’ para gestionar logs de manera segura. Sin embargo, se recomienda no mostrar información sensible mediante los logs.

§FIN DE REACT NATIVE]§

§[DEJAR EL SIGUIENTE TEXTO, INDISTINTAMENTE DE LA TECNOLOGIA]§

Por otra parte, a continuación se detallan otros métodos alternativos de creación de logs:

- Registro de errores no controlados en la aplicación mediante Thread.setDefaultUncaughtExceptionHandler() o Thread.setUncaughtExceptionHandler().
- Registro de eventos de la aplicación a través de Activity, Fragment o clases de servicio personalizadas.

En entornos de producción, se deben establecer los niveles de registro adecuados, evitando registrar información sensible, así como también, eliminar todos los logs no necesarios en dicho entorno. De igual forma, utilizar bibliotecas de registro más avanzadas o personalizadas que puedan enmascarar o cifrar datos sensibles antes de registrarlos, si es absolutamente necesario registrar dicha información para diagnóstico o depuración.

### Referencias

- CWE-532: https://cwe.mitre.org/data/definitions/532.html
- Insecure Logging: https://tools.androidtamer.com/Training/DIVA/01_Insecure_Logging/
