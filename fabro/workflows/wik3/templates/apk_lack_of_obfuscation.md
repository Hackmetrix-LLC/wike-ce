### Descripción

Desde el estado productivo de la aplicación en formato APK, no se debe poder generar una version de desarrollo ya que esta situación, expone el código fuente completo del proyecto móvil, luego de aplicar técnicas de ingeniería inversa, se fue posible entender funciones internas, extraer datos sensible partiendo desde un archivo con formato y extensión APK.

### Componentes Afectados

- https://www.cliente_url.com/modulo1/afectado1?id=1&time=now
    - Parámetro Afectado:  id
- https://www.cliente_url.com/modulo2/afectado2?cat=1&dir=/
    - Parámetro Afectado:  dir

### Detalles

Hackmetrix logró obtener el código fuente del proyecto **§PROYECTO§** a partir del archivo de instalación en formato .APK brindado en el Scope.

A continuación se evidencia el resultado obtenido luego de aplicar ingeniería reversa sobre el aplicativo:

El equipo de AppSec procedió a utilizar la herramienta JADX-GUI con la finalidad de poder visualizar el código fuente de la aplicación como se muestra en la siguiente imagen:

!§ACA-VA-LA-IMAGEN-(Código fuente java sin ofuscar.)§!

### Impacto

Un atacante podría recopilar información grabada en el código fuente, obtener parámetros direcciones URL, puertos, nombres de clases y funciones del aplicativo en el estado de desarrollo a partir del producto final en formato .APK, de esta manera también es posible recopilar la aplicación y volver a distribuirla, dañando la imagen y credibilidad de la compañía.

### Remediación

Hackmetrix recomienda aplicar técnicas de ofuscación con el objetivo de dificultar el entendimiento del modelo del aplicativo y sus funciones internas. Hackmetrix recomienda implementar ProGuard para plataformas Android.

### Referencias

- CWE-656: https://cwe.mitre.org/data/definitions/656.html
- ProGuard: https://www.guardsquare.com/es/productos/proguard
- Open Source Code Obfuscation Tool for Protecting iOS Apps: https://www.polidea.com/blog/open-source-code-obfuscation-tool-for-protecting-ios-apps/
- Protecting Java Code Via Code Obfuscation: http://www.cs.arizona.edu/~collberg/Research/Students/DouglasLow/obfuscation.html
- Open Source Obfuscators in Java: http://java-source.net/open-source/obfuscators
- Cracking Java byte-code encryption: http://www.javaworld.com/javaworld/javaqa/2003-05/01-qa-0509-jcrypt.html

