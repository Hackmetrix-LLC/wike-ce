### Descripción

Los Misconfigured Cloud Storage Buckets son un problema de seguridad común que puede exponer datos sensibles al público en Internet. Este problema ocurre cuando los contenedores de almacenamiento, utilizados para guardar datos en servicios de nube como Amazon S3, Google Cloud Storage, Azure Blob Storage, entre otros, están configurados incorrectamente, permitiendo un acceso no autorizado.

### Componentes Afectados

- https://www.cliente_url.com/modulo1/afectado1?id=1&time=now
    - Parámetro Afectado:  id
- https://www.cliente_url.com/modulo2/afectado2?cat=1&dir=/
    - Parámetro Afectado:  dir

### Detalles

El equipo de Hackmetrix identificó la vulnerabilidad **Misconfigured Cloud Storage Buckets** la cual se presenta debido a que se identificaron contenedores de almacenamiento utilizados para guardar datos en servicios de nube, configurados incorrectamente, permitiendo un acceso no autorizado.

A continuación, se encuentra de manera detallada, como fue posible identificar esta vulnerabilidad:

[REDACTED]

### Impacto

Mediante esta vulnerabilidad, un atacante tiene la capacidad de acceder y listar todos los archivos almacenados en el Bucket §[S3 / GCP / Firebase]§.

### Remediación

Hackmetrix recomienda establecer los permisos adecuados en los directorios que puedan ser accesibles de forma externa y evitar que los usuarios sin privilegios puedan listar el contenido almacenado. A continuación, se encuentra como puede ser implementado en §[AWS S3 / GCP Storage / Firebase Storage]§.

§[AWS S3]§

Hackmetrix recomienda seguir los siguientes pasos para configurar de manera segura el Bucket S3:

1. Inicia sesión en AWS Management Console: Ve a la consola de Amazon S3.

2. Selecciona el Bucket: En el panel de navegación de S3, haz clic en el nombre del bucket que deseas configurar.

3. Accede a la Configuración de Permisos: Dentro del dashboard del bucket, busca la sección de “Permisos”.

4. Bloqueo de Acceso Público: Encuentra la opción de “Bloqueo de acceso público” y haz clic en el botón de “Editar”.

5. Activa el Bloqueo: Verás varias opciones relacionadas con el acceso público. Activa todas para asegurarte de que el bucket no sea accesible públicamente. Las opciones incluyen:

- Bloquear todo el acceso público.
- Ignorar las ACLs (listas de control de acceso) públicas.
- Ignorar las políticas de Bucket públicas.
- Restringir el acceso público a través de nuevas políticas de Bucket y ACLs públicas.

6. Guarda los Cambios: Haz clic en “Guardar cambios” después de activar todas las opciones de bloqueo.

§[GCP Storage]§

Hackmetrix recomienda seguir los siguientes pasos para configurar de manera segura el GCP Storage:

1. Dentro de la Consola de Google Cloud Storage, seleccionar el bucket expuesto publicamente.

2. Acceder al apartado de **Permisos** en la pestaña de la consola.

3. Encontrar la entrada correspondiente a **allUsers** y elimínarla o ajusta el rol a **Sin acceso**.

§[Firebase Storage]§

Hackmetrix recomienda seguir los siguientes pasos para configurar de manera segura el Firebase Storage:

1. Accede a tu **Consola de Firebase**

2. Ve a la **Consola de Firebase** y selecciona tu proyecto.

3. **Navega a Firebase Storage.** En el menú, selecciona “Storage” para acceder a tus buckets de almacenamiento.

4. **Modifica las Reglas de Seguridad**. Dirígete a la pestaña “Reglas”. Edita las reglas para definir quién puede leer o escribir en tu almacenamiento. Un ejemplo para permitir el acceso solo a usuarios autenticados es:

*Code*

```
service firebase.storage {
  match /b/{bucket}/o {
    match /{allPaths=**} {
      allow read, write: if request.auth != null;
    }
  }
}
```

Es importante tener en cuenta que el código anterior permite que solo usuarios autenticados puedan leer o escribir en el Bucket. Es por ello, que el mismo debe ser modificado para **solamente permitir el acceso a cada path a los usuarios correspondientes**.

5. **Publica las Reglas Actualizadas**. Haz clic en “Publicar” para aplicar los cambios.

### Referencias

- Cloud Based Misconfiguration: https://mikey96.medium.com/cloud-based-storage-misconfigurations-critical-bounties-361647f78a29

