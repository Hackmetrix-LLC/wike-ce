### Descripción

Firebase es un Backend-As-A-Service principalmente para aplicaciones móviles. Se enfoca en eliminar el cargo de programar el back-end proporcionando un buen SDK así como muchas otras funcionalidades que facilitan la interacción entre la aplicación y el back-end.

Dentro de este sdk, se encuentra Firebase Realtime Database, el cual es una base de datos del tipo NoSQL que permite almacenar y sincronizar datos entre diversos usuarios.

Dicha base de datos posee permisos de lectura y escritura públicos, los cuales, desde una perspectiva de seguridad, es necesario que estén deshabilitados.

### Componentes Afectados

- https://www.cliente_url.com/modulo1/afectado1?id=1&time=now
    - Parámetro Afectado:  id
- https://www.cliente_url.com/modulo2/afectado2?cat=1&dir=/
    - Parámetro Afectado:  dir

### Detalles

§[REDACTAR]§

### Impacto

Un atacante puede llevar a cabo acciones de §lectura/escritura§ dentro de la base de datos de firebase de §nombre empresa§, de esta forma, es posible obtener datos sensibles, §y/o§ llevar a cabo una modificación de dichos datos, afectando directamente en la §confidencialidad e Integridad§ de los datos.

### Remediación

El equipo de Hackmetrix recomienda modificar las reglas de seguridad de firebase de la siguiente manera, para así evitar que un tercero lea la base de datos del sistema:

*Code:*

```
{
  "rules": {
    "<<path>>": {
    // Allow the request if the condition for each method is true.
      ".read": false,
      ".write": false
    }
  }
}
```

Asi como también, se recomienda ampliamente, eliminar la ApiKey de los distintos ficheros del sistema, evitando así, su uso por un atacante.

### Referencias

- Reglas de seguridad de Firebase: https://firebase.google.com/docs/rules?hl=es-419
- Comienza a usar las reglas de seguridad de Cloud Firestore: https://firebase.google.com/docs/firestore/security/get-started?hl=es-419

