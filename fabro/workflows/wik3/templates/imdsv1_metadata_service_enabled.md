### Descripción

La vulnerabilidad Insecure IMDSv1 Metadata Service Enabled (CWE-16) se produce cuando el servicio de metadatos IMDSv1 (Instance Metadata Service version 1) está habilitado en una instancia de computación en la nube, lo que permite el acceso no seguro a metadatos sensibles. Esto ocurre porque IMDSv1 utiliza un protocolo de red inseguro y no autenticado, lo que facilita la explotación por parte de atacantes.

La activación de IMDSv1 puede tener consecuencias graves, como el acceso no autorizado a metadatos sensibles, como claves de API, credenciales de acceso y datos de configuración. Además, puede permitir ataques de elevación de privilegios y toma de control de la instancia, comprometiendo la seguridad y confidencialidad de los datos almacenados en la instancia.

### Componentes Afectados

- EC2 Instances
    - [REDACTAR]

### Detalles

El equipo de Hackmetrix identificó la vulnerabilidad Insecure **IMDSv1 Metadata Service Enabled** la cual se presenta debido a que se identificaron instancias AWS con la funcionalidad IMDSv1 habilitada.

[REDACTAR]

### Impacto

La activación de IMDSv1 representa un riesgo significativo porque permite el acceso no autorizado a metadatos sensibles, lo que puede llevar a la pérdida de datos confidenciales, la elevación de privilegios y la toma de control de la instancia, comprometiendo la seguridad de la infraestructura en la nube. Eventualmente, mediante la explotación de esta vulnerabilidad, un usuario malintencionado podría robar fácilmente las llaves de acceso de AWS mediante un ataque de Server-Side Request Forgery.

### Remediación

Para mitigar esta vulnerabilidad, Hackmetrix recomienda migrar a IMDSv2, que utiliza un protocolo de red seguro y autenticado. También es importante deshabilitar IMDSv1 en las instancias que no lo requieran e implementar controles de acceso y autenticación adicionales para proteger los metadatos. De esta manera, se puede minimizar el riesgo de explotación y proteger la integridad de los datos y la infraestructura en la nube.

### Referencias

- CWE-16: https://cwe.mitre.org/data/definitions/16
- Funcionamiento de IMDSv2: https://docs.aws.amazon.com/es_es/AWSEC2/latest/UserGuide/instance-metadata-v2-how-it-works.html
