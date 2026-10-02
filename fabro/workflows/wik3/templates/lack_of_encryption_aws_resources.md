### Descripción

AWS recomienda la encriptación como un control de acceso adicional para complementar los controles de acceso basados en identidad, recursos y red. El uso de la encriptación del lado del servidor en los servicios de AWS es la forma más fácil para que un cliente garantice que la encriptación se implemente correctamente y se aplique de manera coherente. Los clientes pueden controlar cuándo se descifran los datos, por quién y en qué condiciones, a medida que se transfieren hacia y desde sus aplicaciones y servicios de AWS.

### Componentes Afectados

- §Volumenes afectados§

### Detalles

El equipo de Hackmetrix identificó múltiples recursos de AWS que no se encuentran encriptados. A continuación, se pueden observar múltiples Volúmenes que no se encuentran encriptados:

§IMAGEN DE LOS VOLUMENES§

### Impacto

Mediante esta vulnerabilidad, un atacante podría leer los datos en texto claro debido a que las snapshots no están encriptadas en AWS. Estas pueden exponer datos sensibles a accesos no autorizados

### Remediación

El equipo de seguridad de Hackmetrix recomienda encriptar aquellos recursos que almacenen información sensible en AWS.

### Referencias

- Cifrado de Amazon EBS: https://docs.aws.amazon.com/es_es/ebs/latest/userguide/ebs-encryption.html
- CWE-311: https://cwe.mitre.org/data/definitions/311.html

