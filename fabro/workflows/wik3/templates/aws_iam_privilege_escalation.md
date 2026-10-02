### Descripción

Se ha identificado una vulnerabilidad de escalamiento de privilegios en el entorno de AWS. Varios usuarios del tenant tienen asignados permisos que les permiten obtener privilegios más altos de los que deberían poseer según sus roles asignados. Esto podría permitir que un usuario malintencionado o comprometido realice acciones que normalmente estarían restringidas, como modificar políticas de seguridad, acceder a recursos sensibles, o tomar control de otros servicios dentro del entorno.

Esta situación puede ocurrir debido a una configuración incorrecta de políticas IAM, donde los permisos otorgados son demasiado amplios o no están bien restringidos. La explotación de esta vulnerabilidad podría comprometer la seguridad y la integridad de la infraestructura en la nube, permitiendo que usuarios no autorizados realicen operaciones críticas.

### Componentes Afectados

- AWS IAM

### Detalles

El equipo de Hackmetrix ha identificado que varios usuarios de IAM tienen permisos excesivos que podrían permitirles elevar sus privilegios.

Hackmetrix clasifica la escalación de privilegios en dos categorías: Confirmada y Potencial. La clasificación "Confirmada" se asigna cuando, aunque no se tenga acceso directo al usuario, se puede verificar que es vulnerable. La categoría "Potencial" se utiliza cuando no se puede confirmar la vulnerabilidad debido a la falta de acceso al usuario afectado.

A continuación, se presentan dos tablas las cuales muestran los usuarios con privilegios **Confirmados** que permiten la escalación de privilegios y los usuarios con privilegios **Potenciales** que pueden permitir una escalación de privilegios:

**Usuarios con Escalación de Privilegios Confirmados**

| Usuario | Privilegios |
| --- | --- |
|  |  |
|  |  |

**Usuarios con Escalación de Privilegios Potencial**

| Usuario | Privilegios |
| --- | --- |
|  |  |
|  |  |

Por otra parte, se detalla como con los distintos permisos identificados es posible realizar una escalación de privilegios:

[FILTRAR SOLO LOS PERMISOS CONFIRMADOS]

[OBTENER DETALLES DE CADA PERMISO DE https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/]

[EJEMPLO]

**CreateNewPolicyVersion**

Un atacante con el permiso **iam:CreatePolicyVersion** puede crear una nueva versión de una política IAM a la que tenga acceso. Esto les permite definir sus propios permisos personalizados. Al crear una nueva versión de una política, esta debe establecerse como la versión predeterminada para que surta efecto. Aunque se podría pensar que se requiere el permiso **iam:SetDefaultPolicyVersion**, es posible incluir una bandera (–set-as-default) al crear una nueva versión que la establezca automáticamente como la nueva versión predeterminada. Esta bandera no requiere el permiso **iam:SetDefaultPolicyVersion**.

Un comando de ejemplo para explotar este método podría ser el siguiente:

```
aws iam create-policy-version –policy-arn target_policy_arn –policy-document file://path/to/administrator/policy.json –set-as-default
```

Donde el archivo **policy.json** incluiría un documento de política que permite cualquier acción contra cualquier recurso en la cuenta.

Este método de escalación de privilegios podría permitir a un usuario obtener acceso total de administrador en la cuenta de AWS.

[FIN DE EJEMPLO]

### Impacto

La explotación de la vulnerabilidad de escalamiento de privilegios en el entorno de AWS podría permitir a usuarios no autorizados realizar acciones que exceden sus permisos asignados. Esto podría resultar en el acceso, modificación o eliminación de datos sensibles, así como en la manipulación de políticas de seguridad críticas. El control total sobre los recursos en la nube podría comprometer la integridad, confidencialidad y disponibilidad de los servicios, lo que representa un riesgo significativo para la seguridad de la organización.

### Remediación

Hackmetrix recomienda revisar y ajustar las políticas de IAM para asegurar que los usuarios solo tengan los privilegios mínimos necesarios para realizar sus tareas. Implementar prácticas de "Least Privilege" (Principio de Mínimos Privilegios) y auditar regularmente las políticas de permisos para identificar y corregir configuraciones potencialmente peligrosas.

### Referencias

- CWE-250: https://cwe.mitre.org/data/definitions/250.html
- AWS-IAM Privilege Escalation: https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/

