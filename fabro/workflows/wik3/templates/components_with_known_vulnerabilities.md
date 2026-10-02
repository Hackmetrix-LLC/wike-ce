### Descripción

Las versiones descontinuadas del software conllevan un grave riesgo de seguridad cuando se trata de servicios que contienen vulnerabilidades reportadas públicamente. Por lo general cuando se trata de versiones muy antiguas, las empresas encargadas de proveer los correspondientes parches de seguridad, dejan de dar soporte para dedicarse a realizarlo en versiones mas recientes del producto. Es común en muchas organizaciones encontrar el uso de versiones de software desactualizadas que ya cuentan con un gran listado de CVE’s públicos.

### Componentes Afectados

- https://www.cliente_url.com/modulo1/afectado1?id=1&time=now
    - Parámetro Afectado:  id
- https://www.cliente_url.com/modulo2/afectado2?cat=1&dir=/
    - Parámetro Afectado:  dir

### Detalles

| **Componente** | **Versión actual** | **Ultima versión** |
| --- | --- | --- |
| pentest1 | Password1!! | Administrator |
| pentest2 | Password2!! | Moderator |
| pentest3 | Password3!! | User |

### Impacto

Un atacante podría utilizar esta falta de actualización para atacar la plataforma mediante vulnerabilidades conocidas (expuestas públicamente en Internet) que afecten a los componentes desactualizados que la aplicación utiliza para su funcionamiento interno.

### Remediación

###El equipo de seguridad de Hackmetrix recomienda actualizar a la ultima version de § Joomla § actualmente soportada, así como también, realizar un update de los componentes instalados en la aplicación.### § EDITAR SEGUN COMPONENTE §

### Referencias

- Microsoft IIS 6.0: https://www.cvedetails.com/vulnerability-list/vendor_id-26/product_id-3436/version_id-13492/Microsoft-IIS-6.0.html
- Microsoft Windows Server 2003: https://www.cvedetails.com/version-search.php, https://www.cvedetails.com/vulnerability-list/vendor_id-26/product_id-7108/Microsoft-Windows-Server-2003.html
- The unfortunate reality of insecure libraries: https://www.aspectsecurity.com/research-presentations/the-unfortunate-reality-of-insecure-libraries

