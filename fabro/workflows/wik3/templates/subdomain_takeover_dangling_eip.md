### Descripción

Se identificó una vulnerabilidad en Route53 donde un registro DNS de tipo A apunta a una IP efímera (Elastic IP) no asignada en AWS. Esto permite a un atacante reclamar la IP y tomar control del subdominio asociado (subdomain takeover), pudiendo redirigir tráfico, alojar contenido malicioso o realizar ataques de phishing.

### Componentes Afectados

- Dominio.afectado

### Detalles

El equipo de Hackmetrix realizo la siguiente consulta para verificar la resolución DNS del §subdominio§

§FOTO DIG A SUBMINIO§

Posteriormente, se utilizo el siguiente comando de AWS CLI para comprobar si la IP esta asignada en el Elastic IP pool de AWS 

§IMAGEN DE LA IP NO ASIGNADA A NINGUN RECURSO§

Como podemos observar, obtenemos un **InvalidAddress.NotFount**, indicando que no esta asignada a ningún recurso, y por lo tanto, puede ser reclamada por cualquier persona.

### Impacto

Un atacante puede tomar control total del subdominio afectado, interceptar tráfico legítimo y acceder a datos sensibles como cookies o tokens si el subdominio es utilizado activamente. Además, podría alojar contenido malicioso (phishing, malware), dañar la reputación de la organización o realizar ataques de ingeniería social aprovechando la confianza en el dominio.

### Remediación

Hackmetrix recomienda eliminar el registro dangling. 

1. Obtener el ID de la zona hospedada en Route53:

```
aws route53 list-hosted-zones --query 'HostedZones[?Name==`<dominio>.`].Id'
```

1. Borrar el registro A para evitar que apunte a una IP no asignada:

```
aws route53 change-resource-record-sets --hosted-zone-id <zone-id> --change-batch '{"Changes":[{"Action":"DELETE","ResourceRecordSet":{"Name":"<subdominio>.","Type":"A","TTL":<ttl>,"ResourceRecords":[{"Value":"X.X.X.X"}]}}]}'
```

### Referencias

- AWS Route53 - Protección contra registros dangling: https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/protection-from-dangling-dns.html
- OWASP - Subdomain Takeover: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover
