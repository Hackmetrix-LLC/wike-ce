### Descripción

La ausencia de configuración de DMARC conlleva serias consecuencias para la seguridad y la reputación digital de una organización. DMARC es un protocolo de autenticación de correo electrónico que ayuda a prevenir el spoofing y el phishing, permitiendo que los servidores de correo verifiquen la autenticidad del remitente y asegurando que los mensajes no sean falsificados.

### Componentes Afectados

- https://www.cliente_url.com/modulo1/afectado1?id=1&time=now
    - Parámetro Afectado:  id
- https://www.cliente_url.com/modulo2/afectado2?cat=1&dir=/
    - Parámetro Afectado:  dir

### Detalles

Durante el análisis, el equipo de Hackmetrix observó que el mecanismo de autenticación por DMARC para validar que un mail es efectivamente perteneciente a la compañía, se encuentra deshabilitado.

§SCREENSHOT – MXTOOLBOX§

Debido a esto, fue posible una suplantación de dirección de email. Como prueba de concepto, se envió un email de parte de **§spoofed@domain.com§** a una dirección de correo de Hackmetrix:

§SCREENSHOT – SPOOFED MAIL§

### Impacto

Un atacante podría enviar correos electrónicos fraudulentos que parezcan provenir de dominios legítimos de la organización, lo que aumenta el riesgo de que los destinatarios caigan en estafas o revelen información confidencial. Esto puede afectar la confianza de los clientes y socios, dañar la reputación de la marca y generar pérdida de negocios.

### Remediación

Para remediar la falta de configuración de DMARC y fortalecer la seguridad del correo electrónico es necesario definir una política DMARC (p=none) inicial para realizar un seguimiento de los correos electrónicos que no pasan la autenticación sin tomar acciones drásticas. Esto permitirá recibir informes de fallos (RUA y RUF) para analizar la situación actual y determinar qué correos electrónicos se están falsificando.

### Remediación

Para corregir este problema de seguridad, el equipo de Hackmetrix recomienda implementar un registro DMARC en el DNS de los dominios afectados con una política adecuada.

**DMARC**

El siguiente ejemplo de registro DNS (tipo “TXT”) establece una política de rechazo para mensajes no autenticados:

Explicación de los parámetros:

- **v=DMARC1**: Indica la versión del protocolo.
- **p=reject**: La política que se aplica en caso de fallo de la autenticación (puede ser “none”, “quarantine” o “reject”).
- **sp=reject**: La política que se aplica en caso de fello de la autenticación en algún subdominio.
- **rua**: Email para recibir reportes adicionales.
- **ruf**: Email para reportes forenses (se considera opcional).
- **adkim=s/aspf=s**: Indica alineación estricta con DKIM/SPF (recomendado).
- **fo=1**: Establece reportar si llega a fallar cualquiera de los mecanismos.

Implementación gradual recomendada:

- **Fase 1**: “p=none” para monitorear sin afectar entregas.
- **Fase 2**: “p=quarantine” para poner en cuarentena mensajes no verificados.
- **Fase 3**: “p=reject” para rechazar mensajes no autenticados.

Es importante verificar que ya están implementados correctamente los registros SPF y DKIM antes de aplicar la política “quarantine” o “reject”.

En caso de que el dominio, no sea utilizado para servicios SMTP es recomendable configurar los siguientes valores para el DKIM y el SPF.

**SPF**

A través de la implementación de Ninguna IP está autorizada para enviar emails desde este dominio

*Value:*

**DKIM**

Al configurar este registro se declara que no hay firma DKIM, por lo tanto, cualquier intento de uso DKIM con un selector distinto fallará.

*Value:*

### Referencias

- What is DMARC?: https://abnormalsecurity.com/glossary/dmarc
- Prevent spoofing with DMARC: https://support.google.com/a/answer/2466580?hl=en
- How to protect domains that do not send email: ****https://www.cloudflare.com/es-la/learning/dns/dns-records/protect-domains-without-email/

### Referencias

- What is DMARC?: https://abnormalsecurity.com/glossary/dmarc
- Prevent spoofing with DMARC: https://support.google.com/a/answer/2466580?hl=en
