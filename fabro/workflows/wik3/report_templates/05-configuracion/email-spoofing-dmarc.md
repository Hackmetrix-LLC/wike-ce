# Email Spoofing due to DMARC Misconfiguration (CWE-345) - {{Media | Baja}}

| Campo | Valor |
|---|---|
| **CVSS Vector** | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N` |
| **CVSS Score** | `{{7.0}}` |
| **CWE** | [CWE-345 – Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html) |
| **OWASP** | A05:2021 – Security Misconfiguration |
| **Estado** | {{Abierto}} |

## Descripción

El dominio carece de registros DMARC/SPF/DKIM correctamente configurados (o DMARC en
`p=none`), lo que permite a un atacante enviar correos suplantando el dominio legítimo de
la organización. Los receptores no pueden distinguir el correo falso del real, habilitando
phishing y fraude (BEC) altamente creíbles.

## Componentes Afectados

- Dominio de correo: `{{cliente.com}}`
- Registros DNS: `{{_dmarc.cliente.com}}`, `{{SPF}}`, `{{DKIM}}`

## Detalles

Se verificó la ausencia/debilidad del registro DMARC y se envió un correo suplantando el
dominio, que fue entregado en la bandeja de entrada.

**Paso 1 — Verificación de la configuración DNS**

```bash
dig +short TXT _dmarc.cliente.com
# (vacío)  ó  "v=DMARC1; p=none"   → no se rechazan correos no autenticados

dig +short TXT cliente.com   # revisar SPF (v=spf1 ... -all vs ~all/?all)
```

**Paso 2 — Envío de correo suplantado (Swaks)**

```bash
swaks --to victima@cliente.com \
      --from "soporte@cliente.com" \
      --header "Subject: Acción requerida en su cuenta" \
      --body "Estimado, confirme sus datos en el siguiente enlace..." \
      --server <mx-objetivo>
```

> _Figura {{N}}: correo recibido en la bandeja de entrada con remitente suplantado `@cliente.com`._

## Impacto

Permite campañas de phishing y fraude (Business Email Compromise) suplantando la identidad
de la organización ante clientes y empleados, con alto impacto reputacional y de fraude.

## Remediación

- Publicar SPF con `-all`, habilitar DKIM y configurar DMARC con `p=reject` (o `p=quarantine`
  como paso intermedio) tras una fase de monitoreo con reportes (`rua`/`ruf`).
- Alinear SPF/DKIM con el dominio `From` y revisar periódicamente los reportes DMARC.

## Referencias

- https://cwe.mitre.org/data/definitions/345.html
- https://dmarc.org/overview/
- https://owasp.org/Top10/A05_2021-Security_Misconfiguration/
