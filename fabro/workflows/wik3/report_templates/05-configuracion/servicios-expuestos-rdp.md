# Public Remote / Administrative Services Exposed (CAPEC-555) - {{Alta}}

| Campo | Valor |
|---|---|
| **CVSS Vector** | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N` |
| **CVSS Score** | `{{8.8}}` |
| **CWE / CAPEC** | [CWE-284 – Improper Access Control](https://cwe.mitre.org/data/definitions/284.html) / [CAPEC-555](https://capec.mitre.org/data/definitions/555.html) |
| **OWASP** | A05:2021 – Security Misconfiguration |
| **Estado** | {{Abierto}} |

## Descripción

Servicios de administración/acceso remoto (RDP, SSH, bases de datos, paneles de gestión)
están expuestos directamente a Internet sin restricción de red. Esto los convierte en
objetivo de fuerza bruta, explotación de vulnerabilidades conocidas (p. ej. BlueKeep
CVE-2019-0708 en RDP) y acceso no autorizado.

## Componentes Afectados

- `{{IP/host}}:{{3389 (RDP) / 22 (SSH) / 3306 (MySQL) / ...}}`

## Detalles

Se identificó el servicio `{{RDP}}` expuesto públicamente.

**Paso 1 — Descubrimiento del servicio expuesto**

```bash
nmap -Pn -sV -p 3389,22,3306 {{IP_OBJETIVO}}
```

```text
PORT     STATE SERVICE       VERSION
3389/tcp open  ms-wbt-server Microsoft Terminal Services
# servicio de administración remota accesible desde Internet
```

> _Figura {{N}}: servicio de acceso remoto accesible públicamente (consola/login expuesto)._

## Impacto

Exposición a fuerza bruta de credenciales y a exploits de vulnerabilidades conocidas del
servicio, pudiendo derivar en acceso no autorizado y compromiso del servidor.

## Remediación

- Restringir el acceso a servicios administrativos por red: VPN, bastion host, listas de
  IP permitidas y firewall (no exponer a 0.0.0.0/0).
- Aplicar MFA, deshabilitar servicios innecesarios y mantenerlos parcheados.
- Monitorear intentos de acceso y aplicar rate-limiting/bloqueo.

## Referencias

- https://capec.mitre.org/data/definitions/555.html
- https://cwe.mitre.org/data/definitions/284.html
- https://owasp.org/Top10/A05_2021-Security_Misconfiguration/
