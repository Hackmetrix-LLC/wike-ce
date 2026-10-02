# wik3

`wik3` es un workflow [Fabro](https://fabro.sh) que orquesta una evaluación
de seguridad caja-gris sobre un target descrito por un `engagement.yaml`.
El pipeline cubre reconocimiento, análisis pasivo, análisis activo
condicional, validación y encadenamiento de hallazgos, captura de evidencia,
revisión senior y entrega de artefactos. El reporte markdown lo edita el
operador.

Dos modos de target:

- `pasivo` — solo OSINT y correlación, cero tráfico al target.
- `activo` — agrega probing autorizado cuando el engagement lo permite
  (IDOR, SQLi/XSS/SSRF marker-based, JWT, login con credenciales,
  `browse.py` para SPAs).

## Estructura del repo

```
fabro/workflows/wik3/
  workflow.fabro              # grafo del pipeline
  workflow.toml               # config de run (sandbox, env, hooks, artifacts)
  engagement.example.yaml     # template comentado del schema
  prompts/                    # instrucciones de cada nodo
    detect-mode.md, recon.md, passive-analyze.md, active-analyze.md,
    validate-chain.md, senior-review.md, check-discoveries.md,
    coverage-scan.md, retest.md
  scripts/                    # helpers invocados desde los prompts
    load_engagement.sh, scope_guard.sh, vuln.sh, tools.sh,
    cred_append.sh, browse.py, screenshot.py, ask_user.sh, say.sh
  docker/                     # imagen fabro-agent
  dashboard/                  # UI del engagement
    server.py                 # backend (basic auth opcional + /admin/*)
    dashboard.html
  report_templates/           # plantillas de reporte por tipo de hallazgo
  templates/                  # plantillas de hallazgos

admin/dashboard/              # UI del operador
  server.py
  dashboard.html

report-now.sh                 # regenera el reporte desde un workspace ya corrido
engagements/, wik3/           # workspace local (gitignored)
```

`fabro/workflows/wik3-report/prompts` apunta al mismo directorio de prompts.

## Límites del agente

- **Read-only por defecto.** `safety.read_only_mode: true` se inyecta al
  crear un engagement. El agente no modifica datos preexistentes; si crea
  registros para probar algo, los documenta en `notes.jsonl` con tag `cleanup`.
- **`scope_guard.sh`** (hook `pre_tool_use`) bloquea requests fuera de scope
  y, en modo read-only, SQL DML/DDL, HTTP destructivo y shell destructivo.
- Los `retest.py` generados se marcan como no auto-ejecutables cuando
  verificar el hallazgo sería destructivo o ruidoso. El runner los saltea.

## Dashboard del engagement

Tres formas de crear un engagement:

1. **Generar con LLM** — pegar texto libre. El modelo arma el YAML, el
   operador lo edita y lo aprueba.
2. **Crear vacío** — sin scope, para importar un reporte previo.
3. **Importar reporte** — subir un PDF o texto. Se extraen hallazgos
   (título, severidad, info, `retest.py`) y, si el engagement está vacío,
   el scope.

La lista muestra una fila por engagement (nombre, estado, tipo, fecha,
findings, cadenas, acciones). Al entrar:

- **Findings** en tabs: validadas, posibles, ataques intentados, cadenas.
  Posibles muestra solo hallazgos con PoC. Falsos positivos y ataques sin
  PoC sólida van a ataques intentados. Se pueden borrar, re-testear o
  marcar como falso positivo en lote.
- **Modal del hallazgo**
  - Qué es: descripción, impacto y afectado. Si falta, se genera al abrir
    y se guarda en `meta.json`.
  - PoC: evidencia capturada o documentación generada desde
    `report_templates/`. Los bloques de código se pueden copiar.
  - Revisión humana: criticidad, nota obligatoria, validar o marcar falso
    positivo. El badge de la revisión automática no reemplaza esa decisión
    (confirmada, manual, o falta un recurso para probarla).
  - Chat sobre ese hallazgo. El historial queda guardado.
- **Scope** editable (in/out). Un `SCOPE_REQUEST` del agente se aprueba o
  se rechaza ahí.
- **Retests** — correr los `retest.py`, regenerarlos y ver el historial.
- **Mensajes** del operador: un modal que no se cierra hasta marcarlos
  como leídos.
- **Equipo** — visible para un team lead: pendientes de validar de su
  equipo.

## Dashboard del operador

Tres pestañas: **Flota**, **Dashboard** y **Equipos**.

- **Flota** — inventario con conteos por instancia (engagements, findings,
  pendientes, severidades) y alta/baja. Cada fila abre los engagements,
  sus findings y el historial de retests.
- **Dashboard** — porcentaje de validadas que no fueron falso positivo,
  porcentaje de validadas sobre el total, tiempo promedio de validación,
  gráfico semanal y tabla por persona. Filtros por ejercicio y por tipo.
- **Equipos** — equipo y rol (hacker o team lead). El lead ve los
  pendientes de su equipo en el dashboard del engagement.
- **Mensajes** — a una instancia o a todas.
- **Feedback** — falsos positivos con nota, exportable a CSV.
- **Branding** — logo y paleta, que el dashboard del engagement hereda.

El operador sincroniza findings desde las instancias y purga del store lo
que esas instancias ya no reportan.

## Corrida local

### Prerrequisitos

- [Fabro CLI](https://fabro.sh) instalado (`fabro doctor`).
- Docker. El sandbox por defecto usa la imagen `fabro-agent:latest`,
  construida desde `fabro/workflows/wik3/docker/Dockerfile`.
- `ANTHROPIC_API_KEY` exportada. Opcional: `SHODAN_API_KEY`,
  `CENSYS_API_ID`, `CENSYS_API_SECRET`, `GITHUB_TOKEN`,
  `BRAVE_SEARCH_API_KEY`. Si faltan, los prompts siguen.

### Quickstart

```bash
mkdir -p engagements
cp fabro/workflows/wik3/engagement.example.yaml engagements/engagement.my-app.yaml
# Editar scope, credenciales y reglas.

fabro run wik3 --goal ./engagements/engagement.my-app.yaml

ls wik3/my-app/
```

El slug sale del filename (`engagement.my-app.yaml` → `my-app`). Cada slug
tiene su workspace en `wik3/<slug>/`. El symlink `wik3/current` apunta al
engagement que está corriendo el agente. El dashboard usa el slug de la
URL, no ese symlink.

El schema comentado está en
[`fabro/workflows/wik3/engagement.example.yaml`](fabro/workflows/wik3/engagement.example.yaml).

Para regenerar el reporte con lo que ya hay en el workspace, sin volver a
correr recon, análisis ni validación:

```bash
./report-now.sh my-app
```

### Dashboard local

```bash
python3 fabro/workflows/wik3/dashboard/server.py \
  --host 127.0.0.1 --port 8666 --wik3-root ./wik3
```

Abrir `http://127.0.0.1:8666`. Sin `WIK3_DASHBOARD_PASSWORD` no hay basic
auth. CRUD, modal de findings, retests e import de PDF funcionan. Lanzar
o frenar el pipeline desde el dashboard requiere el entorno donde corre
el servicio del agente.

## Notas

- `engagements/` y `wik3/` están en `.gitignore`. Ahí van credenciales y
  artefactos de cada corrida.
- La fuente de verdad del engagement es
  `engagements/engagement.<slug>.yaml`. El dashboard lee ese YAML. La
  carpeta del workspace se crea en el primer acceso.
- `wik3/current` indica qué engagement corre el agente. No cambia lo que
  muestra el dashboard.
- Volver a correr el mismo slug conserva `vulns/`, `discovery/queue.jsonl`,
  `creds/vault.jsonl`, `notes.jsonl`, `convo/` y `retest-runs/`. Borrar
  `wik3/<slug>/` empieza de cero.
