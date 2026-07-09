# AGENTS.md

## 1. Propósito del proyecto

Construir una **aplicación de escritorio para Windows** que permita ejecutar un **escaneo manual** de conexiones salientes activas mediante un botón `Scan Now`, asociarlas a su proceso responsable, enriquecerlas con identidad del binario y contexto de red, y clasificarlas por **baseline, afinidad y riesgo potencial**.

Esta app **no es** un antivirus, un EDR, un IDS ni un firewall. No debe intentar capturar tráfico, monitorizar continuamente ni bloquear conexiones.

---

## 2. Decisiones cerradas

Estas decisiones **no están abiertas a debate** y ningún agente puede cambiarlas por iniciativa propia.

### Plataforma
- Objetivo exclusivo: **Windows** en v0.1.
- No introducir compatibilidad multiplataforma “por si acaso”.

### Stack
- Shell desktop: **Tauri 2**
- Backend: **Rust puro**
- Frontend: **HTML5 semántico + Tailwind CSS v4 + JavaScript ESM**
- Persistencia local: **SQLite**

### Prohibiciones de stack
No introducir:
- Electron
- React
- Vue
- Svelte
- Angular
- Next.js
- Node.js como backend principal
- Python como backend principal
- C# como backend principal
- sidecars como arquitectura base
- PostgreSQL/MySQL
- ORMs pesados sin justificación excepcional
- builders frontend innecesarios por costumbre

### Modelo funcional
- La interacción principal es **manual**: botón `Scan Now`.
- No convertir la app en daemon, tray app permanente, watcher continuo ni servicio residente obligatorio.

### Modelo de producto
La app:
- observa;
- enriquece;
- clasifica;
- prioriza para revisión humana.

La app no:
- bloquea tráfico;
- remedia automáticamente;
- aísla procesos;
- descarga herramientas externas para analizar;
- ejecuta binarios externos como parte de su lógica normal.

---

## 3. Modelo de dominio obligatorio

### Identidad
La identidad del sistema se compone siempre de estas cuatro dimensiones:
- `disk_truth`
- `trust_truth`
- `execution_truth`
- `behavior_truth`

No simplificar la identidad a solo nombre de proceso, solo ruta, solo firma o solo hash.

### Hash
- El **SHA-256 es obligatorio para baseline**.
- El hash no es opcional para consolidar baseline.
- El sistema debe soportar **caché de identidad** para no recalcular hash innecesariamente.
- Un cambio de hash debe activar **revalidación**, no ignorarse.

### Baseline
Estados válidos:
- `Unknown`
- `Candidate`
- `Observed_Local`
- `Baseline_Provisional`
- `Baseline_Consolidated`
- `Revalidation_Required`
- `Potentially_Dangerous`

Reglas obligatorias:
- No promocionar por puro “visto antes”.
- No promocionar por simple repetición temporal.
- No fusionar `Observed_Local` con `Baseline_Consolidated`.
- No absolver automáticamente binarios firmados.
- No auto-promocionar unsigned a baseline consolidado estándar sin intervención definida.

### Afinidad
- El baseline es **por afinidad**, no por IP exacta.
- No usar IP como identidad principal de normalidad.
- No usar el puerto como condición rígida única.
- Tener en cuenta hostname/FQDN, root domain, ASN, puerto y contexto.

### Hallazgos críticos
Un proceso con conexión activa cuyo binario no existe en disco o no puede resolverse correctamente debe tratarse como **hallazgo crítico** y no pasar por aprendizaje normal.

---

## 4. Arquitectura obligatoria

La arquitectura mínima debe respetar estos bloques:
- `collector`
- `enricher`
- `risk_engine`
- `baseline_manager`
- `identity_cache`
- `storage_sqlite`
- `exporter`
- `tauri_commands`

No meter toda la lógica en un único archivo o módulo gigante.

### Responsabilidades mínimas
- **Collector**: obtiene snapshot de conexiones salientes activas y las asocia a procesos.
- **Enricher**: resuelve ejecutable, identidad de archivo, hash, firma, ruta y contexto de red.
- **Risk Engine**: calcula baseline, afinidad, score, banda y recomendación.
- **Baseline Manager**: gestiona estados y transiciones.
- **Identity Cache**: evita recalcular hash/trust cuando no ha cambiado el archivo.
- **Storage**: persiste scans, findings, baseline y auditoría en SQLite.
- **Exporter**: exporta resultados a JSON y HTML.
- **Commands**: exponen la API hacia el frontend Tauri.

---

## 5. Contrato principal obligatorio

El comando principal es `scan_now`.

Debe devolver un JSON estable, versionado y compatible con `docs/scan-now-contract.json`.

Campos obligatorios de alto nivel:
- `scan_id`
- `schema_version`
- `started_at`
- `finished_at`
- `duration_ms`
- `host`
- `summary`
- `findings`

Cada finding debe incluir como mínimo:
- datos de conexión local/remota
- proceso
- identidad del binario
- trust/firma
- baseline state
- affinity
- intel
- risk

No renombrar arbitrariamente campos del contrato.
No devolver estructuras distintas entre ejecuciones equivalentes.

---

## 6. Artefactos obligatorios del repo

Si faltan, deben crearse. Si existen, deben actualizarse sin duplicar.

### Raíz
- `README.md`
- `AGENTS.md`
- `.gitignore`
- `.editorconfig`
- `docs/`
- `src-tauri/`
- `src/` o estructura equivalente del frontend

### Documentación obligatoria
- `docs/product-vision.md`
- `docs/architecture.md`
- `docs/threat-model.md`
- `docs/scoring-model.md`
- `docs/scan-now-contract.json`
- `docs/roadmap.md`
- `docs/sqlite-schema.md`
- `docs/testing-strategy.md`

### Backend mínimo esperado
- `src-tauri/src/commands/scan_now.rs`
- `src-tauri/src/core/collector.rs`
- `src-tauri/src/core/enricher.rs`
- `src-tauri/src/core/risk_engine.rs`
- `src-tauri/src/core/baseline_manager.rs`
- `src-tauri/src/core/identity_cache.rs`
- `src-tauri/src/core/storage.rs`
- `src-tauri/src/core/models.rs`
- `src-tauri/src/core/errors.rs`
- `src-tauri/src/core/exporter.rs`
- `src-tauri/src/main.rs`

### Frontend mínimo esperado
- `index.html`
- `src/js/app.js`
- `src/js/api.js`
- `src/js/state.js`
- `src/js/render/summary.js`
- `src/js/render/findings.js`
- `src/js/render/detail.js`
- `src/css/input.css`

### Persistencia
- migración inicial SQLite o script equivalente
- documentación del esquema
- índices razonables

### Testing
- tests del contrato `scan_now`
- tests de scoring
- tests de transiciones de baseline
- tests de afinidad
- tests de caché de identidad
- tests de clasificación de rutas

---

## 7. Reglas de implementación

## Backend Rust
- Separar dominio, IO, persistencia y comandos.
- Usar tipos claros, enums y structs explícitas.
- Usar `Result` y errores propios; evitar `unwrap()` en lógica real.
- Evitar `panic!` salvo tests o casos imposibles.
- Mantener funciones pequeñas y responsabilidades claras.
- Documentar invariantes importantes cuando aporten valor.

No hacer:
- lógica crítica en `main.rs`
- SQL caótico repetido en muchos sitios
- módulos gigantes con múltiples responsabilidades
- cadenas de `if` opacas e inmantenibles para el scoring

## Frontend
- HTML semántico y legible.
- JS ESM modular.
- Renderizado simple, explícito y mantenible.
- Sin framework SPA.
- Sin build chain compleja salvo necesidad real.

No hacer:
- un único HTML/JS monstruoso
- UI “tipo SOC” recargada
- copy alarmista
- features visuales vacías

## SQLite
- Esquema explícito y documentado.
- Tablas claras para scans, observations, identities, baseline, risk decisions, manual decisions e intel.
- Índices donde aporten valor.
- Migraciones o scripts de creación claros.

No hacer:
- tablas intermedias arbitrarias
- duplicación de datos sin motivo claro
- magia ORM innecesaria

## Intel externo
- Es opcional y selectivo.
- No debe ser requisito para que el motor local funcione.
- LLM solo para casos ambiguos y como apoyo interpretativo.

## Dependencias
Antes de añadir una dependencia, comprobar:
1. ¿Resuelve algo que el stack actual no cubre razonablemente?
2. ¿Reduce complejidad neta?
3. ¿Aporta seguridad o robustez real?
4. ¿Tiene sentido en Windows/Tauri/Rust para este proyecto?

Si la respuesta no es claramente sí, no añadirla.

---

## 8. Criterios de aceptación

Una tarea no está terminada hasta que deja código, tests y docs coherentes.

### Criterios globales de v0.1
La entrega debe cumplir simultáneamente:
- app Tauri 2 funcional en Windows
- frontend purista sin frameworks prohibidos
- `scan_now` compatible con `docs/scan-now-contract.json`
- hash SHA-256 operativo para baseline
- caché de identidad funcional
- baseline con estados válidos implementados
- distinción entre conocido, observado local, cambio detectado y potencialmente peligroso
- persistencia SQLite operativa
- tests críticos presentes
- documentación alineada con el código

### Aceptación por bloque
**Collector**
- recoge conexiones salientes activas visibles
- asocia observaciones a PID/proceso
- degrada con elegancia si una observación falla

**Enricher**
- resuelve ejecutable cuando es posible
- detecta archivo ausente o irresoluble
- calcula o recupera hash
- expone trust/firma
- clasifica la ruta correctamente

**Risk Engine**
- asigna banda válida
- produce `reason_codes`
- reacciona a cambios de hash con revalidación
- trata procesos huérfanos como críticos
- no depende de APIs externas para funcionar

**Baseline**
- no promociona por simple repetición ciega
- conserva estados intermedios
- soporta revalidación
- explica por qué un elemento está en un estado dado

**Frontend**
- permite lanzar `Scan Now`
- muestra resumen
- lista findings
- muestra detalle con hash, firma, destino, afinidad y motivos

### Autoevaluación obligatoria antes de cerrar tarea
Responder “sí” a todo:
- ¿He respetado el stack fijado?
- ¿He evitado dependencias innecesarias?
- ¿He generado archivos reales y no solo snippets?
- ¿He mantenido el contrato `scan_now` coherente y versionado?
- ¿He añadido o actualizado tests de lo tocado?
- ¿He actualizado la documentación afectada?
- ¿He evitado rediseñar el producto fuera del alcance?
- ¿No he convertido la app en un EDR/firewall/antivirus?
- ¿El resultado sigue siendo sobrio, ligero y explicable?

Si alguna respuesta es “no”, la tarea no está terminada.

---

## 9. Política de trabajo del agente

### Comportamiento esperado
- implementar de forma incremental;
- hacer cambios pequeños y reversibles;
- mantener repo legible;
- preferir claridad frente a “ingenio”;
- documentar dudas sin rediseñar la arquitectura;
- respetar este archivo como contrato de trabajo.

### Comportamiento prohibido
- improvisar arquitectura nueva;
- ampliar alcance sin pedirlo;
- introducir tecnología no autorizada;
- inventar features “por valor futuro”;
- sustituir decisiones cerradas por preferencias del agente.

### Regla final
Si un agente cree que puede “mejorar” el proyecto desviándose de este archivo, está equivocado por defecto.

La creatividad solo es válida dentro de estos límites.
Fuera de ellos, se considera desviación.

