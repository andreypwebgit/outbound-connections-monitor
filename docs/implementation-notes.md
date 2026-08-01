# Implementation Notes

Decisiones de implementación tomadas donde la documentación normativa
(`docs/*.md` y los contratos internos de trabajo) define el modelo pero no
fija valores o detalles concretos. Este documento **no** redefine el modelo:
lo completa. Si alguna decisión contradice un documento normativo, gana el
documento normativo.

> Nota: las referencias a `AGENTS.md`/`AGENTS-STRICT.md` apuntan a los
> contratos internos para agentes de codificación con IA, que viven en el
> working tree local y **no se publican** en este repositorio. Las reglas de
> producto que imponen están reflejadas públicamente en `README.md`,
> `docs/product-vision.md` y el resto de documentos de `docs/`.

## 1. Baseline

### 1.1 Umbrales de promoción prudente

`baseline-lifecycle.md` exige promoción por señales y no por repetición ciega,
pero no fija umbrales. Valores elegidos (constantes en
`src-tauri/src/core/baseline_manager.rs`):

| Transición | Mínimos cuantitativos | Señales cualitativas requeridas |
|---|---|---|
| `Unknown -> Candidate` | 2 observaciones | ninguna (es "elemento repetido") |
| `Candidate -> Baseline_Provisional` | 5 observaciones y 3 días distintos | firma válida + ruta no sospechosa + afinidad media/alta |
| `Baseline_Provisional -> Baseline_Consolidated` | 15 observaciones y 7 días distintos | firma válida + ruta no sospechosa + afinidad media/alta |

- Un binario **unsigned** nunca auto-promociona más allá de `Candidate`; su vía
  es la validación manual (`Observed_Local`), conforme a la regla "no
  auto-promocionar unsigned a baseline consolidado estándar".
- "Afinidad sostenida" se aproxima evaluando la afinidad de la observación en
  cada scan: como la promoción exige varios días distintos, una afinidad baja
  en cualquiera de las evaluaciones bloquea la promoción de ese día.

### 1.2 Interpretación de la Regla 4 (cambio de hash)

La lista de transiciones del lifecycle solo enumera
`Baseline_Consolidated -> Revalidation_Required`, pero la Regla 4 ("un cambio
de hash en un elemento conocido debe empujar a Revalidation_Required") habla de
"elemento conocido". Se interpretan como "conocidos": `Observed_Local`,
`Baseline_Provisional` y `Baseline_Consolidated`. Los tres pueden transitar a
`Revalidation_Required` al detectarse cambio de hash.

Un cambio de hash sobre un elemento que solo llegó a `Unknown`/`Candidate` no
es "elemento conocido": la identidad nueva entra al ciclo normal como primera
aparición.

### 1.3 Identidad nueva tras cambio de hash

Cuando el archivo físico de un elemento conocido cambia de contenido, la
identidad nueva (el hash nuevo) **nace directamente en
`Revalidation_Required`**, no en `Unknown`: tratarla como primera aparición
neutra ocultaría el cambio. La identidad previa también se empuja a
`Revalidation_Required` (queda trazado en `audit_events`).

### 1.4 Salidas de `Revalidation_Required` y `Potentially_Dangerous`

El lifecycle no define transiciones de salida para estos estados. Sin una
salida, un falso positivo quedaría atrapado para siempre. Decisión: solo por
**decisión manual** (`revalidate_accept`), y siempre hacia `Candidate` para que
el elemento re-aprenda desde un estado intermedio (nunca directamente a
provisional/consolidado).

Tipos de decisión manual soportados por `record_manual_decision`:

- `validate_local`: `Candidate -> Observed_Local` (definida en el lifecycle).
- `revalidate_accept`: `Revalidation_Required | Potentially_Dangerous -> Candidate`.

### 1.5 Una evaluación de baseline por binario y por scan

`seen_count` cuenta **scans que observaron el binario**, no conexiones: un
navegador con 40 sockets no gana 40 puntos de "visto" en un scan. La
implementación memoiza la evaluación por SHA-256 dentro del scan.

### 1.6 Hallazgos críticos sin identidad no persisten

Un proceso huérfano sin hash no puede anclarse a `binary_identity`; su estado
`Potentially_Dangerous` viaja en el finding (efímero, `seen_count = 0`) y no
contamina el aprendizaje. Si el binario sí tiene entrada previa, la entrada se
marca `Potentially_Dangerous` de forma persistente ("Any -> Potentially_Dangerous").

## 2. Afinidad

### 2.1 Pesos de señales

`affinity-model.md` define señales y bandas (90-100 fuerte, 70-89 razonable,
40-69 débil, 0-39 desajuste) pero no pesos. Valores elegidos (constantes en
`src-tauri/src/core/affinity.rs`):

| Señal | Peso |
|---|---|
| `SAME_HOSTNAME` (excluyente con `SAME_ROOT_DOMAIN`) | +60 |
| `SAME_ROOT_DOMAIN` (subdominio nuevo, mismo ecosistema) | +40 |
| `SAME_ASN` (solo si hay dato de ASN) | +20 |
| `SAME_PORT` (puerto ya visto para el binario) | +30 |
| `COMMON_PORT` (puerto nuevo pero habitual: 80/443/53/...) | +10 |
| `ESTABLISHED_PATTERN` (perfil coincidente con `times_seen >= 3`) | +10 |
| `SAME_SIGNER` (continuidad de firmante tras cambio de hash) | +10 |

Propiedades garantizadas (con tests):

- el puerto por sí solo nunca supera `low` (regla 2 del modelo);
- `high` exige hostname exacto + puerto conocido + patrón repetido;
- sin histórico → `none` con señal `NO_HISTORICAL_PROFILE` (conservador).

Mapeo score → nivel: `>=90 high`, `70-89 medium`, `40-69 low`, `<40 none`.

### 2.2 Herencia de perfiles en revalidación

"Mismo hash o cambio razonablemente revalidable" (señal fuerte del modelo): si
el binario acaba de cambiar de hash, sus perfiles históricos son los de la
identidad previa. Se heredan para el cálculo (señal `INHERITED_HISTORY`) y, si
el firmante coincide, se añade `SAME_SIGNER`.

### 2.3 Registro de perfiles al final del scan

Los perfiles del scan actual se graban después de calcular toda la afinidad
del scan: un destino nuevo no debe coincidir consigo mismo dentro del mismo
scan.

### 2.4 Destinos privados

Una IP privada/link-local sin hostname no es "IP pura sospechosa": se marca
con la señal neutra `PRIVATE_NETWORK_DESTINATION` y no genera
`IP_ONLY_DESTINATION` ni penalización en el risk engine.

### 2.5 Root domain sin PSL

`extract_root_domain` deriva el eTLD+1 con heurística local (última etiqueta +
penúltima; sufijos de dos niveles habituales tipo `co.uk`, `com.mx`). No se
incluye la Public Suffix List completa para no depender de datos externos.
Limitación aceptada: sufijos exóticos pueden agrupar mal; la señal de hostname
exacto no se ve afectada.

### 2.6 ASN y país

Sin proveedor externo no hay fuente local fiable de ASN/país: viajan como
`null` en el contrato (permitido) y la señal `SAME_ASN` queda latente hasta que
exista intel opcional. El motor no depende de ella.

## 3. Identity cache

- **Nivel persistente (SQLite)**: clave de invalidación
  `volume_serial + file_id + file_size + last_write_time` (architecture.md §5).
  `volume_serial` y `file_id` se obtienen con `GetFileInformationByHandle`
  (FFI mínimo a kernel32, sin dependencias nuevas: la alternativa de
  `MetadataExt` solo existe en nightly).
- **Nivel por scan (memoria)**: memoización por path dentro de un scan.
- Trust se cachea por SHA-256: contenido idéntico ⇒ misma firma (salvo
  revocación; `verified_at` queda registrado para auditoría futura).
- `binary_id = sha256`. Dos versiones del mismo archivo físico son **dos
  filas** de `binary_identity`; el vínculo entre ellas es la clave física
  (`file_id + volume_serial`) o la ruta normalizada (minúsculas, el filesystem
  de Windows es case-insensitive).
- Un miss con identidad física conocida y hash distinto expone
  `hash_changed = true` + `previous_sha256`: es el trigger de revalidación.

## 4. Summary del contrato

El contrato define los campos del summary pero no su semántica exacta.
Decisión:

| Campo | Fuente |
|---|---|
| `accepted_count` | banda `known_safe` o `known_low` |
| `review_count` | banda `known_moderate` o `known_high` |
| `danger_count` | banda `potentially_dangerous` |
| `unknown_count` | baseline `Unknown` |
| `candidate_count` | baseline `Candidate` |
| `revalidation_count` | baseline `Revalidation_Required` |
| `orphaned_count` | `process.orphaned` |

(El comportamiento anterior mapeaba `candidate_count` a la acción `observe`,
mezclando conceptos de riesgo y baseline.)

## 5. Persistencia

- `scans.raw_json` guarda la respuesta completa del scan. Es la duplicación
  con "razón explícita" que permite `sqlite-schema.md`: exportación
  **reproducible desde lo persistido** (export-format.md) e historial en la UI
  con el shape exacto del contrato. Las tablas normalizadas siguen siendo la
  fuente para consultas analíticas.
- `affinity_profiles.hostname` se añade porque el modelo de afinidad usa
  hostname/FQDN como señal fuerte y el esquema mínimo solo traía root_domain.
- El build bundled de SQLite activa foreign keys por defecto: las escrituras a
  tablas hijas garantizan primero la fila mínima en `binary_identity`.
- Los eventos de auditoría cubren el logging mínimo de `error-handling.md`:
  `scan_started`, `observations_collected`, `collector_error`, `hash_error`,
  `baseline_transition`, `persistence_error`, `scan_exported`, `scan_finished`.
- Migración correctiva de datos (idempotente): las bases creadas por la lógica
  anterior contienen `Observed_Local` sin `manual_validation` (se usaba como
  "visto varias veces"). Como el lifecycle reserva ese estado a la validación
  manual, esas entradas vuelven a `Candidate` al abrir la base.

## 6. Contrato `scan_now`

- Los campos forenses introducidos en v0.3 (`process.services`, `ppid`,
  `parent_name`, `command_line`, `user`) se emitían ya en producción pero no
  estaban en `docs/scan-now-contract.json` (que tiene
  `additionalProperties: false`). Se añadieron al contrato para alinear
  documento y realidad; `schema_version` sigue siendo `v1` porque el JSON
  emitido no cambió de forma.
- `trust.signature_source` ahora cumple el enum del contrato
  (`embedded | catalog | none | unknown`) usando `SignatureType` de
  `Get-AuthenticodeSignature`; antes se emitía el valor fuera de contrato
  `"powershell"`. `chain_status` se mapea a `Trusted | Untrusted | Unknown`.
- `process.started_at` se rellena desde `GetProcessTimes` y se normaliza a
  RFC3339 UTC.

## 7. Enricher

- `SystemProcessMap` se construye con Toolhelp y APIs nativas de
  proceso/token/servicios. No depende de WMIC, CIM ni `tasklist`; los campos
  que Windows deniega quedan sin resolver y el scan continúa.
- `classify_path` compara **componentes** del path, no substrings del string
  completo: `C:\Windows\Temp\x.exe` es `Temp` (no `Windows`) y
  `C:\Program Files\ContemplateApp` ya no cae en `Temp`. Orden de evaluación:
  Temp → Downloads → Desktop → AppData → ProgramFilesX86 → ProgramFiles →
  Windows → UserProfile → Other.
- La lista de procesos protegidos (System, Registry, Memory Compression,
  MsMpEng.exe, csrss.exe, smss.exe, services.exe) se centraliza en
  `Enricher::is_protected_system_process` (heurística v0.3.1 conservada).

## 8. Risk engine

- Mantiene las heurísticas v0.3 (línea de comandos ofuscada, padre ofimático o
  script, proceso de usuario como SYSTEM) y añade los reason codes del modelo
  de scoring, incluidas señales que **reducen** score (`VALID_SIGNATURE`,
  `KNOWN_HASH`, `ESTABLISHED_BASELINE`, `HIGH_AFFINITY`,
  `LOCAL_OBSERVED`/`MANUAL_TRUST`).
- Los hallazgos críticos (huérfano o binario irresoluble no protegido) tienen
  suelo de score 80: ninguna señal positiva los absuelve
  (`potentially_dangerous` mínimo).
- `KNOWN_DESTINATION`/`NEW_DESTINATION` son códigos descriptivos derivados de
  las señales de afinidad y no puntúan por separado (la afinidad ya puntúa):
  el score sigue siendo trazable sin dobles conteos.
- Override de acción: baseline `Revalidation_Required` siempre recomienda
  `revalidate` (salvo banda crítica, que recomienda `investigate`).

## 9. Exportación

- `export_scan(scan_id, format)` reconstruye el scan desde `scans.raw_json`
  (reproducible, sin re-escanear ni cambiar estado) y escribe en `exports/`
  junto al repo (misma convención que `last_scan.json`; la carpeta está en
  `.gitignore`).
- El HTML es autónomo (CSS inline, sin recursos externos) y escapa todo valor
  proveniente del sistema.

## 10. Frontend

- Módulos ESM según AGENTS.md: `api.js` (única capa que toca
  `window.__TAURI__`), `state.js`, `render/summary.js`, `render/findings.js`,
  `render/detail.js` (+ `render/html.js` con helpers de escape/formato).
- Todo valor dinámico se escapa con `escapeHtml` antes de interpolarse
  (el código previo no escapaba nombres de proceso, rutas ni cmdline).
- Sin handlers inline (`onclick`) ni funciones globales: delegación de eventos
  con `data-action`.
- Las clases Tailwind se escriben siempre completas (nunca interpolación
  parcial) para que el escaneo de Tailwind v4 las genere.
- Tras una decisión manual, la UI actualiza el baseline de los findings del
  binario pero **no recalcula** el riesgo mostrado: el snapshot del scan es el
  que fue; el nuevo estado aplica en el siguiente escaneo.

## 11. Versionado

`Cargo.toml` y `tauri.conf.json` pasan a `0.4.0` (los manifests seguían en
0.1.0 mientras el README hablaba de v0.3.1). `app_version` del contrato sale
de `CARGO_PKG_VERSION`; el hostname real sale de `COMPUTERNAME`.

## 12. Build de producción y rutas de datos

- El `identifier` pasó de `com.tauri.dev` (rechazado por `tauri build`) a
  `com.apwebai.out-cxns-monitor`. La app no usaba el app-data dir de Tauri
  antes de este cambio, así que no hay migración de datos implicada.
- Las rutas de datos se resuelven una vez en el arranque (`AppPaths` en
  `core/paths.rs`, inyectado como estado):
  - dev (`debug_assertions`): `../` relativo al cwd de `tauri dev` — raíz del
    repo, comportamiento histórico que evita el hot-reload loop;
  - release: `%LOCALAPPDATA%\com.apwebai.out-cxns-monitor\` vía
    `app_local_data_dir()` (local, no roaming: el baseline es por máquina, no
    debe viajar entre equipos con el perfil).
  Sin esto, el binario instalado en Program Files moría al arrancar por
  intentar crear la DB en una ruta relativa no escribible.
- Ver `docs/build-and-distribution.md` para artefactos, WebView2 y SmartScreen.

## 13. v0.4.1

- **CI/CD**: workflows de GitHub Actions (`ci.yml` tests en push/PR;
  `release.yml` build + release automática en tags `v*` con checksums).
  `cargo test --locked` exige `Cargo.lock` actualizado en cada bump.
- **MITRE ATT&CK**: mapeo presentacional de reason codes a técnicas, solo en
  la UI (`render/detail.js`) para no tocar el contrato `scan_now`
  (`additionalProperties: false`). Referencia canónica del mapeo en
  `docs/scoring-model.md`. Solo correspondencias rigurosas.
- **Búsqueda en hallazgos**: filtro de texto en frontend
  (proceso/ruta/IP/hostname/dominio/sha/puerto/estado/banda), combinable con
  los filtros de categoría; al teclear solo se re-renderiza la lista para
  conservar el foco del input.
- **Roadmap del README**: el "modo residente (tray/ETW)" se retira
  explícitamente por contradecir la decisión cerrada de AGENTS.md (la app es
  de escaneo manual); su lugar lo ocupa la comparativa entre scans prevista
  para v0.5.
- **Enlaces externos de la UI**: los enlaces con `target="_blank"` no llegan
  al navegador por defecto dentro de la webview de Tauri 2; el comando
  `open_external` (rundll32 `url.dll,FileProtocolHandler`, URL validada, sin
  shell) los abre y `app.js` intercepta el click.

## 14. v0.5.0

### 14.1 Collector y procesos nativos

- `GetExtendedTcpTable` (`TCP_TABLE_OWNER_PID_ALL`) sustituye `netstat -ano`
  para TCP IPv4/IPv6. Cada familia degrada de forma independiente y solo se
  aborta el scan si fallan ambas.
- `GetExtendedUdpTable` enumera endpoints UDP con PID, pero la API no ofrece
  peer remoto. Por honestidad del contrato no se generan findings UDP sin
  destino; el número de endpoints queda en auditoría técnica.
- El mapa de procesos usa `CreateToolhelp32Snapshot`, `OpenProcess`,
  `QueryFullProcessImageNameW`, `GetProcessTimes`, token/`LookupAccountSidW`,
  `NtQueryInformationProcess(ProcessCommandLineInformation)` y
  `EnumServicesStatusExW`. Un proceso protegido conserva nombre/PPID y deja
  a `null` los campos que Windows deniegue.
- El hostname del equipo usa `GetComputerNameW`; no depende de que exista la
  variable de entorno `COMPUTERNAME`.
- Authenticode **permanece en PowerShell**: nativizar `WinVerifyTrust` y el
  catálogo no aporta complejidad neta favorable en esta iteración, mientras
  el caché por SHA-256 evita repetir la llamada en scans calientes.

### 14.2 Presupuesto de DNS y rendimiento

El DNS inverso dejó de ser secuencial. Las IP públicas se resuelven en
paralelo con presupuesto total de 200 ms y caché en memoria de proceso. Una
respuesta tardía se guarda para el próximo scan; el snapshot actual mantiene
`hostname/root_domain = null`, sin inventar datos.

Smoke local Windows (48 findings, caché de identidad completamente caliente):
**371 ms**. Un snapshot con binarios nuevos puede seguir tardando varios
segundos por Authenticode, comportamiento explícitamente aceptado para v0.5.

### 14.3 Comparativa entre scans

`get_scan_comparison(scan_id)` carga el payload actual y su predecesor desde
`scans.raw_json`; no modifica `scan_now` (`schema_version` continúa en `v1`).

- identidad de conexión: binario + protocolo + IP remota + puerto remoto;
- identidad de binario: SHA-256, con fallback a ruta y finalmente nombre si
  el binario no pudo resolverse;
- el estado TCP se compara aparte para marcar `CAMBIO` sin contarlo como una
  conexión nueva;
- los recuentos deduplican sockets equivalentes y el primer scan no muestra
  falsos badges `NUEVO` al carecer de referencia.

### 14.4 Gestión del baseline

`get_baseline_entries` es una proyección de lectura de identidades, trust,
contadores, validación y última decisión. Las mutaciones siguen pasando
exclusivamente por `BaselineManager`.

Nueva decisión manual requerida por producto:
`revoke_local_validation`: `Observed_Local -> Candidate`, con
`manual_validation = false`. `revalidate_accept` también limpia esa marca al
volver a `Candidate`; no se permite editar estados libremente.

### 14.5 Calidad

CI ejecuta `cargo fmt --check` y
`cargo clippy --locked --all-targets -- -D warnings` antes de los tests. La
suite v0.5.0 contiene 86 tests. No se añadieron crates ni dependencias JS.

## 15. v0.5.1

### 15.1 Precisión de `SUSPICIOUS_COMMAND_LINE`

La heurística anterior aplicaba `contains()` sobre toda línea de comandos y
trataba cualquier aparición de `bypass`, `hidden`, `nop` o `iex` como
sospechosa. Esto producía falsos positivos en aplicaciones Chromium/Electron:
su flag legítimo `--bypasscsp-schemes` se confundía con la política
`-ExecutionPolicy Bypass` de PowerShell.

Decisión:

- no se crea una allowlist para ChatGPT, ningún otro producto, ruta, hash o
  firmante;
- los indicadores se tokenizan y solo se evalúan si el proceso es
  `powershell`/`pwsh` o la línea invoca explícitamente esos intérpretes;
- los switches (`-EncodedCommand`, `-NoProfile`, `-NonInteractive`) y las
  expresiones (`iex`, `Invoke-Expression`) requieren tokens completos;
- `bypass` solo puntúa como valor de `-ExecutionPolicy`/`-ep`, y `hidden`
  como valor de `-WindowStyle`/`-w`, también en formas `=` o `:`;
- una coincidencia válida mantiene la penalización de 60 puntos.

Los payloads históricos en `scans.raw_json` no se recalculan: conservan la
evaluación reproducible que recibieron. Los nuevos scans usan la heurística
corregida. No cambian el contrato `scan_now`, el lifecycle de baseline ni el
esquema SQLite.

La suite v0.5.1 contiene 89 tests. No se añadieron crates ni dependencias JS.

## 16. v1.0.0

### 16.1 Completitud de evidencia y contrato v2

`scan_now` pasa a `schema_version: "v2"` y añade el bloque obligatorio
`coverage`. La clasificación se calcula en `core/coverage.rs` después del
enriquecimiento y antes de persistir:

- `complete`: collector TCP/UDP completo, ejecución elevada, sin warnings ni
  timeout DNS y con evidencia material/contextual completa en findings no
  protegidos;
- `partial`: el núcleo TCP existe, pero falta elevación o evidencia
  auxiliar/contextual;
- `degraded`: falta una familia TCP o identidad material de un finding no
  protegido.

La cobertura no modifica score, baseline ni recomendaciones. Las limitaciones
estables declaran que el scan es puntual, que UDP no aporta peer remoto, que
el intel externo está desactivado y que DNS tiene 200 ms de presupuesto.

`ScanNowResponse.coverage` es `Option` únicamente para deserializar y
reserializar históricos v1. El schema v2 lo exige, y UI, SQLite y exportador
no inventan cobertura al abrir un payload v1.

### 16.2 Distribución unsigned y supply chain

Microsoft Artifact Signing no está disponible para el proyecto y v1.0.0 se
publica sin firma Authenticode por decisión explícita del propietario. El
workflow no conserva configuración Azure ni scripts de firma inoperantes. La
ausencia de identidad de editor se declara en README, SECURITY, documentación
de distribución y notas de la propia release; checksums y attestation se
presentan solo como controles de integridad y procedencia.

Gates añadidos:

- tag exacto y cuatro versiones sincronizadas;
- acciones fijadas por SHA y Dependabot;
- `npm audit --audit-level=high`;
- test de política que impide reintroducir requisitos de Artifact Signing o
  afirmar que los binarios están firmados;
- checksums SHA-256, SBOM SPDX y GitHub artifact attestation;
- publicación solo después de completar todos los gates.

### 16.3 Calidad

La suite v1.0.0 contiene 101 tests: 80 unitarios, 11 de contrato y 10 de
integración SQLite. Se añadieron pruebas de fallo independiente del collector,
clasificación de cobertura, exportación y compatibilidad histórica v1/v2. No
se añadieron crates ni dependencias JS.

En debug, `tauri-plugin-log` escribe solo en stdout. El destino de archivo
predeterminado podía devolver `Access denied` en perfiles restringidos y
abortaba `npx tauri dev`; el terminal ya proporciona el log necesario y no
debe convertir el logging auxiliar en requisito de arranque.

## 17. Mantenimiento de dependencias posterior a v1.0.0

- Las acciones de CI/release permanecen fijadas por SHA y se actualizan a sus
  revisiones mantenidas; `checkout`, `setup-node` y `action-gh-release` pasan
  a runtimes Node 24 compatibles con los runners hospedados de GitHub.
- Tailwind CSS y su CLI se actualizan conjuntamente a 4.3.3 y se regenera el
  CSS versionado para mantener fuente y artefacto alineados.
- `rusqlite` pasa de 0.31 a 0.40 con SQLite bundled actualizado. Como esa
  versión ya no implementa `ToSql` para `u64`, `duration_ms` se convierte de
  forma comprobada a `i64` antes de persistir; un valor fuera del rango real
  de `INTEGER` se rechaza explícitamente.
- `sha2`, `serde`, `serde_json` y `tauri-plugin-log` se actualizan sin alterar
  el contrato `scan_now`, el esquema SQLite ni el comportamiento del motor.
- La suite queda en 102 tests: 80 unitarios, 11 de contrato y 11 de
  integración SQLite.

## 18. v1.0.1 de mantenimiento

v1.0.1 distribuye el mantenimiento de dependencias integrado después de
v1.0.0. Es una release de parche: no modifica el contrato `scan_now` v2, el
modelo de identidad, el lifecycle de baseline, afinidad, scoring, cobertura
ni el esquema SQLite.

La versión se sincroniza en `package.json`, `package-lock.json`,
`src-tauri/Cargo.toml`, la entrada `app` de `src-tauri/Cargo.lock` y
`src-tauri/tauri.conf.json`. La documentación de firma pasa a referirse a las
releases v1.x para que futuros parches no puedan dejar un aviso principal
obsoleto. La distribución sigue siendo deliberadamente unsigned: checksum,
SBOM y attestation aportan integridad y procedencia, no identidad de editor.
