# Scoring Model

## Objetivo

Asignar a cada finding una banda de riesgo potencial y una recomendación explicable, sin depender de reglas opacas.

## Bandas válidas

- `known_safe`
- `known_low`
- `known_moderate`
- `known_high`
- `potentially_dangerous`

## Estados de baseline válidos

- `Unknown`
- `Candidate`
- `Observed_Local`
- `Baseline_Provisional`
- `Baseline_Consolidated`
- `Revalidation_Required`
- `Potentially_Dangerous`

## Señales que reducen riesgo

- hash conocido y estable;
- firma válida y trust coherente;
- ruta normal;
- alta afinidad;
- patrón repetido y explicable;
- baseline consolidado;
- validación manual previa;
- ausencia de señales negativas externas.

## Señales que elevan riesgo

- hash nuevo;
- firma inválida, ausente o incoherente;
- ruta sospechosa (`Temp`, `AppData`, `Downloads`, etc.);
- archivo ausente o proceso huérfano;
- destino por IP pura;
- afinidad baja;
- dominio/ASN no esperado;
- puerto raro o patrón atípico;
- reputación externa negativa;
- ejecutable del sistema fuera de su ruta normal.

## Score interno orientativo

Escala sugerida de 0 a 100:
- 0–19 → `known_safe`
- 20–39 → `known_low`
- 40–59 → `known_moderate`
- 60–79 → `known_high`
- 80–100 → `potentially_dangerous`

## Reason codes sugeridos

- `KNOWN_HASH`
- `NEW_HASH`
- `VALID_SIGNATURE`
- `INVALID_SIGNATURE`
- `UNSIGNED_BINARY`
- `EXPECTED_PATH`
- `SUSPICIOUS_PATH`
- `HIGH_AFFINITY`
- `LOW_AFFINITY`
- `KNOWN_DESTINATION`
- `NEW_DESTINATION`
- `IP_ONLY_DESTINATION`
- `BAD_REPUTATION_SIGNAL`
- `ORPHANED_IMAGE`
- `MANUAL_TRUST`
- `REVALIDATION_REQUIRED`
- `LOCAL_OBSERVED`

## Acciones recomendadas válidas

- `ignore`
- `observe`
- `review`
- `revalidate`
- `investigate`

## Reglas obligatorias

- el score debe ser trazable a señales concretas;
- un cambio de hash no debe ignorarse;
- `Observed_Local` no equivale a baseline consolidado;
- el riesgo no puede depender únicamente de Intel externo;
- un proceso huérfano debe elevarse a hallazgo crítico.

## Mapeo a MITRE ATT&CK (presentacional)

Algunos reason codes se corresponden con técnicas de MITRE ATT&CK. El mapeo
es **informativo/presentacional** (se muestra en la UI): no forma parte del
contrato `scan_now` ni altera el score. Solo se mapean correspondencias
rigurosas; un reason code sin correspondencia clara no se fuerza.

| Reason code | Técnicas |
|---|---|
| `SUSPICIOUS_COMMAND_LINE` | T1059 (Command and Scripting Interpreter), T1027 (Obfuscated Files or Information) |
| `OFFICE_SPAWNED_NETWORK_PROCESS` | T1566.001 (Spearphishing Attachment), T1204.002 (User Execution: Malicious File) |
| `SCRIPT_SPAWNED_NETWORK_PROCESS` | T1059 (Command and Scripting Interpreter) |
| `USER_PROCESS_AS_SYSTEM` | T1036 (Masquerading) |
| `UNSIGNED_SYSTEM_PROCESS` | T1036.005 (Match Legitimate Name or Location) |
| `SYSTEM_PATH_BUT_NOT_MICROSOFT` | T1036.005 (Match Legitimate Name or Location) |
| `INVALID_SIGNATURE` | T1036.001 (Invalid Code Signature) |
| `ORPHANED_IMAGE` | T1070.004 (Indicator Removal: File Deletion) |
| `FILE_MISSING` | T1070.004 (Indicator Removal: File Deletion) |
| `SUSPICIOUS_PATH` | T1204.002 (User Execution: Malicious File) |

La implementación de referencia vive en `src/js/render/detail.js`
(`MITRE_TECHNIQUES`); si se amplía el mapeo, actualizar ambos.

### Detección contextual de línea de comandos

`SUSPICIOUS_COMMAND_LINE` se reserva para indicadores PowerShell reconocidos
como argumentos completos dentro de `powershell`/`pwsh` o de una invocación
explícita a esos intérpretes. Incluye `-EncodedCommand`, `-NoProfile`,
`-NonInteractive`, `Invoke-Expression`, `-ExecutionPolicy Bypass` y
`-WindowStyle Hidden`, con sus abreviaturas soportadas.

No se buscan palabras por substring en procesos arbitrarios: por ejemplo,
el flag legítimo de Chromium/Electron `--bypasscsp-schemes` no representa
`-ExecutionPolicy Bypass` y no debe elevar el riesgo. Una coincidencia
contextual válida conserva todo su peso; esta precisión no es una allowlist
por nombre, ruta, hash o proveedor.

## Afinidad

La afinidad alimenta el score, pero no lo sustituye.

Niveles:
- `high`
- `medium`
- `low`
- `none`

Se calcula usando combinación de:
- hash o revalidación razonable;
- signer;
- hostname/FQDN;
- root domain;
- ASN;
- puerto;
- patrón histórico.
