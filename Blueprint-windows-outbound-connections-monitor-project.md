# Blueprint completo — App v0.1 de monitorización de conexiones salientes en Windows

## 1. Resumen ejecutivo

### 1.1 Qué es esta aplicación

Esta aplicación es una **herramienta de escritorio para Windows** orientada a ofrecer **visibilidad humana, priorización de riesgo y contexto útil** sobre las **conexiones salientes activas** del equipo en el momento de un escaneo manual.

No pretende ser un antivirus, un EDR completo, un IDS de red ni un firewall. Su objetivo es mucho más concreto y realista:

- detectar y listar las conexiones salientes activas;
- asociarlas al proceso responsable;
- enriquecerlas con identidad del binario, firma, confianza, contexto y reputación externa;
- clasificarlas por afinidad y riesgo potencial;
- reducir la fatiga de alertas mediante baseline progresivo, estados intermedios y lenguaje UX no alarmista;
- ayudar al usuario a distinguir entre tráfico normal, tráfico nuevo razonable y tráfico que merece revisión inmediata.

### 1.2 Problema que resuelve

El usuario objetivo, especialmente un desarrollador o perfil técnico curioso, puede descargar, ejecutar o inspeccionar herramientas nuevas, repositorios, binarios o integraciones que incrementan el riesgo de exposición a:

- stealers;
- binarios con telemetría abusiva;
- herramientas con conexiones salientes opacas;
- procesos legítimos utilizados para exfiltración;
- ruido normal de Windows que, sin contexto, genera ansiedad.

El problema no es solo la amenaza real. El problema es también la **falta de una herramienta ligera, manual y comprensible** que permita responder a preguntas como estas:

- ¿Qué procesos están abriendo conexiones salientes ahora mismo?
- ¿Cuál es el binario exacto que origina esa conexión?
- ¿Ese binario es el esperado o ha cambiado?
- ¿La conexión encaja con su comportamiento histórico?
- ¿Es algo normal del sistema o algo que debería revisar ya?

### 1.3 Propuesta de valor

La propuesta de valor de la v0.1 es:

- **escaneo manual bajo demanda** con botón `Scan Now`;
- **baja fricción** de uso;
- **bajo consumo de recursos**;
- **arquitectura explicable**;
- **clasificación útil sin intentar sustituir al juicio humano**;
- **baseline por afinidad**, no por confianza ciega en “visto antes”;
- **hash obligatorio para baseline**;
- **caché de identidad** para no penalizar rendimiento;
- **enriquecimiento externo selectivo** solo cuando aporte valor.

---

## 2. Objetivo del producto

### 2.1 Objetivo principal

Permitir al usuario ejecutar un escaneo puntual del estado de red saliente de su equipo y obtener una **lista priorizada y explicable** de conexiones activas con foco en:

- conexiones conocidas y coherentes;
- conexiones nuevas pero razonables;
- conexiones anómalas o potencialmente peligrosas.

### 2.2 Objetivos secundarios

- construir una **línea base local** útil y mantenible del comportamiento de red saliente habitual;
- minimizar falsos positivos y fatiga de alertas;
- facilitar validación manual y aprendizaje progresivo;
- almacenar suficiente contexto histórico para permitir revalidación, comparación y cambios de versión del software observado.

### 2.3 No objetivos explícitos de la v0.1

La v0.1 **no** intenta:

- monitorización continua 24/7;
- interceptar tráfico a nivel de kernel;
- capturar paquetes;
- bloquear conexiones automáticamente;
- sustituir antivirus, firewall o EDR;
- detectar inyección en memoria de forma fiable;
- clasificar malware con certeza forense;
- inspeccionar contenido de tráfico cifrado;
- correlacionar eventos de toda la historia del sistema.

La v0.1 es un **priorizador inteligente de conexiones salientes activas**.

---

## 3. Principios de diseño del producto

### 3.1 Principio 1 — Visibilidad antes que automatismo

La app existe para dar contexto útil al usuario. No debe ocultar excesivamente la realidad ni tomar decisiones destructivas por sí sola.

### 3.2 Principio 2 — Seguridad sin paranoia UX

La app debe ayudar a detectar cosas raras sin convertir cada escaneo en una avalancha de sospechas.

### 3.3 Principio 3 — Explicabilidad obligatoria

Toda clasificación relevante debe tener **motivos concretos**:

- firma válida o inválida;
- hash conocido o nuevo;
- destino habitual o nuevo;
- afinidad alta o baja;
- reputación externa limpia o sospechosa;
- ruta del binario normal o anómala;
- proceso huérfano;
- cambio de versión detectado.

### 3.4 Principio 4 — Hash sí, pero no como verdad única

El hash SHA-256 es un ancla fuerte de identidad en disco y es **obligatorio para baseline**, pero no basta por sí solo. La identidad completa del sistema combina:

- **Disk truth**;
- **Trust truth**;
- **Execution truth**;
- **Behavior truth**.

### 3.5 Principio 5 — Baseline por afinidad, no por cansancio

Nada entra en baseline consolidado solo por repetirse. Debe existir repetición, estabilidad, ausencia de señales negativas y coherencia suficiente.

### 3.6 Principio 6 — Primero local, luego externo

El motor local debe resolver la mayor parte del valor de la app. Las fuentes externas deben enriquecer casos dudosos, no reemplazar la lógica central.

### 3.7 Principio 7 — Producto pequeño, útil y mantenible

La v0.1 debe ser relativamente simple, modular y austera.

---

## 4. Usuario objetivo

### 4.1 Perfil principal

Usuario técnico individual en Windows, especialmente:

- desarrollador;
- consultor técnico;
- integrador;
- power user;
- profesional con herramientas de IA, entornos locales, scripts, repositorios y binarios de terceros.

### 4.2 Dolor principal

No dispone de una manera cómoda de distinguir entre:

- tráfico normal de Windows o del stack habitual;
- tráfico nuevo coherente con actividad legítima;
- tráfico que merece investigación inmediata.

### 4.3 Contexto real de uso

- escaneo tras instalar o probar una herramienta;
- escaneo tras descargar un ejecutable o clonar un repo que genera binarios;
- escaneo tras notar comportamiento raro del sistema;
- escaneo periódico para revisar “qué está saliendo” del equipo;
- escaneo después de cambios de versión o actualizaciones.

---

## 5. Casos de uso principales

### 5.1 Caso de uso A — Escaneo puntual tras probar una herramienta nueva

El usuario instala o ejecuta una utilidad nueva. Pulsa `Scan Now` y revisa si aparecen:

- nuevas conexiones;
- procesos sin firma;
- rutas no normales;
- destinos por IP pura;
- tráfico con afinidad baja respecto al comportamiento esperado.

### 5.2 Caso de uso B — Revisión tranquila del estado de red

El usuario ejecuta un escaneo en su equipo ya conocido para verificar que el tráfico visible sigue siendo razonable.

### 5.3 Caso de uso C — Detección de cambio de binario

Un proceso conocido aparece con nuevo hash. La app lo marca como:

- actualización detectada;
- candidato a revalidación;
- cambio no consolidado todavía.

### 5.4 Caso de uso D — Proceso huérfano

Se detecta una conexión activa cuyo ejecutable no puede resolverse correctamente o ya no existe en disco. Se prioriza como potencialmente peligrosa.

### 5.5 Caso de uso E — Aprendizaje progresivo del comportamiento normal

Durante los primeros días, la app observa, puntúa y clasifica sin convertir todo lo nuevo en peligro. Al mismo tiempo, construye baseline con prudencia.

---

## 6. Alcance funcional de la v0.1

### 6.1 Incluido

- app de escritorio para Windows;
- botón manual `Scan Now`;
- snapshot de conexiones salientes activas;
- resolución de proceso propietario;
- enriquecimiento local del ejecutable;
- cálculo y caché de SHA-256;
- verificación de firma/confianza;
- baseline local en SQLite;
- motor de scoring y afinidad;
- clasificación por bandas de riesgo;
- vista de hallazgos;
- detalle por conexión/proceso;
- validación manual de ciertos estados;
- reputación externa opcional/selectiva;
- exportación de resultados.

### 6.2 Excluido en v0.1

- servicio residente permanente;
- notificaciones en segundo plano;
- captura profunda de tráfico;
- análisis de comportamiento en memoria;
- aislamiento automático;
- remediación automática;
- reglas YARA, EDR, hooking, kernel drivers;
- multiusuario o gestión centralizada.

---

## 7. Arquitectura tecnológica elegida

### 7.1 Frontend

- **HTML5 semántico**
- **Tailwind CSS v4**
- **JavaScript ESM**
- sin frameworks frontend pesados

### 7.2 Shell y backend nativo

- **Tauri 2**
- **Rust puro**

### 7.3 Persistencia

- **SQLite** como almacenamiento local principal

### 7.4 Integraciones externas opcionales

- VirusTotal API
- AbuseIPDB API
- OpenRouter API para clasificación asistida por LLM en casos ambiguos
- MCP opcional en versiones posteriores, no obligatorio para v0.1

### 7.5 Razonamiento de la elección

Se elige Tauri 2 + Rust puro porque ofrece:

- backend nativo integrado;
- acceso directo a APIs de Windows;
- menos moving parts que sidecars múltiples;
- buena base para rendimiento y seguridad;
- frontend web ligero con UX flexible;
- posibilidad futura de sidecars solo si alguna pieza lo requiere.

---

## 8. Arquitectura lógica por bloques

La arquitectura se divide en cuatro bloques principales y varios submódulos auxiliares.

### 8.1 Bloque 1 — Collector

Responsable de capturar el estado actual de red saliente visible en el instante del escaneo.

Funciones principales:

- enumerar conexiones TCP activas;
- enumerar endpoints UDP relevantes si aplica;
- asociar cada conexión a un PID;
- obtener información básica del proceso;
- producir observaciones crudas consistentes.

Salida esperada:

- lista de observaciones crudas de red con relación a proceso.

### 8.2 Bloque 2 — Enricher

Responsable de enriquecer cada observación con identidad del ejecutable, confianza y metadatos técnicos.

Funciones principales:

- resolver ruta del ejecutable;
- obtener identidad fuerte del archivo;
- calcular o recuperar hash SHA-256;
- comprobar firma y cadena de confianza;
- clasificar ruta;
- marcar condiciones anómalas;
- resolver hostname/ASN/dominio cuando sea viable.

Salida esperada:

- observaciones enriquecidas con contexto local suficiente.

### 8.3 Bloque 3 — Risk Engine

Responsable de evaluar riesgo, afinidad, estado del baseline y necesidad de revalidación.

Funciones principales:

- consultar baseline existente;
- comparar identidad actual con identidades previas;
- calcular score de afinidad;
- asignar banda de riesgo;
- determinar estado del binario/observación;
- decidir si requiere enriquecimiento externo.

Salida esperada:

- findings listos para UI y persistencia.

### 8.4 Bloque 4 — Intel Adapters

Responsable de consultar fuentes externas solo cuando exista valor real.

Funciones principales:

- consultar reputación de IP/dominio;
- interpretar respuesta externa;
- enriquecer findings con señales adicionales;
- opcionalmente consultar un LLM para resumir o clasificar casos grises.

Salida esperada:

- señales externas añadidas a findings no consolidados.

### 8.5 Submódulos auxiliares

- `storage_sqlite`
- `identity_cache`
- `baseline_manager`
- `exporter`
- `tauri_commands`
- `settings_manager`
- `audit_log`

---

## 9. Modelo conceptual de identidad

La app distingue cuatro dimensiones complementarias de identidad.

### 9.1 Disk truth

Describe el archivo en disco.

Componentes clave:

- `sha256`
- `volume_serial`
- `file_id`
- `normalized_full_path`
- `file_size`
- `last_write_time`

Objetivo:

- identificar con fuerza el binario real almacenado localmente.

### 9.2 Trust truth

Describe la confianza criptográfica del binario.

Componentes clave:

- estado de firma;
- fuente de firma;
- sujeto del certificado;
- thumbprint;
- estado de verificación de cadena;
- resultado de política de confianza.

Objetivo:

- diferenciar entre binarios firmados y verificables frente a binarios sin firma o con confianza dudosa.

### 9.3 Execution truth

Describe la instancia en ejecución.

Componentes clave:

- `pid`
- hora de inicio del proceso
- ruta resuelta del proceso
- disponibilidad del archivo en disco en el momento del escaneo
- flags de proceso huérfano o irresoluble

Objetivo:

- saber qué instancia viva del proceso origina la conexión observada.

### 9.4 Behavior truth

Describe el comportamiento de red observado y su encaje con lo esperado.

Componentes clave:

- IP remota
- hostname o FQDN si existe
- dominio raíz/eTLD+1
- ASN/organización
- puerto remoto
- protocolo
- frecuencia histórica
- afinidad con baseline

Objetivo:

- evaluar si la conducta actual se parece a lo normal para ese binario.

---

## 10. Diseño del baseline

### 10.1 Qué es el baseline

El baseline es una base de conocimiento local que representa comportamientos de red saliente suficientemente observados y explicados como para reducir ruido futuro.

No significa “seguro absoluto”. Significa “patrón suficientemente conocido y coherente dentro del contexto de este equipo”.

### 10.2 Qué no debe ser el baseline

No debe ser:

- una allowlist ciega;
- una lista de “visto antes” sin matices;
- una absolución automática de procesos firmados;
- una base permanente inmune a revalidación.

### 10.3 Filosofía de promoción

La promoción a baseline exige:

- repetición suficiente;
- estabilidad razonable;
- ausencia de señales negativas relevantes;
- coherencia entre identidad del binario y afinidad de red;
- reglas distintas para binarios firmados, conocidos y locales no firmados.

### 10.4 Estados del ciclo de vida

Estados propuestos:

- `Unknown`
- `Candidate`
- `Observed_Local`
- `Baseline_Provisional`
- `Baseline_Consolidated`
- `Revalidation_Required`
- `Potentially_Dangerous`

### 10.5 Significado de cada estado

#### Unknown
Primera aparición o aparición sin contexto suficiente.

#### Candidate
Observación repetida pero todavía no consolidada. Requiere más evidencia o validación.

#### Observed_Local
Binario local no necesariamente firmable o auto-firmado, estable y validado por el usuario, pero no promovido a “seguro” ni a baseline consolidado tradicional.

#### Baseline_Provisional
Patrón suficientemente repetido y coherente, pendiente de más tiempo o confirmaciones.

#### Baseline_Consolidated
Patrón estable, explicable y suficientemente validado en este equipo.

#### Revalidation_Required
Elemento anteriormente conocido que ha cambiado de hash, firma, ruta, afinidad o contexto relevante.

#### Potentially_Dangerous
Conexión o proceso con señales suficientemente fuertes como para priorización inmediata.

### 10.6 Regla clave: no promoción por puro tiempo

Nada pasa a baseline consolidado solo por haber sobrevivido varios días. El tiempo ayuda, pero no sustituye:

- hash estable;
- confianza suficiente;
- reputación sin señales negativas importantes;
- comportamiento de red coherente.

### 10.7 Veredicto de silencio

Concepto funcional:

Una entidad candidata puede progresar si, a lo largo de una ventana de observación, se cumple que:

- no ha recibido señales negativas en consultas externas relevantes;
- no ha cambiado de identidad de archivo de forma sospechosa;
- no ha mostrado afinidad de red degradada;
- su firma y contexto siguen siendo coherentes.

### 10.8 Regla especial para binarios sin firma

Los binarios sin firma no deben auto-promocionarse fácilmente a baseline consolidado estándar.

Alternativa práctica:

- pueden pasar a `Observed_Local` si el usuario los valida y muestran estabilidad suficiente;
- no se tratan como “seguros absolutos”; se tratan como “locales conocidos por el usuario”.

---

## 11. Modelo de afinidad de red

### 11.1 Por qué no usar solo IP o puerto

IP y puerto son señales útiles pero inestables:

- CDNs cambian IPs;
- balanceadores cambian destinos;
- algunos servicios usan puertos distintos según función;
- una misma familia de software puede variar infraestructuras.

### 11.2 Baseline por afinidad

El sistema debe medir cuánto se parece la conexión actual al comportamiento previamente observado del mismo binario o familia de binario.

### 11.3 Niveles de afinidad

#### Afinidad alta
Coinciden la mayoría de señales importantes:

- mismo hash o revalidación razonable;
- mismo signer;
- mismo hostname/FQDN o servicio esperado;
- mismo patrón de puertos;
- mismo ASN o ecosistema coherente.

#### Afinidad media
Hay similitud clara, pero cambia una señal secundaria:

- puerto nuevo pero plausible;
- subdominio nuevo dentro del mismo ecosistema;
- IP distinta dentro del mismo ASN/infraestructura esperada.

#### Afinidad baja
Existen cambios relevantes:

- dominio nuevo;
- IP pura en vez de dominio esperado;
- ASN no habitual;
- destino no relacionado con el software;
- patrón poco frecuente.

### 11.4 Score de afinidad

Ejemplo conceptual:

- coincidencia exacta fuerte: 90–100
- coincidencia razonable: 70–89
- coincidencia débil: 40–69
- desajuste importante: 0–39

El score de afinidad no equivale directamente al score de riesgo, pero lo alimenta.

---

## 12. Modelo de scoring de riesgo

### 12.1 Objetivo

Asignar una banda comprensible de riesgo potencial a cada hallazgo.

### 12.2 Bandas de riesgo propuestas

- `known_safe`
- `known_low`
- `known_moderate`
- `known_high`
- `potentially_dangerous`

### 12.3 Vista UX agregada opcional

Para simplificar la pantalla principal, estas bandas pueden agruparse en:

- **Aceptables**
- **A revisar**
- **Potencialmente peligrosas**

### 12.4 Factores que reducen riesgo

- hash conocido y estable;
- identidad de archivo coherente;
- firma válida y confianza adecuada;
- ruta normal;
- afinidad alta;
- repetición suficiente;
- ausencia de señales negativas externas;
- validación previa del usuario;
- pertenencia a baseline consolidado.

### 12.5 Factores que aumentan riesgo

- hash nuevo o no conocido;
- firma ausente, inválida o inconsistente;
- ruta en `Temp`, `AppData`, `Downloads`, escritorio o zonas raras;
- proceso huérfano;
- destino por IP pura;
- afinidad baja;
- ASN o dominio no esperados;
- puerto raro;
- reputación externa mala o dudosa;
- ejecutables del sistema fuera de ruta normal;
- cambios inesperados del binario.

### 12.6 Reglas especiales de alto impacto

Condiciones que elevan directamente la severidad:

- proceso con conexión activa cuyo binario ya no existe en disco;
- ruta irresoluble;
- firma inconsistente con publisher esperado;
- ejecutable del sistema en ruta incorrecta;
- múltiples señales fuertes acumuladas.

### 12.7 Score orientativo

Escala interna propuesta de 0 a 100.

Ejemplo orientativo:

- 0–19: conocida sin riesgo
- 20–39: conocida con riesgo leve
- 40–59: conocida con riesgo moderado
- 60–79: conocida con riesgo alto
- 80–100: potencialmente peligrosa

---

## 13. Contrato de datos principal: `scan_now`

### 13.1 Objetivo del contrato

Establecer una salida JSON estable, legible y extensible para el comando principal de escaneo.

### 13.2 Requisitos del contrato

- determinista en estructura;
- versionable;
- apto para UI, persistencia y exportación;
- explícito en estados y motivos;
- compatible con futuras ampliaciones sin romper el frontend.

### 13.3 Estructura conceptual principal

```json
{
  "scan_id": "string",
  "schema_version": "v1",
  "started_at": "ISO-8601",
  "finished_at": "ISO-8601",
  "duration_ms": 0,
  "host": {
    "platform": "windows",
    "hostname": "string",
    "app_version": "string"
  },
  "summary": {
    "total_observations": 0,
    "accepted_count": 0,
    "review_count": 0,
    "danger_count": 0,
    "unknown_count": 0,
    "candidate_count": 0,
    "revalidation_count": 0,
    "orphaned_count": 0
  },
  "findings": []
}
```

### 13.4 Estructura conceptual de cada finding

```json
{
  "finding_id": "string",
  "protocol": "TCP",
  "state": "Established",
  "local": {
    "ip": "string",
    "port": 0
  },
  "remote": {
    "ip": "string",
    "port": 443,
    "hostname": "string|null",
    "root_domain": "string|null",
    "asn_org": "string|null",
    "country": "string|null"
  },
  "process": {
    "pid": 0,
    "name": "string",
    "started_at": "ISO-8601|null",
    "path": "string|null",
    "path_class": "Windows|ProgramFiles|AppData|Temp|Downloads|Other|Missing",
    "file_missing": false,
    "orphaned": false
  },
  "binary_identity": {
    "volume_serial": "string|null",
    "file_id": "string|null",
    "file_size": 0,
    "last_write_time": "ISO-8601|null",
    "sha256": "string|null",
    "hash_source": "cache|fresh|null"
  },
  "trust": {
    "signature_status": "Valid|Invalid|Unsigned|Unknown",
    "signature_source": "embedded|catalog|none|unknown",
    "signer_subject": "string|null",
    "signer_thumbprint": "string|null",
    "chain_status": "Trusted|Untrusted|Unknown"
  },
  "baseline": {
    "state": "Unknown|Candidate|Observed_Local|Baseline_Provisional|Baseline_Consolidated|Revalidation_Required|Potentially_Dangerous",
    "seen_count": 0,
    "distinct_days": 0,
    "first_seen": "ISO-8601|null",
    "last_seen": "ISO-8601|null",
    "manual_validation": false
  },
  "affinity": {
    "score": 0,
    "level": "high|medium|low|none",
    "matched_signals": [],
    "mismatched_signals": []
  },
  "intel": {
    "consulted": false,
    "virustotal": {
      "consulted": false,
      "malicious_votes": null
    },
    "abuseipdb": {
      "consulted": false,
      "abuse_confidence_score": null,
      "usage_type": null
    },
    "llm": {
      "consulted": false,
      "confidence": null,
      "summary": null
    }
  },
  "risk": {
    "score": 0,
    "band": "known_safe|known_low|known_moderate|known_high|potentially_dangerous",
    "reason_codes": [],
    "recommended_action": "ignore|observe|review|revalidate|investigate"
  }
}
```

### 13.5 Motivos (`reason_codes`) sugeridos

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

---

## 14. Flujo funcional completo del escaneo

### 14.1 Paso 1 — Inicio de `Scan Now`

El usuario pulsa el botón `Scan Now`.

La app:

- genera `scan_id`;
- registra inicio del escaneo;
- inicializa estructuras en memoria;
- limpia estado temporal.

### 14.2 Paso 2 — Recolección de observaciones crudas

El Collector obtiene conexiones activas visibles y crea una lista inicial de observaciones.

### 14.3 Paso 3 — Asociación con proceso

Cada observación se asocia a un proceso:

- PID
- nombre de proceso
- metadatos básicos de ejecución

### 14.4 Paso 4 — Resolución del ejecutable

Se intenta resolver:

- ruta real del ejecutable;
- existencia del archivo;
- datos básicos del archivo.

Si falla, se marcan flags anómalos.

### 14.5 Paso 5 — Identidad de archivo y caché

Se consulta caché de identidad usando una clave basada en:

- `volume_serial`
- `file_id`
- `file_size`
- `last_write_time`

Si hay hit, se reutilizan hash y trust.

Si no hay hit, se calculan o verifican y luego se almacenan.

### 14.6 Paso 6 — Enriquecimiento de red

Se resuelven cuando sea posible:

- hostname;
- dominio raíz;
- ASN/organización;
- país.

### 14.7 Paso 7 — Consulta al baseline

Se busca si el binario y su patrón de afinidad ya existen en base local.

### 14.8 Paso 8 — Cálculo de afinidad

Se compara la observación actual con el comportamiento histórico del mismo binario.

### 14.9 Paso 9 — Cálculo preliminar de riesgo

El Risk Engine genera un score preliminar y decide si necesita enriquecer con Intel externo.

### 14.10 Paso 10 — Intel externo selectivo

Solo si la observación no está consolidada o tiene señales dudosas, se consulta reputación externa.

### 14.11 Paso 11 — Score final y recomendación

Se calcula score final, banda y acción recomendada.

### 14.12 Paso 12 — Persistencia

Se almacenan:

- scan;
- observaciones;
- findings;
- cambios de estado;
- actualizaciones de baseline;
- auditoría.

### 14.13 Paso 13 — Respuesta al frontend

Se devuelve el JSON final al frontend y se actualiza la UI.

---

## 15. Diseño de la caché de identidad

### 15.1 Objetivo

Reducir el coste de hashing y verificación de firma sin renunciar a identidad fuerte.

### 15.2 Clave de invalidación propuesta

- `volume_serial`
- `file_id`
- `file_size`
- `last_write_time`

### 15.3 Valor cacheado

- `sha256`
- estado de firma
- fuente de firma
- sujeto de firma
- thumbprint
- estado de confianza/cadena
- timestamp de verificación

### 15.4 Reglas

- si la clave coincide, usar caché;
- si cambia cualquier componente relevante, recalcular;
- registrar si el hash proviene de caché o de cálculo fresco.

### 15.5 Beneficio

Hace viable que el hash sea obligatorio para baseline sin penalizar cada `Scan Now` con hashing completo repetido de todos los binarios.

---

## 16. Rutas y clasificación de path

### 16.1 Objetivo

La ruta del ejecutable es una señal contextual importante.

### 16.2 Clases de ruta sugeridas

- `Windows`
- `ProgramFiles`
- `ProgramFilesX86`
- `AppData`
- `Temp`
- `Downloads`
- `Desktop`
- `UserProfile`
- `Other`
- `Missing`

### 16.3 Reglas de clasificación

La clasificación debe hacerse con normalización real de rutas, evitando errores del tipo:

- carpetas con nombres engañosos;
- subrutas anómalas;
- coincidencias solo por prefijo textual.

### 16.4 Uso de esta señal

- reduce o eleva riesgo;
- influye en promoción de baseline;
- ayuda a explicar hallazgos al usuario.

---

## 17. Procesos huérfanos y anomalías críticas

### 17.1 Definición

Se considera proceso huérfano o hallazgo crítico cuando existe conexión activa pero el binario:

- ya no existe en disco;
- no puede resolverse de forma fiable;
- muestra inconsistencias graves entre proceso y archivo.

### 17.2 Tratamiento en v0.1

Estos hallazgos no pasan por aprendizaje normal.

Acción:

- priorización inmediata;
- banda alta o potencialmente peligrosa;
- reason codes específicos;
- visibilidad destacada en UI.

### 17.3 Motivos posibles

- `ORPHANED_IMAGE`
- `MISSING_ON_DISK`
- `PATH_UNRESOLVABLE`
- `EXECUTION_IDENTITY_MISMATCH`

---

## 18. Intel Adapters

### 18.1 Filosofía

Las consultas externas son apoyo, no núcleo. Deben ser:

- selectivas;
- controladas;
- con mínimo envío de datos;
- explicables;
- desacopladas del motor local.

### 18.2 Provider interface conceptual

Cada proveedor debe implementar una interfaz homogénea.

Ejemplo conceptual:

- `query_ip_reputation(ip)`
- `query_domain_context(domain)`
- `classify_finding(json)`

### 18.3 VirusTotal

Uso previsto:

- reputación de IP;
- señal de motores que la catalogan como maliciosa o no.

### 18.4 AbuseIPDB

Uso previsto:

- abuso reportado;
- contexto de ISP;
- usage type;
- señal de datacenter/CDN/hosting.

### 18.5 OpenRouter / LLM

Uso previsto:

- solo casos ambiguos;
- resumir la interpretación del hallazgo;
- apoyar clasificación cuando las señales son mixtas.

No usar el LLM como juez absoluto.

### 18.6 Reglas de activación

No consultar Intel externo si:

- el elemento está consolidado y con alta afinidad;
- el score local ya es muy bajo o muy alto de forma evidente.

Consultar si:

- estado `Unknown`;
- estado `Candidate`;
- `Revalidation_Required`;
- afinidad baja;
- IP pura o contexto débil;
- señales mixtas.

---

## 19. Diseño UX/UI

### 19.1 Objetivo UX

Reducir ansiedad, mejorar comprensión y guiar a la acción.

### 19.2 Pantallas mínimas de v0.1

- pantalla principal / dashboard
- listado de findings
- panel de detalle de un finding
- vista de historial reciente de scans
- vista de baseline / revalidaciones
- ajustes mínimos

### 19.3 Pantalla principal

Elementos:

- botón `Scan Now`
- timestamp del último escaneo
- resumen visual de hallazgos
- tarjetas de estado global
- acceso rápido a revisión

### 19.4 Listado de findings

Cada fila debe mostrar como mínimo:

- proceso
- destino
- estado baseline
- banda de riesgo
- razón principal
- acción sugerida

### 19.5 Panel de detalle

Debe mostrar:

- proceso y PID
- ruta completa
- hash
- firma y confianza
- identidad del archivo
- destino completo
- afinidad
- histórico resumido
- señales externas
- motivos de clasificación
- acción recomendada

### 19.6 Lenguaje UX recomendado

No usar lenguaje de pánico por defecto.

Ejemplos útiles:

- `Aprendiendo`
- `Conocida`
- `Cambio detectado`
- `A revisar`
- `Potencialmente peligrosa`
- `Validada manualmente`
- `Requiere revalidación`

### 19.7 Distinciones visuales importantes

- procesos huérfanos destacados;
- cambios de hash visibles;
- binarios locales validados manualmente separados de baseline estándar;
- hallazgos consolidados claramente diferenciados de hallazgos nuevos.

---

## 20. Diseño del modo de aprendizaje inicial

### 20.1 Problema a resolver

Sin un arranque prudente, el usuario puede abandonar la herramienta el primer día por fatiga de alertas.

### 20.2 Solución general

La app debe arrancar con un modo de aprendizaje controlado durante los primeros días, donde:

- observa más de lo que sentencia;
- prioriza solo las señales fuertes;
- construye baseline con prudencia;
- comunica que está aprendiendo.

### 20.3 Ventana inicial sugerida

- 5 a 7 días orientativos
- no rígidos ni mágicos
- combinación de tiempo, repetición y coherencia

### 20.4 Regla operativa

Durante la fase inicial:

- solo alertas altas para casos claramente problemáticos;
- el resto se muestran como observados, candidatos o en consolidación;
- no se auto-promocionan rápidamente binarios desconocidos o frágiles.

### 20.5 Contextos sugeridos de muestreo

- tras reinicio
- tras inicio de sesión
- con navegador abierto
- con stack habitual de trabajo abierto
- con equipo en reposo

### 20.6 Meta UX

La herramienta debe decir implícitamente:

> “Estoy construyendo contexto y te aviso solo de lo importante.”

---

## 21. Almacenamiento SQLite

### 21.1 Filosofía

SQLite sirve como almacén local único, simple y robusto para v0.1.

### 21.2 Entidades lógicas principales

- `scans`
- `network_observations`
- `binary_identity`
- `binary_hash_cache`
- `trust_records`
- `baseline_entries`
- `affinity_profiles`
- `risk_decisions`
- `manual_decisions`
- `intel_results`
- `audit_events`

### 21.3 Propuesta conceptual de tablas

#### `scans`
Metadatos del escaneo.

#### `network_observations`
Snapshot crudo y enriquecido por conexión.

#### `binary_identity`
Identidad física y lógica del binario.

#### `binary_hash_cache`
Caché reutilizable de hash y trust.

#### `baseline_entries`
Estados y reglas de baseline por binario/patrón.

#### `affinity_profiles`
Patrones históricos de comportamiento de red.

#### `risk_decisions`
Resultado del motor por finding.

#### `manual_decisions`
Aprobaciones, promociones y validaciones del usuario.

#### `intel_results`
Resultados de reputación o clasificación externa.

#### `audit_events`
Trazabilidad de eventos internos.

### 21.4 Índices importantes

- por `sha256`
- por `file_id + volume_serial`
- por `scan_id`
- por `process_name`
- por `remote_ip`
- por `root_domain`
- por `baseline_state`
- por `risk_band`

---

## 22. Estados y transiciones

### 22.1 Transiciones principales

- `Unknown -> Candidate`
- `Candidate -> Observed_Local`
- `Candidate -> Baseline_Provisional`
- `Baseline_Provisional -> Baseline_Consolidated`
- `Baseline_Consolidated -> Revalidation_Required`
- `Any -> Potentially_Dangerous` si hay señal crítica

### 22.2 Reglas conceptuales de transición

#### Unknown -> Candidate
Se ha visto más de una vez o existe suficiente contexto inicial.

#### Candidate -> Observed_Local
El usuario valida un binario local no firmado o no auto-promocionable.

#### Candidate -> Baseline_Provisional
Repetición suficiente + silencio razonable + identidad estable + coherencia adecuada.

#### Provisional -> Consolidated
Más tiempo + más contextos + alta afinidad sostenida.

#### Consolidated -> Revalidation_Required
Cambio de hash, firma, ruta o patrón de red relevante.

#### Any -> Potentially_Dangerous
Proceso huérfano, firma muy problemática, ruta muy sospechosa o acumulación crítica de señales.

---

## 23. Revalidación y actualizaciones

### 23.1 Problema

Los binarios legítimos cambian. El sistema debe distinguir entre:

- actualización legítima;
- cambio dudoso;
- suplantación.

### 23.2 Estrategia

Cuando cambia el hash:

- no destruir automáticamente el baseline previo;
- crear estado `Revalidation_Required`;
- comparar signer, ruta, metadata y afinidad;
- ofrecer UX clara tipo “Se ha detectado una nueva versión”.

### 23.3 Resultado UX deseable

Ejemplo:

- `Nuevo hash detectado para git.exe`
- `La firma y la ruta siguen siendo coherentes`
- `Se recomienda revalidar esta actualización`

---

## 24. Rendimiento y presupuestos

### 24.1 Objetivo general

El botón `Scan Now` debe sentirse rápido y usable.

### 24.2 Presupuestos orientativos

- p50 escaneo: < 1 s si la caché está caliente y el número de binarios activos es razonable
- p95 escaneo: < 3 s
- consultas externas: opcionales y desacoplables visualmente si retrasan el flujo

### 24.3 Palancas de rendimiento

- caché de hash/trust
- agrupación por binario
- enriquecimiento externo selectivo
- ejecución concurrente controlada
- evitar trabajo duplicado para procesos repetidos

### 24.4 Qué no sacrificar por rendimiento

- hash obligatorio para baseline
- integridad del contrato JSON
- trazabilidad básica
- explicabilidad de findings

---

## 25. Seguridad y privacidad

### 25.1 Principio de minimización

La app debe retener y enviar el mínimo necesario.

### 25.2 Datos sensibles potenciales

- rutas locales completas
- nombres de usuario en paths
- dominios consultados
- metadatos del equipo

### 25.3 Reglas de privacidad

- no enviar paths completos a terceros salvo necesidad explícita;
- no enviar datos superfluos al LLM;
- permitir desactivar Intel externo;
- registrar qué proveedores externos se consultaron;
- separar claramente datos locales y externos.

### 25.4 Seguridad local

- proteger la base SQLite frente a corrupción básica;
- validar entradas de proveedores externos;
- no ejecutar nada descargado;
- no permitir que el motor se automodifique;
- logs sin filtrar secretos innecesarios.

---

## 26. Gestión de errores

### 26.1 Filosofía

La app debe degradar con elegancia.

### 26.2 Casos de error típicos

- no se puede resolver el proceso;
- no se puede leer el ejecutable;
- no se puede calcular hash;
- error de verificación de firma;
- fallo de DNS o ASN;
- fallo de proveedor externo;
- base SQLite bloqueada o degradada.

### 26.3 Estrategia

- registrar error técnico;
- exponer en UI una versión comprensible;
- seguir con el resto del pipeline siempre que sea posible;
- marcar datos faltantes explícitamente como `unknown`, nunca inventarlos.

---

## 27. Exportación y reporting

### 27.1 Objetivo

Permitir que el usuario guarde y comparta resultados de manera útil.

### 27.2 Formatos sugeridos

- JSON completo del escaneo
- HTML legible
- CSV resumido opcional

### 27.3 Contenido exportable

- summary del scan
- findings completos
- reasons
- baseline state
- recomendaciones

---

## 28. Testing y validación

### 28.1 Objetivo

Asegurar que la v0.1 es fiable, estable y no sobre-reacciona.

### 28.2 Capas de test

- unit tests de scoring;
- unit tests de transición de estados;
- tests de serialización JSON;
- tests de caché de identidad;
- tests de clasificación de rutas;
- tests de afinidad;
- tests de degradación cuando faltan datos;
- tests de integración con SQLite.

### 28.3 Escenarios mínimos a cubrir

- proceso firmado y conocido con destino habitual;
- proceso firmado con hash nuevo;
- binario sin firma validado manualmente;
- proceso huérfano;
- IP pura sin hostname;
- dominio nuevo con afinidad baja;
- binario conocido con puerto nuevo pero plausible;
- fallo de proveedores externos;
- cambio de versión legítimo.

### 28.4 Datos de prueba

Conviene disponer de:

- fixtures JSON;
- hallazgos simulados;
- baseline inicial controlado;
- mocks de Intel externo.

---

## 29. Observabilidad interna de la propia app

### 29.1 Objetivo

La app debe ser depurable sin convertirse en una plataforma de telemetría excesiva.

### 29.2 Logs internos mínimos

- inicio y fin de cada escaneo;
- número de observaciones recogidas;
- hits/misses de caché;
- consultas externas realizadas;
- transiciones de estado;
- errores técnicos relevantes.

### 29.3 Métricas locales útiles

- duración total del scan;
- duración por fase;
- número de binarios hasheados en frío;
- ratio de caché;
- distribución de bandas de riesgo;
- elementos en revalidación.

---

## 30. Supuestos de la v0.1

- el usuario ejecuta la app manualmente;
- el sistema operativo es Windows;
- el número de conexiones activas visibles en un instante es manejable;
- el número de binarios con red activa suele ser razonable;
- el usuario valora explicabilidad y control;
- no todos los entornos tendrán acceso o deseo de consultar Intel externo.

---

## 31. Riesgos principales del proyecto

### 31.1 Riesgo A — Fatiga de alertas

Mitigación:

- baseline prudente;
- lenguaje UX moderado;
- estados intermedios;
- agrupación en aceptables / revisar / peligrosas.

### 31.2 Riesgo B — Falsa confianza por “visto antes”

Mitigación:

- hash obligatorio;
- revalidación;
- baseline por afinidad;
- no promoción ciega por tiempo.

### 31.3 Riesgo C — Demasiado mantenimiento en entornos de desarrollo

Mitigación:

- estado `Observed_Local`;
- validación manual puntual;
- no castigar todo binario unsigned como peligroso.

### 31.4 Riesgo D — Exceso de complejidad prematura

Mitigación:

- sin monitorización continua en v0.1;
- sin sidecars salvo necesidad real;
- sin captura de paquetes;
- sin motor de bloqueo.

### 31.5 Riesgo E — Sobreconfianza en Intel externo

Mitigación:

- Intel externo solo como señal adicional;
- motor local como núcleo;
- LLM solo para casos ambiguos.

---

## 32. Decisiones de producto cerradas para v0.1

### 32.1 Decisiones ya tomadas

- aplicación de escritorio para Windows
- frontend purista
- Tauri 2
- Rust puro en backend
- SQLite local
- botón `Scan Now`
- hash SHA-256 obligatorio para baseline
- caché de identidad
- baseline por estados
- afinidad de red en lugar de coincidencia binaria simplista
- procesos huérfanos como hallazgos críticos
- Intel externo selectivo
- LLM no como motor principal

### 32.2 Decisiones deliberadamente pospuestas

- monitorización continua
- Sysmon/ETW obligatorios
- sidecars
- notificaciones en background
- bloqueo automático
- consola centralizada
- multi-host

---

## 33. Roadmap evolutivo sugerido

### 33.1 v0.1

- scan manual
- baseline local
- scoring
- exportación
- UX básica completa

### 33.2 v0.2

- histórico opcional más rico
- integración con Sysmon opcional
- timeline básica
- mejores comparativas entre scans

### 33.3 v0.3

- detección de patrones repetitivos o beaconing simple
- mejores reglas de cambio de afinidad
- mayor ergonomía en gestión del baseline

### 33.4 v1.0

- producto endurecido
- arquitectura estable
- validación extensa de rendimiento
- más madurez en revisión y exportación

---

## 34. Blueprint operativo de implementación

### 34.1 Flujo de construcción recomendado

1. cerrar contrato JSON;
2. cerrar modelo SQLite;
3. crear Collector mínimo;
4. implementar Enricher local;
5. implementar caché de identidad;
6. implementar baseline manager;
7. implementar scoring y afinidad;
8. integrar frontend;
9. integrar Intel externo selectivo;
10. endurecer UX y testing.

### 34.2 Criterio de calidad mínimo para considerar la v0.1 válida

La v0.1 será considerada válida si logra simultáneamente:

- devolver un escaneo manual útil y comprensible;
- clasificar sin generar ansiedad constante;
- detectar cambios de hash y procesos huérfanos;
- mantener tiempos razonables;
- permitir al usuario diferenciar entre conocido, observado, cambio y peligro potencial.

---

## 35. Conclusión final del Blueprint

La app v0.1 queda definida como una **herramienta de escritorio nativa-ligera para Windows**, diseñada para ofrecer **visibilidad humana, contexto técnico y priorización realista** sobre conexiones salientes activas.

Su propuesta no es competir con un EDR ni con un antivirus, sino cubrir un hueco muy concreto con una solución explicable y sobria:

- observación manual;
- identidad fuerte del binario;
- baseline prudente;
- afinidad contextual;
- riesgo interpretable;
- control del usuario.

El diseño final evita dos errores típicos:

1. convertir todo lo nuevo en sospechoso y hacer inviable la UX;
2. convertir todo lo repetido en confiable y abrir huecos graves.

La arquitectura resultante equilibra:

- seguridad y utilidad;
- rigor técnico y sencillez;
- rendimiento y riqueza contextual;
- automatización y juicio humano.

Eso convierte esta v0.1 en un producto pequeño, serio, defendible y con una base excelente para crecer sin degenerar en un megaproyecto desde el día uno.

---

# Apéndice ejecutivo para agentes — Manifiesto operable y restrictivo

Este apéndice no existe para explicar la visión. Existe para **restringir** a cualquier agente de IA que trabaje sobre este proyecto.

Su función es impedir desviaciones de arquitectura, sobreingeniería, inventos innecesarios y entregables ambiguos.

Si este apéndice entra en conflicto con una propuesta creativa del agente, **manda este apéndice**.

---

## A. Decisiones cerradas

### A.1 Regla absoluta

El agente **no está autorizado** a tomar decisiones de arquitectura principales fuera de lo especificado aquí.

Si detecta ambigüedad, debe:

- elegir la opción más conservadora;
- respetar lo ya fijado;
- documentar la duda;
- no rediseñar el sistema.

### A.2 Plataforma objetivo cerrada

La aplicación es **solo para Windows** en v0.1.

Queda prohibido:

- proponer compatibilidad Linux/macOS en v0.1;
- introducir abstracciones multiplataforma “por si acaso”;
- añadir capas de compatibilidad innecesarias.

### A.3 Stack tecnológico cerrado

El stack queda fijado así y no puede ser sustituido:

- shell desktop: **Tauri 2**
- backend: **Rust puro**
- frontend: **HTML5 + Tailwind CSS v4 + JavaScript ESM**
- almacenamiento local: **SQLite**

Queda prohibido introducir como sustitutos o equivalentes:

- Electron
- React
- Vue
- Svelte
- Angular
- Next.js
- Vite como dependencia obligatoria de runtime del frontend
- Webpack
- Node.js como backend principal
- Python como backend principal
- C# como backend principal
- sidecars como arquitectura base
- PostgreSQL, MySQL o cualquier BD servidor

### A.4 Filosofía de producto cerrada

La app **no es**:

- un antivirus;
- un EDR;
- un IDS;
- un firewall;
- un capturador de paquetes;
- un monitor en segundo plano permanente.

Queda prohibido introducir en v0.1:

- bloqueo automático de conexiones;
- remediación automática;
- cuarentena;
- drivers;
- hooking de kernel;
- ETW obligatorio;
- Sysmon obligatorio;
- packet capture;
- monitorización continua.

### A.5 Modelo funcional cerrado

La interacción principal de v0.1 es un **escaneo manual mediante botón `Scan Now`**.

Queda prohibido rediseñar el flujo principal como:

- demonio permanente;
- tray app siempre residente;
- scheduler interno obligatorio;
- watcher continuo de conexiones.

### A.6 Modelo de identidad cerrado

La identidad lógica del sistema está compuesta por estas cuatro dimensiones y no puede ser simplificada a una sola:

- `disk truth`
- `trust truth`
- `execution truth`
- `behavior truth`

El agente no debe reducir el modelo a:

- solo nombre de proceso;
- solo ruta;
- solo firma;
- solo hash.

### A.7 Política de hash cerrada

El **SHA-256 es obligatorio para baseline**.

Queda prohibido:

- tratar el hash como opcional dentro del baseline;
- sustituir SHA-256 por MD5/SHA-1 como identidad principal;
- omitir hash por “optimización”;
- usar solo signer + path + process_name para consolidar baseline.

El agente sí debe:

- implementar caché para evitar recalcular innecesariamente;
- soportar revalidación al cambiar hash;
- distinguir entre hash de caché y hash recién calculado.

### A.8 Política de baseline cerrada

El baseline:

- no es una allowlist ciega;
- no se basa en “visto antes” a secas;
- no promociona por simple repetición temporal;
- no absuelve automáticamente binarios firmados.

Estados válidos:

- `Unknown`
- `Candidate`
- `Observed_Local`
- `Baseline_Provisional`
- `Baseline_Consolidated`
- `Revalidation_Required`
- `Potentially_Dangerous`

Queda prohibido:

- inventar estados adicionales sin necesidad crítica;
- fusionar `Observed_Local` con `Baseline_Consolidated`;
- promocionar unsigned a baseline consolidado estándar sin intervención explícita definida.

### A.9 Política de afinidad cerrada

El sistema usa **afinidad de red**, no coincidencia ingenua por IP.

Queda prohibido:

- modelar baseline solo por IP exacta;
- considerar un dominio raíz masivo como prueba definitiva de normalidad;
- usar el puerto como condición rígida y única;
- ignorar cambios razonables de CDN/ASN/subdominio.

### A.10 Política de Intel externo cerrada

El motor local es el núcleo. Intel externo es enriquecimiento opcional y selectivo.

Queda prohibido:

- hacer depender el escaneo básico de APIs externas;
- consultar VirusTotal/AbuseIPDB para todos los findings indiscriminadamente;
- usar LLM como juez principal del riesgo.

El LLM solo puede emplearse en casos ambiguos y como apoyo interpretativo.

### A.11 Política de UX cerrada

La UX debe ser sobria, clara y sin histeria.

Queda prohibido:

- lenguaje alarmista por defecto;
- interfaces recargadas “tipo SOC”;
- gráficas complejas innecesarias en v0.1;
- dashboards de marketing vacíos;
- terminología grandilocuente tipo “AI-powered threat eradication”.

### A.12 Política de dependencias cerrada

El agente debe minimizar dependencias.

Queda prohibido:

- introducir librerías solo por comodidad si el estándar o el core del lenguaje lo resuelve;
- meter frameworks de estado frontend pesados;
- añadir ORMs complejos para SQLite en v0.1 si no existe una justificación sólida;
- introducir builders frontend innecesarios “por costumbre”.

### A.13 Política de persistencia cerrada

SQLite es la única base de datos de v0.1.

Queda prohibido:

- introducir servicio de sincronización remota;
- inventar cachés distribuidas;
- separar en múltiples motores de persistencia;
- proponer telemetría centralizada del producto como requisito base.

### A.14 Política de seguridad cerrada

La app debe observar, enriquecer y clasificar. No debe ejecutar ni descargar binarios externos como parte de su función normal.

Queda prohibido:

- auto-ejecutar herramientas del sistema sin control;
- descargar artefactos de terceros para “mejorar” detección;
- introducir auto-updaters no solicitados;
- enviar información sensible al exterior sin necesidad funcional clara.

---

## B. Artefactos obligatorios

### B.1 Regla general

El agente debe entregar **archivos físicos concretos**, no solo explicaciones o fragmentos sueltos.

Toda tarea de implementación debe dejar cambios reales en artefactos persistentes del repo.

### B.2 Artefactos mínimos de raíz

Obligatorios:

- `README.md`
- `AGENTS.md`
- `.gitignore`
- `.editorconfig`
- `docs/`
- `src-tauri/`
- `src/` o estructura equivalente del frontend purista dentro del proyecto Tauri

Si ya existen, deben actualizarse en vez de duplicarse.

### B.3 Artefactos documentales obligatorios

Deben existir estos documentos y mantenerse alineados con el código:

- `docs/product-vision.md`
- `docs/architecture.md`
- `docs/threat-model.md`
- `docs/scoring-model.md`
- `docs/scan-now-contract.json`
- `docs/roadmap.md`
- `docs/sqlite-schema.md`
- `docs/testing-strategy.md`

El agente no debe sustituir estos documentos por comentarios dispersos o tickets genéricos.

### B.4 Artefactos backend obligatorios

Dentro de `src-tauri/` deben existir, como mínimo, módulos equivalentes a:

- `src/commands/scan_now.rs`
- `src/core/collector.rs`
- `src/core/enricher.rs`
- `src/core/risk_engine.rs`
- `src/core/baseline_manager.rs`
- `src/core/identity_cache.rs`
- `src/core/storage.rs`
- `src/core/models.rs`
- `src/core/errors.rs`
- `src/core/exporter.rs`
- `src/main.rs` o el entrypoint equivalente

Se permiten pequeños ajustes de nombres, pero no la desaparición de estas responsabilidades.

### B.5 Artefactos frontend obligatorios

Debe existir un frontend físico y legible con, como mínimo:

- `index.html`
- `src/js/app.js`
- `src/js/api.js`
- `src/js/state.js`
- `src/js/render/summary.js`
- `src/js/render/findings.js`
- `src/js/render/detail.js`
- `src/css/input.css` o estructura equivalente de Tailwind v4

Queda prohibido entregar frontend como:

- un único HTML gigantesco e inmantenible;
- un framework SPA no solicitado;
- plantillas inline desordenadas sin separación mínima.

### B.6 Artefactos de persistencia obligatorios

Debe existir:

- definición explícita del esquema SQLite;
- mecanismo de creación inicial de tablas;
- documentación del esquema;
- fixtures o datos de ejemplo para testing si procede.

Artefactos sugeridos/esperables:

- `src-tauri/migrations/0001_initial.sql`
- `src-tauri/migrations/0002_indexes.sql`
- `docs/sqlite-schema.md`

### B.7 Artefactos de testing obligatorios

El agente debe entregar tests físicos, no solo promesas de tests.

Como mínimo deben existir:

- tests de `scan_now` JSON shape
- tests del scoring
- tests de transición de estados
- tests de afinidad
- tests de caché de identidad
- tests de clasificación de rutas

Se esperan archivos equivalentes a:

- `src-tauri/tests/scan_now_contract.rs`
- `src-tauri/tests/risk_engine.rs`
- `src-tauri/tests/baseline_transitions.rs`
- `src-tauri/tests/affinity.rs`
- `src-tauri/tests/identity_cache.rs`

### B.8 Artefactos de configuración obligatorios

Deben existir archivos de configuración mínimos para que el proyecto sea reproducible:

- `Cargo.toml`
- `src-tauri/tauri.conf.json` o equivalente soportado
- configuración Tailwind v4 si aplica al flujo elegido
- scripts mínimos de desarrollo/validación

### B.9 Artefactos de exportación obligatorios

Debe existir soporte real o esqueleto funcional para exportación al menos a:

- JSON
- HTML

### B.10 Artefactos de trazabilidad obligatorios

Debe existir una forma explícita de:

- registrar auditoría básica de escaneos;
- registrar errores internos;
- registrar hits y misses de caché;
- registrar cambios de estado.

---

## C. Reglas de implementación

### C.1 Filosofía general de implementación

El código debe parecer escrito por un **ingeniero senior sobrio**, no por un generador apresurado de snippets.

El agente debe priorizar:

- claridad;
- bajo acoplamiento;
- nombres consistentes;
- contratos explícitos;
- modularidad real;
- control de errores;
- explicabilidad.

### C.2 Reglas de Rust

El backend Rust debe cumplir estas reglas:

- separar modelos, lógica de dominio, IO y comandos de Tauri;
- no meter toda la lógica en `main.rs`;
- usar `Result` y tipos de error propios, no `unwrap()` indiscriminados;
- evitar `panic!` salvo situaciones imposibles o tests;
- tipar estados y bandas de riesgo con enums;
- tipar estructuras JSON con structs claras;
- aislar llamadas a Windows APIs en módulos concretos;
- evitar funciones gigantes;
- documentar invariantes importantes.

Queda prohibido:

- lógica crítica en cadenas de `if` opacas y repetidas;
- reutilizar structs ambiguas para varios fines incompatibles;
- meter SQL inline caótico en múltiples sitios sin capa mínima de orden.

### C.3 Reglas de frontend

El frontend debe ser:

- semántico;
- ligero;
- modular;
- sin framework SPA.

Debe cumplir:

- HTML legible;
- JS ESM separado por responsabilidades;
- renderizado explícito y simple;
- componentes de UI pequeños y claros;
- cero dependencias frontend pesadas salvo necesidad clarísima.

Queda prohibido:

- introducir React/Vue/Svelte “por ergonomía”;
- meter build chains complejas sin necesidad;
- esconder toda la UI en una sola función de render masiva;
- abusar de clases utilitarias caóticas sin orden visual mínimo.

### C.4 Reglas de SQLite

La persistencia debe ser explícita y entendible.

Debe cumplir:

- tablas con nombres claros;
- claves primarias definidas;
- índices donde aporten valor;
- separación razonable entre observaciones, identidad, baseline y decisiones;
- migraciones o scripts iniciales claros.

Queda prohibido:

- inventar tablas intermedias sin función clara;
- duplicar datos porque “simplifica” un poco el código;
- ocultar el esquema en una capa mágica no documentada;
- usar un ORM pesado si no aporta valor real.

### C.5 Reglas del contrato JSON

El contrato `scan_now` es un artefacto de primer nivel.

Debe cumplir:

- shape estable;
- `schema_version` explícita;
- campos faltantes representados como `null`/`unknown`, no inventados;
- serialización consistente;
- compatibilidad con tests del contrato.

Queda prohibido:

- renombrar campos arbitrariamente;
- meter estructuras improvisadas distintas entre ejecuciones;
- devolver arrays heterogéneos sin tipado claro.

### C.6 Reglas de baseline y scoring

La lógica de baseline y scoring debe ser determinista, auditable y comprensible.

Debe cumplir:

- reason codes explícitos;
- score derivado de reglas y señales identificables;
- transición de estados controlada;
- revalidación explícita al cambiar hash;
- distinción clara entre `Observed_Local` y baseline consolidado.

Queda prohibido:

- modelos opacos sin trazabilidad;
- depender de un LLM para asignar el estado principal;
- mezclar scoring y rendering UI en el mismo módulo.

### C.7 Reglas de dependencias

Cada dependencia nueva debe justificarse por escrito en la tarea o el commit.

Preguntas obligatorias antes de añadir una dependencia:

1. ¿Resuelve algo que no cubre razonablemente el estándar o el stack actual?
2. ¿Reduce complejidad neta, no solo local?
3. ¿Evita código inseguro o frágil?
4. ¿Tiene sentido mantenerla en Windows/Tauri/Rust?

Si la respuesta no es claramente sí, no debe añadirse.

### C.8 Reglas de seguridad y privacidad

El agente debe implementar con mentalidad de minimización:

- no enviar más datos de los necesarios a Intel externo;
- no registrar secretos innecesarios;
- no filtrar paths completos al exterior salvo necesidad justificada;
- no almacenar basura sensible sin propósito.

### C.9 Reglas de documentación

Toda pieza importante debe dejar huella documental.

Si el agente toca:

- esquema SQLite;
- contrato JSON;
- estados del baseline;
- scoring;
- estructura del proyecto;

entonces debe actualizar la documentación correspondiente en `docs/`.

### C.10 Reglas de cambios grandes

Si la tarea es grande, el agente debe dividirla en pasos pequeños y reversibles.

Queda prohibido:

- hacer refactors masivos sin justificación;
- mezclar arquitectura, UI, DB y tests en una única mega-entrega caótica;
- cambiar demasiadas cosas sin actualizar docs.

### C.11 Reglas de estilo del producto

El resultado debe transmitir:

- sobriedad;
- precisión;
- utilidad;
- austeridad técnica.

Queda prohibido:

- estética de dashboard corporativo genérico;
- copy inflado;
- gimmicks visuales;
- features “wow” sin valor operativo.

---

## D. Criterios de aceptación

### D.1 Regla general

Una tarea **no está terminada** porque el agente “crea que ya funciona”.

Una tarea solo se considera terminada si cumple criterios verificables y deja artefactos concretos.

### D.2 Criterios globales de aceptación de v0.1

La v0.1 solo se considera aceptable si cumple simultáneamente:

1. Existe una app de escritorio Tauri 2 funcional en Windows.
2. El frontend es purista y no usa frameworks frontend no autorizados.
3. El comando `Scan Now` devuelve un JSON compatible con `docs/scan-now-contract.json`.
4. El backend calcula o recupera `sha256` para cualquier binario que pueda entrar en baseline.
5. Existe caché de identidad funcional.
6. Existen estados de baseline implementados según este Blueprint.
7. Existen tests del contrato JSON, scoring y transiciones.
8. Existen pantallas mínimas funcionales para resumen, listado y detalle.
9. El sistema distingue al menos entre conocido, observado local, cambio detectado y potencialmente peligroso.
10. El código y la documentación están alineados.

### D.3 Criterios de aceptación del Collector

El Collector se acepta solo si:

- recoge conexiones salientes activas visibles;
- asocia observaciones a PID/proceso;
- no rompe el flujo completo si una observación falla;
- devuelve estructuras consistentes y tipadas.

### D.4 Criterios de aceptación del Enricher

El Enricher se acepta solo si:

- resuelve ruta del ejecutable cuando sea posible;
- detecta archivo ausente o irresoluble;
- calcula o recupera hash mediante caché;
- expone trust/signature metadata;
- clasifica correctamente la ruta en una categoría válida.

### D.5 Criterios de aceptación del Risk Engine

El Risk Engine se acepta solo si:

- asigna banda de riesgo válida;
- produce `reason_codes` explícitos;
- maneja cambios de hash como revalidación;
- detecta procesos huérfanos como hallazgos críticos;
- diferencia entre `Observed_Local` y baseline consolidado;
- no depende de Intel externo para funcionar.

### D.6 Criterios de aceptación del baseline

El baseline se acepta solo si:

- no promociona por simple repetición ciega;
- conserva estados intermedios;
- soporta revalidación;
- persiste en SQLite;
- puede explicar por qué un elemento está en un estado dado.

### D.7 Criterios de aceptación del frontend

El frontend se acepta solo si:

- permite lanzar `Scan Now`;
- muestra resumen del escaneo;
- lista findings con estado y banda;
- abre detalle con hash, firma, destino, afinidad y motivos;
- no depende de framework SPA;
- mantiene una estructura mínima ordenada.

### D.8 Criterios de aceptación de persistencia

La persistencia se acepta solo si:

- existe esquema SQLite inicial reproducible;
- se registran scans y findings;
- se registran baseline entries y decisiones;
- existen índices razonables;
- la documentación del esquema está actualizada.

### D.9 Criterios de aceptación de testing

La implementación se acepta solo si:

- los tests críticos existen físicamente;
- el shape del JSON está validado;
- las transiciones del baseline están cubiertas;
- el scoring tiene cobertura mínima significativa;
- la caché de identidad está probada;
- los escenarios críticos tienen fixtures o mocks.

### D.10 Criterios de aceptación de documentación

Una entrega no está completa si toca arquitectura o dominio y no actualiza:

- `docs/architecture.md`
- `docs/scan-now-contract.json`
- `docs/scoring-model.md`
- `docs/sqlite-schema.md`
- `docs/testing-strategy.md`

según corresponda.

### D.11 Criterios mecánicos de autoevaluación del agente

Antes de dar una tarea por terminada, el agente debe poder contestar “sí” a todo esto:

- ¿He respetado el stack fijado sin sustituirlo?
- ¿He evitado dependencias no justificadas?
- ¿He generado archivos reales y no solo fragmentos?
- ¿El contrato `scan_now` sigue siendo coherente y versionado?
- ¿Existen tests para lo tocado?
- ¿He actualizado documentación afectada?
- ¿He evitado rediseñar la app fuera del alcance?
- ¿No he convertido el producto en un EDR/firewall/antivirus?
- ¿El resultado sigue siendo sobrio, ligero y explicable?

Si alguna respuesta es “no”, la tarea no debe marcarse como terminada.

### D.12 Criterio final de “Definition of Done”

Una entrega solo está realmente terminada cuando deja:

- código funcional;
- tests ejecutables o claramente preparados;
- documentación actualizada;
- artefactos persistentes en repo;
- cero desviaciones de arquitectura no autorizadas.

---

## E. Cláusula final para agentes

Si un agente cree que puede “mejorar” este proyecto desviándose de estas decisiones, está equivocado por defecto.

El comportamiento correcto no es improvisar una arquitectura nueva.
El comportamiento correcto es:

- respetar el Blueprint;
- respetar este apéndice;
- implementar de forma incremental;
- documentar dudas;
- no inventar alcance.

La creatividad aquí solo es aceptable dentro de los límites fijados.
Fuera de esos límites, se considera desviación.

