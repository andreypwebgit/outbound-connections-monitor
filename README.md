# Outbound Connections Monitor (OCM)

[![Web Oficial](https://img.shields.io/badge/🌐_Web_Oficial-ocm.apwebai.es-2563eb?style=for-the-badge)](https://ocm.apwebai.es/)
[![Licencia](https://img.shields.io/badge/Licencia-MIT-green?style=for-the-badge)](LICENSE)
[![Descargas](https://img.shields.io/github/v/release/andreypwebgit/outbound-connections-monitor?style=for-the-badge&label=Descargas&color=orange)](https://github.com/andreypwebgit/outbound-connections-monitor/releases/latest)
[![CI](https://github.com/andreypwebgit/outbound-connections-monitor/actions/workflows/ci.yml/badge.svg)](https://github.com/andreypwebgit/outbound-connections-monitor/actions/workflows/ci.yml)

**Web oficial: [https://ocm.apwebai.es/](https://ocm.apwebai.es/)** — información del proyecto, guía de uso y descargas.

Analizador local y bajo demanda de conexiones salientes para Windows, estable,
explicable y transparente sobre la cobertura real de cada escaneo.

> **⚠️ Aviso de firma:** los binarios oficiales v1.x no están firmados
> con Authenticode. Windows puede mostrar `Editor desconocido` o una
> advertencia de SmartScreen. Descarga OCM únicamente desde la
> [release oficial](https://github.com/andreypwebgit/outbound-connections-monitor/releases/latest)
> y verifica `checksums.txt` y la attestation de GitHub. La release mantiene
> SHA-256, SBOM SPDX y procedencia vinculada al workflow y al commit.

## 🏗 Arquitectura actual (v1.0)

El proyecto está diseñado bajo estrictos requerimientos de simplicidad operativa, evitando la sobrecarga tecnológica ("bloatware"). Se rige por el principio de **Zero Trust** (Confianza Cero).

*   **Core Backend (Rust):** Lógica pesada, gestión de memoria segura, e interacción nativa con el sistema operativo. Módulos puros:
    *   `Collector`: captura TCP IPv4/IPv6 con `GetExtendedTcpTable` y enumeración UDP con `GetExtendedUdpTable`, sin `netstat` ni parsing de texto localizado.
    *   `Enricher`: inventario nativo de procesos (Toolhelp + APIs de proceso, token y servicios) para ruta, PPID, usuario, inicio y línea de comandos; identidad física (`file_id`, `volume_serial`), SHA-256 y Authenticode cacheado.
    *   `Identity Cache`: caché de dos niveles (SQLite + memoria por scan) que evita recalcular hash y firma si el archivo no cambió, y detecta cambios de contenido (`hash_changed`) que disparan revalidación.
    *   `Baseline Manager`: máquina de estados completa (`Unknown → Candidate → Baseline_Provisional → Baseline_Consolidated`, `Observed_Local` por validación manual, `Revalidation_Required` ante cambios, `Potentially_Dangerous` para hallazgos críticos) con promoción prudente por señales, nunca por repetición ciega.
    *   `Affinity Engine`: afinidad de red real contra perfiles históricos por binario (hostname, root domain, puerto, patrón repetido), con herencia de histórico en revalidaciones.
    *   `Risk Engine`: motor heurístico explicable con señales que elevan y **reducen** riesgo, reason codes trazables y detección de tácticas "Living off the Land".
    *   `Storage (SQLite)`: persistencia completa (scans, observaciones, identidades, trust, baseline, perfiles de afinidad, decisiones de riesgo, decisiones manuales y eventos de auditoría) con migraciones idempotentes.
    *   `Exporter`: exportación JSON (shape del contrato) y HTML autónomo, reproducibles desde el scan persistido.
    *   `Scan Diff`: consulta entre snapshots persistidos para conexiones nuevas/cambiadas, binarios nuevos y cambios de baseline, sin alterar el contrato `scan_now`.
    *   `Coverage Engine`: mide qué familias y etapas del pipeline aportaron
        evidencia, clasifica el snapshot como `complete`, `partial` o
        `degraded` y expone limitaciones y warnings sin convertirlos en una
        puntuación de seguridad.
*   **Presentación / Desktop (Tauri 2):** Actúa como el puente ligero entre la interfaz gráfica y el sistema operativo, permitiendo un binario pequeño e independiente con comunicación asíncrona mediante eventos en tiempo real.
*   **Frontend UI:** 
    *   HTML5 semántico y Vanilla JavaScript **ESM modular** (`api.js`, `state.js`, `render/*`). **Cero dependencias a frameworks SPA (React/Vue/Angular)**.
    *   **Tailwind CSS v4** para un sistema de diseño reactivo, altamente pulido y moderno.

---

## ✨ Funcionalidades y contexto forense (v1.0)

*   **Escaneo "On-Demand" con Feedback UX:** captura fotográfica de conexiones TCP con peer remoto verificable y enumeración técnica de endpoints UDP (Windows no expone su peer en esa API), con progreso asíncrono en la UI.
*   **Panel de completitud del scan (v1.0):** muestra cobertura TCP/UDP por
    familia, ejecución elevada, contexto de proceso, identidad/hash/trust,
    resolución DNS, limitaciones inherentes y warnings. Es calidad de
    evidencia, no una afirmación de que el equipo sea seguro.
*   **Contrato `scan_now` v2:** incorpora el bloque `coverage`; los históricos
    v1 continúan abriéndose y exportándose sin inventar cobertura
    retrospectiva.
*   **Collector nativo y rápido (v0.5):** conexiones y procesos se consultan mediante APIs de Windows. El DNS inverso corre en paralelo con presupuesto acotado; un smoke real con 48 findings y caché caliente completó el scan en **371 ms**.
*   **Caché de identidad:** los hashes y firmas se reutilizan entre scans mientras el archivo no cambie (clave `volume_serial + file_id + file_size + last_write_time`); el contrato expone `hash_source: cache|fresh`. Un cambio de contenido activa revalidación automática del baseline.
*   **Baseline por estados con decisiones manuales:** validación local de binarios (`Candidate → Observed_Local`) y aceptación de revalidaciones desde la propia UI, con auditoría persistida.
*   **Afinidad de red:** cada destino se compara con el patrón histórico del binario (mismo hostname, mismo dominio raíz, puerto habitual, patrón repetido) y produce señales explicables que alimentan el score.
*   **Historial de escaneos:** los scans persistidos se pueden volver a abrir desde la UI con fidelidad total al contrato.
*   **¿Qué hay nuevo? (v0.5):** resumen de diferencias contra el scan anterior y badges `NUEVO` / `CAMBIO` por finding.
*   **Gestión del baseline (v0.5):** vista global de binarios, estados, contadores, trust y validaciones, con acciones restringidas al lifecycle para validar, revocar validación local o aceptar revalidaciones.
*   **Exportación JSON y HTML:** informes reproducibles desde lo persistido, autónomos y sobrios, en la carpeta `exports/`.
*   **Linaje y Contexto de Ejecución:** Proceso Padre, **Línea de Comandos** completa, **Usuario** e instante de inicio del proceso.
*   **Resolución DNS Inversa (Hostname):** Las IPs remotas se traducen a nombres de dominio (y dominio raíz derivado) para contextualizar los destinos.
*   **Inteligencia Heurística Avanzada:** El *Risk Engine* castiga procesos de red hijos de Office (`winword.exe`), scripts de sistema u ofuscación en línea de comandos (ej. `-enc`, `-bypass`), y bonifica firmas válidas, baseline consolidado y alta afinidad.
*   **Línea de comandos contextual (v0.5.1):** los indicadores de PowerShell se reconocen como argumentos completos y dentro de su intérprete; flags legítimos de Chromium/Electron como `--bypasscsp-schemes` ya no producen falsos positivos, sin rebajar la penalización de `-ExecutionPolicy Bypass` o `-EncodedCommand`.
*   **Excepciones de Sistema (Protected Processes):** Reconoce procesos fuertemente protegidos del Kernel (`System`, `MsMpEng.exe`) evitando falsos positivos al justificar por qué no se pueden obtener hashes o rutas de disco.
*   **Auditoría técnica:** eventos internos (`scan_started`, transiciones de baseline, errores de hash/persistencia, exports) quedan registrados en `audit_events`.
*   **Filtro de búsqueda en hallazgos (v0.4.1):** filtrado instantáneo por proceso, IP, hostname, dominio, ruta o hash, combinable con los filtros de riesgo.
*   **Mapeo MITRE ATT&CK (v0.4.1):** los reason codes con correspondencia rigurosa muestran sus técnicas (T1059, T1036.005, T1070.004…) enlazadas a attack.mitre.org.
*   **Supply chain de release (v1.0):** acciones fijadas por SHA, versiones
    sincronizadas, auditoría npm, build y tests en Windows 2022, checksums,
    SBOM y attestation antes de publicar. Los binarios se declaran
    explícitamente unsigned; la integridad y procedencia no se presentan como
    sustituto de una firma de editor.
*   **Tests del dominio crítico:** 102 tests (80 unitarios, 11 de contrato y
    11 de integración SQLite), incluidos collector degradado, reglas de
    completitud, exportación y compatibilidad histórica v1/v2; CI añade
    `cargo fmt --check` y Clippy sin warnings.

---

## ⚙️ Requisitos de Ejecución (Entorno de Desarrollo)

1.  **Sistema Operativo:** Windows 10/11.
2.  **Node.js / npm:** Para la resolución del diseño (Tailwind) y el CLI de Tauri.
3.  **Rust Toolchain:** Instalador de `rustup` que provee `cargo` y el compilador de Rust.
4.  **C++ Build Tools:** Herramientas nativas de compilación de Visual Studio.

**Ejecución Rápida:**
Abre una terminal de **PowerShell como Administrador** (esencial para auditar procesos PPL / SYSTEM) en la raíz del proyecto.
```powershell
# 1. Instalar dependencias web (Tailwind)
npm install

# 2. Levantar la aplicación en modo desarrollo
npx tauri dev
```

**Build de Producción (instalador distribuible):**
```powershell
npx tauri build
```
Genera instaladores **MSI** y **NSIS** en `src-tauri/target/release/bundle/`
que se instalan con doble clic en cualquier Windows 10+ sin Rust ni Node.
Detalles, requisitos del equipo destino y ubicación de datos en
[docs/build-and-distribution.md](docs/build-and-distribution.md).

---

## 🚀 Roadmap de Evolución y Posibles Mejoras

Aunque OCM ya ofrece capacidades tácticas potentes, estas son algunas rutas para seguir escalando su madurez de ciberseguridad:

### 1. APIs Nativas (Rendimiento Total)
*   ✅ **Hecho en v0.5.0** — IP Helper y APIs nativas de proceso sustituyen `netstat`/WMIC/`tasklist`. Authenticode permanece en PowerShell, amortizado por caché; `WinVerifyTrust` nativo queda como optimización futura solo si reduce complejidad neta.

### 2. Integración de Threat Intelligence (IoCs)
*   **APIs de Terceros (opt-in):** Conectar IPs remotas y hashes extraños a bases de datos como **VirusTotal** y **AbuseIPDB** para verificar si una conexión pertenece a una *botnet* conocida. Será siempre **opcional y explícito**: el motor local funciona al 100 % sin red y esa garantía de privacidad se mantiene.
*   ~~**MITRE ATT&CK:**~~ ✅ **Hecho en v0.4.1** — los `reason_codes` con correspondencia rigurosa muestran sus técnicas ATT&CK en la UI (mapeo documentado en [docs/scoring-model.md](docs/scoring-model.md)).

### 3. Diagnóstico Impulsado por IA
*   **Modelos Locales / Cloud (LLM):** Enviar el snapshot forense recolectado (hash, ppid, cmdline) a un modelo de IA entrenado en ciberseguridad para obtener una explicación narrada del por qué un proceso podría ser malicioso o benigno, actuando como un segundo piloto de análisis. Igual que el punto 2: solo como apoyo opcional para casos ambiguos.

### 4. Comparativa entre Escaneos y Gestión del Baseline
*   ✅ **Hecho en v0.5.0 — Diff entre scans:** conexiones nuevas/cambiadas, binarios nuevos y transiciones de baseline respecto al snapshot anterior.
*   ✅ **Hecho en v0.5.0 — Gestión del baseline:** listado global y transiciones manuales válidas, incluida la revocación de `Observed_Local`.
*   *Nota de diseño:* el "modo residente" (tray/ETW) que se contempló en versiones anteriores de este roadmap queda **descartado por diseño**: OCM es una herramienta de escaneo manual y no debe convertirse en daemon ni EDR (decisión cerrada del proyecto; ver [docs/product-vision.md](docs/product-vision.md)).

### 5. Firma, build reproducible y supply chain
*   ✅ **Hecho en v0.4.1** — cada push a `main` ejecuta la suite completa de tests en GitHub Actions, y cada tag `v*` compila los instaladores y publica la release con checksums automáticamente (ver [docs/build-and-distribution.md](docs/build-and-distribution.md)).
*   ✅ **Endurecido en v0.5.0** — el CI exige formato Rust canónico y Clippy con warnings tratados como errores.
*   ✅ **Hecho en v1.0.0** — tag exacto y manifiestos sincronizados, acciones
    fijadas por commit, build y tests en Windows 2022, SBOM SPDX, checksums
    SHA-256 y attestation de procedencia como gates obligatorios. La release
    v1.x se publica sin firma Authenticode y lo declara de forma visible.
*   ✅ **Mantenimiento v1.0.1** — dependencias de aplicación y acciones
    actualizadas, lockfiles sincronizados y suite ampliada a 102 tests, sin
    alterar el contrato `scan_now` v2 ni el comportamiento funcional.

### 6. Transparencia de cobertura
*   ✅ **Hecho en v1.0.0** — panel y contrato de completitud de evidencia con
    estados `complete`, `partial` y `degraded`, contadores por etapa,
    limitaciones explícitas y compatibilidad fiel con históricos v1. Consulta
    [docs/scan-completeness.md](docs/scan-completeness.md).

---

## 💡 Sobre el Autor & APWebAI

OCM ha sido desarrollado como contribución **Open Source** por **Andrey Pérez**. En [APWebAI](https://apwebai.es/) nos dedicamos a la **ingeniería web purista**: rendimiento, semántica y arquitecturas sin sobrecarga tecnológica.

¿Te preocupa cómo los agentes de IA (ChatGPT, Claude, Perplexity) están leyendo tu web corporativa? Descubre nuestro estándar **Agentic Resource Discovery (ARD)** y audita tu dominio gratis en: **[https://ard.apwebai.es](https://ard.apwebai.es)**

---

## 📄 Licencia

Este proyecto se distribuye bajo la licencia [MIT](LICENSE).
