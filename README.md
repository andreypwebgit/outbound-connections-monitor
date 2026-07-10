# Outbound Connections Monitor (OCM)

[![Web Oficial](https://img.shields.io/badge/🌐_Web_Oficial-ocm.apwebai.es-2563eb?style=for-the-badge)](https://ocm.apwebai.es/)
[![Licencia](https://img.shields.io/badge/Licencia-MIT-green?style=for-the-badge)](LICENSE)
[![Descargas](https://img.shields.io/badge/Descargas-v0.4.0-orange?style=for-the-badge)](https://github.com/andreypwebgit/outbound-connections-monitor/releases/latest)

**Web oficial: [https://ocm.apwebai.es/](https://ocm.apwebai.es/)** — información del proyecto, guía de uso y descargas.

Visibilidad humana y contexto técnico avanzado sobre conexiones salientes para sistemas Windows, diseñado para analistas de ciberseguridad y *Threat Hunters*.

> **ℹ️ Nota sobre Windows SmartScreen:** los instaladores de OCM todavía no están firmados digitalmente con un certificado de código. Por eso, la primera vez que ejecutes el instalador (o la app), Windows mostrará el aviso *"Windows protegió tu PC"*. Es el comportamiento normal de SmartScreen con software nuevo sin firma, no una detección de amenaza. Para continuar: haz clic en **"Más información"** y después en **"Ejecutar de todas formas"**. Si prefieres no hacerlo, siempre puedes compilar la app desde este código fuente (ver más abajo).

## 🏗 Arquitectura Actual (v0.4)

El proyecto está diseñado bajo estrictos requerimientos de simplicidad operativa, evitando la sobrecarga tecnológica ("bloatware"). Se rige por el principio de **Zero Trust** (Confianza Cero).

*   **Core Backend (Rust):** Lógica pesada, gestión de memoria segura, e interacción nativa con el sistema operativo. Módulos puros:
    *   `Collector`: Captura de estado de red nativo usando comandos del sistema y WMI (con fallback CIM cuando WMIC no existe).
    *   `Enricher`: Resolución avanzada de procesos, linaje (PPID), extracción de línea de comandos, identidad física del archivo (`file_id`, `volume_serial`), validación criptográfica (SHA-256) y estado de firmas (Authenticode embedded/catalog).
    *   `Identity Cache`: caché de dos niveles (SQLite + memoria por scan) que evita recalcular hash y firma si el archivo no cambió, y detecta cambios de contenido (`hash_changed`) que disparan revalidación.
    *   `Baseline Manager`: máquina de estados completa (`Unknown → Candidate → Baseline_Provisional → Baseline_Consolidated`, `Observed_Local` por validación manual, `Revalidation_Required` ante cambios, `Potentially_Dangerous` para hallazgos críticos) con promoción prudente por señales, nunca por repetición ciega.
    *   `Affinity Engine`: afinidad de red real contra perfiles históricos por binario (hostname, root domain, puerto, patrón repetido), con herencia de histórico en revalidaciones.
    *   `Risk Engine`: motor heurístico explicable con señales que elevan y **reducen** riesgo, reason codes trazables y detección de tácticas "Living off the Land".
    *   `Storage (SQLite)`: persistencia completa (scans, observaciones, identidades, trust, baseline, perfiles de afinidad, decisiones de riesgo, decisiones manuales y eventos de auditoría) con migraciones idempotentes.
    *   `Exporter`: exportación JSON (shape del contrato) y HTML autónomo, reproducibles desde el scan persistido.
*   **Presentación / Desktop (Tauri 2):** Actúa como el puente ligero entre la interfaz gráfica y el sistema operativo, permitiendo un binario pequeño e independiente con comunicación asíncrona mediante eventos en tiempo real.
*   **Frontend UI:** 
    *   HTML5 semántico y Vanilla JavaScript **ESM modular** (`api.js`, `state.js`, `render/*`). **Cero dependencias a frameworks SPA (React/Vue/Angular)**.
    *   **Tailwind CSS v4** para un sistema de diseño reactivo, altamente pulido y moderno.

---

## ✨ Funcionalidades y Contexto Forense (v0.4)

*   **Escaneo "On-Demand" con Feedback UX:** Captura fotográfica de las conexiones TCP/UDP con una interfaz que transmite el progreso asíncrono del backend al usuario en tiempo real.
*   **Caché de identidad:** los hashes y firmas se reutilizan entre scans mientras el archivo no cambie (clave `volume_serial + file_id + file_size + last_write_time`); el contrato expone `hash_source: cache|fresh`. Un cambio de contenido activa revalidación automática del baseline.
*   **Baseline por estados con decisiones manuales:** validación local de binarios (`Candidate → Observed_Local`) y aceptación de revalidaciones desde la propia UI, con auditoría persistida.
*   **Afinidad de red:** cada destino se compara con el patrón histórico del binario (mismo hostname, mismo dominio raíz, puerto habitual, patrón repetido) y produce señales explicables que alimentan el score.
*   **Historial de escaneos:** los scans persistidos se pueden volver a abrir desde la UI con fidelidad total al contrato.
*   **Exportación JSON y HTML:** informes reproducibles desde lo persistido, autónomos y sobrios, en la carpeta `exports/`.
*   **Linaje y Contexto de Ejecución:** Proceso Padre, **Línea de Comandos** completa, **Usuario** e instante de inicio del proceso.
*   **Resolución DNS Inversa (Hostname):** Las IPs remotas se traducen a nombres de dominio (y dominio raíz derivado) para contextualizar los destinos.
*   **Inteligencia Heurística Avanzada:** El *Risk Engine* castiga procesos de red hijos de Office (`winword.exe`), scripts de sistema u ofuscación en línea de comandos (ej. `-enc`, `-bypass`), y bonifica firmas válidas, baseline consolidado y alta afinidad.
*   **Excepciones de Sistema (Protected Processes):** Reconoce procesos fuertemente protegidos del Kernel (`System`, `MsMpEng.exe`) evitando falsos positivos al justificar por qué no se pueden obtener hashes o rutas de disco.
*   **Auditoría técnica:** eventos internos (`scan_started`, transiciones de baseline, errores de hash/persistencia, exports) quedan registrados en `audit_events`.
*   **Tests del dominio crítico:** 70 tests (contrato JSON, scoring, transiciones de baseline, afinidad, caché de identidad, clasificación de rutas e integración SQLite).

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
*   Sustituir llamadas indirectas por invocaciones a `IPHLPAPI.DLL`, `EnumProcesses` y verificaciones directas a la API criptográfica de Windows (`WinVerifyTrust`). Esto bajará el tiempo de ejecución a milisegundos e incrementará la resiliencia frente a malware que interfiere con binarios del sistema.

### 2. Integración de Threat Intelligence (IoCs)
*   **APIs de Terceros:** Conectar IPs remotas y hashes extraños a bases de datos como **VirusTotal** y **AbuseIPDB** para verificar si una conexión pertenece a una *botnet* conocida.
*   **Reglas YARA y MITRE ATT&CK:** Mapear los `reason_codes` generados por el *Risk Engine* a las tácticas y técnicas oficiales del framework MITRE ATT&CK para un reporte más estandarizado.

### 3. Diagnóstico Impulsado por IA
*   **Modelos Locales / Cloud (LLM):** Enviar el snapshot forense recolectado (hash, ppid, cmdline) a un modelo de IA entrenado en ciberseguridad para obtener una explicación narrada del por qué un proceso podría ser malicioso o benigno, actuando como un segundo piloto de análisis.

### 4. Modo Residente (EDR Agent)
*   **Background / Tray App:** Permitir que la aplicación minimice a la bandeja del sistema y recolecte telemetría silenciosamente con `ETW` (Event Tracing for Windows) para capturar conexiones efímeras sin depender de un escaneo fotográfico manual.

### 5. Automatización del Build en CI
*   Los instaladores `.msi` / `.exe` ya se generan localmente con `npx tauri build` (ver [docs/build-and-distribution.md](docs/build-and-distribution.md)). El siguiente paso es automatizarlo con GitHub Actions y añadir firma de código para eliminar el aviso de SmartScreen.

---

## 💡 Sobre el Autor & APWebAI

OCM ha sido desarrollado como contribución **Open Source** por **Andrey Pérez**. En [APWebAI](https://apwebai.es/) nos dedicamos a la **ingeniería web purista**: rendimiento, semántica y arquitecturas sin sobrecarga tecnológica.

¿Te preocupa cómo los agentes de IA (ChatGPT, Claude, Perplexity) están leyendo tu web corporativa? Descubre nuestro estándar **Agentic Resource Discovery (ARD)** y audita tu dominio gratis en: **[https://ard.apwebai.es](https://ard.apwebai.es)**

---

## 📄 Licencia

Este proyecto se distribuye bajo la licencia [MIT](LICENSE).
