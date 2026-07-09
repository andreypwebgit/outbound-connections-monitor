# Outbound Connections Monitor (OCM)

Visibilidad humana y contexto técnico avanzado sobre conexiones salientes para sistemas Windows, diseñado para analistas de ciberseguridad y *Threat Hunters*.

## 🏗 Arquitectura Actual (v0.3.1)

El proyecto está diseñado bajo estrictos requerimientos de simplicidad operativa, evitando la sobrecarga tecnológica ("bloatware"). Se rige por el principio de **Zero Trust** (Confianza Cero).

*   **Core Backend (Rust):** Lógica pesada, gestión de memoria segura, e interacción nativa con el sistema operativo. Módulos puros:
    *   `Collector`: Captura de estado de red nativo usando comandos del sistema y WMI.
    *   `Enricher`: Resolución avanzada de procesos, linaje (PPID), extracción de línea de comandos, validación criptográfica (SHA-256) y estado de firmas (Authenticode).
    *   `Risk Engine`: Motor heurístico inteligente capaz de detectar tácticas de ofuscación ("Living off the Land") y escalada de privilegios.
    *   `Baseline Manager & Storage`: Persistencia local estructurada en **SQLite** puro para recordar comportamientos históricos, con soporte para migraciones limpias (retrocompatible).
    *   `DNS Resolver`: Resolución inversa de IPs remotos mediante llamadas a red nativas (sin dependencias pesadas C/C++).
*   **Presentación / Desktop (Tauri 2):** Actúa como el puente ligero entre la interfaz gráfica y el sistema operativo, permitiendo un binario pequeño e independiente con comunicación asíncrona mediante eventos en tiempo real.
*   **Frontend UI:** 
    *   HTML5 semántico y Vanilla JavaScript. **Cero dependencias a frameworks SPA (React/Vue/Angular)**.
    *   **Tailwind CSS v4** para un sistema de diseño reactivo, altamente pulido y moderno.

---

## ✨ Funcionalidades y Contexto Forense (v0.3.1)

*   **Escaneo "On-Demand" con Feedback UX:** Captura fotográfica de las conexiones TCP/UDP con una interfaz que transmite el progreso asíncrono del backend al usuario en tiempo real.
*   **Linaje y Contexto de Ejecución:** Extrae el Proceso Padre (quién lo ejecutó), la **Línea de Comandos** completa (útil para ver argumentos maliciosos o scripts en Base64), y el **Usuario** bajo el que corre.
*   **Resolución DNS Inversa (Hostname):** Las IPs anónimas remotas son traducidas a nombres de dominio legibles en milisegundos para contextualizar los destinos.
*   **Inteligencia Heurística Avanzada:** El *Risk Engine* no solo clasifica, sino que analiza comportamientos. Castiga fuertemente procesos de red hijos de Office (`winword.exe`), scripts de sistema, u ofuscación en línea de comandos (ej. `-enc`, `-bypass`).
*   **Excepciones de Sistema (Protected Processes):** Reconoce procesos fuertemente protegidos del Kernel (`System`, `MsMpEng.exe`) evitando falsos positivos al justificar por qué no se pueden obtener hashes o rutas de disco.
*   **Persistencia Completa (SQLite):** Guarda en disco cada aspecto forense (identidades binarias, histórico de baselines, decisiones de riesgo) sin dependencias adicionales de bases de datos externas.
*   **Panel Interactivo Avanzado:** Clasificación automatizada (Safe, Review, Danger, Other) con totales coherentes e inspección a fondo (Acordeón UX) para el *Threat Hunter*.

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

### 5. Compilación a Producción
*   Generar instaladores pre-empaquetados (`.msi` / `.exe`) usando GitHub Actions. Esto elimina la necesidad de requerir un entorno Node/Rust en el cliente, logrando un despliegue "Zero-Config".
