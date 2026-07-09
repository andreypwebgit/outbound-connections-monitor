# Outbound Connections Monitor

Visibilidad humana y contexto técnico sobre conexiones salientes para sistemas Windows.

## 🏗 Arquitectura Actual (v0.1)

El proyecto está diseñado bajo los estrictos requerimientos de simplicidad operativa, evitando la sobrecarga tecnológica ("bloatware").

*   **Core Backend (Rust):** Lógica pesada, gestión de memoria segura, y acceso al sistema. Dividido en módulos puros:
    *   `Collector`: Captura de estado de red nativo.
    *   `Enricher`: Resolución de procesos y evaluación criptográfica (SHA-256).
    *   `Risk Engine`: Motor de puntuación heurístico (0-100).
    *   `Storage`: Persistencia local en **SQLite** puro (sin dependencias ORM).
*   **Presentación / Desktop (Tauri 2):** Actúa como el puente ligero entre la interfaz gráfica y el sistema operativo.
*   **Frontend UI:** 
    *   HTML5 semántico y Vanilla JavaScript. **Cero dependencias a frameworks SPA (React/Vue/Angular)**.
    *   **Tailwind CSS v4** para el sistema de diseño reactivo y mantenible.

---

## ✨ Funcionalidades Actuales (v0.1)

*   **Escaneo "On-Demand" (Scan Now):** Captura fotográfica de las conexiones TCP/UDP activas y establecidas del sistema en el momento de la ejecución.
*   **Asociación de Procesos:** Vinculación de puertos locales y remotos con el `PID` y la ruta en disco del ejecutable responsable (`wmic`/`netstat`).
*   **Clasificación de Riesgo:** Evaluación heurística básica asignando "Bands" (ej. `KNOWN_SAFE`, `POTENTIALLY_DANGEROUS`) basado en la ubicación del binario y la información inicial.
*   **Exportación Local:** Generación de un reporte JSON completo de todos los hallazgos al finalizar el escaneo.

---

## ⚙️ Requisitos de Ejecución (Entorno de Desarrollo)

Dado que actualmente el software debe lanzarse en modo desarrollo, se requieren las siguientes herramientas:

1.  **Sistema Operativo:** Windows 10/11.
2.  **Node.js / npm:** Para la resolución del diseño (Tailwind) y el CLI de Tauri.
3.  **Rust Toolchain:** Instalador de `rustup` que provee `cargo` y el compilador de Rust.
4.  **C++ Build Tools:** Herramientas nativas de compilación de Visual Studio (requeridas por Rust en Windows).

**Ejecución:**
```powershell
# Instalar dependencias web (Tailwind)
npm install

# Levantar la aplicación en modo desarrollo
npx tauri dev
```

---

## 🛠 Troubleshooting (Solución de problemas frecuentes)

*   **Error:** `failed to run 'cargo metadata'... program not found`
    *   **Solución:** Rust no está instalado o no está en el `PATH`. Descarga e instala Rust desde rustup.rs, reinicia el terminal, y vuelve a intentarlo.
*   **Advertencia:** `unused variable: _path` durante la compilación.
    *   **Solución:** Ninguna acción necesaria. Las validaciones de firmas de código (Authenticode) nativas de Windows están mockeadas en v0.1 por simplicidad de diseño; la variable se omitió deliberadamente.
*   **Pantalla en blanco / Fallo de conexión del WebView (puerto 1420):**
    *   **Solución:** Asegúrate de que `tauri.conf.json` no tiene definida la clave `devUrl`. Al ser Vanilla JS puro sin servidor local Vite, Tauri debe servir los archivos directamente desde el disco (`frontendDist`).
*   **Procesos huérfanos o acceso denegado a rutas (`System`):**
    *   **Solución:** Ejecutar el terminal (PowerShell) como Administrador antes de lanzar `npx tauri dev`.

---

## 🚀 Recomendaciones y Roadmap de Evolución

La v0.1 es una prueba de concepto sólida de extremo a extremo, pero tiene limitantes claros si queremos que se vuelva una herramienta de grado de producción (Product-led).

### Mejoras Funcionales y de Rendimiento (Hacia v0.2)
1.  **Integración con APIs Nativas (C/C++ Bindings):** Sustituir el uso de comandos shell (`netstat`, `wmic`) por llamadas nativas a la API de Windows (`IPHLPAPI.DLL`, `EnumProcesses`). Esto reducirá el tiempo de escaneo de varios segundos a milisegundos.
2.  **Verificación de Firmas Authenticode:** Integrar `WinVerifyTrust` en Rust para validar matemáticamente si los procesos de Windows (ej. `svchost.exe`, `MsMpEng.exe`) son legítimos de Microsoft o suplantaciones de malware.
3.  **Módulos de Inteligencia (Intel):** Conectar el backend de Rust con APIs de VirusTotal y AbuseIPDB para enriquecer las IPs destino y el hash SHA-256 de los ejecutables extraños.
4.  **Monitorización Continua (Background Mode):** En lugar de un botón "Scan Now", la app debería residir en la bandeja del sistema (System Tray) recopilando datos pasivamente.

### Mejoras Operativas y de Despliegue (Distribución Local)
1.  **Distribución de Instaladores (`.msi` / `.exe`):** El usuario final **jamás** debería tener que instalar Node.js ni Rust. Mediante GitHub Actions, podemos usar `tauri build` para generar un instalador de Windows firmado (Portable/Instalable). El usuario simplemente hará doble clic.
2.  **Mecanismo de Auto-Actualización:** Integrar el updater nativo de Tauri para mandar parches directamente al instalador final.

### Transformación hacia un Modelo SaaS (Hacia v1.0 / v2.0)
Si la visión a largo plazo es monetizar la herramienta u ofrecerla a flotas corporativas empresariales:

1.  **De Aplicación Desktop a Agente Ligero (EDR Agent):**
    *   Quitar la interfaz gráfica (Tauri) del equipo cliente. Compilar el backend de Rust como un "Windows Service" puro de ínfimo consumo de RAM ( < 15 MB).
    *   El agente corre silenciosamente enviando telemetría (conexiones, baselines locales) a la nube de manera segura (mTLS / gRPC).
2.  **Consola en la Nube (SaaS Web Panel):**
    *   Reescribir el Frontend que tenemos y alojarlo en la nube (Vercel/AWS) con un framework robusto.
    *   Los analistas de ciberseguridad iniciarían sesión en la web para monitorizar 500 ordenadores al mismo tiempo, ver el Risk Engine de toda la flota corporativa, establecer políticas globales y recibir alertas en Slack/Email.
3.  **Threat Intelligence Centralizado:**
    *   Realizar el cálculo de afinidad y heurística en los servidores cloud para no afectar la CPU de los portátiles de los usuarios.
