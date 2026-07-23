# Build y Distribución

Cómo generar los artefactos de producción de OCM para Windows y cómo
distribuirlos a equipos que no tienen herramientas de desarrollo.

## Releases automáticas (CI)

Desde v0.4.1 la vía recomendada es el pipeline de GitHub Actions:

- **`.github/workflows/ci.yml`** — en cada push/PR a `main` compila Tailwind,
  exige `cargo fmt --check`, ejecuta Clippy con warnings como error y lanza la
  suite completa de tests en un runner Windows.
- **`.github/workflows/release.yml`** — al empujar un tag `v*` ejecuta los
  tests, compila los instaladores (`npx tauri build`), genera
  `checksums.txt` (SHA-256) y **publica la release de GitHub** con los tres
  archivos adjuntos y notas generadas a partir de los commits.

Publicar una versión nueva se reduce a:

```powershell
# actualizar version en src-tauri/Cargo.toml y src-tauri/tauri.conf.json
git tag vX.Y.Z
git push origin vX.Y.Z
```

El build local descrito a continuación sigue siendo válido para desarrollo
y verificación manual.

## Requisitos (solo en la máquina que construye)

- Windows 10/11
- Node.js + npm (Tailwind y el CLI de Tauri)
- Rust toolchain (`rustup` con target MSVC)
- Visual Studio C++ Build Tools

El equipo **destino** no necesita nada de esto (ver "Requisitos del equipo
destino").

## Comando de build

```powershell
# En la raíz del repo
npm install        # solo la primera vez
npx tauri build
```

Qué hace, en orden:

1. `beforeBuildCommand` (`npm run build`): compila Tailwind a `src/css/output.css`.
2. `cargo build --release` del backend Rust.
3. Bundling de instaladores Windows según `bundle.targets` de
   `src-tauri/tauri.conf.json` (`msi` + `nsis`). La primera vez descarga
   automáticamente las herramientas WiX y NSIS (requiere red).

## Artefactos generados

Ver la sección "Resultado del build verificado" al final para los nombres
exactos. Rutas:

| Artefacto | Ruta | Uso |
|---|---|---|
| Instalador MSI (WiX) | `src-tauri/target/release/bundle/msi/*.msi` | Instalación clásica / despliegue corporativo (GPO, Intune) |
| Instalador NSIS | `src-tauri/target/release/bundle/nsis/*-setup.exe` | Instalador ligero de doble clic (recomendado para usuarios finales) |
| Ejecutable suelto | `src-tauri/target/release/out-cxns-monitor.exe` | Solo para pruebas: funciona con doble clic pero **no** instala WebView2 ni crea accesos directos |

Cualquiera de los dos instaladores cumple el objetivo de distribución: el
usuario hace doble clic, instala y ejecuta sin Rust/Node.

## Requisitos del equipo destino

- **Windows 10 o superior.**
- **WebView2 Runtime**: los Windows 10/11 actualizados ya lo incluyen. Si
  falta, ambos instaladores lo **descargan e instalan automáticamente**
  (`webviewInstallMode: downloadBootstrapper` en `tauri.conf.json`); en ese
  caso la instalación necesita conexión a Internet.
- **Permisos**: la app funciona como usuario normal. Ejecutarla como
  administrador mejora la resolución de procesos de otros usuarios/SYSTEM
  (misma recomendación que en desarrollo).

## Dónde guarda datos la app instalada

En producción la app **no** escribe junto al ejecutable (Program Files no es
escribible): usa el directorio de datos local del usuario.

```
%LOCALAPPDATA%\com.apwebai.out-cxns-monitor\
├── ocm_baseline.db     (baseline, identidades, historial, auditoría)
├── last_scan.json      (export automático del último scan)
└── exports\            (exportaciones JSON/HTML bajo demanda)
```

En desarrollo (`npx tauri dev`) se mantiene el comportamiento histórico: los
mismos archivos en la raíz del repo. La selección de ruta ocurre una vez en el
arranque (`src-tauri/src/lib.rs` + `core/paths.rs`) según `debug_assertions`.

Consecuencia: el baseline de producción y el de desarrollo son bases de datos
independientes. La primera ejecución en un equipo nuevo empieza con baseline
vacío (todo aparecerá como `Unknown`, es el comportamiento esperado del
modelo).

## SmartScreen y firma de código

Los artefactos **no están firmados** con certificado de código. Windows
SmartScreen mostrará "Windows protegió tu PC" la primera vez: el usuario debe
pulsar *Más información → Ejecutar de todas formas*. Para distribución amplia,
el paso pendiente es firmar con un certificado (EV) de código, fuera del
alcance actual.

## Desinstalación

Ambos instaladores registran la app en *Configuración → Aplicaciones*. La
desinstalación **no** borra `%LOCALAPPDATA%\com.apwebai.out-cxns-monitor\`
(el baseline del usuario se conserva deliberadamente; borrarlo es manual).

## Cambios de configuración que habilitaron el build

- `identifier`: `com.tauri.dev` → `com.apwebai.out-cxns-monitor`. Tauri
  rechaza el build de producción con el identifier por defecto.
- `bundle.targets`: `"all"` → `["msi", "nsis"]` (explícito para Windows; se
  eliminó la sección `android` del scaffolding, el proyecto es Windows-only).
- `bundle.windows.webviewInstallMode`: `downloadBootstrapper` explícito.
- Rutas de datos por perfil (dev/release) vía `AppPaths` — sin esto el
  ejecutable instalado moría al arrancar intentando crear la base de datos en
  una ruta relativa al cwd.

## Resultado del build verificado

Build de referencia: 2026-07-10, v0.5.0, `npx tauri build`, Tauri 2.11.x,
perfil release, exit code 0, "Finished 2 bundles".

| Artefacto | Tamaño |
|---|---|
| `bundle/msi/out-cxns-monitor_0.5.0_x64_en-US.msi` | 3,82 MiB |
| `bundle/nsis/out-cxns-monitor_0.5.0_x64-setup.exe` | 2,65 MiB |
| `target/release/app.exe` (binario suelto, sin instalador) | 10,60 MiB |

Nota: el binario suelto conserva el nombre del package Cargo (`app.exe`); los
instaladores lo despliegan como `out-cxns-monitor.exe` con accesos directos.

Smoke test v0.5.0 realizado con `npx tauri dev`: ventana WebView2 operativa,
scan real, historial/diff y gestión del baseline renderizados. Con identity
cache completamente caliente, un snapshot de 45 findings terminó en 366 ms.

Smoke test v0.5.1 realizado el 2026-07-23 con `npx tauri dev`: compilación
debug correcta, `target/debug/app.exe` iniciado y ventana WebView2
`Outbound Connections Monitor` operativa. La instancia de desarrollo se
cerró de forma controlada después de la comprobación.
