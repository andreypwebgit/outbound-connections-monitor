# Build y Distribución

Cómo generar los artefactos de producción de OCM para Windows y cómo
distribuirlos a equipos que no tienen herramientas de desarrollo.

## Releases automáticas (CI)

La vía oficial es el pipeline de GitHub Actions:

- **`.github/workflows/ci.yml`** — en cada push/PR a `main` compila Tailwind,
  exige `cargo fmt --check`, ejecuta Clippy con warnings como error y lanza la
  suite completa de tests en un runner Windows.
- **`.github/workflows/release.yml`** — un tag `vX.Y.Z` exacto valida las
  cuatro versiones, comprueba la política de publicación, ejecuta los mismos
  gates, construye ejecutable, MSI y NSIS, y publica `checksums.txt`, SBOM
  SPDX y attestation de procedencia junto a los binarios.

Las acciones de terceros están fijadas por SHA completo y Dependabot propone
sus actualizaciones. Los runners son `windows-2022`, Node está fijado a la
línea 20 y las dependencias Rust/npm quedan cerradas por `Cargo.lock` y
`package-lock.json`.

Publicar una versión nueva se reduce a:

```powershell
# sincronizar Cargo.toml, tauri.conf.json, package.json y package-lock.json
.\scripts\validate-release.ps1 -Tag vX.Y.Z
git tag vX.Y.Z
git push origin vX.Y.Z
```

No debe crearse el tag hasta que CI esté verde. Un fallo de test, build, SBOM,
attestation o publicación detiene el workflow.

## Política de firma de la release

Los binarios oficiales v1.x no están firmados con Authenticode porque el
proyecto no dispone de un certificado de firma de código público. El workflow
no solicita credenciales Azure, no descarga clientes de firma y no presenta
checksums o attestations como si fueran una identidad de editor.

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
| Ejecutable suelto | `src-tauri/target/release/app.exe` | Solo para pruebas: funciona con doble clic pero **no** instala WebView2 ni crea accesos directos; la release lo publica como `out-cxns-monitor.exe` |

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

## Firma, SmartScreen y verificación

El ejecutable, MSI y NSIS oficiales v1.x no están firmados con Authenticode.
Windows puede mostrar `Editor desconocido` o una advertencia de SmartScreen.
No debe recomendarse ignorar la advertencia: antes de ejecutar hay que
comprobar que el archivo procede de la release oficial, que su SHA-256 coincide
con `checksums.txt` y que la attestation lo vincula al workflow de este
repositorio.

Verificación local:

```powershell
Get-AuthenticodeSignature .\out-cxns-monitor.exe |
  Select-Object Status, StatusMessage, SignerCertificate
Get-FileHash .\out-cxns-monitor.exe -Algorithm SHA256
```

`Get-AuthenticodeSignature` debe informar `NotSigned`; no es un fallo de
descarga sino el estado publicado y documentado. El hash debe coincidir con
`checksums.txt`. Con GitHub CLI también puede verificarse la procedencia:

```powershell
gh attestation verify .\out-cxns-monitor.exe `
  --repo andreypwebgit/outbound-connections-monitor
```

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

Validación local v1.0.0 realizada el 2026-07-23:

- `npx tauri build --no-bundle --ci`: exit code 0 y
  `target/release/app.exe` generado;
- `npx tauri bundle --bundles nsis --ci`: NSIS 1.0.0 generado;
- `npx tauri dev`: watcher iniciado, compilación debug, `target/debug/app.exe`
  mantenido en ejecución durante el smoke y cierre controlado;
- el bundle MSI local requiere que la característica opcional VBSCRIPT de
  Windows esté habilitada. La release oficial se construye en
  `windows-2022`, donde el workflow debe producir ambos formatos antes de
  publicar.

Validación local v1.0.1 realizada el 2026-08-01:

- versiones y tag `v1.0.1` sincronizados; política de release unsigned en
  verde;
- `npm ci`, `npm audit --audit-level=high` y build Tailwind 4.3.3 en verde,
  con cero vulnerabilidades;
- `cargo fmt --check`, Clippy con warnings como error y 102 tests en verde;
- `npx tauri build --no-bundle --ci`: ejecutable release 1.0.1 generado;
- `npx tauri bundle --bundles nsis --ci`:
  `out-cxns-monitor_1.0.1_x64-setup.exe` generado;
- `npx tauri dev`: compilación debug 1.0.1, ventana
  `Outbound Connections Monitor` abierta y respondiendo, seguida de cierre
  controlado.

El MSI se mantiene como gate remoto: el workflow de release en
`windows-2022` debe producir ejecutable, MSI y NSIS antes de publicar.
