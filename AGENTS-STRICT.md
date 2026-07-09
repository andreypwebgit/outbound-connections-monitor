# AGENTS-STRICT.md

## Modo estricto

Este archivo es una **capa restrictiva adicional** sobre `AGENTS.md`.

Si existe cualquier conflicto entre:
- ideas del agente,
- convenciones genéricas del ecosistema,
- sugerencias “innovadoras”,
- o interpretaciones libres del alcance,

manda siempre este archivo.

El objetivo de este modo no es explorar. El objetivo es **ejecutar con disciplina**.

---

## 1. Regla suprema

El agente **no está aquí para rediseñar** el producto.

El agente está aquí para:
- implementar lo ya decidido;
- refinar sin desviar;
- completar artefactos faltantes;
- endurecer calidad;
- mantener el proyecto pequeño, claro y controlado.

Si el agente cree que una idea nueva “podría mejorar” el proyecto, debe asumir por defecto que **no debe introducirla**.

---

## 2. Prohibiciones absolutas

### 2.1 No rediseñar arquitectura
Queda prohibido:
- cambiar el stack;
- introducir nuevas capas arquitectónicas;
- convertir el proyecto en multiplataforma;
- convertir el escaneo manual en monitorización continua;
- transformar la app en antivirus, EDR, IDS o firewall.

### 2.2 No introducir tecnología no autorizada
Queda prohibido añadir, proponer o migrar a:
- Electron
- React
- Vue
- Svelte
- Angular
- Next.js
- Node backend principal
- Python backend principal
- C# backend principal
- sidecars como base
- Webpack
- Vite como obligación estructural del frontend
- ORMs pesados
- bases de datos servidor
- telemetría remota del producto

### 2.3 No sobreingeniería
Queda prohibido:
- añadir abstracciones “por limpieza futura” si hoy no hacen falta;
- crear módulos genéricos vacíos sin uso real;
- meter patrones enterprise sin necesidad;
- introducir event buses, capas de dominio infladas o factories innecesarias;
- crear más tablas, más servicios o más modelos de los necesarios.

### 2.4 No creatividad de alcance
Queda prohibido:
- inventar features;
- ampliar el roadmap por iniciativa propia;
- añadir “nice to have” sin solicitud;
- meter automatismos de seguridad no pedidos;
- introducir asistentes IA internos, chatbots o paneles “smart”.

---

## 3. Mandatos cerrados

### 3.1 Stack obligatorio
- Windows only
- Tauri 2
- Rust puro
- HTML5 semántico
- Tailwind CSS v4
- JavaScript ESM
- SQLite

### 3.2 Modelo funcional obligatorio
- botón `Scan Now`
- snapshot manual
- enriquecimiento local
- baseline por estados
- afinidad de red
- scoring explicable
- exportación

### 3.3 Modelo de identidad obligatorio
Siempre respetar:
- `disk_truth`
- `trust_truth`
- `execution_truth`
- `behavior_truth`

Nunca reducir a una sola dimensión.

### 3.4 Política de hash obligatoria
- SHA-256 obligatorio para baseline
- caché de identidad obligatoria
- cambio de hash = revalidación
- hash no opcional dentro del baseline

### 3.5 Política de baseline obligatoria
Estados válidos y únicos:
- `Unknown`
- `Candidate`
- `Observed_Local`
- `Baseline_Provisional`
- `Baseline_Consolidated`
- `Revalidation_Required`
- `Potentially_Dangerous`

No inventar estados nuevos salvo autorización explícita.

---

## 4. Regla de mínima complejidad

Ante dos opciones válidas, elegir siempre la más simple que:
- respete el Blueprint,
- respete `AGENTS.md`,
- mantenga tipado, claridad y trazabilidad,
- no comprometa seguridad básica.

No optimizar para un futuro hipotético.
No construir para necesidades imaginarias.
No preparar infraestructura para versiones que todavía no existen.

---

## 5. Regla de dependencias

Cada dependencia nueva es sospechosa por defecto.

Solo puede añadirse si cumple las cuatro condiciones:
1. resuelve un problema real y actual del proyecto;
2. evita complejidad neta, no la desplaza;
3. encaja de forma natural con Tauri/Rust/Windows o con el frontend purista;
4. su ausencia obligaría a una solución claramente peor.

Si no se cumplen las cuatro, no se añade.

---

## 6. Regla de implementación

El código debe parecer hecho por un ingeniero sobrio y exigente.

### Backend
- funciones pequeñas;
- enums y structs claras;
- errores tipados;
- cero `unwrap()` en rutas reales de ejecución;
- separación limpia entre collector, enricher, risk engine, baseline y storage;
- SQL explícito y entendible;
- nada de lógica crítica en `main.rs`.

### Frontend
- HTML claro;
- JS ESM modular;
- render simple;
- cero framework SPA;
- cero artificio visual;
- UX sobria y utilitaria.

### Persistencia
- esquema SQLite explícito;
- índices razonables;
- nombres claros;
- sin magia ORM innecesaria;
- sin tablas decorativas.

---

## 7. Regla de documentación obligatoria

Si el agente toca cualquiera de estas piezas:
- contrato JSON,
- esquema SQLite,
- estados del baseline,
- scoring,
- estructura del proyecto,
- artefactos principales,

entonces debe actualizar la documentación correspondiente.

No se acepta código que cambie el comportamiento sin dejar rastro documental.

---

## 8. Regla de entregables

El agente debe dejar siempre **archivos reales**.

No se acepta como entrega válida:
- pseudocódigo sin implementación;
- fragmentos sueltos;
- explicaciones sin cambios persistentes;
- “sugerencias” en lugar de artefactos.

Toda tarea debe aterrizar en:
- código,
- tests,
- docs,
- o una combinación explícita de ellos.

---

## 9. Regla de calidad mínima

Nada se da por terminado si no cumple estas condiciones:
- el stack sigue intacto;
- no se ha ampliado alcance;
- el contrato `scan_now` sigue coherente;
- hay tests de lo tocado o se actualizan los existentes;
- la documentación afectada está alineada;
- no se ha introducido complejidad ornamental;
- el resultado sigue siendo sobrio, ligero y explicable.

---

## 10. Señales de desvío

Si el agente se descubre proponiendo o haciendo cualquiera de estas cosas, debe detenerse y corregirse:
- “He añadido esta capa para futuras integraciones”
- “He preparado compatibilidad multiplataforma”
- “He metido este framework para ir más rápido”
- “He creado esta abstracción por limpieza”
- “He normalizado más tablas por si acaso”
- “He añadido monitorización continua porque aporta más valor”
- “He incorporado una librería porque es estándar en la industria”

En este proyecto, esas frases son señales de deriva.

---

## 11. Criterio final

Este proyecto debe salir:
- pequeño,
- serio,
- controlado,
- mantenible,
- explicable,
- sin florituras.

La misión del agente no es impresionar.
La misión del agente es **obedecer bien, construir limpio y no desmadrarse**.

---

## 12. Política de Zero Trust (Confianza Cero)

En el ámbito de seguridad y para este proyecto en particular, rige el principio:
**"Todas las conexiones son sospechosas (potencialmente peligrosas) hasta que se demuestre lo contrario"**.

Esto implica:
- Las clasificaciones de `KNOWN_SAFE` deben ganarse a base de pruebas (firmas criptográficas válidas, baselines históricos maduros).
- En la interfaz, la información nunca debe ocultarse por defecto asumiendo que es inofensiva. Todo se muestra y el usuario filtra manualmente.
- Ante la duda técnica o falta de información fiable sobre un binario o servicio, la heurística siempre debe empujar la puntuación de riesgo hacia arriba (`REVIEW` o `DANGER`).
