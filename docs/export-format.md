# Export Format

## Objetivo

Definir qué se exporta y con qué nivel de detalle en v0.1.

## Formatos soportados en v0.1

- JSON
- HTML

CSV puede evaluarse más adelante, pero no es obligatorio en v0.1.

## Exportación JSON

### Propósito

Conservar una representación fiel y reutilizable del resultado del escaneo.

### Regla

El JSON exportado debe respetar el mismo shape base definido en `docs/scan-now-contract.json`.

### Contenido mínimo

- metadatos del scan;
- summary;
- findings completos;
- baseline state;
- affinity;
- risk;
- reason codes;
- recommended action.

## Exportación HTML

### Propósito

Proporcionar una vista legible y compartible por humanos.

### Contenido mínimo

- fecha y hora del escaneo;
- resumen global;
- listado de findings;
- banda de riesgo por finding;
- baseline state por finding;
- proceso, ruta y destino;
- reason codes principales;
- recomendación.

## Reglas obligatorias

- exportar no debe cambiar el estado del sistema;
- exportar no debe depender de proveedores externos;
- exportar no debe inventar campos ausentes;
- exportar debe marcar valores no resueltos como `null`, `unknown` o equivalente claro;
- exportar debe ser reproducible a partir del resultado persistido del scan.

## Qué no hacer

- no meter branding exagerado;
- no convertir el HTML en dashboard complejo;
- no ocultar reason codes importantes;
- no alterar el contrato JSON para “embellecer” la salida;
- no generar exportaciones que cambien el significado del finding.

## Regla final

El export existe para preservar y compartir resultados, no para reinterpretarlos.
Debe ser fiel, sobrio y útil.