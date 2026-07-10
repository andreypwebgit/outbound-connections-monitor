# Error Handling

## Objetivo

Definir cómo debe degradar la aplicación cuando faltan datos, fallan componentes o no se puede completar una parte del pipeline.

## Principio principal

La app debe degradar con elegancia.
Debe continuar el escaneo siempre que sea razonablemente posible y marcar con claridad lo no resuelto.

## Regla general

Cuando una fase falla:
- registrar el error técnico;
- marcar los campos afectados como `null`, `unknown` o equivalente claro;
- continuar con el resto del pipeline si es seguro hacerlo;
- no inventar datos;
- no abortar todo el scan salvo fallo realmente crítico del sistema.

## Fallos previstos

### 1. Fallo al enumerar conexiones
El collector consulta IPv4 e IPv6 por separado. Si una familia falla, conserva
la otra y registra `collector_warning`; solo falla la operación global cuando
fallan ambas tablas TCP.

### 2. Fallo al resolver proceso o path
El finding debe seguir existiendo si la conexión fue observada, pero con path ausente o estado degradado.

### 3. Fallo al calcular hash
No inventar hash.
El finding debe reflejar que no hay `sha256` disponible.
Si el hash es obligatorio para baseline, el sistema no debe consolidar ese elemento.

### 4. Fallo de trust/firma
No bloquear todo el scan.
Marcar `signature_status` o `chain_status` como `Unknown` si no puede resolverse de forma fiable.

### 5. Fallo en hostname, ASN o enriquecimiento de red
Mantener IP y puerto observados.
Marcar resto de campos como `null` o `unknown`.
El DNS inverso tiene un presupuesto total de 200 ms: las resoluciones tardías
no bloquean el scan y quedan cacheadas en memoria para snapshots posteriores.

### 6. Fallo de Intel externo
No romper el escaneo.
El finding debe mantenerse con `intel.consulted = false` o con el subresultado degradado correspondiente.

### 7. Fallo de persistencia parcial
Registrar error técnico.
Si no se puede persistir parte del resultado, el sistema debe intentar preservar al menos el resultado en memoria para la UI actual si ya existe.

## Reglas obligatorias

- no usar errores silenciosos en lógica crítica;
- no ocultar fallos estructurales reales;
- no convertir excepciones técnicas en datos falsos;
- no bloquear la UI por fallos no críticos de enriquecimiento;
- no degradar un hallazgo crítico a benigno por falta de datos.

## Tratamiento de procesos huérfanos

Si la resolución del binario indica ausencia real o incoherencia fuerte entre proceso y archivo, no debe tratarse como simple error técnico neutro. Debe considerarse señal de riesgo.

## Logging mínimo esperado

Registrar al menos:
- inicio/fin del scan;
- número de observaciones recogidas;
- errores de collector;
- fallos de hash/trust;
- fallos de Intel externo;
- errores de persistencia;
- transiciones relevantes de estado.

## Regla final

La app no debe aparentar certeza cuando no la tiene.
Es preferible un finding incompleto pero honesto que una clasificación “bonita” basada en datos inventados.
