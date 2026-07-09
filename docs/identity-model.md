# Identity Model

## Objetivo

Definir la identidad del sistema de forma suficientemente fuerte para evitar errores de clasificación basados solo en nombre de proceso, ruta o “visto antes”.

## Regla principal

La identidad del sistema siempre se modela con cuatro dimensiones complementarias:
- `disk_truth`
- `trust_truth`
- `execution_truth`
- `behavior_truth`

Ninguna de estas dimensiones es suficiente por sí sola.

## 1. `disk_truth`

Describe el archivo en disco.

Campos clave:
- `sha256`
- `volume_serial`
- `file_id`
- `normalized_path`
- `file_size`
- `last_write_time`

### Regla
El SHA-256 es obligatorio para baseline, pero debe convivir con identidad física del archivo cuando sea posible.

## 2. `trust_truth`

Describe la confianza criptográfica del binario.

Campos clave:
- `signature_status`
- `signature_source`
- `signer_subject`
- `signer_thumbprint`
- `chain_status`

### Regla
La firma válida reduce riesgo, pero no equivale automáticamente a confianza absoluta ni sustituye el resto de señales.

## 3. `execution_truth`

Describe la instancia viva observada.

Campos clave:
- `pid`
- `started_at`
- `resolved_path`
- `file_missing`
- `orphaned`

### Regla
La identidad en ejecución debe permitir detectar incoherencias entre el proceso vivo y el archivo esperado.

## 4. `behavior_truth`

Describe el comportamiento de red observado.

Campos clave:
- `remote_ip`
- `hostname`
- `root_domain`
- `asn_org`
- `remote_port`
- `protocol`
- `affinity_score`
- `affinity_level`

### Regla
La conducta de red debe interpretarse en contexto. No debe reducirse a IP fija ni a puerto aislado.

## Lo que no se debe hacer

No reducir identidad a:
- solo `process_name`;
- solo `path`;
- solo `sha256`;
- solo firma;
- solo IP remota.

## Uso operativo del modelo

- `disk_truth` ancla identidad del archivo;
- `trust_truth` aporta contexto criptográfico;
- `execution_truth` valida la instancia observada;
- `behavior_truth` evalúa si la conexión encaja con lo esperable.

## Regla final

El motor debe combinar estas cuatro dimensiones para baseline, afinidad, scoring y revalidación.
Cualquier simplificación adicional se considera degradación del modelo.