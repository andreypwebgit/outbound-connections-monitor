# Baseline Lifecycle

## Objetivo

Definir de forma compacta y operativa los estados válidos del baseline y las transiciones permitidas.

## Regla principal

El baseline no es una allowlist ciega ni una lista de “visto antes”.
El baseline representa patrones suficientemente observados, estables y explicables dentro de este equipo.

## Estados válidos y únicos

- `Unknown`
- `Candidate`
- `Observed_Local`
- `Baseline_Provisional`
- `Baseline_Consolidated`
- `Revalidation_Required`
- `Potentially_Dangerous`

No se deben inventar estados nuevos sin autorización explícita.

## Definición de estados

### `Unknown`
Primera aparición o aparición sin contexto suficiente.

### `Candidate`
Elemento repetido o con contexto parcial, pero todavía no consolidado.

### `Observed_Local`
Elemento local validado manualmente por el usuario, normalmente útil para entornos de desarrollo, pero que no debe confundirse con baseline consolidado estándar.

### `Baseline_Provisional`
Patrón suficientemente repetido y coherente, pendiente de más evidencia o estabilidad.

### `Baseline_Consolidated`
Patrón estable, explicable y suficientemente validado en este equipo.

### `Revalidation_Required`
Elemento previamente conocido cuyo hash, trust, ruta o afinidad ha cambiado de forma relevante.

### `Potentially_Dangerous`
Elemento con señales suficientemente fuertes como para priorización inmediata.

## Transiciones permitidas

- `Unknown -> Candidate`
- `Candidate -> Observed_Local`
- `Candidate -> Baseline_Provisional`
- `Baseline_Provisional -> Baseline_Consolidated`
- `Baseline_Consolidated -> Revalidation_Required`
- `Any -> Potentially_Dangerous`

## Reglas obligatorias

### 1. No promoción por simple repetición temporal
Nada entra en `Baseline_Consolidated` solo por haber aparecido varias veces o durante varios días.

### 2. Hash obligatorio para baseline
No se consolida baseline sin SHA-256 válido o recuperable para identidad del binario.

### 3. `Observed_Local` no equivale a “seguro”
`Observed_Local` existe para reducir ruido en desarrollo local, no para absolver binarios sin firma o locales.

### 4. Revalidación obligatoria al cambiar hash
Un cambio de hash en un elemento conocido no debe ignorarse. Debe empujar a `Revalidation_Required` salvo justificación explícita y validada.

### 5. Procesos huérfanos no aprenden
Si un proceso tiene conexión activa y su binario no existe o no puede resolverse correctamente, no pasa por ciclo normal de aprendizaje. Se trata como hallazgo crítico.

## Señales útiles para promoción prudente

Pueden ayudar a pasar de `Candidate` a `Baseline_Provisional`:
- hash estable;
- trust/firma coherentes;
- ruta normal;
- afinidad media/alta sostenida;
- ausencia de señales negativas externas relevantes;
- repetición en contextos distintos.

## Señales que bloquean promoción automática

- hash ausente sin justificación;
- trust inválido o incoherente;
- ruta sospechosa;
- afinidad baja persistente;
- reputación externa claramente negativa;
- proceso huérfano;
- cambios frecuentes no explicados.

## Regla final

El baseline debe reducir ruido sin crear confianza ciega.
Si hay duda, el sistema debe preferir `Candidate` o `Revalidation_Required` frente a consolidar demasiado pronto.