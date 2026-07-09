# Affinity Model

## Objetivo

Definir cómo se calcula la afinidad de red de un finding respecto al comportamiento histórico esperado del mismo binario o familia de observación.

## Regla principal

La afinidad existe para evitar dos errores:
- confiar ciegamente en IPs exactas;
- tratar cualquier variación legítima como sospechosa.

## Niveles válidos

- `high`
- `medium`
- `low`
- `none`

## Score orientativo

Escala interna sugerida: 0 a 100.

- 90–100: coincidencia fuerte
- 70–89: coincidencia razonable
- 40–69: coincidencia débil
- 0–39: desajuste relevante

## Señales de afinidad

### Señales fuertes
- mismo hash o cambio razonablemente revalidable;
- mismo signer;
- mismo hostname/FQDN o muy próximo;
- mismo root domain dentro del ecosistema esperado;
- mismo ASN o infraestructura razonable;
- puerto habitual o plausible.

### Señales medias
- subdominio nuevo dentro del mismo ecosistema;
- IP distinta pero ASN coherente;
- puerto diferente pero compatible con el rol del software;
- ligera variación de destino sin romper el patrón histórico.

### Señales débiles o negativas
- IP pura sin hostname esperable;
- dominio nuevo no relacionado;
- ASN no habitual;
- puerto raro sin contexto;
- patrón de red sin precedentes razonables;
- cambio múltiple simultáneo de destino, ASN y puerto.

## Reglas obligatorias

### 1. No usar IP exacta como identidad principal
La IP puede ser una señal, pero no puede ser el ancla única de normalidad.

### 2. No usar el puerto como regla absoluta
El puerto ayuda, pero no debe decidir por sí solo.

### 3. Root domain no equivale a confianza total
Un dominio grande o genérico no basta para asumir seguridad.

### 4. La afinidad alimenta el score, no lo sustituye
Una afinidad alta reduce riesgo, pero no neutraliza por sí sola un hash nuevo, una firma problemática o un proceso huérfano.

## Ejemplos operativos

### Afinidad alta
Mismo binario, misma firma, mismo ecosistema de destino y patrón de puerto estable.

### Afinidad media
Mismo binario y signer, dominio relacionado pero no exacto, puerto nuevo plausible.

### Afinidad baja
Mismo binario aparente, pero destino por IP pura y ASN no esperado.

### Afinidad nula
Cambio fuerte en varias señales críticas sin relación clara con el histórico.

## Regla final

Ante la duda, preferir una afinidad más conservadora antes que inflar afinidad artificialmente.
La afinidad debe ayudar a reducir falsos positivos, no a justificar confianza automática.