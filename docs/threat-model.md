# Threat Model

## Alcance del modelo de amenaza

La v0.1 está diseñada para priorizar hallazgos sospechosos relacionados con conexiones salientes activas visibles en Windows. No pretende cubrir toda la superficie de amenazas del host.

## Amenazas que sí intenta iluminar

- binarios nuevos con conexiones salientes inesperadas;
- herramientas con telemetría agresiva u opaca;
- procesos legítimos en rutas anómalas;
- ejecutables sin firma con comportamiento de red dudoso;
- cambios de hash en binarios conocidos;
- destinos nuevos con baja afinidad;
- uso de IP pura en vez de destino esperable;
- procesos huérfanos con conexión activa;
- tráfico razonablemente anómalo para el binario observado.

## Amenazas que puede señalar parcialmente

- stealers básicos o commodity malware que abren conexiones visibles;
- loaders o binarios oportunistas en rutas de usuario;
- exfiltración simple observable desde procesos no esperados;
- abuso de herramientas firmadas con comportamiento poco coherente.

## Amenazas que no cubre bien en v0.1

- inyección en memoria sin señales visibles suficientes;
- kernel malware;
- tráfico cifrado cuyo contenido no puede inspeccionarse;
- malware sin conexión activa en el momento del escaneo;
- escenarios forenses completos;
- detección basada en packet capture;
- persistencia avanzada no observable por este flujo.

## Supuestos operativos

- el escaneo es manual y puntual;
- la app observa el estado visible en ese instante;
- el usuario puede ejecutar escaneos repetidos para construir contexto;
- el motor local es la base de decisión;
- Intel externo solo añade señales, no sustituye al juicio central.

## Señales fuertes de riesgo

- binario ausente o irresoluble con conexión activa;
- hash nuevo en binario previamente consolidado;
- firma inválida o inconsistente;
- ruta sospechosa;
- destino por IP pura con baja afinidad;
- reputación externa negativa;
- múltiples señales fuertes acumuladas.

## Riesgos de diseño a evitar

- falsa confianza por “visto antes”;
- fatiga de alertas por baseline mal diseñado;
- sobredependencia de reputación externa;
- uso del LLM como juez principal;
- sobreingeniería que convierta la app en otra cosa.

## Controles de diseño

- SHA-256 obligatorio para baseline;
- baseline por estados;
- `Observed_Local` para desarrollo local;
- revalidación al cambiar hash;
- afinidad de red en vez de IP fija;
- clasificación sobria y explicable;
- procesos huérfanos como hallazgos críticos.