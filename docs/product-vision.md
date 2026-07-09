# Product Vision

## Qué es

Aplicación de escritorio para Windows que ejecuta un escaneo manual de conexiones salientes activas mediante `Scan Now`, las asocia a su proceso responsable, las enriquece con identidad del binario y contexto de red, y las clasifica por baseline, afinidad y riesgo potencial.

## Qué problema resuelve

Da visibilidad útil y priorización humana sobre el tráfico saliente del equipo sin convertir la herramienta en un antivirus, un EDR o un monitor continuo. Ayuda a distinguir entre:

- tráfico normal del sistema o del stack habitual;
- tráfico nuevo pero razonable;
- tráfico que merece revisión inmediata.

## Usuario objetivo

Usuario técnico individual en Windows, especialmente desarrollador, integrador, consultor técnico o power user que prueba herramientas, binarios, repositorios, scripts o entornos locales y quiere entender qué está saliendo del equipo.

## Objetivo principal

Ofrecer un escaneo puntual, rápido, explicable y útil del estado de red saliente visible del equipo.

## Objetivos secundarios

- construir baseline local útil y mantenible;
- reducir fatiga de alertas;
- detectar cambios de hash y revalidaciones;
- priorizar hallazgos críticos como procesos huérfanos;
- permitir validación manual en entornos de desarrollo.

## No objetivos de v0.1

- monitorización continua;
- bloqueo automático;
- remediación automática;
- packet capture;
- drivers o hooking;
- sustitución de antivirus/firewall/EDR;
- análisis forense completo;
- clasificación infalible de malware.

## Principios del producto

1. Visibilidad antes que automatismo.
2. Seguridad sin paranoia UX.
3. Explicabilidad obligatoria.
4. Hash obligatorio para baseline, pero no como verdad única.
5. Baseline por afinidad, no por “visto antes”.
6. Primero local, luego externo.
7. Producto pequeño, útil y mantenible.

## Interacción principal

La interacción principal de v0.1 es manual: botón `Scan Now`.

## Resultado esperado

Una lista de findings con:

- proceso responsable;
- identidad del binario;
- trust/firma;
- baseline state;
- afinidad;
- score y banda de riesgo;
- motivos y recomendación.