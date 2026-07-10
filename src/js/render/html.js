// Helpers compartidos de renderizado.

/** Escapa texto no confiable (nombres de proceso, rutas, cmdline...) antes de interpolarlo en HTML. */
export function escapeHtml(value) {
  if (value === null || value === undefined) return '';
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

/** Formatea una fecha ISO a hora local legible, o un fallback claro. */
export function formatDate(iso, fallback = 'No disponible') {
  if (!iso) return fallback;
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? fallback : date.toLocaleString();
}
