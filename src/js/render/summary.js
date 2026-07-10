import { escapeHtml, formatDate } from './html.js';

/**
 * Bloque de resumen del scan: contadores del summary del contrato + metadatos.
 * Los contadores vienen del backend (no se recuentan en la UI).
 */
export function renderSummary(scan, isHistorical, comparison) {
  const s = scan.summary;

  const chip = (label, value, colorClass = 'text-gray-100') => `
    <div class="bg-gray-700 p-3 rounded">
      <span class="block text-gray-400 text-xs uppercase tracking-wider">${label}</span>
      <span class="text-xl font-mono ${colorClass}">${value}</span>
    </div>`;

  const historicalBanner = isHistorical
    ? `<div class="mb-4 px-3 py-2 rounded border border-blue-700 bg-blue-950 text-blue-300 text-sm flex justify-between items-center">
        <span>Viendo un escaneo del historial. Las decisiones manuales siguen afectando al baseline actual.</span>
        <button data-action="back-live" class="ml-4 text-xs underline hover:text-blue-100">Cerrar</button>
      </div>`
    : '';

  const comparisonBlock = !comparison
    ? '<p class="mt-4 text-xs text-gray-500">Comparativa no disponible.</p>'
    : comparison.previous_scan_id
      ? `<div class="mt-4 border-t border-gray-700 pt-4">
          <div class="flex justify-between items-baseline gap-2 mb-2">
            <h3 class="text-xs uppercase tracking-wider text-gray-400">Cambios respecto al scan anterior</h3>
            <span class="font-mono text-[10px] text-gray-600">${escapeHtml(comparison.previous_scan_id)}</span>
          </div>
          <div class="grid grid-cols-4 gap-3 text-sm">
            ${chip('Conexiones nuevas', comparison.new_connections_count, 'text-blue-300')}
            ${chip('Conexiones cambiadas', comparison.changed_connections_count, 'text-purple-300')}
            ${chip('Binarios nuevos', comparison.new_binaries_count, 'text-cyan-300')}
            ${chip('Cambios baseline', comparison.baseline_changes_count, 'text-orange-300')}
          </div>
        </div>`
      : '<p class="mt-4 text-xs text-gray-500">Primer scan persistido: todavía no existe una referencia anterior.</p>';

  return `
    <div class="bg-gray-800 border border-gray-700 rounded-lg p-6 mb-6 shadow-sm">
      ${historicalBanner}
      <div class="flex justify-between items-baseline mb-3 flex-wrap gap-2">
        <h2 class="text-lg font-semibold">Resumen</h2>
        <p class="text-xs text-gray-500 font-mono">
          ${escapeHtml(scan.scan_id)} · ${escapeHtml(scan.host.hostname)} ·
          ${formatDate(scan.started_at)} · ${scan.duration_ms} ms
        </p>
      </div>
      <div class="grid grid-cols-4 gap-4 text-sm mb-3">
        ${chip('Total', s.total_observations)}
        ${chip('Aceptadas', s.accepted_count, 'text-green-400')}
        ${chip('Revisión', s.review_count, 'text-yellow-400')}
        ${chip('Peligro', s.danger_count, 'text-red-400')}
      </div>
      <div class="grid grid-cols-4 gap-4 text-sm">
        ${chip('Baseline unknown', s.unknown_count, 'text-gray-300')}
        ${chip('Candidatos', s.candidate_count, 'text-blue-300')}
        ${chip('Revalidación', s.revalidation_count, 'text-orange-300')}
        ${chip('Huérfanos', s.orphaned_count, s.orphaned_count > 0 ? 'text-red-400' : 'text-gray-300')}
      </div>
      ${comparisonBlock}
      <div class="mt-4 flex gap-2 justify-end text-xs">
        <button data-action="export" data-format="json" class="px-3 py-1.5 rounded border border-gray-600 text-gray-300 hover:bg-gray-700 transition-colors">Exportar JSON</button>
        <button data-action="export" data-format="html" class="px-3 py-1.5 rounded border border-gray-600 text-gray-300 hover:bg-gray-700 transition-colors">Exportar HTML</button>
      </div>
      <p id="export-result" class="text-xs text-gray-500 mt-2 text-right"></p>
    </div>`;
}
