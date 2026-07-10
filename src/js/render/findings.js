import { state, comparisonForFinding, getBandCategory, visibleFindings } from '../state.js';
import { escapeHtml } from './html.js';
import { renderDetail } from './detail.js';

/**
 * Estilos por categoría con clases Tailwind COMPLETAS (nunca interpolación
 * parcial: Tailwind v4 solo genera clases que aparecen literales en el código).
 */
const FILTER_STYLES = {
  safe: {
    active: 'bg-green-900 border-green-500 text-green-300',
    label: 'SAFE',
    row: 'text-green-400',
  },
  review: {
    active: 'bg-yellow-900 border-yellow-500 text-yellow-300',
    label: 'REVIEW',
    row: 'text-yellow-400',
  },
  danger: {
    active: 'bg-red-900 border-red-500 text-red-300',
    label: 'DANGER',
    row: 'text-red-400',
  },
  unknown: {
    active: 'bg-gray-800 border-gray-500 text-gray-300',
    label: 'OTHER',
    row: 'text-gray-400',
  },
};

const INACTIVE_FILTER = 'opacity-50 bg-transparent border-gray-600 text-gray-400';

/** Sección de hallazgos: cabecera con filtros + contenedor de la lista. */
export function renderFindingsSection() {
  const buttons = Object.entries(FILTER_STYLES)
    .map(([category, style]) => {
      const activeCls = state.filters[category] ? style.active : INACTIVE_FILTER;
      return `<button data-action="toggle-filter" data-category="${category}"
                class="px-3 py-1 rounded border transition-colors ${activeCls}">${style.label}</button>`;
    })
    .join('');

  return `
    <div class="flex justify-between items-center mb-3 gap-3 flex-wrap">
      <h3 class="text-lg font-semibold">Hallazgos</h3>
      <div class="flex gap-2 items-center flex-wrap">
        <input id="findings-search" type="search" value="${escapeHtml(state.searchQuery)}"
               placeholder="Filtrar por proceso, IP, dominio, ruta…"
               class="bg-gray-800 border border-gray-600 rounded px-3 py-1 text-xs text-gray-200 placeholder-gray-500 w-64 focus:outline-none focus:ring-1 focus:ring-blue-500">
        <div class="flex gap-2 text-xs font-mono">${buttons}</div>
      </div>
    </div>
    <div id="findings-container" class="space-y-3"></div>`;
}

/** Rellena #findings-container según el estado y los filtros actuales. */
export function renderFindingsList() {
  const container = document.getElementById('findings-container');
  if (!container) return;

  const visible = visibleFindings();
  if (visible.length === 0) {
    container.innerHTML =
      '<div class="text-center py-8 text-gray-500 border border-dashed border-gray-700 rounded-lg">No hay hallazgos que coincidan con los filtros o la búsqueda actuales.</div>';
    return;
  }

  container.innerHTML = visible.map(({ finding, index }) => renderFindingRow(finding, index)).join('');
}

function renderFindingRow(finding, index) {
  const rowId = `row-${index}`;
  const category = getBandCategory(finding.risk.band);
  const riskColor = FILTER_STYLES[category].row;
  const comparison = comparisonForFinding(finding.finding_id);
  const newBadge = comparison?.is_new_connection || comparison?.is_new_binary
    ? '<span class="ml-2 px-1.5 py-0.5 bg-blue-950 text-blue-300 text-[10px] font-bold rounded border border-blue-700">NUEVO</span>'
    : '';
  const changedBadge = comparison?.connection_changed || comparison?.previous_baseline_state
    ? '<span class="ml-2 px-1.5 py-0.5 bg-purple-950 text-purple-300 text-[10px] font-bold rounded border border-purple-700">CAMBIO</span>'
    : '';
  const baselineChange = comparison?.previous_baseline_state
    ? `<span class="block text-[10px] text-orange-300">${escapeHtml(comparison.previous_baseline_state)} &rarr; ${escapeHtml(finding.baseline.state)}</span>`
    : '';

  const servicesBadge =
    finding.process.services && finding.process.services.length > 0
      ? `<span class="ml-2 px-1.5 py-0.5 bg-blue-900 text-blue-200 text-[10px] rounded border border-blue-700">${escapeHtml(finding.process.services.join(', '))}</span>`
      : '';

  const hostname = finding.remote.hostname ? `(${escapeHtml(finding.remote.hostname)})` : '';

  return `
    <div class="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden shadow-sm">
      <div class="p-4 flex justify-between items-center cursor-pointer hover:bg-gray-700 transition-colors"
           data-action="toggle-row" data-row="${rowId}">
        <div class="pointer-events-none">
          <div class="font-mono text-sm mb-1 flex items-center">
            <span class="font-bold">${escapeHtml(finding.process.name)}</span>
            <span class="text-gray-500 ml-2">PID: ${finding.process.pid}</span>
            ${servicesBadge}
            ${newBadge}
            ${changedBadge}
          </div>
          <div class="text-xs text-gray-400">${escapeHtml(finding.protocol)} ${escapeHtml(finding.local.ip)}:${finding.local.port} &rarr; ${escapeHtml(finding.remote.ip)}:${finding.remote.port} ${hostname}</div>
        </div>
        <div class="text-right pointer-events-none">
          <div class="text-xs uppercase tracking-wider mb-1 font-bold ${riskColor}">${escapeHtml(finding.risk.band)}</div>
          <div class="text-xs text-gray-500 flex items-center justify-end gap-1">
            ${escapeHtml(finding.baseline.state)} · afinidad ${escapeHtml(finding.affinity.level)}
            <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="ml-1 opacity-50"><polyline points="6 9 12 15 18 9"></polyline></svg>
          </div>
          ${baselineChange}
        </div>
      </div>
      ${renderDetail(finding, rowId)}
    </div>`;
}
