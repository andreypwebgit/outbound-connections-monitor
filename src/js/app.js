// Orquestador de la UI: wiring de eventos y coordinación entre api, state y render.

import * as api from './api.js';
import { state, setScan, setComparison, toggleFilter, applyBaselineToFindings } from './state.js';
import { renderSummary } from './render/summary.js';
import { renderFindingsSection, renderFindingsList } from './render/findings.js';
import { escapeHtml, formatDate } from './render/html.js';

/** Último scan lanzado en vivo, para poder volver desde la vista histórica. */
let lastLiveScan = null;

document.addEventListener('DOMContentLoaded', async () => {
  const scanBtn = document.getElementById('scan-btn');
  const historyBtn = document.getElementById('history-btn');
  const baselineBtn = document.getElementById('baseline-btn');
  const appContent = document.getElementById('app-content');

  await api.onScanProgress((message) => {
    const progressText = document.getElementById('scan-progress-text');
    if (progressText) {
      progressText.textContent = message;
    }
  });

  scanBtn?.addEventListener('click', () => runScan(appContent));
  historyBtn?.addEventListener('click', () => showHistory(appContent));
  baselineBtn?.addEventListener('click', () => showBaseline(appContent));

  // Enlaces externos (footer): target="_blank" no abre el navegador por
  // defecto dentro de la webview, así que se delega al backend.
  document.addEventListener('click', (event) => {
    const link = event.target.closest('a[target="_blank"]');
    if (!link) return;
    event.preventDefault();
    api.openExternal(link.href).catch((error) => console.error('openExternal:', error));
  });

  // Búsqueda libre en hallazgos: re-render solo de la lista para que el
  // input conserve el foco mientras se teclea.
  appContent.addEventListener('input', (event) => {
    if (event.target.id !== 'findings-search') return;
    state.searchQuery = event.target.value;
    renderFindingsList();
  });

  // Delegación de eventos para todo el contenido dinámico.
  appContent.addEventListener('click', (event) => {
    const target = event.target.closest('[data-action]');
    if (!target) return;

    switch (target.dataset.action) {
      case 'toggle-row': {
        const detail = document.getElementById(`detail-${target.dataset.row}`);
        detail?.classList.toggle('hidden');
        break;
      }
      case 'toggle-filter': {
        toggleFilter(target.dataset.category);
        refreshFindingsSection();
        break;
      }
      case 'export': {
        handleExport(target.dataset.format);
        break;
      }
      case 'manual-decision': {
        handleManualDecision(target.dataset.sha, target.dataset.decision, target);
        break;
      }
      case 'baseline-decision': {
        handleBaselineDecision(appContent, target.dataset.sha, target.dataset.decision, target);
        break;
      }
      case 'load-scan': {
        loadHistoricalScan(appContent, target.dataset.scanId);
        break;
      }
      case 'back-live': {
        if (lastLiveScan) {
          setScan(lastLiveScan, { historical: false });
          renderDashboard(appContent);
        } else {
          renderWelcome(appContent);
        }
        break;
      }
      default:
        break;
    }
  });
});

// ----------------------------------------------------------------------
// Vistas
// ----------------------------------------------------------------------

function renderWelcome(appContent) {
  appContent.innerHTML = `
    <div id="welcome-message" class="text-center py-12 text-gray-500">
      <p>Haz clic en "Scan Now" para analizar las conexiones salientes activas.</p>
    </div>`;
}

async function runScan(appContent) {
  appContent.innerHTML = `
    <div class="bg-gray-800 border border-gray-700 rounded-lg p-8 shadow-sm flex flex-col items-center justify-center min-h-[200px]">
      <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mb-4"></div>
      <p class="text-blue-400 font-semibold mb-2">Analizando actividad de red...</p>
      <p id="scan-progress-text" class="text-xs text-gray-500 font-mono">Iniciando escáner...</p>
    </div>`;

  try {
    const result = await api.scanNow();
    lastLiveScan = result;
    setScan(result, { historical: false });
    await loadComparison(result.scan_id);
    renderDashboard(appContent);
  } catch (error) {
    appContent.innerHTML = `<div class="text-center py-12 text-red-500"><p>Error durante el escaneo: ${escapeHtml(error)}</p></div>`;
  }
}

function renderDashboard(appContent) {
  const scan = state.currentScan;
  if (!scan || !Array.isArray(scan.findings)) {
    appContent.innerHTML =
      '<div class="text-center py-12 text-yellow-500"><p>Escaneo completado, pero no se devolvió el formato esperado.</p></div>';
    return;
  }

  appContent.innerHTML = `
    ${renderSummary(scan, state.isHistorical, state.currentComparison)}
    <div id="findings-section">${renderFindingsSection()}</div>`;
  renderFindingsList();
}

function refreshFindingsSection() {
  const section = document.getElementById('findings-section');
  if (!section) return;
  section.innerHTML = renderFindingsSection();
  renderFindingsList();
}

async function showHistory(appContent) {
  appContent.innerHTML = '<div class="text-center py-12 text-gray-500"><p>Cargando historial...</p></div>';

  try {
    state.history = await api.getScanHistory();
  } catch (error) {
    appContent.innerHTML = `<div class="text-center py-12 text-red-500"><p>Error cargando historial: ${escapeHtml(error)}</p></div>`;
    return;
  }

  if (state.history.length === 0) {
    appContent.innerHTML =
      '<div class="text-center py-12 text-gray-500"><p>Todavía no hay escaneos persistidos. Lanza tu primer "Scan Now".</p></div>';
    return;
  }

  const rows = state.history
    .map(
      (entry) => `
      <tr class="border-t border-gray-700 hover:bg-gray-700">
        <td class="px-3 py-2 font-mono text-xs">${escapeHtml(entry.scan_id)}</td>
        <td class="px-3 py-2 text-gray-300">${formatDate(entry.started_at)}</td>
        <td class="px-3 py-2 text-gray-400 text-right">${entry.duration_ms} ms</td>
        <td class="px-3 py-2 text-right">${entry.total_observations}</td>
        <td class="px-3 py-2 text-right text-green-400">${entry.accepted_count}</td>
        <td class="px-3 py-2 text-right text-yellow-400">${entry.review_count}</td>
        <td class="px-3 py-2 text-right ${entry.danger_count > 0 ? 'text-red-400 font-bold' : 'text-gray-500'}">${entry.danger_count}</td>
        <td class="px-3 py-2 text-right">
          <button data-action="load-scan" data-scan-id="${escapeHtml(entry.scan_id)}"
                  class="px-2 py-1 rounded border border-gray-600 text-gray-300 hover:bg-gray-700 transition-colors text-xs">Ver</button>
        </td>
      </tr>`
    )
    .join('');

  appContent.innerHTML = `
    <div class="bg-gray-800 border border-gray-700 rounded-lg p-6 shadow-sm">
      <h2 class="text-lg font-semibold mb-4">Historial de escaneos</h2>
      <div class="overflow-x-auto">
        <table class="w-full text-sm">
          <thead>
            <tr class="text-xs text-gray-500 uppercase tracking-wider">
              <th class="px-3 py-2 text-left">Scan</th>
              <th class="px-3 py-2 text-left">Fecha</th>
              <th class="px-3 py-2 text-right">Duración</th>
              <th class="px-3 py-2 text-right">Total</th>
              <th class="px-3 py-2 text-right">Aceptadas</th>
              <th class="px-3 py-2 text-right">Revisión</th>
              <th class="px-3 py-2 text-right">Peligro</th>
              <th class="px-3 py-2"></th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    </div>`;
}

async function loadHistoricalScan(appContent, scanId) {
  appContent.innerHTML = '<div class="text-center py-12 text-gray-500"><p>Cargando escaneo...</p></div>';
  try {
    const scan = await api.getScan(scanId);
    setScan(scan, { historical: true });
    await loadComparison(scan.scan_id);
    renderDashboard(appContent);
  } catch (error) {
    appContent.innerHTML = `<div class="text-center py-12 text-red-500"><p>Error cargando el escaneo: ${escapeHtml(error)}</p></div>`;
  }
}

const BASELINE_STATE_STYLES = {
  Unknown: 'border-gray-600 bg-gray-800 text-gray-300',
  Candidate: 'border-blue-800 bg-blue-950 text-blue-300',
  Observed_Local: 'border-cyan-800 bg-cyan-950 text-cyan-300',
  Baseline_Provisional: 'border-green-800 bg-green-950 text-green-300',
  Baseline_Consolidated: 'border-emerald-700 bg-emerald-950 text-emerald-300',
  Revalidation_Required: 'border-orange-700 bg-orange-950 text-orange-300',
  Potentially_Dangerous: 'border-red-700 bg-red-950 text-red-300',
};

function baselineAction(entry) {
  if (entry.state === 'Candidate') {
    return ['validate_local', 'Validar localmente', 'border-blue-700 text-blue-300 hover:bg-blue-950'];
  }
  if (entry.state === 'Observed_Local') {
    return ['revoke_local_validation', 'Revocar validación', 'border-cyan-700 text-cyan-300 hover:bg-cyan-950'];
  }
  if (entry.state === 'Revalidation_Required' || entry.state === 'Potentially_Dangerous') {
    return ['revalidate_accept', 'Aceptar revalidación', 'border-orange-700 text-orange-300 hover:bg-orange-950'];
  }
  return null;
}

async function showBaseline(appContent) {
  appContent.innerHTML = '<div class="text-center py-12 text-gray-500"><p>Cargando baseline...</p></div>';

  let entries;
  try {
    entries = await api.getBaselineEntries();
  } catch (error) {
    appContent.innerHTML = `<div class="text-center py-12 text-red-500"><p>Error cargando el baseline: ${escapeHtml(error)}</p></div>`;
    return;
  }

  const rows = entries.map((entry) => {
    const action = baselineAction(entry);
    const actionButton = action
      ? `<button data-action="baseline-decision" data-sha="${escapeHtml(entry.sha256)}" data-decision="${action[0]}"
                 class="px-2 py-1 rounded border ${action[2]} transition-colors text-xs">${action[1]}</button>`
      : '<span class="text-xs text-gray-600">Sin acción manual</span>';
    const stateStyle = BASELINE_STATE_STYLES[entry.state] || 'border-gray-600 bg-gray-800 text-gray-300';
    const validation = entry.manual_validation
      ? '<span class="text-cyan-300">Manual activa</span>'
      : '<span class="text-gray-500">Sin validación manual</span>';

    return `<article class="border border-gray-700 rounded-lg p-4 flex justify-between items-start gap-5 hover:bg-gray-700">
      <div class="min-w-0 flex-1">
        <p class="text-xs text-gray-300 break-all">${escapeHtml(entry.normalized_path) || 'Ruta no disponible'}</p>
        <p class="font-mono text-[10px] text-gray-600 break-all mt-1">${escapeHtml(entry.sha256)}</p>
        ${entry.signer_subject ? `<p class="text-[10px] text-gray-500 mt-1">${escapeHtml(entry.signer_subject)}</p>` : ''}
      </div>
      <div class="w-60 shrink-0 text-right">
        <div class="flex justify-end items-center gap-2 flex-wrap">
          <span class="inline-block px-2 py-1 rounded border text-[10px] ${stateStyle}">${escapeHtml(entry.state)}</span>
          <span class="font-mono text-xs text-gray-300">${entry.seen_count}<span class="text-gray-600"> vistos / ${entry.distinct_days}d</span></span>
        </div>
        <p class="text-xs mt-2">${validation} <span class="text-gray-600">· ${escapeHtml(entry.last_manual_decision) || 'sin decisión'}</span></p>
        <p class="text-[10px] text-gray-500 mt-1">Último visto: ${formatDate(entry.last_seen)}</p>
        <div class="mt-3">${actionButton}</div>
      </div>
    </article>`;
  }).join('');

  appContent.innerHTML = `<div class="bg-gray-800 border border-gray-700 rounded-lg p-6 shadow-sm">
    <div class="flex justify-between items-start gap-4 mb-4">
      <div>
        <h2 class="text-lg font-semibold">Gestión del baseline</h2>
        <p class="text-xs text-gray-500 mt-1">Las acciones disponibles son transiciones cerradas del lifecycle; no se permite editar estados libremente.</p>
      </div>
      <span class="text-xs text-gray-500">${entries.length} binario(s)</span>
    </div>
    ${entries.length === 0
      ? '<div class="text-center py-8 text-gray-500 border border-dashed border-gray-700 rounded-lg">El baseline todavía está vacío.</div>'
      : `<div class="space-y-3">${rows}</div>`}
  </div>`;
}

async function loadComparison(scanId) {
  try {
    setComparison(await api.getScanComparison(scanId));
  } catch (error) {
    // La comparativa es una capa de consulta: un fallo no oculta el scan.
    console.error('getScanComparison:', error);
    setComparison(null);
  }
}

// ----------------------------------------------------------------------
// Acciones
// ----------------------------------------------------------------------

async function handleExport(format) {
  const output = document.getElementById('export-result');
  if (!state.currentScan) return;
  if (output) output.textContent = 'Exportando...';

  try {
    const path = await api.exportScan(state.currentScan.scan_id, format);
    if (output) output.textContent = `Exportado a: ${path}`;
  } catch (error) {
    if (output) output.textContent = `Error al exportar: ${error}`;
  }
}

async function handleManualDecision(sha256, decisionType, button) {
  button.disabled = true;
  button.textContent = 'Aplicando...';

  try {
    const baseline = await api.recordManualDecision(sha256, decisionType);
    // El baseline es global: se refleja en todos los findings del binario.
    // El riesgo mostrado NO se recalcula: es el snapshot del scan; el nuevo
    // estado aplicará en el próximo escaneo.
    applyBaselineToFindings(sha256, baseline);
    renderFindingsList();
  } catch (error) {
    button.disabled = false;
    button.textContent = 'Error — reintentar';
    button.title = String(error);
  }
}

async function handleBaselineDecision(appContent, sha256, decisionType, button) {
  button.disabled = true;
  button.textContent = 'Aplicando...';
  try {
    await api.recordManualDecision(sha256, decisionType);
    await showBaseline(appContent);
  } catch (error) {
    button.disabled = false;
    button.textContent = 'Error — reintentar';
    button.title = String(error);
  }
}
