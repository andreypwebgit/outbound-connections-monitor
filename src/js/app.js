// Orquestador de la UI: wiring de eventos y coordinación entre api, state y render.

import * as api from './api.js';
import { state, setScan, toggleFilter, applyBaselineToFindings } from './state.js';
import { renderSummary } from './render/summary.js';
import { renderFindingsSection, renderFindingsList } from './render/findings.js';
import { escapeHtml, formatDate } from './render/html.js';

/** Último scan lanzado en vivo, para poder volver desde la vista histórica. */
let lastLiveScan = null;

document.addEventListener('DOMContentLoaded', async () => {
  const scanBtn = document.getElementById('scan-btn');
  const historyBtn = document.getElementById('history-btn');
  const appContent = document.getElementById('app-content');

  await api.onScanProgress((message) => {
    const progressText = document.getElementById('scan-progress-text');
    if (progressText) {
      progressText.textContent = message;
    }
  });

  scanBtn?.addEventListener('click', () => runScan(appContent));
  historyBtn?.addEventListener('click', () => showHistory(appContent));

  // Enlaces externos (footer): target="_blank" no abre el navegador por
  // defecto dentro de la webview, así que se delega al backend.
  document.addEventListener('click', (event) => {
    const link = event.target.closest('a[target="_blank"]');
    if (!link) return;
    event.preventDefault();
    api.openExternal(link.href).catch((error) => console.error('openExternal:', error));
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
    ${renderSummary(scan, state.isHistorical)}
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
    renderDashboard(appContent);
  } catch (error) {
    appContent.innerHTML = `<div class="text-center py-12 text-red-500"><p>Error cargando el escaneo: ${escapeHtml(error)}</p></div>`;
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
