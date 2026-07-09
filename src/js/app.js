const { invoke } = window.__TAURI__.core;

// Store global findings state for filtering
let currentFindings = [];
let activeFilters = {
  safe: true,
  review: true,
  danger: true,
  unknown: true
};

document.addEventListener('DOMContentLoaded', () => {
  const scanBtn = document.getElementById('scan-btn');
  const appContent = document.getElementById('app-content');

  if (scanBtn) {
    scanBtn.addEventListener('click', async () => {
      appContent.innerHTML = '<div class="text-center py-12 text-blue-400"><p>Escaneando conexiones (esto puede tardar unos segundos)...</p></div>';
      
      try {
        const result = await invoke('scan_now');
        currentFindings = result.findings;
        renderDashboard(result);
      } catch (error) {
        appContent.innerHTML = `<div class="text-center py-12 text-red-500"><p>Error durante el escaneo: ${error}</p></div>`;
      }
    });
  }
});

function getBandCategory(band) {
  const b = band.toLowerCase();
  if (b.includes('safe') || b === 'known_safe') return 'safe';
  if (b.includes('danger') || b === 'investigate') return 'danger';
  if (b.includes('review') || b === 'revalidate' || b === 'observe') return 'review';
  return 'unknown';
}

function toggleFilter(category) {
  activeFilters[category] = !activeFilters[category];
  
  // Update button UI
  const btn = document.getElementById(`filter-btn-${category}`);
  if (btn) {
    if (activeFilters[category]) {
      btn.classList.remove('opacity-50', 'bg-transparent', 'border-gray-600');
      btn.classList.add(`bg-${getCategoryColor(category)}-900`, `border-${getCategoryColor(category)}-500`, `text-${getCategoryColor(category)}-300`);
    } else {
      btn.classList.add('opacity-50', 'bg-transparent', 'border-gray-600');
      btn.classList.remove(`bg-${getCategoryColor(category)}-900`, `border-${getCategoryColor(category)}-500`, `text-${getCategoryColor(category)}-300`);
    }
  }
  
  renderFindingsList();
}

// Make toggleFilter global for inline onclick
window.toggleFilter = toggleFilter;

function getCategoryColor(cat) {
  switch(cat) {
    case 'safe': return 'green';
    case 'danger': return 'red';
    case 'review': return 'yellow';
    default: return 'gray';
  }
}

function renderDashboard(result) {
  const appContent = document.getElementById('app-content');
  if (!result || !result.findings) {
    appContent.innerHTML = '<div class="text-center py-12 text-yellow-500"><p>Escaneo completado, pero no se devolvió formato esperado.</p></div>';
    return;
  }

  let html = `<div class="bg-gray-800 border border-gray-700 rounded-lg p-6 mb-6 shadow-sm">
    <h2 class="text-lg font-semibold mb-2">Resumen</h2>
    <div class="grid grid-cols-4 gap-4 text-sm">
      <div class="bg-gray-700 p-3 rounded"><span class="block text-gray-400 text-xs uppercase tracking-wider">Total</span><span class="text-xl font-mono">${result.summary.total_observations}</span></div>
      <div class="bg-gray-700 p-3 rounded"><span class="block text-gray-400 text-xs uppercase tracking-wider">Review</span><span class="text-xl font-mono text-yellow-400">${result.summary.review_count}</span></div>
      <div class="bg-gray-700 p-3 rounded"><span class="block text-gray-400 text-xs uppercase tracking-wider">Danger</span><span class="text-xl font-mono text-red-400">${result.summary.danger_count}</span></div>
    </div>
  </div>`;
  
  html += `
    <div class="flex justify-between items-center mb-3">
      <h3 class="text-lg font-semibold">Hallazgos</h3>
      <div class="flex gap-2 text-xs font-mono">
        <button id="filter-btn-safe" onclick="toggleFilter('safe')" class="px-3 py-1 rounded border border-green-500 bg-green-900 text-green-300 transition-colors">SAFE</button>
        <button id="filter-btn-review" onclick="toggleFilter('review')" class="px-3 py-1 rounded border border-yellow-500 bg-yellow-900 text-yellow-300 transition-colors">REVIEW</button>
        <button id="filter-btn-danger" onclick="toggleFilter('danger')" class="px-3 py-1 rounded border border-red-500 bg-red-900 text-red-300 transition-colors">DANGER</button>
        <button id="filter-btn-unknown" onclick="toggleFilter('unknown')" class="px-3 py-1 rounded border border-gray-500 bg-gray-800 text-gray-300 transition-colors">OTHER</button>
      </div>
    </div>
    <div id="findings-container" class="space-y-3"></div>
  `;
  
  appContent.innerHTML = html;
  
  // Make sure toggle toggleRow is available globally
  window.toggleRow = function(id) {
    const el = document.getElementById(`detail-${id}`);
    if (el) {
      el.classList.toggle('hidden');
    }
  };

  renderFindingsList();
}

function renderFindingsList() {
  const container = document.getElementById('findings-container');
  if (!container) return;
  
  let html = '';
  let visibleCount = 0;
  
  for (let i = 0; i < currentFindings.length; i++) {
    const finding = currentFindings[i];
    const category = getBandCategory(finding.risk.band);
    
    if (!activeFilters[category]) {
      continue;
    }
    
    visibleCount++;
    const rowId = `row-${i}`;
    const riskColor = category === 'safe' ? 'text-green-400' : (category === 'danger' ? 'text-red-400' : (category === 'review' ? 'text-yellow-400' : 'text-gray-400'));
    
    // Humanizar códigos de razón
    const humanReasons = finding.risk.reason_codes.map(code => {
      const map = {
        'UNSIGNED_SYSTEM_PROCESS': 'Proceso de sistema sin firma válida',
        'SYSTEM_PATH_BUT_NOT_MICROSOFT': 'En ruta de Windows pero no firmado por Microsoft',
        'EXECUTING_FROM_TEMP_OR_DOWNLOADS': 'Ejecutándose desde Temp o Descargas',
        'NEW_DESTINATION': 'Destino IP nunca visto',
        'UNKNOWN_BASELINE': 'Comportamiento no conocido (Baseline)',
        'INVALID_SIGNATURE': 'Firma digital inválida (Authenticode error)',
        'FILE_MISSING': 'Archivo borrado o inaccesible en disco',
        'VALID_MICROSOFT_SIGNATURE': 'Firmado digitalmente por Microsoft',
        'ESTABLISHED_BASELINE': 'Comportamiento habitual (Baseline sólido)'
      };
      return map[code] || code;
    });

    const servicesBadge = finding.process.services && finding.process.services.length > 0
      ? `<span class="ml-2 px-1.5 py-0.5 bg-blue-900 text-blue-200 text-[10px] rounded border border-blue-700">${finding.process.services.join(', ')}</span>`
      : '';

    html += `
      <div class="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden shadow-sm">
        <div class="p-4 flex justify-between items-center cursor-pointer hover:bg-gray-750 transition-colors" onclick="toggleRow('${rowId}')">
          <div>
            <div class="font-mono text-sm mb-1 flex items-center">
              <span class="font-bold">${finding.process.name}</span> 
              <span class="text-gray-500 ml-2">PID: ${finding.process.pid}</span>
              ${servicesBadge}
            </div>
            <div class="text-xs text-gray-400">${finding.protocol} ${finding.local.ip}:${finding.local.port} &rarr; ${finding.remote.ip}:${finding.remote.port} ${finding.remote.hostname ? `(${finding.remote.hostname})` : ''}</div>
          </div>
          <div class="text-right">
            <div class="text-xs uppercase tracking-wider mb-1 font-bold ${riskColor}">${finding.risk.band}</div>
            <div class="text-xs text-gray-500 flex items-center justify-end gap-1">
              ${finding.baseline.state}
              <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="ml-1 opacity-50"><polyline points="6 9 12 15 18 9"></polyline></svg>
            </div>
          </div>
        </div>
        
        <!-- Detalle Desplegable -->
        <div id="detail-${rowId}" class="hidden bg-gray-900 p-4 border-t border-gray-700 text-sm grid grid-cols-2 gap-4">
          <div>
            <h4 class="text-gray-500 text-xs uppercase mb-2">Detalles del Proceso</h4>
            <p class="mb-1 text-gray-300 break-all"><span class="text-gray-500 mr-2">Ruta:</span>${finding.process.path || 'No disponible'}</p>
            <p class="mb-1 text-gray-300 break-all"><span class="text-gray-500 mr-2">SHA-256:</span><span class="font-mono text-xs">${finding.binary_identity.sha256 || 'N/A'}</span></p>
            <p class="mb-1 text-gray-300"><span class="text-gray-500 mr-2">Authenticode:</span>
              <span class="${finding.trust.signature_status.includes('Valid') ? 'text-green-400' : 'text-yellow-400'}">${finding.trust.signature_status}</span>
              ${finding.trust.signer_subject ? `<br><span class="text-xs ml-2 text-gray-400">Firmante: ${finding.trust.signer_subject}</span>` : ''}
            </p>
          </div>
          <div>
            <h4 class="text-gray-500 text-xs uppercase mb-2">Motor de Riesgo (Score: ${finding.risk.score})</h4>
            <ul class="list-disc pl-4 space-y-1 text-gray-300">
              ${humanReasons.map(r => `<li>${r}</li>`).join('') || '<li class="text-gray-500">Sin razones específicas</li>'}
            </ul>
            <p class="mt-3 text-xs text-gray-400">Baseline visto por primera vez: ${finding.baseline.first_seen ? new Date(finding.baseline.first_seen).toLocaleString() : 'Hoy'}</p>
          </div>
        </div>
      </div>
    `;
  }
  
  if (visibleCount === 0) {
    html = `<div class="text-center py-8 text-gray-500 border border-dashed border-gray-700 rounded-lg">No hay hallazgos que coincidan con los filtros actuales.</div>`;
  }
  
  container.innerHTML = html;
}
