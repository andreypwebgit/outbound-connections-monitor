const { invoke } = window.__TAURI__.core;

document.addEventListener('DOMContentLoaded', () => {
  const scanBtn = document.getElementById('scan-btn');
  const appContent = document.getElementById('app-content');

  if (scanBtn) {
    scanBtn.addEventListener('click', async () => {
      appContent.innerHTML = '<div class="text-center py-12 text-blue-400"><p>Escaneando conexiones...</p></div>';
      
      try {
        const result = await invoke('scan_now');
        renderResults(result);
      } catch (error) {
        appContent.innerHTML = `<div class="text-center py-12 text-red-500"><p>Error durante el escaneo: ${error}</p></div>`;
      }
    });
  }
});

function renderResults(result) {
  const appContent = document.getElementById('app-content');
  if (!result || !result.findings) {
    appContent.innerHTML = '<div class="text-center py-12 text-yellow-500"><p>Escaneo completado, pero no se devolvió formato esperado.</p></div>';
    return;
  }

  // Very basic render for now
  let html = `<div class="bg-gray-800 border border-gray-700 rounded-lg p-6 mb-6 shadow-sm">
    <h2 class="text-lg font-semibold mb-2">Resumen</h2>
    <div class="grid grid-cols-4 gap-4 text-sm">
      <div class="bg-gray-700 p-3 rounded"><span class="block text-gray-400 text-xs uppercase tracking-wider">Total</span><span class="text-xl font-mono">${result.summary.total_observations}</span></div>
      <div class="bg-gray-700 p-3 rounded"><span class="block text-gray-400 text-xs uppercase tracking-wider">Review</span><span class="text-xl font-mono text-yellow-400">${result.summary.review_count}</span></div>
      <div class="bg-gray-700 p-3 rounded"><span class="block text-gray-400 text-xs uppercase tracking-wider">Danger</span><span class="text-xl font-mono text-red-400">${result.summary.danger_count}</span></div>
    </div>
  </div>`;
  
  html += `<h3 class="text-lg font-semibold mb-3">Hallazgos (${result.findings.length})</h3>`;
  html += `<div class="space-y-3">`;
  
  for (const finding of result.findings) {
    const riskColor = finding.risk.band === 'known_safe' ? 'text-green-400' : (finding.risk.band.includes('danger') ? 'text-red-400' : 'text-yellow-400');
    
    html += `
      <div class="bg-gray-800 border border-gray-700 rounded-lg p-4 flex justify-between items-center">
        <div>
          <div class="font-mono text-sm mb-1">${finding.process.name} <span class="text-gray-500">(${finding.process.pid})</span></div>
          <div class="text-xs text-gray-400">${finding.protocol} ${finding.local.ip}:${finding.local.port} &rarr; ${finding.remote.ip}:${finding.remote.port} ${finding.remote.hostname ? `(${finding.remote.hostname})` : ''}</div>
        </div>
        <div class="text-right">
          <div class="text-xs uppercase tracking-wider mb-1 font-semibold ${riskColor}">${finding.risk.band}</div>
          <div class="text-xs text-gray-500">${finding.baseline.state}</div>
        </div>
      </div>
    `;
  }
  
  html += `</div>`;
  appContent.innerHTML = html;
}
