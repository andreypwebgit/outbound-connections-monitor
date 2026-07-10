// Capa de acceso a los comandos Tauri. Único módulo que conoce window.__TAURI__.

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

/** Lanza un escaneo manual completo. Devuelve ScanNowResponse (contrato v1). */
export function scanNow() {
  return invoke('scan_now');
}

/** Metadatos de los últimos escaneos persistidos (más reciente primero). */
export function getScanHistory() {
  return invoke('get_scan_history');
}

/** Recupera un scan completo persistido por su scan_id. */
export function getScan(scanId) {
  return invoke('get_scan', { scanId });
}

/** Compara un scan persistido con el inmediatamente anterior. */
export function getScanComparison(scanId) {
  return invoke('get_scan_comparison', { scanId });
}

/** Lista las identidades conocidas por el lifecycle del baseline. */
export function getBaselineEntries() {
  return invoke('get_baseline_entries');
}

/** Exporta un scan persistido a 'json' o 'html'. Devuelve la ruta del archivo. */
export function exportScan(scanId, format) {
  return invoke('export_scan', { scanId, format });
}

/**
 * Registra una decisión manual sobre un binario (por SHA-256).
 * decisionType: 'validate_local' | 'revoke_local_validation' | 'revalidate_accept'.
 * Devuelve el BaselineInfo resultante.
 */
export function recordManualDecision(sha256, decisionType, notes = null) {
  return invoke('record_manual_decision', { sha256, decisionType, notes });
}

/** Suscribe un callback a los eventos de progreso del escaneo. */
export function onScanProgress(callback) {
  return listen('scan-progress', (event) => callback(event.payload));
}

/**
 * Abre una URL http(s) en el navegador por defecto del sistema.
 * En la webview de Tauri, target="_blank" no llega al navegador del
 * usuario: los enlaces externos se delegan a este comando.
 */
export function openExternal(url) {
  return invoke('open_external', { url });
}
