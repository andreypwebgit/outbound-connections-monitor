// Estado de la UI. Sin framework: un objeto mutable simple y helpers puros.

export const state = {
  /** Scan mostrado actualmente (ScanNowResponse) o null. */
  currentScan: null,
  /** true si el scan mostrado se cargó desde el historial. */
  isHistorical: false,
  /** Último historial cargado (ScanHistoryEntry[]). */
  history: [],
  /** Filtros de la lista de hallazgos por categoría de riesgo. */
  filters: {
    safe: true,
    review: true,
    danger: true,
    unknown: true,
  },
};

/** Mapea una banda de riesgo del contrato a la categoría visual de la UI. */
export function getBandCategory(band) {
  const b = (band || '').toLowerCase();
  if (b === 'known_safe' || b === 'known_low') return 'safe';
  if (b === 'potentially_dangerous') return 'danger';
  if (b === 'known_moderate' || b === 'known_high') return 'review';
  return 'unknown';
}

export function setScan(scan, { historical = false } = {}) {
  state.currentScan = scan;
  state.isHistorical = historical;
}

export function toggleFilter(category) {
  if (category in state.filters) {
    state.filters[category] = !state.filters[category];
  }
}

/** Findings visibles según los filtros activos, con su índice original. */
export function visibleFindings() {
  if (!state.currentScan || !Array.isArray(state.currentScan.findings)) return [];
  return state.currentScan.findings
    .map((finding, index) => ({ finding, index }))
    .filter(({ finding }) => state.filters[getBandCategory(finding.risk.band)]);
}

/**
 * Actualiza el baseline de todos los findings del scan actual que comparten
 * el mismo SHA-256 (tras una decisión manual).
 */
export function applyBaselineToFindings(sha256, baseline) {
  if (!state.currentScan) return;
  for (const finding of state.currentScan.findings) {
    if (finding.binary_identity.sha256 === sha256) {
      finding.baseline = { ...finding.baseline, ...baseline };
    }
  }
}
