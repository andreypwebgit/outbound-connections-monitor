// Estado de la UI. Sin framework: un objeto mutable simple y helpers puros.

export const state = {
  /** Scan mostrado actualmente (ScanNowResponse) o null. */
  currentScan: null,
  /** Comparativa de consulta del scan mostrado contra su predecesor. */
  currentComparison: null,
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
  /** Texto de búsqueda libre sobre los hallazgos. */
  searchQuery: '',
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
  state.currentComparison = null;
  state.isHistorical = historical;
}

export function setComparison(comparison) {
  state.currentComparison = comparison;
}

export function comparisonForFinding(findingId) {
  return state.currentComparison?.findings?.find((item) => item.finding_id === findingId) || null;
}

export function toggleFilter(category) {
  if (category in state.filters) {
    state.filters[category] = !state.filters[category];
  }
}

/** `true` si el finding coincide con el texto de búsqueda libre. */
function matchesSearch(finding, query) {
  if (!query) return true;
  const haystack = [
    finding.process.name,
    finding.process.path,
    finding.remote.ip,
    finding.remote.hostname,
    finding.remote.root_domain,
    finding.binary_identity.sha256,
    String(finding.remote.port),
    finding.baseline.state,
    finding.risk.band,
  ]
    .filter(Boolean)
    .join(' ')
    .toLowerCase();
  return haystack.includes(query);
}

/** Findings visibles según filtros de categoría y búsqueda, con su índice original. */
export function visibleFindings() {
  if (!state.currentScan || !Array.isArray(state.currentScan.findings)) return [];
  const query = state.searchQuery.trim().toLowerCase();
  return state.currentScan.findings
    .map((finding, index) => ({ finding, index }))
    .filter(({ finding }) => state.filters[getBandCategory(finding.risk.band)])
    .filter(({ finding }) => matchesSearch(finding, query));
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
