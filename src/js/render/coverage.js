import { escapeHtml } from './html.js';

const STATUS = {
  complete: {
    label: 'Completo',
    panel: 'border-emerald-800 bg-emerald-950/30',
    badge: 'border-emerald-700 bg-emerald-950 text-emerald-300',
  },
  partial: {
    label: 'Parcial',
    panel: 'border-amber-800 bg-amber-950/30',
    badge: 'border-amber-700 bg-amber-950 text-amber-300',
  },
  degraded: {
    label: 'Degradado',
    panel: 'border-red-800 bg-red-950/30',
    badge: 'border-red-700 bg-red-950 text-red-300',
  },
};

const LIMITATION_LABELS = {
  POINT_IN_TIME_SNAPSHOT: 'Fotografía puntual: no incluye conexiones que terminaron fuera del instante del scan.',
  UDP_REMOTE_PEER_NOT_AVAILABLE: 'Windows enumera endpoints UDP con PID, pero esta API no expone el peer remoto.',
  EXTERNAL_INTEL_NOT_ENABLED: 'ASN, país y reputación externa no forman parte del motor local.',
  DNS_RESOLUTION_BUDGET_200_MS: 'El DNS inverso tiene un presupuesto global de 200 ms.',
};

function yesNo(value) {
  return value ? 'Sí' : 'No';
}

function metric(label, value, detail = '') {
  return `<div class="border border-gray-700 bg-gray-900/60 rounded p-3">
    <span class="block text-[10px] uppercase tracking-wider text-gray-500">${label}</span>
    <span class="block mt-1 text-sm font-mono text-gray-200">${escapeHtml(String(value))}</span>
    ${detail ? `<span class="block mt-1 text-[10px] text-gray-500">${detail}</span>` : ''}
  </div>`;
}

export function renderCoverage(scan) {
  const coverage = scan.coverage;
  if (!coverage) {
    return `<section class="mt-4 border border-gray-700 bg-gray-900/40 rounded-lg p-4">
      <div class="flex justify-between items-start gap-3">
        <div>
          <h3 class="text-sm font-semibold text-gray-300">Completitud del scan</h3>
          <p class="text-xs text-gray-500 mt-1">Este histórico usa ${escapeHtml(scan.schema_version || 'un esquema anterior')} y no registraba cobertura. No se infiere información retrospectiva.</p>
        </div>
        <span class="px-2 py-1 rounded border border-gray-600 text-[10px] text-gray-400">No disponible</span>
      </div>
    </section>`;
  }

  const style = STATUS[coverage.status] || {
    label: coverage.status,
    panel: 'border-gray-700 bg-gray-900/40',
    badge: 'border-gray-600 bg-gray-800 text-gray-300',
  };
  const elevated = coverage.elevated === true
    ? 'Sí'
    : coverage.elevated === false
      ? 'No'
      : 'No resuelto';
  const c = coverage.collector;
  const p = coverage.process;
  const i = coverage.identity;
  const d = coverage.dns;

  const limitations = coverage.limitations
    .map((code) => `<li><span class="font-mono text-[10px] text-gray-500">${escapeHtml(code)}</span> — ${escapeHtml(LIMITATION_LABELS[code] || code)}</li>`)
    .join('');
  const warnings = coverage.warnings.length
    ? `<ul class="mt-2 space-y-1 text-xs text-amber-200">${coverage.warnings.map((warning) => `<li>• ${escapeHtml(warning)}</li>`).join('')}</ul>`
    : '<p class="mt-2 text-xs text-gray-500">Sin advertencias técnicas adicionales.</p>';

  return `<section class="mt-4 border rounded-lg p-4 ${style.panel}">
    <div class="flex justify-between items-start gap-3">
      <div>
        <h3 class="text-sm font-semibold">Completitud del scan</h3>
        <p class="text-xs text-gray-400 mt-1">Describe la cobertura de la evidencia, no el nivel de seguridad del equipo.</p>
      </div>
      <span class="px-2 py-1 rounded border text-[10px] font-semibold uppercase tracking-wider ${style.badge}">${escapeHtml(style.label)}</span>
    </div>

    <div class="grid grid-cols-2 md:grid-cols-4 gap-2 mt-4">
      ${metric('Ejecución elevada', elevated)}
      ${metric('TCP IPv4 / IPv6', `${yesNo(c.tcp_ipv4_collected)} / ${yesNo(c.tcp_ipv6_collected)}`, `${c.tcp_observations} observaciones`)}
      ${metric('UDP IPv4 / IPv6', `${yesNo(c.udp_ipv4_collected)} / ${yesNo(c.udp_ipv6_collected)}`, `${c.udp_owner_endpoints} endpoints · ${c.udp_findings} findings`)}
      ${metric('Contexto proceso', `${p.complete_context}/${p.findings}`, `${p.protected_system_findings} findings protegidos`)}
      ${metric('Rutas / usuarios', `${p.path_resolved}/${p.user_resolved}`, `de ${p.findings} findings`)}
      ${metric('Cmdline / padre', `${p.command_line_resolved}/${p.parent_resolved}`, `de ${p.findings} findings`)}
      ${metric('Identidad completa', `${i.complete_identity}/${p.findings}`, `hash fresh ${i.hash_fresh} · cache ${i.hash_cache}`)}
      ${metric('Hash / trust ausente', `${i.hash_unavailable}/${i.trust_unknown}`, `trust resuelto ${i.trust_resolved}`)}
      ${metric('DNS público', `${d.resolved}/${d.public_ip_candidates}`, `cache ${d.cache_hits} · sin PTR ${d.no_ptr_record} · timeout ${d.timed_out}`)}
    </div>

    <details class="mt-4 border-t border-gray-700/70 pt-3">
      <summary class="cursor-pointer text-xs text-gray-300 hover:text-white">Limitaciones y advertencias</summary>
      <ul class="mt-2 space-y-1 text-xs text-gray-400">${limitations}</ul>
      ${warnings}
    </details>
  </section>`;
}
