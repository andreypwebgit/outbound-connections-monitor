import { escapeHtml, formatDate } from './html.js';

/** Traducción legible de los reason codes del motor de riesgo. */
const REASON_LABELS = {
  ORPHANED_IMAGE: 'Proceso con conexión activa sin binario resoluble (hallazgo crítico)',
  FILE_MISSING: 'Archivo borrado o inaccesible en disco',
  PROTECTED_SYSTEM_PROCESS: 'Proceso protegido del sistema (PPL/Kernel)',
  SUSPICIOUS_PATH: 'Ejecutándose desde una ruta sospechosa (Temp/Descargas)',
  EXPECTED_PATH: 'Ruta de instalación habitual',
  UNSIGNED_SYSTEM_PROCESS: 'Proceso en ruta de sistema sin firma válida',
  SYSTEM_PATH_BUT_NOT_MICROSOFT: 'En ruta de Windows pero no firmado por Microsoft',
  VALID_MICROSOFT_SIGNATURE: 'Firmado digitalmente por Microsoft',
  SUSPICIOUS_COMMAND_LINE: 'Línea de comandos sospechosa u ofuscada',
  OFFICE_SPAWNED_NETWORK_PROCESS: 'Proceso ofimático generó proceso con red',
  SCRIPT_SPAWNED_NETWORK_PROCESS: 'Script generó proceso con red',
  USER_PROCESS_AS_SYSTEM: 'Proceso típico de usuario ejecutado como SYSTEM',
  INVALID_SIGNATURE: 'Firma digital inválida (error Authenticode)',
  UNSIGNED_BINARY: 'Binario sin firma digital',
  VALID_SIGNATURE: 'Firma digital válida y cadena de confianza correcta',
  NEW_HASH: 'El contenido del binario cambió respecto a lo conocido',
  KNOWN_HASH: 'Hash conocido y estable en este equipo',
  UNKNOWN_BASELINE: 'Comportamiento aún no conocido (baseline)',
  ESTABLISHED_BASELINE: 'Comportamiento habitual consolidado (baseline)',
  REVALIDATION_REQUIRED: 'Elemento conocido con cambios: requiere revalidación',
  LOCAL_OBSERVED: 'Binario validado manualmente en este equipo',
  MANUAL_TRUST: 'Confianza otorgada manualmente por el usuario',
  HIGH_AFFINITY: 'Destino con alta afinidad al histórico',
  LOW_AFFINITY: 'Destino con baja afinidad al histórico',
  KNOWN_DESTINATION: 'Destino dentro del patrón histórico del binario',
  NEW_DESTINATION: 'Destino nuevo para este binario',
  IP_ONLY_DESTINATION: 'Destino por IP pública sin hostname resoluble',
};

/** Traducción legible de las señales de afinidad. */
const AFFINITY_SIGNAL_LABELS = {
  SAME_HOSTNAME: 'Mismo hostname que el histórico',
  SAME_ROOT_DOMAIN: 'Mismo dominio raíz (subdominio nuevo)',
  SAME_ASN: 'Misma organización de red (ASN)',
  SAME_PORT: 'Puerto ya usado por este binario',
  COMMON_PORT: 'Puerto habitual de tráfico saliente',
  ESTABLISHED_PATTERN: 'Patrón repetido en el histórico',
  SAME_SIGNER: 'Mismo firmante tras el cambio de binario',
  INHERITED_HISTORY: 'Histórico heredado de la versión anterior',
  PRIVATE_NETWORK_DESTINATION: 'Destino en red privada/local',
  NO_HISTORICAL_PROFILE: 'Sin histórico previo para este binario',
  NEW_ROOT_DOMAIN: 'Dominio raíz nuevo no relacionado',
  NEW_ASN: 'Organización de red (ASN) no habitual',
  NEW_PORT: 'Puerto no visto y poco habitual',
  IP_ONLY_DESTINATION: 'IP pura sin hostname esperable',
  MULTI_SIGNAL_DRIFT: 'Cambio simultáneo de varias señales críticas',
};

export function humanizeReason(code) {
  return REASON_LABELS[code] || code;
}

/**
 * Mapeo de reason codes a técnicas MITRE ATT&CK.
 * Solo se mapean correspondencias rigurosas; la referencia canónica del
 * mapeo vive en docs/scoring-model.md. Es información presentacional:
 * no forma parte del contrato scan_now.
 */
const MITRE_TECHNIQUES = {
  SUSPICIOUS_COMMAND_LINE: [
    { id: 'T1059', name: 'Command and Scripting Interpreter' },
    { id: 'T1027', name: 'Obfuscated Files or Information' },
  ],
  OFFICE_SPAWNED_NETWORK_PROCESS: [
    { id: 'T1566.001', name: 'Phishing: Spearphishing Attachment' },
    { id: 'T1204.002', name: 'User Execution: Malicious File' },
  ],
  SCRIPT_SPAWNED_NETWORK_PROCESS: [
    { id: 'T1059', name: 'Command and Scripting Interpreter' },
  ],
  USER_PROCESS_AS_SYSTEM: [{ id: 'T1036', name: 'Masquerading' }],
  UNSIGNED_SYSTEM_PROCESS: [
    { id: 'T1036.005', name: 'Masquerading: Match Legitimate Name or Location' },
  ],
  SYSTEM_PATH_BUT_NOT_MICROSOFT: [
    { id: 'T1036.005', name: 'Masquerading: Match Legitimate Name or Location' },
  ],
  INVALID_SIGNATURE: [{ id: 'T1036.001', name: 'Masquerading: Invalid Code Signature' }],
  ORPHANED_IMAGE: [{ id: 'T1070.004', name: 'Indicator Removal: File Deletion' }],
  FILE_MISSING: [{ id: 'T1070.004', name: 'Indicator Removal: File Deletion' }],
  SUSPICIOUS_PATH: [{ id: 'T1204.002', name: 'User Execution: Malicious File' }],
};

/** URL de una técnica/subtécnica en attack.mitre.org (T1036.005 -> T1036/005). */
function mitreUrl(techniqueId) {
  return `https://attack.mitre.org/techniques/${techniqueId.replace('.', '/')}/`;
}

/** Técnicas MITRE únicas asociadas a los reason codes de un finding. */
export function mitreTechniquesFor(reasonCodes) {
  const seen = new Map();
  for (const code of reasonCodes || []) {
    for (const technique of MITRE_TECHNIQUES[code] || []) {
      if (!seen.has(technique.id)) {
        seen.set(technique.id, technique);
      }
    }
  }
  return [...seen.values()];
}

function mitreBadges(reasonCodes) {
  const techniques = mitreTechniquesFor(reasonCodes);
  if (techniques.length === 0) return '';
  const badges = techniques
    .map(
      (t) => `<a href="${mitreUrl(t.id)}" target="_blank" rel="noopener noreferrer"
        class="inline-block px-1.5 py-0.5 m-0.5 rounded border text-[10px] border-purple-800 bg-purple-950 text-purple-300 hover:text-purple-100 transition-colors"
        title="${escapeHtml(t.name)}">${escapeHtml(t.id)} · ${escapeHtml(t.name)}</a>`
    )
    .join('');
  return `
    <div class="mt-3 border-t border-gray-700 pt-2">
      <h4 class="text-gray-500 text-xs uppercase mb-2">Técnicas MITRE ATT&amp;CK relacionadas</h4>
      <div>${badges}</div>
    </div>`;
}

function signalBadges(signals, positive) {
  if (!signals || signals.length === 0) return '<span class="text-gray-600">—</span>';
  const cls = positive
    ? 'bg-green-950 text-green-300 border-green-800'
    : 'bg-red-950 text-red-300 border-red-800';
  return signals
    .map((s) => `<span class="inline-block px-1.5 py-0.5 m-0.5 rounded border text-[10px] ${cls}" title="${escapeHtml(s)}">${escapeHtml(AFFINITY_SIGNAL_LABELS[s] || s)}</span>`)
    .join('');
}

function manualDecisionControls(finding) {
  const sha = finding.binary_identity.sha256;
  if (!sha) return '';

  const buttons = [];
  if (finding.baseline.state === 'Candidate') {
    buttons.push(`
      <button data-action="manual-decision" data-sha="${escapeHtml(sha)}" data-decision="validate_local"
              class="px-2 py-1 rounded border border-blue-700 text-blue-300 hover:bg-blue-950 transition-colors text-xs">
        Validar localmente (Observed_Local)
      </button>`);
  }
  if (finding.baseline.state === 'Revalidation_Required' || finding.baseline.state === 'Potentially_Dangerous') {
    buttons.push(`
      <button data-action="manual-decision" data-sha="${escapeHtml(sha)}" data-decision="revalidate_accept"
              class="px-2 py-1 rounded border border-orange-700 text-orange-300 hover:bg-orange-950 transition-colors text-xs">
        Aceptar revalidación (&rarr; Candidate)
      </button>`);
  }
  if (buttons.length === 0) return '';
  return `<div class="mt-3 flex gap-2 flex-wrap">${buttons.join('')}</div>`;
}

/** Panel de detalle desplegable de un finding. */
export function renderDetail(finding, rowId) {
  const trust = finding.trust;
  const identity = finding.binary_identity;
  const baseline = finding.baseline;
  const affinity = finding.affinity;

  const trustColor = trust.signature_status === 'Valid' ? 'text-green-400'
    : trust.signature_status === 'Invalid' ? 'text-red-400'
    : 'text-yellow-400';

  const hashSourceBadge = identity.hash_source
    ? `<span class="ml-1 px-1 py-0.5 rounded text-[10px] border whitespace-nowrap inline-block ${identity.hash_source === 'cache' ? 'border-gray-600 text-gray-400' : 'border-blue-800 text-blue-300'}">${identity.hash_source === 'cache' ? 'caché' : 'recalculado'}</span>`
    : '';

  const manualBadge = baseline.manual_validation
    ? '<span class="ml-2 px-1.5 py-0.5 rounded border border-blue-700 bg-blue-950 text-blue-300 text-[10px]">Validado manualmente</span>'
    : '';

  return `
    <div id="detail-${rowId}" class="hidden bg-gray-900 p-4 border-t border-gray-700 text-sm grid grid-cols-[3fr_2fr] gap-4">
      <div>
        <h4 class="text-gray-500 text-xs uppercase mb-2">Proceso y binario</h4>
        <p class="mb-1 text-gray-300 break-all"><span class="text-gray-500 mr-2">Ruta:</span>${escapeHtml(finding.process.path) || 'No disponible'}</p>
        <p class="mb-1 text-gray-300 break-all"><span class="text-gray-500 mr-2">SHA-256:</span><span class="font-mono text-xs">${escapeHtml(identity.sha256) || 'N/A'}</span>${hashSourceBadge}</p>
        <p class="mb-1 text-gray-300"><span class="text-gray-500 mr-2">Authenticode:</span>
          <span class="${trustColor}">${escapeHtml(trust.signature_status)}</span>
          <span class="text-xs text-gray-500">(${escapeHtml(trust.signature_source)})</span>
          ${trust.signer_subject ? `<br><span class="text-xs ml-2 text-gray-400">Firmante: ${escapeHtml(trust.signer_subject)}</span>` : ''}
        </p>
        <div class="mt-3 border-t border-gray-700 pt-2">
          <p class="mb-1 text-gray-300"><span class="text-gray-500 mr-2">Usuario:</span>${escapeHtml(finding.process.user) || 'Desconocido'}</p>
          <p class="mb-1 text-gray-300"><span class="text-gray-500 mr-2">Proceso padre:</span>${escapeHtml(finding.process.parent_name) || 'Desconocido'} ${finding.process.ppid ? `(PID: ${finding.process.ppid})` : ''}</p>
          <p class="mb-1 text-gray-300"><span class="text-gray-500 mr-2">Inicio:</span>${formatDate(finding.process.started_at, 'Desconocido')}</p>
          <p class="mb-1 text-gray-300 break-all"><span class="text-gray-500 mr-2">CmdLine:</span><span class="font-mono text-xs">${escapeHtml(finding.process.command_line) || 'No disponible'}</span></p>
        </div>
        <div class="mt-3 border-t border-gray-700 pt-2">
          <h4 class="text-gray-500 text-xs uppercase mb-2">Baseline${manualBadge}</h4>
          <p class="mb-1 text-gray-300"><span class="text-gray-500 mr-2">Estado:</span>${escapeHtml(baseline.state)}</p>
          <p class="mb-1 text-gray-300"><span class="text-gray-500 mr-2">Observaciones:</span>${baseline.seen_count} en ${baseline.distinct_days} día(s) distinto(s)</p>
          <p class="mb-1 text-gray-300"><span class="text-gray-500 mr-2">Visto por primera vez:</span>${formatDate(baseline.first_seen, 'Hoy')}</p>
          ${manualDecisionControls(finding)}
        </div>
      </div>
      <div>
        <h4 class="text-gray-500 text-xs uppercase mb-2">Motor de riesgo (score: ${finding.risk.score} · ${escapeHtml(finding.risk.band)})</h4>
        <ul class="list-disc pl-4 space-y-1 text-gray-300">
          ${finding.risk.reason_codes.map((r) => `<li title="${escapeHtml(r)}">${escapeHtml(humanizeReason(r))}</li>`).join('') || '<li class="text-gray-500">Sin razones específicas</li>'}
        </ul>
        <p class="mt-2 text-xs text-gray-400">Acción recomendada: <span class="font-mono text-gray-300">${escapeHtml(finding.risk.recommended_action)}</span></p>
        ${mitreBadges(finding.risk.reason_codes)}
        <div class="mt-3 border-t border-gray-700 pt-2">
          <h4 class="text-gray-500 text-xs uppercase mb-2">Afinidad de red (score: ${affinity.score} · ${escapeHtml(affinity.level)})</h4>
          <p class="mb-1 text-gray-300 break-all"><span class="text-gray-500 mr-2">Destino:</span>${escapeHtml(finding.remote.ip)}:${finding.remote.port}
            ${finding.remote.hostname ? `<br><span class="text-xs ml-2 text-gray-400">${escapeHtml(finding.remote.hostname)}</span>` : ''}
            ${finding.remote.root_domain ? `<span class="text-xs text-gray-500"> · dominio raíz: ${escapeHtml(finding.remote.root_domain)}</span>` : ''}
          </p>
          <p class="text-xs text-gray-500 mt-2 mb-1">Señales coincidentes:</p>
          <div>${signalBadges(affinity.matched_signals, true)}</div>
          <p class="text-xs text-gray-500 mt-2 mb-1">Señales divergentes:</p>
          <div>${signalBadges(affinity.mismatched_signals, false)}</div>
        </div>
      </div>
    </div>`;
}
