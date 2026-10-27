/**
 * PulseGuard Cyberpunk Electron Frontend Logic.
 * Communicates with the local Python REST API on http://127.0.0.1:48201.
 */

const API_BASE = (window.pulseguard && window.pulseguard.backendUrl) || 'http://127.0.0.1:48201';

// Global UI State
const appState = {
  engineOnline: false,
  watcherActive: false,
  watchedPath: null,
  signaturesCount: 0,
  quarantineCount: 0,
  lastScanResults: [],
  processes: [],
  auditLogs: [],
};

// --- Initialization ---
document.addEventListener('DOMContentLoaded', () => {
  setupNavigation();
  setupScanControls();
  setupProcessControls();
  setupQuarantineControls();
  setupWatcherControls();
  setupAuditControls();

  appendLog('INITIALISATION', 'Interface PulseGuard chargée. Connexion au pont API...', 'info');

  // Initial data fetch & recurring polling
  fetchStatus();
  fetchQuarantine();
  fetchEvents();
  setInterval(fetchStatus, 3000);
  setInterval(fetchEvents, 4000);
});

// --- Tab Navigation ---
function setupNavigation() {
  const navItems = document.querySelectorAll('.nav-item');
  const panes = document.querySelectorAll('.tab-pane');

  navItems.forEach((item) => {
    item.addEventListener('click', () => {
      const targetTab = item.getAttribute('data-tab');
      navItems.forEach((n) => n.classList.remove('active'));
      panes.forEach((p) => p.classList.remove('active'));

      item.classList.add('active');
      const targetPane = document.getElementById(`pane-${targetTab}`);
      if (targetPane) targetPane.classList.add('active');

      // Refresh specific tab data on switch
      if (targetTab === 'quarantine') fetchQuarantine();
      if (targetTab === 'processes' && appState.processes.length === 0) fetchProcesses();
      if (targetTab === 'watcher') fetchEvents();
    });
  });

  // Dashboard shortcut buttons
  document.getElementById('btn-goto-scanner')?.addEventListener('click', () => {
    document.querySelector('.nav-item[data-tab="scanner"]')?.click();
  });
  document.getElementById('btn-goto-processes')?.addEventListener('click', () => {
    document.querySelector('.nav-item[data-tab="processes"]')?.click();
  });
  document.getElementById('btn-quick-scan-downloads')?.addEventListener('click', () => {
    document.querySelector('.nav-item[data-tab="scanner"]')?.click();
    const downloadsPath = window.pulseguard?.platform === 'win32' ? 'C:\\Users\\lulu6\\Downloads' : '~/Downloads';
    document.getElementById('scan-target-path').value = downloadsPath;
    startScan();
  });
  document.getElementById('btn-refresh-dashboard')?.addEventListener('click', () => {
    fetchStatus();
    fetchEvents();
    showToast('Tableau de bord actualisé', 'success');
  });
}

// --- Status API ---
async function fetchStatus() {
  try {
    const res = await fetch(`${API_BASE}/api/status`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();

    appState.engineOnline = true;
    appState.signaturesCount = data.signatures || 0;
    appState.quarantineCount = data.quarantine_count || 0;
    appState.watcherActive = !!data.watcher_active;
    appState.watchedPath = data.watched_path || null;

    updateStatusUI(data);
  } catch (err) {
    appState.engineOnline = false;
    updateOfflineUI();
  }
}

function updateStatusUI(data) {
  // Topbar
  const enginePill = document.getElementById('pill-engine-status');
  const engineText = document.getElementById('engine-status-text');
  const dot = enginePill.querySelector('.dot');
  dot.className = 'dot pulse-green';
  engineText.textContent = 'ONLINE';

  document.getElementById('top-vault-count').textContent = `${data.quarantine_count} ISOLÉS`;
  document.getElementById('nav-quarantine-badge').textContent = data.quarantine_count;

  const watcherPill = document.getElementById('pill-watcher-status');
  const watcherText = document.getElementById('top-watcher-text');
  const watcherDot = watcherPill.querySelector('.dot');
  if (data.watcher_active) {
    watcherDot.className = 'dot pulse-green';
    watcherText.textContent = 'ACTIF';
  } else {
    watcherDot.className = 'dot';
    watcherText.textContent = 'INACTIF';
  }

  // Dashboard Stats
  document.getElementById('stat-signatures').textContent = data.signatures || 4;
  document.getElementById('stat-quarantine-count').textContent = data.quarantine_count || 0;
  document.getElementById('stat-watcher-status').textContent = data.watcher_active ? 'ACTIF' : 'INACTIF';

  // Vault dir label in quarantine tab
  const vaultLabel = document.getElementById('vault-dir-label');
  if (vaultLabel && data.vault_path) {
    vaultLabel.textContent = data.vault_path;
  }

  // Watcher controls in Watcher tab
  const watcherCheckbox = document.getElementById('watcher-toggle-checkbox');
  const watcherLed = document.getElementById('watcher-led');
  const watcherTitle = document.getElementById('watcher-title-status');
  const watcherDesc = document.getElementById('watcher-desc-status');
  if (watcherCheckbox && watcherLed) {
    watcherCheckbox.checked = data.watcher_active;
    if (data.watcher_active) {
      watcherLed.className = 'watcher-led active';
      watcherTitle.textContent = 'SENTINELLE ACTIVE';
      watcherDesc.textContent = `Surveillance temps réel sur : ${data.watched_path || 'Répertoire configuré'}`;
    } else {
      watcherLed.className = 'watcher-led';
      watcherTitle.textContent = 'SENTINELLE INACTIVE';
      watcherDesc.textContent = 'Aucun répertoire n\'est actuellement surveillé en arrière-plan.';
    }
  }
}

function updateOfflineUI() {
  const enginePill = document.getElementById('pill-engine-status');
  const engineText = document.getElementById('engine-status-text');
  const dot = enginePill.querySelector('.dot');
  dot.className = 'dot pulse-red';
  engineText.textContent = 'OFFLINE';
}

// --- File Scanner ---
function setupScanControls() {
  const btnBrowseFile = document.getElementById('btn-browse-file');
  const btnBrowseFolder = document.getElementById('btn-browse-folder');
  const btnStartScan = document.getElementById('btn-start-scan');
  const inputPath = document.getElementById('scan-target-path');

  btnBrowseFile?.addEventListener('click', async () => {
    if (window.pulseguard?.selectFile) {
      const filePath = await window.pulseguard.selectFile();
      if (filePath) inputPath.value = filePath;
    }
  });

  btnBrowseFolder?.addEventListener('click', async () => {
    if (window.pulseguard?.selectDirectory) {
      const dirPath = await window.pulseguard.selectDirectory();
      if (dirPath) inputPath.value = dirPath;
    }
  });

  btnStartScan?.addEventListener('click', () => {
    startScan();
  });
}

async function startScan() {
  const pathInput = document.getElementById('scan-target-path');
  const targetPath = pathInput.value.trim();

  if (!targetPath) {
    showToast('Veuillez spécifier un fichier ou dossier à analyser.', 'danger');
    return;
  }

  const recursive = document.getElementById('scan-opt-recursive')?.checked ?? true;
  const quarantine = document.getElementById('scan-opt-quarantine')?.checked ?? true;

  const progressBox = document.getElementById('scan-progress-box');
  const progressBar = document.getElementById('scan-progress-bar');
  const progressStatus = document.getElementById('scan-progress-status');
  const progressPercent = document.getElementById('scan-progress-percent');
  const resultsBox = document.getElementById('scan-results-box');
  const tbody = document.getElementById('scan-results-tbody');
  const btnStart = document.getElementById('btn-start-scan');

  progressBox.style.display = 'block';
  resultsBox.style.display = 'none';
  progressBar.style.width = '15%';
  progressPercent.textContent = '15%';
  progressStatus.textContent = 'Initialisation du moteur d\'analyse...';
  btnStart.disabled = true;

  appendLog('SCAN_START', `Lancement de l'analyse : ${targetPath} (récursif=${recursive}, quarantaine=${quarantine})`, 'info');

  let simProgress = 15;
  const timer = setInterval(() => {
    if (simProgress < 85) {
      simProgress += Math.floor(Math.random() * 12) + 5;
      if (simProgress > 85) simProgress = 85;
      progressBar.style.width = `${simProgress}%`;
      progressPercent.textContent = `${simProgress}%`;
      progressStatus.textContent = `Calcul des empreintes SHA-256 et heuristique (${simProgress}%)...`;
    }
  }, 120);

  try {
    const res = await fetch(`${API_BASE}/api/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path: targetPath, recursive, quarantine }),
    });

    clearInterval(timer);
    progressBar.style.width = '100%';
    progressPercent.textContent = '100%';
    progressStatus.textContent = 'Analyse terminée !';

    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      throw new Error(errData.error || `Erreur serveur HTTP ${res.status}`);
    }

    const data = await res.json();
    appState.lastScanResults = data.results || [];

    setTimeout(() => {
      progressBox.style.display = 'none';
      renderScanResults(data);
      btnStart.disabled = false;
    }, 400);

    fetchStatus();
    fetchQuarantine();
  } catch (err) {
    clearInterval(timer);
    progressBox.style.display = 'none';
    btnStart.disabled = false;
    showToast(`Erreur d'analyse : ${err.message}`, 'danger');
    appendLog('SCAN_ERROR', `Échec de l'analyse : ${err.message}`, 'error');
  }
}

function renderScanResults(data) {
  const resultsBox = document.getElementById('scan-results-box');
  const tbody = document.getElementById('scan-results-tbody');
  resultsBox.style.display = 'block';
  tbody.innerHTML = '';

  const scannedCount = data.scanned_count || 0;
  const infectedCount = data.infected_count || 0;
  let quarantinedCount = 0;

  document.getElementById('res-total-scanned').textContent = scannedCount;
  document.getElementById('res-total-infected').textContent = infectedCount;

  if (!data.results || data.results.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" class="empty-state">Aucun fichier trouvé dans la cible spécifiée.</td></tr>';
    return;
  }

  data.results.forEach((item) => {
    if (item.quarantine_id) quarantinedCount++;
    const tr = document.createElement('tr');

    const badgeClass = item.is_infected ? 'badge-status badge-infected' : 'badge-status badge-clean';
    const statusText = item.is_infected ? 'INFECTÉ' : 'SAIN';
    const threatDisplay = item.threat_name ? `<span style="color:var(--neon-crimson);font-weight:700;">${escapeHtml(item.threat_name)}</span>` : '<span style="color:var(--text-dim);">-</span>';
    const hashDisplay = item.file_hash ? `<span class="hash-code">${item.file_hash.substring(0, 16)}...</span>` : '-';
    const qDisplay = item.quarantine_id
      ? `<span class="badge-status badge-clean">ISOLÉ (${item.quarantine_id.substring(0, 8)})</span>`
      : item.is_infected
      ? `<span class="badge-status badge-warning">NON ISOLÉ</span>`
      : '<span style="color:var(--text-dim);">-</span>';

    tr.innerHTML = `
      <td><span class="${badgeClass}">${statusText}</span></td>
      <td title="${escapeHtml(item.file_path)}"><strong>${escapeHtml(getFileName(item.file_path))}</strong><br><small style="color:var(--text-dim);">${escapeHtml(item.file_path)}</small></td>
      <td>${threatDisplay}</td>
      <td>${hashDisplay}</td>
      <td>${qDisplay}</td>
    `;
    tbody.appendChild(tr);
  });

  document.getElementById('res-total-quarantined').textContent = quarantinedCount;

  if (infectedCount > 0) {
    showToast(`⚠️ Alerte : ${infectedCount} menace(s) détectée(s) !`, 'danger');
    appendLog('THREAT_DETECTED', `${infectedCount} menace(s) identifiée(s) lors du scan de ${scannedCount} fichiers.`, 'error');
    setShieldThreatState(true);
  } else {
    showToast(`Scan terminé : ${scannedCount} fichiers analysés, aucun danger.`, 'success');
    appendLog('SCAN_CLEAN', `Analyse terminée avec succès. Aucun danger sur ${scannedCount} fichiers.`, 'info');
    setShieldThreatState(false);
  }
}

// --- Process Scanner ---
function setupProcessControls() {
  const btnScanProcs = document.getElementById('btn-scan-processes');
  const searchInput = document.getElementById('filter-processes-input');

  btnScanProcs?.addEventListener('click', fetchProcesses);

  searchInput?.addEventListener('input', (e) => {
    const query = e.target.value.toLowerCase().trim();
    filterProcesses(query);
  });
}

async function fetchProcesses() {
  const tbody = document.getElementById('processes-tbody');
  tbody.innerHTML = '<tr><td colspan="5" class="empty-state">Inspection de la table des processus en cours...</td></tr>';

  try {
    const res = await fetch(`${API_BASE}/api/processes?limit=60`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    appState.processes = data.processes || [];
    renderProcesses(appState.processes);
    appendLog('RAM_SCAN', `Inspection mémoire terminée. ${appState.processes.length} processus analysés.`, 'info');
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="5" class="empty-state" style="color:var(--neon-crimson);">Échec du scan mémoire : ${err.message}</td></tr>`;
    showToast('Impossible de récupérer la liste des processus', 'danger');
  }
}

function renderProcesses(procList) {
  const tbody = document.getElementById('processes-tbody');
  tbody.innerHTML = '';

  if (procList.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" class="empty-state">Aucun processus correspondant.</td></tr>';
    return;
  }

  procList.forEach((p) => {
    const tr = document.createElement('tr');
    const badge = p.is_infected
      ? '<span class="badge-status badge-infected">SUSPECT</span>'
      : '<span class="badge-status badge-clean">PROTÉGÉ</span>';
    const threat = p.threat_name ? `<span style="color:var(--neon-crimson);">${escapeHtml(p.threat_name)}</span>` : '<span style="color:var(--text-dim);">-</span>';

    tr.innerHTML = `
      <td><code>${p.pid}</code></td>
      <td><strong>${escapeHtml(p.name || 'Inconnu')}</strong></td>
      <td title="${escapeHtml(p.exe_path || '')}"><small style="color:var(--text-dim);">${escapeHtml(p.exe_path || 'N/A')}</small></td>
      <td>${badge}</td>
      <td>${threat}</td>
    `;
    tbody.appendChild(tr);
  });
}

function filterProcesses(query) {
  if (!query) {
    renderProcesses(appState.processes);
    return;
  }
  const filtered = appState.processes.filter(
    (p) => (p.name && p.name.toLowerCase().includes(query)) || (p.exe_path && p.exe_path.toLowerCase().includes(query)) || String(p.pid).includes(query)
  );
  renderProcesses(filtered);
}

// --- Quarantine Vault ---
function setupQuarantineControls() {
  document.getElementById('btn-refresh-quarantine')?.addEventListener('click', () => {
    fetchQuarantine();
    showToast('Coffre-fort actualisé', 'success');
  });
}

async function fetchQuarantine() {
  const tbody = document.getElementById('quarantine-tbody');
  try {
    const res = await fetch(`${API_BASE}/api/quarantine`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    renderQuarantine(data.records || []);
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="5" class="empty-state">Erreur de chargement du coffre : ${err.message}</td></tr>`;
  }
}

function renderQuarantine(records) {
  const tbody = document.getElementById('quarantine-tbody');
  tbody.innerHTML = '';

  document.getElementById('nav-quarantine-badge').textContent = records.length;
  document.getElementById('stat-quarantine-count').textContent = records.length;
  document.getElementById('top-vault-count').textContent = `${records.length} ISOLÉS`;

  if (records.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" class="empty-state">Le coffre-fort est vide. Aucune menace isolée.</td></tr>';
    return;
  }

  records.forEach((r) => {
    const tr = document.createElement('tr');
    const dateFormatted = new Date(r.quarantined_at).toLocaleString('fr-FR');
    const sevBadge = `<span class="badge-status badge-infected">${escapeHtml(r.severity || 'HIGH')}</span>`;

    tr.innerHTML = `
      <td><small style="color:var(--text-dim);">${dateFormatted}</small></td>
      <td title="${escapeHtml(r.original_path)}"><strong>${escapeHtml(getFileName(r.original_path))}</strong><br><small style="color:var(--text-dim);">${escapeHtml(r.original_path)}</small></td>
      <td><strong style="color:var(--neon-crimson);">${escapeHtml(r.threat_name)}</strong></td>
      <td>${sevBadge}</td>
      <td>
        <button class="btn-success-sm" data-action="restore" data-id="${r.record_id}">Restaurer</button>
        <button class="btn-danger-sm" data-action="delete" data-id="${r.record_id}" style="margin-left:6px;">Broyer</button>
      </td>
    `;
    tbody.appendChild(tr);
  });

  // Action listeners
  tbody.querySelectorAll('button[data-action="restore"]').forEach((btn) => {
    btn.addEventListener('click', () => restoreQuarantineFile(btn.getAttribute('data-id')));
  });
  tbody.querySelectorAll('button[data-action="delete"]').forEach((btn) => {
    btn.addEventListener('click', () => deleteQuarantineFile(btn.getAttribute('data-id')));
  });
}

async function restoreQuarantineFile(recordId) {
  try {
    const res = await fetch(`${API_BASE}/api/quarantine/restore`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ record_id: recordId }),
    });
    const data = await res.json();
    if (data.success) {
      showToast(`Fichier restauré avec succès : ${data.restored_path}`, 'success');
      appendLog('VAULT_RESTORE', `Restauration intègre du fichier : ${data.restored_path}`, 'info');
      fetchQuarantine();
      fetchStatus();
    } else {
      showToast(`Échec de la restauration : ${data.error}`, 'danger');
    }
  } catch (err) {
    showToast(`Erreur : ${err.message}`, 'danger');
  }
}

async function deleteQuarantineFile(recordId) {
  if (!confirm('Êtes-vous sûr de vouloir broyer et supprimer définitivement ce fichier du coffre ?')) {
    return;
  }
  try {
    const res = await fetch(`${API_BASE}/api/quarantine/delete`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ record_id: recordId }),
    });
    const data = await res.json();
    if (data.success) {
      showToast('Fichier broyé et effacé du coffre.', 'success');
      appendLog('VAULT_SHRED', `Suppression sécurisée du fichier chiffré ${recordId}`, 'warn');
      fetchQuarantine();
      fetchStatus();
    } else {
      showToast(`Échec de suppression : ${data.error}`, 'danger');
    }
  } catch (err) {
    showToast(`Erreur : ${err.message}`, 'danger');
  }
}

// --- Watcher Sentinel ---
function setupWatcherControls() {
  const toggle = document.getElementById('watcher-toggle-checkbox');
  const pathInput = document.getElementById('watcher-path-input');
  const btnBrowse = document.getElementById('btn-browse-watcher-folder');

  btnBrowse?.addEventListener('click', async () => {
    if (window.pulseguard?.selectDirectory) {
      const dirPath = await window.pulseguard.selectDirectory();
      if (dirPath) pathInput.value = dirPath;
    }
  });

  toggle?.addEventListener('change', async () => {
    const activate = toggle.checked;
    const path = pathInput.value.trim();
    const quarantine = document.getElementById('watcher-opt-quarantine')?.checked ?? true;

    if (activate && !path) {
      showToast('Veuillez spécifier un répertoire à surveiller.', 'danger');
      toggle.checked = false;
      return;
    }

    try {
      const res = await fetch(`${API_BASE}/api/watch/toggle`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ active: activate, path, quarantine }),
      });
      const data = await res.json();

      if (data.watcher_active) {
        showToast(`Sentinelle activée sur : ${data.watched_path}`, 'success');
        appendLog('WATCHER_ACTIVE', `Surveillance en temps réel engagée sur ${data.watched_path}`, 'info');
      } else {
        showToast('Sentinelle désactivée.', 'info');
        appendLog('WATCHER_STOPPED', 'Surveillance en arrière-plan arrêtée.', 'warn');
      }
      fetchStatus();
    } catch (err) {
      toggle.checked = !activate;
      showToast(`Erreur Sentinelle : ${err.message}`, 'danger');
    }
  });
}

async function fetchEvents() {
  try {
    const res = await fetch(`${API_BASE}/api/events`);
    if (!res.ok) return;
    const data = await res.json();
    renderWatcherEvents(data.events || []);
  } catch (err) {
    // Ignore silent poll error
  }
}

function renderWatcherEvents(events) {
  const tbody = document.getElementById('watcher-events-tbody');
  const dashboardEvents = document.getElementById('dashboard-recent-events');

  if (events.length === 0) {
    tbody.innerHTML = '<tr><td colspan="4" class="empty-state">En attente d\'événements de fichiers...</td></tr>';
    dashboardEvents.innerHTML = '<div class="empty-state">Aucun événement suspect récent détecté. Tout est calme.</div>';
    return;
  }

  tbody.innerHTML = '';
  dashboardEvents.innerHTML = '';

  const recentReversed = [...events].reverse();

  recentReversed.slice(0, 15).forEach((ev) => {
    const tr = document.createElement('tr');
    const badge = ev.is_infected
      ? '<span class="badge-status badge-infected">INFECTÉ</span>'
      : '<span class="badge-status badge-clean">SAIN</span>';
    const threat = ev.threat_name ? `<strong style="color:var(--neon-crimson);">${escapeHtml(ev.threat_name)}</strong>` : '-';
    const action = ev.quarantine_id
      ? `<span class="badge-status badge-clean">ISOLÉ</span>`
      : '<span style="color:var(--text-dim);">-</span>';

    tr.innerHTML = `
      <td title="${escapeHtml(ev.file_path)}"><strong>${escapeHtml(getFileName(ev.file_path))}</strong></td>
      <td>${badge}</td>
      <td>${threat}</td>
      <td>${action}</td>
    `;
    tbody.appendChild(tr);
  });

  // Also update dashboard preview
  recentReversed.slice(0, 5).forEach((ev) => {
    const div = document.createElement('div');
    div.className = 'vault-meta-item';
    div.style.padding = '8px 0';
    div.innerHTML = `
      <span class="meta-label">[${ev.status}]</span>
      <strong style="color:${ev.is_infected ? 'var(--neon-crimson)' : 'var(--neon-emerald)'}">${escapeHtml(getFileName(ev.file_path))}</strong>
      ${ev.threat_name ? `— <em>${escapeHtml(ev.threat_name)}</em>` : ''}
    `;
    dashboardEvents.appendChild(div);
  });
}

// --- Audit Terminal Logs ---
function setupAuditControls() {
  document.getElementById('btn-clear-logs')?.addEventListener('click', () => {
    document.getElementById('audit-log-terminal').innerHTML = '';
    showToast('Console d\'audit effacée', 'info');
  });

  document.getElementById('btn-refresh-logs')?.addEventListener('click', () => {
    fetchStatus();
    appendLog('AUDIT_SYNC', 'Synchronisation de l\'état de sécurité demandée.', 'info');
  });
}

function appendLog(category, message, level = 'info') {
  const terminal = document.getElementById('audit-log-terminal');
  if (!terminal) return;

  const now = new Date();
  const timeStr = now.toTimeString().split(' ')[0] + '.' + String(now.getMilliseconds()).padStart(3, '0');

  const div = document.createElement('div');
  div.className = `log-entry ${level}`;
  div.innerHTML = `[${timeStr}] <strong style="color:var(--neon-cyan)">[${escapeHtml(category)}]</strong> ${escapeHtml(message)}`;

  terminal.appendChild(div);
  terminal.scrollTop = terminal.scrollHeight;
}

// --- UI Helpers ---
function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.innerHTML = `<span>${escapeHtml(message)}</span>`;

  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(100%)';
    toast.style.transition = 'all 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

function setShieldThreatState(isThreat) {
  const badge = document.getElementById('dashboard-shield-badge');
  const shieldIcon = document.getElementById('shield-core-icon');
  if (!badge) return;

  if (isThreat) {
    badge.className = 'shield-status-badge status-threat';
    badge.textContent = 'MENACE ACTIVE DÉTECTÉE !';
    if (shieldIcon) {
      shieldIcon.querySelector('svg').style.color = 'var(--neon-crimson)';
      shieldIcon.querySelector('svg').style.filter = 'drop-shadow(0 0 15px var(--neon-crimson))';
    }
  } else {
    badge.className = 'shield-status-badge status-protected';
    badge.textContent = 'SYSTÈME SÉCURISÉ & PROTÉGÉ';
    if (shieldIcon) {
      shieldIcon.querySelector('svg').style.color = 'var(--neon-emerald)';
      shieldIcon.querySelector('svg').style.filter = 'drop-shadow(0 0 12px var(--neon-emerald))';
    }
  }
}

function getFileName(filePath) {
  if (!filePath) return '';
  return filePath.split(/[\\/]/).pop();
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
