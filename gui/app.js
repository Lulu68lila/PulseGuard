/**
 * PulseGuard Enterprise Security Suite — Client Controller.
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
  setupWindowControls();
  setupNavigation();
  setupScanControls();
  setupProcessControls();
  setupQuarantineControls();
  setupWatcherControls();
  setupAuditControls();

  appendLog('SYS_INIT', 'PulseGuard Endpoint Shield initialisé. Liaison API active.', 'info');

  // Initial telemetry fetch & periodic polling
  fetchStatus();
  fetchQuarantine();
  fetchEvents();
  setInterval(fetchStatus, 3000);
  setInterval(fetchEvents, 4000);
});

// --- Window Controls (Minimize, Maximize, Close) ---
function setupWindowControls() {
  document.getElementById('ctrl-minimize')?.addEventListener('click', () => {
    if (window.pulseguard?.minimize) {
      window.pulseguard.minimize();
    }
  });

  document.getElementById('ctrl-maximize')?.addEventListener('click', () => {
    if (window.pulseguard?.maximize) {
      window.pulseguard.maximize();
    }
  });

  document.getElementById('ctrl-close')?.addEventListener('click', () => {
    if (window.pulseguard?.close) {
      window.pulseguard.close();
    } else {
      window.close();
    }
  });
}

// --- Tab Navigation ---
function setupNavigation() {
  const navLinks = document.querySelectorAll('.nav-link');
  const panes = document.querySelectorAll('.view-panel');

  navLinks.forEach((link) => {
    link.addEventListener('click', () => {
      const targetTab = link.getAttribute('data-tab');
      navLinks.forEach((n) => n.classList.remove('active'));
      panes.forEach((p) => p.classList.remove('active'));

      link.classList.add('active');
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
    document.querySelector('.nav-link[data-tab="scanner"]')?.click();
  });
  document.getElementById('btn-goto-processes')?.addEventListener('click', () => {
    document.querySelector('.nav-link[data-tab="processes"]')?.click();
  });
  document.getElementById('btn-quick-scan-downloads')?.addEventListener('click', () => {
    document.querySelector('.nav-link[data-tab="scanner"]')?.click();
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
  // Titlebar Engine Indicator
  const enginePill = document.getElementById('pill-engine-status');
  const engineText = document.getElementById('engine-status-text');
  const dot = enginePill.querySelector('.status-indicator-dot');
  if (dot) dot.className = 'status-indicator-dot online';
  if (engineText) engineText.textContent = 'ONLINE';

  // Titlebar Quarantine Count
  const topVault = document.getElementById('top-vault-count');
  if (topVault) topVault.textContent = String(data.quarantine_count || 0);

  // Navigation badge
  const navBadge = document.getElementById('nav-quarantine-badge');
  if (navBadge) navBadge.textContent = String(data.quarantine_count || 0);

  // Titlebar Watcher Indicator
  const watcherText = document.getElementById('top-watcher-text');
  const watcherDot = document.getElementById('watcher-indicator-dot');
  if (watcherDot && watcherText) {
    if (data.watcher_active) {
      watcherDot.className = 'status-indicator-dot online';
      watcherText.textContent = 'ACTIF';
    } else {
      watcherDot.className = 'status-indicator-dot';
      watcherText.textContent = 'INACTIF';
    }
  }

  // Dashboard Stats
  const statSig = document.getElementById('stat-signatures');
  if (statSig) statSig.textContent = data.signatures || 4;

  const statQ = document.getElementById('stat-quarantine-count');
  if (statQ) statQ.textContent = data.quarantine_count || 0;

  const statWatcher = document.getElementById('stat-watcher-status');
  const statWatcherFoot = document.getElementById('stat-watcher-footer');
  if (statWatcher) {
    statWatcher.textContent = data.watcher_active ? 'Actif' : 'Inactif';
    statWatcher.style.color = data.watcher_active ? 'var(--accent-emerald)' : 'var(--text-muted)';
  }
  if (statWatcherFoot) {
    statWatcherFoot.textContent = data.watcher_active
      ? (data.watched_path ? `Sur : ${getFileName(data.watched_path)}` : 'En surveillance')
      : 'Surveillance de répertoire';
  }

  // Vault dir label in quarantine tab
  const vaultLabel = document.getElementById('vault-dir-label');
  if (vaultLabel && data.vault_path) {
    vaultLabel.textContent = data.vault_path;
  }

  // Watcher controls in Watcher tab
  const watcherCheckbox = document.getElementById('watcher-toggle-checkbox');
  const watcherIndicator = document.getElementById('watcher-card-indicator');
  const watcherTitle = document.getElementById('watcher-title-status');
  const watcherDesc = document.getElementById('watcher-desc-status');
  if (watcherCheckbox && watcherIndicator) {
    watcherCheckbox.checked = !!data.watcher_active;
    if (data.watcher_active) {
      watcherIndicator.className = 'sentinel-indicator-box active';
      if (watcherTitle) watcherTitle.textContent = 'Sentinelle active';
      if (watcherDesc) watcherDesc.textContent = `Surveillance continue sur : ${data.watched_path || 'Répertoire configuré'}`;
    } else {
      watcherIndicator.className = 'sentinel-indicator-box';
      if (watcherTitle) watcherTitle.textContent = 'Sentinelle inactive';
      if (watcherDesc) watcherDesc.textContent = 'Aucun dossier n\'est actuellement sous écoute active.';
    }
  }
}

function updateOfflineUI() {
  const enginePill = document.getElementById('pill-engine-status');
  const engineText = document.getElementById('engine-status-text');
  const dot = enginePill?.querySelector('.status-indicator-dot');
  if (dot) dot.className = 'status-indicator-dot offline';
  if (engineText) engineText.textContent = 'OFFLINE';
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
  const btnStart = document.getElementById('btn-start-scan');

  progressBox.style.display = 'block';
  resultsBox.style.display = 'none';
  progressBar.style.width = '15%';
  progressPercent.textContent = '15%';
  progressStatus.textContent = 'Initialisation du moteur d\'analyse...';
  btnStart.disabled = true;

  appendLog('SCAN_EXEC', `Analyse démarrée : ${targetPath} (récursif=${recursive}, quarantaine=${quarantine})`, 'info');

  let simProgress = 15;
  const timer = setInterval(() => {
    if (simProgress < 85) {
      simProgress += Math.floor(Math.random() * 12) + 5;
      if (simProgress > 85) simProgress = 85;
      progressBar.style.width = `${simProgress}%`;
      progressPercent.textContent = `${simProgress}%`;
      progressStatus.textContent = `Empreintes SHA-256 et heuristique (${simProgress}%)...`;
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
    }, 350);

    fetchStatus();
    fetchQuarantine();
  } catch (err) {
    clearInterval(timer);
    progressBox.style.display = 'none';
    btnStart.disabled = false;
    showToast(`Erreur d'analyse : ${err.message}`, 'danger');
    appendLog('SCAN_ERR', `Échec d'analyse : ${err.message}`, 'error');
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

  document.getElementById('res-total-scanned').textContent = String(scannedCount);
  document.getElementById('res-total-infected').textContent = String(infectedCount);

  if (!data.results || data.results.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" class="empty-state-cell">Aucun fichier trouvé dans la cible spécifiée.</td></tr>';
    return;
  }

  data.results.forEach((item) => {
    if (item.quarantine_id) quarantinedCount++;
    const tr = document.createElement('tr');

    const badgeClass = item.is_infected ? 'badge-tag badge-infected' : 'badge-tag badge-clean';
    const statusText = item.is_infected ? 'INFECTÉ' : 'SAIN';
    const threatDisplay = item.threat_name
      ? `<strong style="color:var(--accent-crimson);">${escapeHtml(item.threat_name)}</strong>`
      : '<span style="color:var(--text-dim);">-</span>';
    const hashDisplay = item.file_hash
      ? `<span class="code-font" style="font-size:0.75rem;color:var(--text-muted);">${item.file_hash.substring(0, 16)}...</span>`
      : '-';
    const qDisplay = item.quarantine_id
      ? `<span class="badge-tag badge-clean">ISOLÉ</span>`
      : item.is_infected
      ? `<span class="badge-tag badge-infected">NON ISOLÉ</span>`
      : '<span style="color:var(--text-dim);">-</span>';

    tr.innerHTML = `
      <td><span class="${badgeClass}">${statusText}</span></td>
      <td title="${escapeHtml(item.file_path)}">
        <strong>${escapeHtml(getFileName(item.file_path))}</strong>
        <div style="font-size:0.72rem;color:var(--text-muted);">${escapeHtml(item.file_path)}</div>
      </td>
      <td>${threatDisplay}</td>
      <td>${hashDisplay}</td>
      <td>${qDisplay}</td>
    `;
    tbody.appendChild(tr);
  });

  document.getElementById('res-total-quarantined').textContent = String(quarantinedCount);

  if (infectedCount > 0) {
    showToast(`${infectedCount} menace(s) détectée(s) lors du scan`, 'danger');
    appendLog('ALERT', `${infectedCount} menace(s) identifiée(s) parmi ${scannedCount} fichiers analysés.`, 'error');
    setShieldThreatState(true);
  } else {
    showToast(`Scan terminé : ${scannedCount} fichiers vérifiés, intégrité confirmée`, 'success');
    appendLog('SCAN_OK', `Scan complété avec succès. 0 menace sur ${scannedCount} fichiers.`, 'info');
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
  tbody.innerHTML = '<tr><td colspan="5" class="empty-state-cell">Inspection des processus actifs en cours...</td></tr>';

  try {
    const res = await fetch(`${API_BASE}/api/processes?limit=60`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    appState.processes = data.processes || [];
    renderProcesses(appState.processes);
    appendLog('RAM_AUDIT', `Inspection mémoire terminée (${appState.processes.length} processus analysés).`, 'info');
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="5" class="empty-state-cell" style="color:var(--accent-crimson);">Échec du scan mémoire : ${err.message}</td></tr>`;
    showToast('Impossible de contacter le sous-système processus', 'danger');
  }
}

function renderProcesses(procList) {
  const tbody = document.getElementById('processes-tbody');
  tbody.innerHTML = '';

  if (procList.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" class="empty-state-cell">Aucun processus correspondant.</td></tr>';
    return;
  }

  procList.forEach((p) => {
    const tr = document.createElement('tr');
    const badge = p.is_infected
      ? '<span class="badge-tag badge-infected">SUSPECT</span>'
      : '<span class="badge-tag badge-clean">PROTÉGÉ</span>';
    const threat = p.threat_name
      ? `<strong style="color:var(--accent-crimson);">${escapeHtml(p.threat_name)}</strong>`
      : '<span style="color:var(--text-dim);">-</span>';

    tr.innerHTML = `
      <td class="code-font" style="font-weight:600;">${p.pid}</td>
      <td><strong>${escapeHtml(p.name || 'Inconnu')}</strong></td>
      <td title="${escapeHtml(p.exe_path || '')}"><span style="color:var(--text-muted);font-size:0.75rem;">${escapeHtml(p.exe_path || 'N/A')}</span></td>
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
    showToast('Coffre de quarantaine actualisé', 'success');
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
    tbody.innerHTML = `<tr><td colspan="5" class="empty-state-cell">Erreur lors de la lecture du coffre : ${err.message}</td></tr>`;
  }
}

function renderQuarantine(records) {
  const tbody = document.getElementById('quarantine-tbody');
  tbody.innerHTML = '';

  const countStr = String(records.length);
  document.getElementById('nav-quarantine-badge').textContent = countStr;
  document.getElementById('stat-quarantine-count').textContent = countStr;
  document.getElementById('top-vault-count').textContent = countStr;

  if (records.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" class="empty-state-cell">Le coffre-fort est vide. Aucune menace isolée.</td></tr>';
    return;
  }

  records.forEach((r) => {
    const tr = document.createElement('tr');
    const dateFormatted = new Date(r.quarantined_at).toLocaleString('fr-FR');
    const sevBadge = `<span class="badge-tag badge-infected">${escapeHtml(r.severity || 'HIGH')}</span>`;

    tr.innerHTML = `
      <td><span style="color:var(--text-muted);font-size:0.78rem;">${dateFormatted}</span></td>
      <td title="${escapeHtml(r.original_path)}">
        <strong>${escapeHtml(getFileName(r.original_path))}</strong>
        <div style="font-size:0.72rem;color:var(--text-muted);">${escapeHtml(r.original_path)}</div>
      </td>
      <td><strong style="color:var(--accent-crimson);">${escapeHtml(r.threat_name)}</strong></td>
      <td>${sevBadge}</td>
      <td>
        <button class="btn-table-action restore" data-action="restore" data-id="${r.record_id}">Restaurer</button>
        <button class="btn-table-action shred" data-action="delete" data-id="${r.record_id}">Broyer</button>
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
      showToast(`Fichier restauré avec intégrité : ${data.restored_path}`, 'success');
      appendLog('VAULT_REST', `Restauration réussie du fichier : ${data.restored_path}`, 'info');
      fetchQuarantine();
      fetchStatus();
    } else {
      showToast(`Échec de restauration : ${data.error}`, 'danger');
    }
  } catch (err) {
    showToast(`Erreur : ${err.message}`, 'danger');
  }
}

async function deleteQuarantineFile(recordId) {
  if (!confirm('Voulez-vous détruire définitivement ce fichier et écraser ses données sur le disque ?')) {
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
      appendLog('VAULT_SHRED', `Suppression définitive et shred du payload ${recordId}`, 'warn');
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
      showToast('Spécifiez un dossier valide pour enclencher la veille.', 'danger');
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
        showToast(`Sentinelle engagée sur : ${data.watched_path}`, 'success');
        appendLog('WATCH_ON', `Surveillance continue active sur ${data.watched_path}`, 'info');
      } else {
        showToast('Sentinelle désactivée', 'info');
        appendLog('WATCH_OFF', 'Surveillance continue suspendue.', 'warn');
      }
      fetchStatus();
    } catch (err) {
      toggle.checked = !activate;
      showToast(`Erreur sentinelle : ${err.message}`, 'danger');
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
    tbody.innerHTML = '<tr><td colspan="4" class="empty-state-cell">En attente d\'événements de fichiers...</td></tr>';
    dashboardEvents.innerHTML = `
      <div class="empty-state-notice">
        <svg class="empty-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
          <circle cx="12" cy="12" r="10"/>
          <path d="m9 12 2 2 4-4"/>
        </svg>
        <span>Aucune menace récente détectée sur le système. Les défenses sont au vert.</span>
      </div>`;
    return;
  }

  tbody.innerHTML = '';
  dashboardEvents.innerHTML = '';

  const recentReversed = [...events].reverse();

  recentReversed.slice(0, 15).forEach((ev) => {
    const tr = document.createElement('tr');
    const badge = ev.is_infected
      ? '<span class="badge-tag badge-infected">INFECTÉ</span>'
      : '<span class="badge-tag badge-clean">SAIN</span>';
    const threat = ev.threat_name
      ? `<strong style="color:var(--accent-crimson);">${escapeHtml(ev.threat_name)}</strong>`
      : '<span style="color:var(--text-dim);">-</span>';
    const action = ev.quarantine_id
      ? `<span class="badge-tag badge-clean">ISOLÉ</span>`
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
  recentReversed.slice(0, 4).forEach((ev) => {
    const div = document.createElement('div');
    div.style.cssText = 'display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid var(--border-hairline);';
    div.innerHTML = `
      <div>
        <strong style="color:${ev.is_infected ? 'var(--accent-crimson)' : 'var(--text-primary)'};">${escapeHtml(getFileName(ev.file_path))}</strong>
        <span style="color:var(--text-muted);font-size:0.75rem;margin-left:8px;">${ev.threat_name ? escapeHtml(ev.threat_name) : 'Intégrité vérifiée'}</span>
      </div>
      <span class="badge-tag ${ev.is_infected ? 'badge-infected' : 'badge-clean'}">${ev.status}</span>
    `;
    dashboardEvents.appendChild(div);
  });
}

// --- Audit Console Logs ---
function setupAuditControls() {
  document.getElementById('btn-clear-logs')?.addEventListener('click', () => {
    document.getElementById('audit-log-terminal').innerHTML = '';
    showToast('Vue du journal effacée', 'info');
  });

  document.getElementById('btn-refresh-logs')?.addEventListener('click', () => {
    fetchStatus();
    appendLog('SYNC', 'Synchronisation manuelle de l\'état de sécurité.', 'info');
  });
}

function appendLog(category, message, level = 'info') {
  const terminal = document.getElementById('audit-log-terminal');
  if (!terminal) return;

  const now = new Date();
  const timeStr = now.toTimeString().split(' ')[0] + '.' + String(now.getMilliseconds()).padStart(3, '0');

  const div = document.createElement('div');
  div.className = `log-entry ${level}`;
  div.innerHTML = `<span style="color:var(--text-dim)">[${timeStr}]</span> <strong style="color:var(--accent-blue)">[${escapeHtml(category)}]</strong> ${escapeHtml(message)}`;

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
    toast.style.transform = 'translateX(20px)';
    toast.style.transition = 'all 0.2s ease';
    setTimeout(() => toast.remove(), 250);
  }, 3500);
}

function setShieldThreatState(isThreat) {
  const badge = document.getElementById('dashboard-shield-badge');
  const heroCard = document.getElementById('dashboard-hero-card');
  const shieldEmblem = document.getElementById('hero-shield-emblem');
  const sideState = document.getElementById('sidebar-protection-state');

  if (!badge) return;

  if (isThreat) {
    badge.className = 'protection-chip threat';
    badge.innerHTML = '<span class="chip-dot"></span><span>MENACE ACTIVE DÉTECTÉE</span>';
    if (heroCard) heroCard.style.borderColor = 'rgba(239, 68, 68, 0.4)';
    if (shieldEmblem) {
      shieldEmblem.style.color = 'var(--accent-crimson)';
      shieldEmblem.style.background = 'rgba(239, 68, 68, 0.15)';
    }
    if (sideState) {
      sideState.textContent = 'Menace Active';
      sideState.style.color = 'var(--accent-crimson)';
    }
  } else {
    badge.className = 'protection-chip protected';
    badge.innerHTML = '<span class="chip-dot"></span><span>PROTECTION COMPLÈTE ACTIVE</span>';
    if (heroCard) heroCard.style.borderColor = 'var(--border-hairline)';
    if (shieldEmblem) {
      shieldEmblem.style.color = 'var(--accent-emerald)';
      shieldEmblem.style.background = 'rgba(16, 185, 129, 0.15)';
    }
    if (sideState) {
      sideState.textContent = 'Bouclier Actif';
      sideState.style.color = 'var(--text-primary)';
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
