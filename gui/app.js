/**
 * PulseGuard Total Security — Bitdefender Controller.
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
  isScanning: false,
  scanPollTimer: null,
  processes: [],
  auditLogs: [],
};

// --- Initialization ---
document.addEventListener('DOMContentLoaded', () => {
  setupWindowControls();
  setupNavigation();
  setupDashboardActions();
  setupScanControls();
  setupProcessControls();
  setupQuarantineControls();
  setupAuditControls();

  appendLog('SYS_INIT', 'PulseGuard Total Security initialisé. Moteur local prêt.', 'info');

  // Initial telemetry fetch & periodic polling
  fetchStatus();
  fetchQuarantine();
  fetchEvents();
  setInterval(fetchStatus, 3000);
  setInterval(fetchEvents, 4000);

  // Initial welcome notification in bottom-left
  setTimeout(() => {
    showBottomLeftNotification(
      'Protection Active',
      'Le moteur de détection heuristique et la base de signatures sont opérationnels.',
      'safe'
    );
  }, 1000);
});

// --- Frameless Window Controls ---
function setupWindowControls() {
  document.getElementById('ctrl-minimize')?.addEventListener('click', () => {
    if (window.pulseguard?.minimize) window.pulseguard.minimize();
  });

  document.getElementById('ctrl-maximize')?.addEventListener('click', () => {
    if (window.pulseguard?.maximize) window.pulseguard.maximize();
  });

  document.getElementById('ctrl-close')?.addEventListener('click', () => {
    if (window.pulseguard?.close) window.pulseguard.close();
    else window.close();
  });
}

// --- Navigation Tabs ---
function setupNavigation() {
  const navItems = document.querySelectorAll('.nav-item');
  const panels = document.querySelectorAll('.tab-panel');

  navItems.forEach((item) => {
    item.addEventListener('click', () => {
      const targetTab = item.getAttribute('data-tab');
      navItems.forEach((n) => n.classList.remove('active'));
      panels.forEach((p) => p.classList.remove('active'));

      item.classList.add('active');
      const targetPanel = document.getElementById(`pane-${targetTab}`);
      if (targetPanel) targetPanel.classList.add('active');

      if (targetTab === 'quarantine') fetchQuarantine();
      if (targetTab === 'processes' && appState.processes.length === 0) fetchProcesses();
    });
  });

  // Shortcut link buttons
  document.getElementById('btn-goto-scanner')?.addEventListener('click', () => {
    document.querySelector('.nav-item[data-tab="protection"]')?.click();
  });
  document.getElementById('btn-goto-quarantine')?.addEventListener('click', () => {
    document.querySelector('.nav-item[data-tab="quarantine"]')?.click();
  });
  document.getElementById('btn-goto-processes')?.addEventListener('click', () => {
    document.querySelector('.nav-item[data-tab="processes"]')?.click();
  });
}

// --- Dashboard Quick Actions ---
function setupDashboardActions() {
  // 1. Analyse Rapide
  document.getElementById('btn-run-quick-scan')?.addEventListener('click', () => {
    triggerScanWorkflow('quick');
  });

  // 2. Analyse Complète
  document.getElementById('btn-run-system-scan')?.addEventListener('click', () => {
    triggerScanWorkflow('system');
  });

  // 4. Protection Temps Réel (Watcher Toggle)
  const watcherToggle = document.getElementById('dash-watcher-toggle');
  watcherToggle?.addEventListener('change', async () => {
    const active = watcherToggle.checked;
    const defaultPath = window.pulseguard?.platform === 'win32' ? 'C:\\Users\\lulu6\\Downloads' : '/tmp';

    try {
      const res = await fetch(`${API_BASE}/api/watch/toggle`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ active, path: defaultPath, quarantine: true }),
      });
      const data = await res.json();
      appState.watcherActive = !!data.watcher_active;
      updateWatcherUI(data);

      if (data.watcher_active) {
        showBottomLeftNotification(
          'Sentinelle Activée',
          `Surveillance en direct active sur : ${data.watched_path || defaultPath}`,
          'safe'
        );
        appendLog('WATCH_ON', `Veille temps réel engagée sur ${data.watched_path || defaultPath}`, 'info');
      } else {
        showBottomLeftNotification(
          'Sentinelle Suspendue',
          'La surveillance continue des fichiers a été arrêtée.',
          'info'
        );
        appendLog('WATCH_OFF', 'Veille temps réel suspendue par l\'utilisateur.', 'warn');
      }
    } catch (err) {
      watcherToggle.checked = !active;
      showBottomLeftNotification('Erreur Sentinelle', err.message, 'threat');
    }
  });
}

// --- Real-time Bitdefender Scan Workflow ---
async function triggerScanWorkflow(scanType, customPath = null) {
  if (appState.isScanning) {
    showBottomLeftNotification('Analyse en cours', 'Une analyse est déjà en train de s\'exécuter.', 'info');
    return;
  }

  const overlay = document.getElementById('scan-overlay');
  const overlayTitle = document.getElementById('overlay-scan-title');
  const overlayPercent = document.getElementById('overlay-progress-percent');
  const overlayFill = document.getElementById('overlay-progress-fill');
  const overlayFile = document.getElementById('overlay-current-file');
  const overlayScanned = document.getElementById('overlay-scanned-count');
  const overlayInfected = document.getElementById('overlay-infected-count');
  const overlayQuarantined = document.getElementById('overlay-quarantined-count');
  const overlayTime = document.getElementById('overlay-elapsed-time');

  // Reset overlay counters
  overlayPercent.textContent = '0%';
  overlayFill.style.width = '0%';
  overlayFile.textContent = 'Initialisation de l\'analyse...';
  overlayScanned.textContent = '0';
  overlayInfected.textContent = '0';
  overlayQuarantined.textContent = '0';
  overlayTime.textContent = '00:00:00';

  if (scanType === 'quick') overlayTitle.textContent = 'Analyse Rapide en cours...';
  else if (scanType === 'system') overlayTitle.textContent = 'Analyse du Système en cours...';
  else overlayTitle.textContent = 'Analyse Ciblée en cours...';

  overlay.style.display = 'flex';
  appState.isScanning = true;

  appendLog('SCAN_LAUNCH', `Lancement de l'analyse (${scanType.toUpperCase()})`, 'info');

  try {
    const payload = { scan_type: scanType, recursive: true, quarantine: true };
    if (customPath) payload.path = customPath;

    const startRes = await fetch(`${API_BASE}/api/scan/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    if (!startRes.ok) {
      const err = await startRes.json();
      throw new Error(err.error || 'Erreur lors du démarrage du scan');
    }

    // Start polling progress
    const startTime = Date.now();
    appState.scanPollTimer = setInterval(async () => {
      try {
        const progRes = await fetch(`${API_BASE}/api/scan/progress`);
        if (!progRes.ok) return;
        const prog = await progRes.json();

        // Update progress visuals
        const elapsedSec = Math.floor((Date.now() - startTime) / 1000);
        overlayTime.textContent = formatTime(elapsedSec);
        overlayPercent.textContent = `${prog.progress_percent}%`;
        overlayFill.style.width = `${prog.progress_percent}%`;
        overlayFile.textContent = prog.current_file || 'Vérification des signatures...';
        overlayScanned.textContent = String(prog.scanned_count);
        overlayInfected.textContent = String(prog.infected_count);
        overlayQuarantined.textContent = String(prog.quarantined_count);

        if (!prog.running && prog.progress_percent >= 100) {
          clearInterval(appState.scanPollTimer);
          appState.isScanning = false;

          setTimeout(() => {
            overlay.style.display = 'none';
            renderCompletedScanResults(prog);
            fetchStatus();
            fetchQuarantine();
          }, 600);
        }
      } catch (pollErr) {
        console.error('Polling error:', pollErr);
      }
    }, 200);
  } catch (err) {
    overlay.style.display = 'none';
    appState.isScanning = false;
    showBottomLeftNotification('Échec de l\'analyse', err.message, 'threat');
    appendLog('SCAN_ERR', `Erreur : ${err.message}`, 'error');
  }
}

// Stop scan button listener on overlay
document.getElementById('btn-overlay-stop-scan')?.addEventListener('click', async () => {
  try {
    await fetch(`${API_BASE}/api/scan/stop`, { method: 'POST' });
    clearInterval(appState.scanPollTimer);
    appState.isScanning = false;
    document.getElementById('scan-overlay').style.display = 'none';
    showBottomLeftNotification('Analyse Interrompue', 'L\'analyse a été annulée par l\'utilisateur.', 'info');
    appendLog('SCAN_CANCEL', 'Analyse stoppée manuellement.', 'warn');
  } catch (e) {
    console.error(e);
  }
});

function renderCompletedScanResults(prog) {
  // Switch to protection tab to view table
  document.querySelector('.nav-item[data-tab="protection"]')?.click();
  const resultsBox = document.getElementById('scan-results-box');
  const tbody = document.getElementById('scan-results-tbody');
  resultsBox.style.display = 'block';
  tbody.innerHTML = '';

  document.getElementById('res-total-scanned').textContent = String(prog.scanned_count);
  document.getElementById('res-total-infected').textContent = String(prog.infected_count);
  document.getElementById('res-total-quarantined').textContent = String(prog.quarantined_count);

  if (!prog.results || prog.results.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" class="empty-cell">Aucun fichier présent dans la zone ciblée.</td></tr>';
    return;
  }

  prog.results.forEach((item) => {
    const tr = document.createElement('tr');
    const badgeClass = item.is_infected ? 'badge-tag badge-infected' : 'badge-tag badge-clean';
    const statusText = item.is_infected ? 'INFECTÉ' : 'SAIN';
    const threatDisplay = item.threat_name
      ? `<strong style="color:var(--bd-red);">${escapeHtml(item.threat_name)}</strong>`
      : '<span style="color:var(--text-dim);">-</span>';
    const hashDisplay = item.file_hash
      ? `<span style="font-family:monospace;font-size:0.75rem;color:var(--text-muted);">${item.file_hash.substring(0, 16)}...</span>`
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

  if (prog.infected_count > 0) {
    showBottomLeftNotification(
      'Alerte : Menace détectée',
      `${prog.infected_count} élément(s) malveillant(s) identifié(s) et neutralisé(s).`,
      'threat'
    );
    appendLog('THREAT', `${prog.infected_count} menace(s) identifiée(s) parmi ${prog.scanned_count} fichiers.`, 'error');
    setHeroThreatState(true);
  } else {
    showBottomLeftNotification(
      'Analyse Terminée',
      `Examen complété : ${prog.scanned_count} fichiers vérifiés, aucun danger détecté.`,
      'safe'
    );
    appendLog('CLEAN', `Scan terminé : ${prog.scanned_count} fichiers sains.`, 'info');
    setHeroThreatState(false);
  }
}

// --- Protection Tab Custom Scan Controls ---
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
    const targetPath = inputPath.value.trim();
    if (!targetPath) {
      showBottomLeftNotification('Chemin requis', 'Veuillez sélectionner un fichier ou un dossier à analyser.', 'threat');
      return;
    }
    triggerScanWorkflow('custom', targetPath);
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
  const dot = enginePill?.querySelector('.dot-status');
  if (dot) dot.className = 'dot-status green';
  if (engineText) engineText.textContent = 'ONLINE';

  document.getElementById('top-sig-count').textContent = `${data.signatures || 4} SIGNATURES`;
  document.getElementById('nav-quarantine-badge').textContent = String(data.quarantine_count || 0);
  document.getElementById('dash-quarantine-count').textContent = `${data.quarantine_count || 0} isolés`;

  updateWatcherUI(data);

  const vaultLabel = document.getElementById('vault-dir-label');
  if (vaultLabel && data.vault_path) vaultLabel.textContent = data.vault_path;
}

function updateWatcherUI(data) {
  const dashToggle = document.getElementById('dash-watcher-toggle');
  const dashBadge = document.getElementById('dash-watcher-badge');
  const dashDesc = document.getElementById('dash-watcher-desc');

  if (dashToggle && dashBadge) {
    dashToggle.checked = !!data.watcher_active;
    if (data.watcher_active) {
      dashBadge.className = 'card-status-badge active';
      dashBadge.textContent = 'ACTIF';
      if (dashDesc) dashDesc.textContent = `Surveillance en cours sur : ${data.watched_path || 'Téléchargements'}`;
    } else {
      dashBadge.className = 'card-status-badge';
      dashBadge.textContent = 'INACTIF';
      if (dashDesc) dashDesc.textContent = 'Surveillance active des écritures disque et debouncing automatique.';
    }
  }
}

function updateOfflineUI() {
  const enginePill = document.getElementById('pill-engine-status');
  const engineText = document.getElementById('engine-status-text');
  const dot = enginePill?.querySelector('.dot-status');
  if (dot) dot.className = 'dot-status red';
  if (engineText) engineText.textContent = 'OFFLINE';
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
  tbody.innerHTML = '<tr><td colspan="5" class="empty-cell">Inspection des processus actifs en cours...</td></tr>';

  try {
    const res = await fetch(`${API_BASE}/api/processes?limit=60`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    appState.processes = data.processes || [];
    renderProcesses(appState.processes);
    showBottomLeftNotification('Audit RAM Terminé', `${appState.processes.length} processus vérifiés en mémoire.`, 'safe');
    appendLog('RAM_AUDIT', `Inspection mémoire terminée (${appState.processes.length} processus analysés).`, 'info');
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="5" class="empty-cell" style="color:var(--bd-red);">Échec de l'audit RAM : ${err.message}</td></tr>`;
    showBottomLeftNotification('Erreur RAM', err.message, 'threat');
  }
}

function renderProcesses(procList) {
  const tbody = document.getElementById('processes-tbody');
  tbody.innerHTML = '';

  if (procList.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" class="empty-cell">Aucun processus trouvé.</td></tr>';
    return;
  }

  procList.forEach((p) => {
    const tr = document.createElement('tr');
    const badge = p.is_infected
      ? '<span class="badge-tag badge-infected">SUSPECT</span>'
      : '<span class="badge-tag badge-clean">PROTÉGÉ</span>';
    const threat = p.threat_name
      ? `<strong style="color:var(--bd-red);">${escapeHtml(p.threat_name)}</strong>`
      : '<span style="color:var(--text-dim);">-</span>';

    tr.innerHTML = `
      <td style="font-family:monospace;font-weight:600;">${p.pid}</td>
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
    showBottomLeftNotification('Coffre Actualisé', 'Le catalogue de quarantaine a été synchronisé.', 'safe');
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
    tbody.innerHTML = `<tr><td colspan="5" class="empty-cell">Erreur lors de la lecture du coffre : ${err.message}</td></tr>`;
  }
}

function renderQuarantine(records) {
  const tbody = document.getElementById('quarantine-tbody');
  tbody.innerHTML = '';

  const countStr = String(records.length);
  document.getElementById('nav-quarantine-badge').textContent = countStr;
  document.getElementById('dash-quarantine-count').textContent = `${countStr} isolés`;

  if (records.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" class="empty-cell">Le coffre-fort est vide. Aucune menace isolée.</td></tr>';
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
      <td><strong style="color:var(--bd-red);">${escapeHtml(r.threat_name)}</strong></td>
      <td>${sevBadge}</td>
      <td>
        <button class="btn-action-restore" data-action="restore" data-id="${r.record_id}">Restaurer</button>
        <button class="btn-action-shred" data-action="delete" data-id="${r.record_id}">Broyer</button>
      </td>
    `;
    tbody.appendChild(tr);
  });

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
      showBottomLeftNotification('Fichier Restauré', `Fichier restauré avec intégrité : ${data.restored_path}`, 'safe');
      appendLog('VAULT_REST', `Restauration réussie du fichier : ${data.restored_path}`, 'info');
      fetchQuarantine();
      fetchStatus();
    } else {
      showBottomLeftNotification('Échec Restauration', data.error, 'threat');
    }
  } catch (err) {
    showBottomLeftNotification('Erreur', err.message, 'threat');
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
      showBottomLeftNotification('Fichier Broyé', 'Le fichier a été écrasé et retiré du coffre.', 'safe');
      appendLog('VAULT_SHRED', `Suppression définitive du payload ${recordId}`, 'warn');
      fetchQuarantine();
      fetchStatus();
    } else {
      showBottomLeftNotification('Échec Suppression', data.error, 'threat');
    }
  } catch (err) {
    showBottomLeftNotification('Erreur', err.message, 'threat');
  }
}

// --- Real-time Watcher Events ---
async function fetchEvents() {
  try {
    const res = await fetch(`${API_BASE}/api/events`);
    if (!res.ok) return;
    const data = await res.json();
    const events = data.events || [];
    if (events.length > 0 && appState.lastEventCount !== events.length) {
      appState.lastEventCount = events.length;
      const latest = events[events.length - 1];
      if (latest.is_infected) {
        showBottomLeftNotification(
          'Sentinelle : Menace Bloquée',
          `Menace identifiée et isolée : ${getFileName(latest.file_path)}`,
          'threat'
        );
      }
    }
  } catch (err) {
    // Ignore polling errors
  }
}

// --- Audit Console ---
function setupAuditControls() {
  document.getElementById('btn-clear-logs')?.addEventListener('click', () => {
    document.getElementById('audit-log-terminal').innerHTML = '';
    showBottomLeftNotification('Journal', 'La console a été réinitialisée.', 'info');
  });

  document.getElementById('btn-refresh-logs')?.addEventListener('click', () => {
    fetchStatus();
    appendLog('SYNC', 'Synchronisation de l\'état de sécurité.', 'info');
  });
}

function appendLog(category, message, level = 'info') {
  const terminal = document.getElementById('audit-log-terminal');
  if (!terminal) return;

  const now = new Date();
  const timeStr = now.toTimeString().split(' ')[0] + '.' + String(now.getMilliseconds()).padStart(3, '0');

  const div = document.createElement('div');
  div.className = `log-entry ${level}`;
  div.innerHTML = `<span style="color:var(--text-dim)">[${timeStr}]</span> <strong style="color:var(--bd-blue)">[${escapeHtml(category)}]</strong> ${escapeHtml(message)}`;

  terminal.appendChild(div);
  terminal.scrollTop = terminal.scrollHeight;
}

// --- BITDEFENDER FLOATING NOTIFICATION SYSTEM (BOTTOM-LEFT / BAS À GAUCHE) ---
function showBottomLeftNotification(title, message, type = 'safe') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const notif = document.createElement('div');
  notif.className = `bd-notification ${type}`;

  const shieldSvg = type === 'threat'
    ? `<svg class="notif-shield-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`
    : `<svg class="notif-shield-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>`;

  notif.innerHTML = `
    <div class="notif-topbar">
      <div class="notif-title-group">
        ${shieldSvg}
        <span class="notif-title">${escapeHtml(title)}</span>
      </div>
      <button class="notif-close-btn" title="Fermer la notification">
        <svg viewBox="0 0 10 10"><path d="M1 1l8 8M9 1l-8 8" stroke="currentColor" stroke-width="1.5"/></svg>
      </button>
    </div>
    <div class="notif-body-text">${escapeHtml(message)}</div>
    <div class="notif-timestamp">À l'instant</div>
  `;

  // Attach close button click handler (Petite croix ✕)
  const closeBtn = notif.querySelector('.notif-close-btn');
  closeBtn?.addEventListener('click', (e) => {
    e.stopPropagation();
    dismissNotification(notif);
  });

  container.appendChild(notif);

  // Auto-dismiss after 6.5 seconds
  const autoTimer = setTimeout(() => {
    dismissNotification(notif);
  }, 6500);

  notif._autoTimer = autoTimer;
}

function dismissNotification(notif) {
  if (notif._isDismissed) return;
  notif._isDismissed = true;
  clearTimeout(notif._autoTimer);

  notif.style.opacity = '0';
  notif.style.transform = 'translateY(15px) scale(0.95)';
  setTimeout(() => notif.remove(), 250);
}

// --- UI Helpers ---
function setHeroThreatState(isThreat) {
  const badge = document.getElementById('dashboard-shield-badge');
  const heroCard = document.getElementById('dashboard-hero-card');
  const shieldEmblem = document.getElementById('hero-shield-emblem');
  const protectLabel = document.getElementById('sidebar-protect-label');

  if (!badge) return;

  if (isThreat) {
    badge.className = 'hero-status-pill threat';
    badge.innerHTML = '<span class="status-indicator"></span><span>MENACE ACTIVE IDENTIFIÉE</span>';
    if (heroCard) heroCard.style.borderColor = 'rgba(239, 68, 68, 0.4)';
    if (shieldEmblem) {
      shieldEmblem.style.borderColor = 'var(--bd-red)';
      shieldEmblem.style.color = 'var(--bd-red)';
      shieldEmblem.style.background = 'radial-gradient(circle, rgba(239, 68, 68, 0.2) 0%, transparent 70%)';
    }
    if (protectLabel) {
      protectLabel.textContent = 'Menace active !';
      protectLabel.style.color = 'var(--bd-red)';
    }
  } else {
    badge.className = 'hero-status-pill protected';
    badge.innerHTML = '<span class="status-indicator"></span><span>VOUS ÊTES EN SÉCURITÉ</span>';
    if (heroCard) heroCard.style.borderColor = 'var(--bd-border)';
    if (shieldEmblem) {
      shieldEmblem.style.borderColor = 'rgba(16, 185, 129, 0.4)';
      shieldEmblem.style.color = 'var(--bd-green)';
      shieldEmblem.style.background = 'radial-gradient(circle, rgba(16, 185, 129, 0.16) 0%, transparent 70%)';
    }
    if (protectLabel) {
      protectLabel.textContent = 'Appareil protégé';
      protectLabel.style.color = '#ffffff';
    }
  }
}

function formatTime(totalSec) {
  const h = String(Math.floor(totalSec / 3600)).padStart(2, '0');
  const m = String(Math.floor((totalSec % 3600) / 60)).padStart(2, '0');
  const s = String(totalSec % 60).padStart(2, '0');
  return `${h}:${m}:${s}`;
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
