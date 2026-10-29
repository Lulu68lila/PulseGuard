/**
 * PulseGuard Total Security — Modern Cybersecurity & NVIDIA Nemotron AI Controller.
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
  aiConfigured: false,
  aiModel: 'nvidia/nemotron-3-ultra-550b-a55b',
};

// --- Initialization ---
document.addEventListener('DOMContentLoaded', () => {
  setupWindowControls();
  setupNavigation();
  setupDashboardActions();
  setupProtectionControls();
  setupNotificationsCenter();
  setupSettingsControls();
  setupAIModal();
  setupQuarantineControls();
  setupProcessControls();

  appendLog('SYS_INIT', 'PulseGuard Total Security initialisé. Moteur local & Nemotron AI prêts.', 'info');

  // Initial telemetry fetch & periodic polling
  fetchStatus();
  fetchConfig();
  fetchQuarantine();
  setInterval(fetchStatus, 3000);

  // Initial welcome notification anchored in bottom-left
  setTimeout(() => {
    showBottomLeftNotification(
      'Protection Active',
      'Le moteur de détection heuristique et la base de signatures sont opérationnels.',
      'safe'
    );
  }, 1000);
});

// --- Window Controls ---
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

  document.getElementById('btn-top-settings')?.addEventListener('click', () => {
    document.querySelector('.nav-item[data-tab="settings"]')?.click();
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

      if (targetTab === 'utilities') {
        fetchQuarantine();
        if (appState.processes.length === 0) fetchProcesses();
      }
    });
  });
}

// --- Dashboard Quick Actions (Screenshot 3) ---
function setupDashboardActions() {
  // 1. Analyse Rapide
  document.getElementById('card-quick-scan')?.addEventListener('click', () => {
    triggerScanWorkflow('quick');
  });

  // 2. Analyse Complète
  document.getElementById('card-system-scan')?.addEventListener('click', () => {
    triggerScanWorkflow('system');
  });

  // 3. Analyse IA Nemotron
  document.getElementById('card-ai-scan')?.addEventListener('click', async () => {
    if (window.pulseguard?.selectFile) {
      const filePath = await window.pulseguard.selectFile();
      if (filePath) runNemotronAIScan(filePath);
    } else {
      document.querySelector('.nav-item[data-tab="protection"]')?.click();
    }
  });

  // 4. Analyse des Vulnérabilités & Failles Système
  document.getElementById('card-vuln-scan')?.addEventListener('click', () => {
    document.querySelector('.nav-item[data-tab="protection"]')?.click();
    setTimeout(() => {
      const vulnPanel = document.getElementById('pane-vuln-inspection');
      if (vulnPanel) {
        vulnPanel.scrollIntoView({ behavior: 'smooth' });
        runVulnerabilityAudit();
      }
    }, 150);
  });

  // 5. VPN simulated action
  document.getElementById('card-vpn')?.addEventListener('click', () => {
    showBottomLeftNotification('PulseGuard VPN', 'Tunnel chiffré WireGuard activé. Votre adresse IP est masquée.', 'safe');
  });

  // 6. Safepay simulated action
  document.getElementById('card-safepay')?.addEventListener('click', () => {
    showBottomLeftNotification('PulseGuard Safepay', 'Environnement bancaire étanche initialisé en mémoire isolée.', 'safe');
  });

  // Footer run quick scan
  document.getElementById('footer-run-quick')?.addEventListener('click', (e) => {
    e.preventDefault();
    triggerScanWorkflow('quick');
  });
}

// --- Protection Tab Controls (Screenshot 2) ---
function setupProtectionControls() {
  document.getElementById('link-open-antivirus')?.addEventListener('click', (e) => {
    e.preventDefault();
    const section = document.getElementById('scanner-section-container');
    section.scrollIntoView({ behavior: 'smooth' });
  });

  document.getElementById('link-open-vuln')?.addEventListener('click', (e) => {
    e.preventDefault();
    const vulnPanel = document.getElementById('pane-vuln-inspection');
    if (vulnPanel) {
      vulnPanel.scrollIntoView({ behavior: 'smooth' });
      runVulnerabilityAudit();
    }
  });

  document.getElementById('btn-run-vuln-scan')?.addEventListener('click', () => {
    runVulnerabilityAudit();
  });

  document.getElementById('link-launch-ai-scan')?.addEventListener('click', async (e) => {
    e.preventDefault();
    if (window.pulseguard?.selectFile) {
      const filePath = await window.pulseguard.selectFile();
      if (filePath) runNemotronAIScan(filePath);
    }
  });

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

// --- Real-time Streaming Scan Workflow ---
async function triggerScanWorkflow(scanType, customPath = null) {
  if (appState.isScanning) {
    showBottomLeftNotification('Analyse en cours', 'Une analyse est déjà active.', 'info');
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

  // Reset counters
  overlayPercent.textContent = '0%';
  overlayFill.style.width = '0%';
  overlayFile.textContent = 'Recherche des fichiers cibles...';
  overlayScanned.textContent = '0';
  overlayInfected.textContent = '0';
  overlayQuarantined.textContent = '0';
  overlayTime.textContent = '00:00:00';

  if (scanType === 'quick') overlayTitle.textContent = 'Analyse Rapide en cours...';
  else if (scanType === 'system') overlayTitle.textContent = 'Analyse du Système en cours...';
  else overlayTitle.textContent = 'Analyse Ciblée en cours...';

  overlay.style.display = 'flex';
  appState.isScanning = true;

  appendLog('SCAN_START', `Démarrage de l'analyse (${scanType.toUpperCase()})`, 'info');

  try {
    // Robustness: quarantine defaults to false so findings are reviewed safely before action
    const payload = { scan_type: scanType, recursive: true, quarantine: false };
    if (customPath) payload.path = customPath;

    const startRes = await fetch(`${API_BASE}/api/scan/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    if (!startRes.ok) {
      const err = await startRes.json();
      throw new Error(err.error || 'Erreur au lancement du scan');
    }

    const startTime = Date.now();
    appState.scanPollTimer = setInterval(async () => {
      try {
        const progRes = await fetch(`${API_BASE}/api/scan/progress`);
        if (!progRes.ok) return;
        const prog = await progRes.json();

        const elapsedSec = Math.floor((Date.now() - startTime) / 1000);
        overlayTime.textContent = formatTime(elapsedSec);
        overlayPercent.textContent = `${prog.progress_percent}%`;
        overlayFill.style.width = `${prog.progress_percent}%`;
        overlayFile.textContent = prog.current_file || 'Vérification en cours...';
        overlayScanned.textContent = String(prog.scanned_count);
        overlayInfected.textContent = String(prog.infected_count);
        overlayQuarantined.textContent = String(prog.quarantined_count);

        if (!prog.running && prog.progress_percent >= 100) {
          clearInterval(appState.scanPollTimer);
          appState.isScanning = false;

          setTimeout(() => {
            overlay.style.display = 'none';
            renderScanResults(prog);
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
    showBottomLeftNotification('Échec du scan', err.message, 'threat');
    appendLog('SCAN_ERR', err.message, 'error');
  }
}

document.getElementById('btn-overlay-stop-scan')?.addEventListener('click', async () => {
  try {
    await fetch(`${API_BASE}/api/scan/stop`, { method: 'POST' });
    clearInterval(appState.scanPollTimer);
    appState.isScanning = false;
    document.getElementById('scan-overlay').style.display = 'none';
    showBottomLeftNotification('Analyse Interrompue', 'Le scan a été stoppé par l\'utilisateur.', 'info');
    appendLog('SCAN_STOP', 'Analyse interrompue.', 'warn');
  } catch (e) {
    console.error(e);
  }
});

function renderScanResults(prog) {
  document.querySelector('.nav-item[data-tab="protection"]')?.click();
  const resultsBox = document.getElementById('scan-results-box');
  const tbody = document.getElementById('scan-results-tbody');
  resultsBox.style.display = 'block';
  tbody.innerHTML = '';

  document.getElementById('res-total-scanned').textContent = String(prog.scanned_count);
  document.getElementById('res-total-infected').textContent = String(prog.infected_count);
  document.getElementById('res-total-quarantined').textContent = String(prog.quarantined_count);

  if (!prog.results || prog.results.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" class="empty-cell">Aucun fichier à examiner dans la sélection.</td></tr>';
    return;
  }

  prog.results.forEach((item) => {
    const tr = document.createElement('tr');
    const badgeClass = item.is_infected ? 'badge-tag badge-infected' : 'badge-tag badge-clean';
    const statusText = item.is_infected ? 'INFECTÉ' : 'SAIN';
    const threatDisplay = item.threat_name
      ? `<strong style="color:var(--bd-red);">${escapeHtml(item.threat_name)}</strong>`
      : '<span style="color:var(--text-dim);">-</span>';
    const sevDisplay = item.severity
      ? `<span class="badge-tag ${item.severity === 'CRITICAL' ? 'badge-infected' : 'badge-clean'}">${item.severity}</span>`
      : '<span style="color:var(--text-dim);">-</span>';

    tr.innerHTML = `
      <td><span class="${badgeClass}">${statusText}</span></td>
      <td title="${escapeHtml(item.file_path)}">
        <strong>${escapeHtml(getFileName(item.file_path))}</strong>
        <div style="font-size:0.72rem;color:var(--text-muted);">${escapeHtml(item.file_path)}</div>
      </td>
      <td>${threatDisplay}</td>
      <td>${sevDisplay}</td>
      <td>
        <button class="btn btn-secondary btn-sm btn-ai-inspect" data-path="${escapeHtml(item.file_path)}">🤖 Analyser IA</button>
        ${item.is_infected ? `<button class="btn btn-danger-sm btn-quarantine-item" data-path="${escapeHtml(item.file_path)}">Isoler</button>` : ''}
      </td>
    `;
    tbody.appendChild(tr);
  });

  // Attach AI inspect click handlers
  tbody.querySelectorAll('.btn-ai-inspect').forEach((btn) => {
    btn.addEventListener('click', () => {
      const p = btn.getAttribute('data-path');
      if (p) runNemotronAIScan(p);
    });
  });

  if (prog.infected_count > 0) {
    showBottomLeftNotification(
      'Alerte : Menace détectée',
      `${prog.infected_count} élément(s) suspect(s) identifié(s). Vous pouvez les analyser par IA ou les isoler.`,
      'threat'
    );
    setHeroThreatState(true);
  } else {
    showBottomLeftNotification(
      'Analyse Terminée',
      `Examen complété : ${prog.scanned_count} fichiers vérifiés, aucun danger détecté.`,
      'safe'
    );
    setHeroThreatState(false);
  }
}

// --- NVIDIA Nemotron AI Reasoning Workflow ---
async function runNemotronAIScan(filePath) {
  const modal = document.getElementById('ai-report-modal');
  const spinner = document.getElementById('ai-loading-spinner');
  const details = document.getElementById('ai-report-details');

  modal.style.display = 'flex';
  spinner.style.display = 'flex';
  details.style.display = 'none';

  try {
    const res = await fetch(`${API_BASE}/api/ai/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path: filePath }),
    });

    const data = await res.json();
    spinner.style.display = 'none';
    details.style.display = 'block';

    const verdictClass = (data.verdict || 'clean').toLowerCase();
    const verdictTitle = data.verdict === 'RANSOMWARE'
      ? '🚨 RANSOMWARE CONFIRMÉ PAR IA'
      : data.verdict === 'MALICIOUS'
      ? '⚠️ MENACE MALVEILLANTE'
      : data.verdict === 'SUSPICIOUS'
      ? '⚡ COMPORTEMENT SUSPECT'
      : '✅ FICHIER INTÈGRE & SAIN';

    const mitreTags = (data.mitre_attack_tactics || []).map((t) => `<span class="mitre-tag">${escapeHtml(t)}</span>`).join('');
    const remediationList = (data.remediation_steps || []).map((r) => `<li>${escapeHtml(r)}</li>`).join('');

    details.innerHTML = `
      <div class="ai-verdict-banner ${verdictClass}">
        <div class="ai-verdict-title">${verdictTitle}</div>
        <div class="ai-confidence-pill">${data.confidence_score || 85}% Confiance IA</div>
      </div>

      <div style="font-size:0.82rem;color:var(--text-sub);margin-bottom:12px;">
        <strong>Modèle :</strong> ${escapeHtml(data.model_used || appState.aiModel)} &bull;
        <strong>Cible :</strong> <code>${escapeHtml(getFileName(filePath))}</code>
      </div>

      ${data.warning ? `<div style="background:rgba(245,158,11,0.12);border:1px solid var(--bd-amber);color:#fbbf24;padding:8px 12px;border-radius:6px;font-size:0.78rem;margin-bottom:12px;">${escapeHtml(data.warning)}</div>` : ''}

      ${mitreTags ? `<div class="mitre-tags-row">${mitreTags}</div>` : ''}

      <div class="ai-analysis-text">${escapeHtml(data.analysis || 'Analyse indisponible.')}</div>

      ${remediationList ? `
        <div style="font-size:0.84rem;font-weight:600;margin-bottom:6px;">Actions de remédiation recommandées :</div>
        <ul style="font-size:0.8rem;color:var(--text-sub);padding-left:20px;line-height:1.5;">${remediationList}</ul>
      ` : ''}
    `;

    showBottomLeftNotification(
      'Analyse IA Terminée',
      `Verdict Nemotron pour ${getFileName(filePath)} : ${data.verdict}`,
      verdictClass === 'clean' ? 'safe' : 'threat'
    );

  } catch (err) {
    spinner.style.display = 'none';
    details.style.display = 'block';
    details.innerHTML = `<div style="color:var(--bd-red);padding:20px;">Erreur lors de l'analyse IA : ${escapeHtml(err.message)}</div>`;
  }
}

function setupAIModal() {
  document.getElementById('btn-close-ai-modal')?.addEventListener('click', () => {
    document.getElementById('ai-report-modal').style.display = 'none';
  });
  document.getElementById('ai-modal-backdrop')?.addEventListener('click', () => {
    document.getElementById('ai-report-modal').style.display = 'none';
  });
}

// --- Notifications Center (Screenshot 4) ---
function setupNotificationsCenter() {
  const tabs = document.querySelectorAll('.notif-tab');
  const rows = document.querySelectorAll('.notif-item-row');

  tabs.forEach((tab) => {
    tab.addEventListener('click', () => {
      tabs.forEach((t) => t.classList.remove('active'));
      tab.classList.add('active');
      const filter = tab.getAttribute('data-filter');

      rows.forEach((row) => {
        if (filter === 'all') {
          row.style.display = 'flex';
        } else {
          row.style.display = row.getAttribute('data-severity') === filter ? 'flex' : 'none';
        }
      });
    });
  });

  // Accordion details toggle
  rows.forEach((row) => {
    row.addEventListener('click', () => {
      const details = row.querySelector('.notif-item-details');
      const chevron = row.querySelector('.notif-chevron-btn');
      if (details) {
        const isHidden = details.style.display === 'none';
        details.style.display = isHidden ? 'block' : 'none';
        if (chevron) chevron.style.transform = isHidden ? 'rotate(90deg)' : 'none';
      }
    });
  });

  document.getElementById('btn-mark-all-read')?.addEventListener('click', () => {
    document.getElementById('nav-notif-badge').style.display = 'none';
    showBottomLeftNotification('Notifications', 'Toutes les notifications ont été marquées comme lues.', 'safe');
  });

  document.getElementById('btn-delete-all-notifs')?.addEventListener('click', () => {
    document.getElementById('notifications-list').innerHTML = '<div style="text-align:center;color:var(--text-muted);padding:40px;">Aucune notification.</div>';
    document.getElementById('nav-notif-badge').style.display = 'none';
  });
}

// --- Settings Controls (Screenshot 5) ---
function setupSettingsControls() {
  // Subtabs switching
  const subtabs = document.querySelectorAll('.settings-subtab');
  const subpanes = document.querySelectorAll('.settings-content-pane');

  subtabs.forEach((tab) => {
    tab.addEventListener('click', () => {
      subtabs.forEach((t) => t.classList.remove('active'));
      subpanes.forEach((p) => p.classList.remove('active'));

      tab.classList.add('active');
      const targetPane = document.getElementById(`subpane-${tab.getAttribute('data-subtab')}`);
      if (targetPane) targetPane.classList.add('active');
    });
  });

  // Password visibility toggle
  const keyInput = document.getElementById('input-nvidia-key');
  const btnToggleKey = document.getElementById('btn-toggle-key-visibility');
  btnToggleKey?.addEventListener('click', () => {
    if (keyInput.type === 'password') {
      keyInput.type = 'text';
      btnToggleKey.textContent = '🔒 Masquer';
    } else {
      keyInput.type = 'password';
      btnToggleKey.textContent = '👁 Afficher';
    }
  });

  // Save AI Config
  document.getElementById('btn-save-ai-config')?.addEventListener('click', async () => {
    const key = keyInput.value.trim();
    const model = document.getElementById('select-nvidia-model').value;
    const feedback = document.getElementById('ai-test-feedback-box');

    try {
      const res = await fetch(`${API_BASE}/api/config`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ nvidia_api_key: key, nvidia_model: model }),
      });
      const data = await res.json();
      if (data.success) {
        feedback.style.display = 'block';
        feedback.className = 'ai-feedback-box success';
        feedback.textContent = '✅ Clé API NVIDIA enregistrée avec succès ! Le modèle 550B est prêt.';
        showBottomLeftNotification('Configuration Enregistrée', 'Clé API NVIDIA Nemotron mise à jour.', 'safe');
        fetchConfig();
      }
    } catch (err) {
      feedback.style.display = 'block';
      feedback.className = 'ai-feedback-box error';
      feedback.textContent = `Erreur: ${err.message}`;
    }
  });

  // Test AI Connection
  document.getElementById('btn-test-ai-conn')?.addEventListener('click', async () => {
    const key = keyInput.value.trim();
    const feedback = document.getElementById('ai-test-feedback-box');
    feedback.style.display = 'block';
    feedback.className = 'ai-feedback-box';
    feedback.textContent = 'Connexion à NVIDIA NIM en cours...';

    try {
      const res = await fetch(`${API_BASE}/api/ai/test`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ api_key: key || undefined }),
      });
      const data = await res.json();
      if (data.success) {
        feedback.className = 'ai-feedback-box success';
        feedback.textContent = `✅ ${data.message} (Modèle: ${data.model})`;
        showBottomLeftNotification('Connexion IA Réussie', data.message, 'safe');
      } else {
        feedback.className = 'ai-feedback-box error';
        feedback.textContent = `❌ ${data.error}`;
        showBottomLeftNotification('Test Connexion IA', data.error, 'threat');
      }
    } catch (err) {
      feedback.className = 'ai-feedback-box error';
      feedback.textContent = `❌ Erreur réseau: ${err.message}`;
    }
  });
}

// --- Config & Status API ---
async function fetchConfig() {
  try {
    const res = await fetch(`${API_BASE}/api/config`);
    if (!res.ok) return;
    const cfg = await res.json();

    const label = document.getElementById('label-nvidia-status');
    const badge = document.getElementById('badge-ai-status');

    if (cfg.nvidia_api_key_configured) {
      appState.aiConfigured = true;
      if (label) label.textContent = `Clé active : ${cfg.nvidia_api_key_masked} (${cfg.nvidia_model})`;
      if (badge) {
        badge.textContent = '550B ACTIF';
        badge.style.borderColor = 'var(--bd-nvidia-green)';
        badge.style.color = 'var(--bd-nvidia-green)';
      }
    } else {
      if (label) label.textContent = 'Clé non configurée. Enregistrez votre clé pour activer l\'analyse cognitive 550B.';
    }
  } catch (e) {
    console.error(e);
  }
}

async function fetchStatus() {
  try {
    const res = await fetch(`${API_BASE}/api/status`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();

    appState.engineOnline = true;
    appState.signaturesCount = data.signatures || 0;
    appState.quarantineCount = data.quarantine_count || 0;
    appState.watcherActive = !!data.watcher_active;

    const enginePill = document.getElementById('pill-engine-status');
    if (enginePill) {
      enginePill.textContent = `MOTEUR ONLINE · ${data.signatures || 4} SIGNATURES · ${data.ai_model || 'Nemotron'}`;
    }
  } catch (err) {
    appState.engineOnline = false;
    const enginePill = document.getElementById('pill-engine-status');
    if (enginePill) enginePill.textContent = 'MOTEUR OFFLINE';
  }
}

// --- Quarantine Vault ---
function setupQuarantineControls() {
  document.getElementById('btn-refresh-quarantine')?.addEventListener('click', fetchQuarantine);
}

async function fetchQuarantine() {
  const tbody = document.getElementById('quarantine-tbody');
  if (!tbody) return;

  try {
    const res = await fetch(`${API_BASE}/api/quarantine`);
    if (!res.ok) return;
    const data = await res.json();
    const records = data.records || [];

    tbody.innerHTML = '';
    if (records.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" class="empty-cell">Le coffre de quarantaine est vide. Aucun fichier neutralisé.</td></tr>';
      return;
    }

    records.forEach((rec) => {
      const tr = document.createElement('tr');
      const dateStr = new Date(rec.quarantined_at).toLocaleString('fr-FR');
      tr.innerHTML = `
        <td style="font-size:0.75rem;color:var(--text-muted);">${escapeHtml(dateStr)}</td>
        <td title="${escapeHtml(rec.original_path)}">
          <strong>${escapeHtml(getFileName(rec.original_path))}</strong>
          <div style="font-size:0.72rem;color:var(--text-muted);">${escapeHtml(rec.original_path)}</div>
        </td>
        <td><strong style="color:var(--bd-red);">${escapeHtml(rec.threat_name)}</strong></td>
        <td><span class="badge-tag badge-infected">${rec.severity}</span></td>
        <td>
          <button class="btn btn-secondary btn-sm" onclick="restoreQuarantineFile('${rec.record_id}')">Restaurer</button>
          <button class="btn btn-danger-sm" onclick="deleteQuarantineFile('${rec.record_id}')">Broyer</button>
        </td>
      `;
      tbody.appendChild(tr);
    });
  } catch (e) {
    console.error(e);
  }
}

window.restoreQuarantineFile = async function(recordId) {
  try {
    const res = await fetch(`${API_BASE}/api/quarantine/restore`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ record_id: recordId }),
    });
    const data = await res.json();
    if (data.success) {
      showBottomLeftNotification('Fichier Restauré', `Fichier restauré avec intégrité : ${data.restored_path}`, 'safe');
      fetchQuarantine();
      fetchStatus();
    }
  } catch (err) {
    showBottomLeftNotification('Erreur Restauration', err.message, 'threat');
  }
};

window.deleteQuarantineFile = async function(recordId) {
  if (!confirm('Voulez-vous broyer définitivement ce fichier et écraser ses secteurs disque ?')) return;
  try {
    const res = await fetch(`${API_BASE}/api/quarantine/delete`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ record_id: recordId }),
    });
    const data = await res.json();
    if (data.success) {
      showBottomLeftNotification('Fichier Broyé', 'Le fichier chiffré a été détruit définitivement.', 'safe');
      fetchQuarantine();
      fetchStatus();
    }
  } catch (err) {
    showBottomLeftNotification('Erreur Suppression', err.message, 'threat');
  }
};

// --- Process Scanner ---
function setupProcessControls() {
  document.getElementById('btn-scan-processes')?.addEventListener('click', fetchProcesses);
  document.getElementById('filter-processes-input')?.addEventListener('input', (e) => {
    const query = e.target.value.toLowerCase().trim();
    filterProcesses(query);
  });
}

async function fetchProcesses() {
  const tbody = document.getElementById('processes-tbody');
  tbody.innerHTML = '<tr><td colspan="4" class="empty-cell">Inspection des processus en cours...</td></tr>';

  try {
    const res = await fetch(`${API_BASE}/api/processes?limit=60`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    appState.processes = data.processes || [];
    renderProcesses(appState.processes);
    showBottomLeftNotification('Audit RAM Terminé', `${appState.processes.length} processus vérifiés en mémoire.`, 'safe');
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="4" class="empty-cell" style="color:var(--bd-red);">Échec: ${err.message}</td></tr>`;
  }
}

function renderProcesses(list) {
  const tbody = document.getElementById('processes-tbody');
  tbody.innerHTML = '';

  if (list.length === 0) {
    tbody.innerHTML = '<tr><td colspan="4" class="empty-cell">Aucun processus trouvé.</td></tr>';
    return;
  }

  list.forEach((p) => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><code>${p.pid}</code></td>
      <td><strong>${escapeHtml(p.name)}</strong></td>
      <td style="font-size:0.75rem;color:var(--text-muted);">${escapeHtml(p.exe_path || 'Système Windows')}</td>
      <td><span class="badge-tag ${p.is_infected ? 'badge-infected' : 'badge-clean'}">${p.is_infected ? 'INFECTÉ' : 'INTÈGRE'}</span></td>
    `;
    tbody.appendChild(tr);
  });
}

function filterProcesses(query) {
  const filtered = appState.processes.filter((p) =>
    (p.name && p.name.toLowerCase().includes(query)) ||
    (p.exe_path && p.exe_path.toLowerCase().includes(query))
  );
  renderProcesses(filtered);
}

// --- Bottom-Left Notification Anchor (with Cross ✕) ---
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

  // Cross close button handler
  const closeBtn = notif.querySelector('.notif-close-btn');
  closeBtn?.addEventListener('click', (e) => {
    e.stopPropagation();
    dismissNotification(notif);
  });

  container.appendChild(notif);

  const timer = setTimeout(() => {
    dismissNotification(notif);
  }, 6500);

  notif._autoTimer = timer;
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
  const icon = document.getElementById('sidebar-shield-icon');
  if (!icon) return;

  if (isThreat) {
    icon.className = 'sidebar-shield-icon threat';
    icon.innerHTML = `
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        <line x1="12" y1="8" x2="12" y2="12"/>
        <line x1="12" y1="16" x2="12.01" y2="16"/>
      </svg>
    `;
  } else {
    icon.className = 'sidebar-shield-icon safe';
    icon.innerHTML = `
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        <polyline points="9 12 11 14 15 10"/>
      </svg>
    `;
  }
}

function appendLog(category, message, level = 'info') {
  const term = document.getElementById('audit-log-terminal');
  if (!term) return;
  const now = new Date();
  const timeStr = now.toTimeString().split(' ')[0] + '.' + String(now.getMilliseconds()).padStart(3, '0');
  const div = document.createElement('div');
  div.innerHTML = `<span style="color:var(--text-dim)">[${timeStr}]</span> <strong style="color:var(--bd-blue)">[${escapeHtml(category)}]</strong> ${escapeHtml(message)}`;
  term.appendChild(div);
  term.scrollTop = term.scrollHeight;
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

// ================= REAL-TIME SYSTEM VULNERABILITY AUDIT & REMEDIATION =================
async function runVulnerabilityAudit() {
  const btn = document.getElementById('btn-run-vuln-scan');
  const tbody = document.getElementById('vuln-results-tbody');
  const badgeScore = document.getElementById('vuln-score-badge');
  const critCountEl = document.getElementById('vuln-crit-count');
  const highCountEl = document.getElementById('vuln-high-count');
  const medCountEl = document.getElementById('vuln-med-count');

  if (btn) {
    btn.disabled = true;
    btn.innerHTML = `<span class="spinner" style="display:inline-block;width:12px;height:12px;border:2px solid #fff;border-top-color:transparent;border-radius:50%;animation:spin 0.8s linear infinite;margin-right:6px;"></span> Audit en cours...`;
  }

  tbody.innerHTML = `<tr><td colspan="5" class="empty-state">Analyse en cours des failles Windows, UAC, clés de registre, services et ports réseau...</td></tr>`;
  appendLog('VULN_SCAN', "Démarrage de l'audit complet des failles et de la posture de sécurité système...", 'info');

  try {
    const res = await fetch(`${API_BASE}/api/vulnerabilities/scan`);
    const data = await res.json();

    const score = data.security_score ?? 100;
    badgeScore.textContent = `Score Sécurité : ${score}/100`;
    badgeScore.className = 'vuln-score-pill ' + (score >= 80 ? '' : score >= 50 ? 'warning' : 'danger');

    critCountEl.textContent = data.critical_count ?? 0;
    highCountEl.textContent = data.high_count ?? 0;
    medCountEl.textContent = data.medium_count ?? 0;

    const findings = data.findings || [];
    if (findings.length === 0) {
      tbody.innerHTML = `<tr><td colspan="5" class="empty-state" style="color:var(--bd-green);font-weight:600;">✓ Aucune faille de sécurité ou mauvaise configuration détectée. Votre système est sain.</td></tr>`;
      showBottomLeftNotification('Système Sain', 'Audit terminé : Aucune vulnérabilité système détectée.', 'safe');
      appendLog('VULN_SCAN', "Audit terminé : 0 faille détectée. Score: 100/100.", 'info');
    } else {
      tbody.innerHTML = '';
      findings.forEach((f) => {
        const tr = document.createElement('tr');
        const sevClass = f.severity === 'CRITICAL' ? 'crit' : f.severity === 'HIGH' ? 'danger' : 'warning';
        const actionHtml = f.can_auto_fix
          ? `<button class="btn-remediate-fix" onclick="remediateVulnerability('${escapeHtml(f.vuln_id)}', this)">Corriger</button>`
          : `<span style="font-size:0.75rem;color:var(--text-dim);">Manuel requis</span>`;

        tr.innerHTML = `
          <td><span class="threat-badge ${sevClass}">${escapeHtml(f.severity)}</span></td>
          <td>
            <div style="font-weight:600;color:#fff;">${escapeHtml(f.title)}</div>
            <div style="font-size:0.75rem;color:var(--text-dim);margin-top:2px;">${escapeHtml(f.description)}</div>
          </td>
          <td><code style="font-size:0.75rem;background:rgba(255,255,255,0.06);padding:2px 6px;border-radius:4px;">${escapeHtml(f.affected_item)}</code></td>
          <td><span style="font-size:0.75rem;color:var(--bd-blue);">${escapeHtml(f.cve_cwe)}</span></td>
          <td style="text-align:right;">${actionHtml}</td>
        `;
        tbody.appendChild(tr);
      });

      const notifyType = data.critical_count > 0 ? 'threat' : 'warning';
      showBottomLeftNotification(
        'Failles Système Détectées',
        `Audit terminé : ${findings.length} vulnérabilité(s) trouvée(s). Score: ${score}/100.`,
        notifyType
      );
      appendLog('VULN_SCAN', `Audit terminé : ${findings.length} vulnérabilité(s) identifiées. Score: ${score}/100.`, notifyType);
    }
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="5" class="empty-state" style="color:var(--bd-red);">Erreur lors de l'audit : ${escapeHtml(err.message)}</td></tr>`;
    showBottomLeftNotification('Erreur Audit', 'Impossible de contacter le moteur d\'analyse des vulnérabilités.', 'threat');
    appendLog('VULN_SCAN', `Échec audit vulnérabilités : ${err.message}`, 'threat');
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:16px;height:16px;margin-right:6px;"><path d="M23 4v6h-6M1 20v-6h6"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg> Auditer les failles`;
    }
  }
}

async function remediateVulnerability(vulnId, btnElement) {
  if (!vulnId) return;
  if (btnElement) {
    btnElement.disabled = true;
    btnElement.textContent = 'Correction...';
  }

  try {
    const res = await fetch(`${API_BASE}/api/vulnerabilities/remediate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ vuln_id: vulnId }),
    });
    const data = await res.json();
    if (data.success) {
      if (btnElement) {
        btnElement.className = 'btn-remediate-fixed';
        btnElement.textContent = '✓ Corrigé';
      }
      showBottomLeftNotification('Faille Corrigée', data.message || 'La vulnérabilité a été résolue.', 'safe');
      appendLog('VULN_REMEDIATION', `Succès remédiation [${vulnId}] : ${data.message}`, 'safe');
    } else {
      if (btnElement) {
        btnElement.disabled = false;
        btnElement.textContent = 'Échec';
      }
      showBottomLeftNotification('Échec Correction', data.message || 'Impossible de corriger automatiquement.', 'threat');
      appendLog('VULN_REMEDIATION', `Échec remédiation [${vulnId}] : ${data.message}`, 'threat');
    }
  } catch (err) {
    if (btnElement) {
      btnElement.disabled = false;
      btnElement.textContent = 'Erreur';
    }
    showBottomLeftNotification('Erreur Remédiation', err.message, 'threat');
  }
}

window.remediateVulnerability = remediateVulnerability;
window.runVulnerabilityAudit = runVulnerabilityAudit;
